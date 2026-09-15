#include <cassert>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <intrin.h>
#include <iostream>
#include <malloc.h>
#include <mutex>
#include <thread>
#include <cstdio>
#include <fstream>
#include <atomic>

#include <PEMapper/pefile.h>

#include <Logger/Logger.h>
#include "core/io/usermode_client.h"
#include <thread>
#include <SymParser/symparser.hpp>

#include "host/config/config.h"
#include "core/exec/unicorn_engine.h"
#include "core/exec/timing_spoof.h"
#include "core/exec/target_compat.h"
#include "core/memory/unicorn_memory.h"
#include "core/profile/active_profile.h"
#include "core/hardware/hardware_runtime.h"
#include "core/memory/guest_memory_runtime.h"
#include "core/process/unicorn_threading.h"
#include "core/loader/environment.h"
#include "core/loader/kernel_structs.h"

#include "host/providers/ntoskrnl_provider.h"
#include "host/providers/static_export_provider.h"
#include "host/providers/provider.h"
#include "host/providers/export_contract_runtime.h"
#include "host/providers/usermode_provider.h"
#include "api/io/flt_filter.h"
#include "api/ob/cm_callback.h"
#include "api/ob/ob_object.h"
#include "api/ps/ps_process.h"
#include "core/registry/virtual_fs.h"
#include "core/diagnostics/diag_center.h"
#include "core/devirt/vtil_analysis.h"
#include "api/io/io_device.h"
#include "api/nt/nt_memory.h"
#include "api/ke/ke_misc.h"
#include "api/ke/ke_sync.h"
#include "api/ke/ke_timer.h"
#include "api/ke/ke_event.h"
#include "core/coverage/edge_coverage.h"

static bool NoPause = false;
static bool TargetCompatEnabled = false;
static bool EacServiceEmu = false;
// Neutralizes a protected driver's DriverEntry guard wrapper so the real initializer
// runs instead of returning the driver's self-test sentinel. See kevlar.cpp usage.
static bool DriverEntryGateBypassEnabled = false;
// Analysis-only memory pre-seeds: --poke <rva>=<hex> writes a 64-bit value into the
// mapped driver image at an RVA once relocation has been applied. Lets a manifest slot
// the file leaves zero (and the loader would normally fill) be supplied for testing.
static std::vector<std::pair<uint64_t, uint64_t>> g_Pokes;
// --watch-rva <rva>[,<rva>...]: log the full register file each time one of these RVAs
// executes (capped per RVA). Answers "what values does this instruction actually see"
// without a debugger, which is what a stalled VM loop needs.
static std::vector<uint64_t> g_WatchRvas;
static std::vector<int> g_WatchHits;
static constexpr int kWatchHitCap = 48;
static std::string AflBitmapPath;
static std::string CoverageBasePath;
static std::string CoverageOutPath;

// advapi32 SDDL API (declared here to avoid windows.h include-order churn)
extern "C" BOOL WINAPI ConvertStringSecurityDescriptorToSecurityDescriptorW(
    LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision,
    PSECURITY_DESCRIPTOR* SecurityDescriptor, PVOID* SecurityDescriptorSize);
static bool SelfTest = false;
bool g_EosServerPipeEnabled = false;
std::unordered_map<uint32_t, uint32_t> g_StatusOverrides;

// Host-level selftest for the ke_* semantics: exercises IRQL, APC queue/delivery,
// DPC queue and timer cancel/periodic directly against the built environment.
// Runs without a target driver; smoke.ps1 invokes `KEVLAR.exe --selftest`.
static int RunSelfTest() {
    int Fails = 0;
    auto Check = [&Fails](bool Cond, const char* Msg) {
        if (Cond)
            Logger::Log("{GRN}  [PASS] %s{RESET}\n", Msg);
        else {
            Logger::Log("{RED}  [FAIL] %s{RESET}\n", Msg);
            Fails++;
        }
    };

    const uint64_t SelftestBase = 0xFFFFF10000000000ULL;
    const uint64_t RegionSize = 0x1000;
    void* RegionHost = _aligned_malloc((size_t)RegionSize, 0x1000);
    if (!RegionHost) { Logger::Log("{RED}selftest: region alloc failed{RESET}\n"); return 1; }
    memset(RegionHost, 0, (size_t)RegionSize);
    if (!UnicornEmu::MapRegionPtr(UnicornEmu::PrimaryEngine, SelftestBase, RegionSize, UC_PROT_ALL, RegionHost, "SelftestRegion")) {
        Logger::Log("{RED}selftest: region map failed{RESET}\n");
        return 1;
    }
    UnicornMem::TrackExisting(SelftestBase, RegionHost, RegionSize, "SelftestRegion");

    uint8_t* R = (uint8_t*)RegionHost;
    // Guest routines (position-independent):
    //   APC:  rax=[r8]; [rax]=0x41414141; ret     (r8 = &Apc->NormalContext)
    //   DPC:  rax=rdx; [rax]=0x42424242; ret       (rdx = DeferredContext)
    //   cancel/timer probes: same shape, distinct markers
    static const uint8_t ApcRoutine[]  = { 0x49, 0x8B, 0x00, 0xC7, 0x00, 0x41, 0x41, 0x41, 0x41, 0xC3 };
    static const uint8_t DpcRoutine[]  = { 0x48, 0x89, 0xD0, 0xC7, 0x00, 0x42, 0x42, 0x42, 0x42, 0xC3 };
    static const uint8_t CancelRoutine[] = { 0x48, 0x89, 0xD0, 0xC7, 0x00, 0x43, 0x43, 0x43, 0x43, 0xC3 };
    static const uint8_t TimerRoutine[] = { 0x48, 0x89, 0xD0, 0xC7, 0x00, 0x44, 0x44, 0x44, 0x44, 0xC3 };
    memcpy(R + 0x100, ApcRoutine, sizeof(ApcRoutine));
    memcpy(R + 0x200, DpcRoutine, sizeof(DpcRoutine));
    memcpy(R + 0x300, CancelRoutine, sizeof(CancelRoutine));
    memcpy(R + 0x350, TimerRoutine, sizeof(TimerRoutine));

    const uint64_t ApcMarker = SelftestBase + 0x000;
    const uint64_t DpcMarker = SelftestBase + 0x010;
    const uint64_t CancelMarker = SelftestBase + 0x020;
    const uint64_t TimerMarker = SelftestBase + 0x030;

    // --- IRQL ---
    Logger::Log("{CYN}=== SELFTEST: IRQL ==={RESET}\n");
    UCHAR Old = h_KfRaiseIrql(2);
    Check(Old == 0 && h_KeGetCurrentIrql() == 2, "KfRaiseIrql(2)->0, KeGetCurrentIrql()==2");
    h_KeLowerIrql(0);
    Check(h_KeGetCurrentIrql() == 0, "KeLowerIrql(0)->KeGetCurrentIrql()==0");
    Check(h_KeRaiseIrql(2) == 0 && h_KeGetCurrentIrql() == 2, "KeRaiseIrql(2)->0, KeGetCurrentIrql()==2");
    Check(h_KeRaiseIrqlToDpcLevel() == 2, "KeRaiseIrqlToDpcLevel() at DPC returns old IRQL 2");
    h_KeLowerIrql(0);

    // --- APC: critical region suppresses, delivery runs KernelRoutine ---
    // Structs live in the guest region; pass their guest addresses to the ke_*
    // handlers (UcPtr resolves them), read fields back from the host copies.
    Logger::Log("{CYN}=== SELFTEST: APC ==={RESET}\n");
    uint64_t ApcGuest = SelftestBase + 0x400;
    _KAPC* ApcHost = (_KAPC*)(R + 0x400);
    h_KeInitializeApc((_KAPC*)ApcGuest, (_KTHREAD*)&FakeKernelThread, 0, (void*)(SelftestBase + 0x100), nullptr, nullptr, 0, (void*)ApcMarker);
    h_KeEnterCriticalRegion();
    BOOLEAN Inserted = h_KeInsertQueueApc((_KAPC*)ApcGuest, nullptr, nullptr, 0);
    Check(Inserted && ApcHost->Inserted == 1, "KeInsertQueueApc queued while in critical region");
    h_KeLeaveCriticalRegion();
    h_KeTestAlertThread(0);
    Check(ApcHost->Inserted == 0, "APC delivered after leaving critical region (Inserted cleared)");
    volatile uint32_t* ApcMarkerHost = (volatile uint32_t*)UnicornMem::UcToHost(ApcMarker);
    for (int I = 0; I < 200 && *ApcMarkerHost != 0x41414141; I++) Sleep(10);
    Check(*ApcMarkerHost == 0x41414141, "APC KernelRoutine ran and wrote the marker");

    // --- DPC via KeInsertQueueDpc ---
    Logger::Log("{CYN}=== SELFTEST: DPC ==={RESET}\n");
    uint64_t DpcGuest = SelftestBase + 0x500;
    _KDPC* DpcHost = (_KDPC*)(R + 0x500);
    h_KeInitializeDpc((_KDPC*)DpcGuest, (void*)(SelftestBase + 0x200), (void*)DpcMarker);
    Check((uint64_t)DpcHost->DeferredRoutine == (SelftestBase + 0x200), "KeInitializeDpc stored the routine");
    Check(h_KeInsertQueueDpc((_KDPC*)DpcGuest, nullptr, nullptr), "KeInsertQueueDpc accepted the DPC");
    volatile uint32_t* DpcMarkerHost = (volatile uint32_t*)UnicornMem::UcToHost(DpcMarker);
    for (int I = 0; I < 200 && *DpcMarkerHost != 0x42424242; I++) Sleep(10);
    Check(*DpcMarkerHost == 0x42424242, "DPC routine ran");

    // --- Timer DPC fires; KeCancelTimer prevents a canceled timer's DPC ---
    Logger::Log("{CYN}=== SELFTEST: Timer ==={RESET}\n");
    uint64_t TimerGuest = SelftestBase + 0x600;
    uint64_t TimerDpcGuest = SelftestBase + 0x700;
    LARGE_INTEGER Due; Due.QuadPart = -100000;   // 10ms relative
    h_KeInitializeTimer((_KTIMER*)TimerGuest);
    h_KeInitializeDpc((_KDPC*)TimerDpcGuest, (void*)(SelftestBase + 0x350), (void*)TimerMarker);
    h_KeSetTimer((_KTIMER*)TimerGuest, Due, (_KDPC*)TimerDpcGuest);
    volatile uint32_t* TimerMarkerHost = (volatile uint32_t*)UnicornMem::UcToHost(TimerMarker);
    for (int I = 0; I < 200 && *TimerMarkerHost != 0x44444444; I++) Sleep(10);
    Check(*TimerMarkerHost == 0x44444444, "timer DPC fired after the due time");

    uint64_t CancelTimerGuest = SelftestBase + 0x800;
    uint64_t CancelDpcGuest = SelftestBase + 0x900;
    h_KeInitializeTimer((_KTIMER*)CancelTimerGuest);
    h_KeInitializeDpc((_KDPC*)CancelDpcGuest, (void*)(SelftestBase + 0x300), (void*)CancelMarker);
    h_KeSetTimer((_KTIMER*)CancelTimerGuest, Due, (_KDPC*)CancelDpcGuest);
    Check(h_KeCancelTimer((_KTIMER*)CancelTimerGuest), "KeCancelTimer cancels a pending timer");
    volatile uint32_t* CancelMarkerHost = (volatile uint32_t*)UnicornMem::UcToHost(CancelMarker);
    Sleep(100);
    Check(*CancelMarkerHost == 0, "canceled timer's DPC did not fire");

    Logger::Log("{CYN}=== SELFTEST %s (%d failures) ==={RESET}\n", Fails == 0 ? "PASS" : "FAIL", Fails);
    return Fails == 0 ? 0 : 1;
}

__forceinline void InitDirs() {
    char ExePath[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, ExePath, MAX_PATH);
    std::string ExePathStr = ExePath;
    auto LastSlash = ExePathStr.find_last_of("\\/");
    if (LastSlash != std::string::npos)
        KevlarGlobal::ExeDir = ExePathStr.substr(0, LastSlash + 1);
    else
        KevlarGlobal::ExeDir = ".\\";

    auto CacheDir = KevlarGlobal::GetCacheDir();
    std::filesystem::create_directories(CacheDir);
}

int main(int Argc, char* Argv[]) {
    std::set_terminate([]() {
        Logger::Log("{RED}=== std::terminate() called === (thread %u){RESET}\n", GetCurrentThreadId());
        fflush(stdout);
        fflush(stderr);
        abort();
    });

    _set_abort_behavior(0, _WRITE_ABORT_MSG);

    SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* ExInfo) -> LONG {
        auto Rec = ExInfo->ExceptionRecord;
        auto Ctx = ExInfo->ContextRecord;
        Logger::Log("{RED}=== KEVLAR HOST CRASH === (thread %u){RESET}\n", GetCurrentThreadId());
        Logger::Log("{RED}Exception 0x%08x at RIP=0x%llx{RESET}\n", Rec->ExceptionCode, Ctx->Rip);
        HMODULE HMod = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)Ctx->Rip, &HMod);
        if (HMod) {
            char ModName[MAX_PATH] = {};
            GetModuleFileNameA(HMod, ModName, MAX_PATH);
            Logger::Log("{RED}Module: %s + 0x%llx{RESET}\n", ModName, Ctx->Rip - (uint64_t)HMod);
        }
        Logger::Log("{RED}RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx{RESET}\n",
            Ctx->Rax, Ctx->Rbx, Ctx->Rcx, Ctx->Rdx);
        Logger::Log("{RED}RSI=0x%llx RDI=0x%llx RSP=0x%llx RBP=0x%llx{RESET}\n",
            Ctx->Rsi, Ctx->Rdi, Ctx->Rsp, Ctx->Rbp);
        Logger::Log("{RED}R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx{RESET}\n",
            Ctx->R8, Ctx->R9, Ctx->R10, Ctx->R11);
        Logger::Log("{RED}R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx{RESET}\n",
            Ctx->R12, Ctx->R13, Ctx->R14, Ctx->R15);
        if (Rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && Rec->NumberParameters >= 2) {
            Logger::Log("{RED}Access violation: %s address 0x%llx{RESET}\n",
                Rec->ExceptionInformation[0] == 0 ? "read" : "write",
                Rec->ExceptionInformation[1]);
        }
        fflush(stdout);
        fflush(stderr);
        return EXCEPTION_EXECUTE_HANDLER;
    });
    InitDirs();

    auto LogPath = KevlarGlobal::ExeDir + "kevlar.log";
    Logger::InitFile(LogPath.c_str());
    atexit(Logger::CloseFile);

    auto ThreadLogDir = KevlarGlobal::ExeDir + "easyanticheat_threads";
    if (Logger::EnablePerThreadFiles(ThreadLogDir.c_str())) {
        Logger::MarkThreadStart("main");
        Logger::Log("{CYN}Per-thread logging enabled: {WHT}%s{RESET}\n", ThreadLogDir.c_str());
    } else {
        Logger::Log("{YEL}Per-thread logging disabled: failed to initialize thread log folder{RESET}\n");
    }

    DWORD DwMode;
    auto HOut = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(HOut, &DwMode);
    DwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(HOut, DwMode);

    Logger::Log("{CYN}KEVLAR - Kernel Export Virtualization Layer And Runtime{RESET}\n");

    auto PrintUsage = [](const char* Exe) {
        Logger::Log("{WHT}Usage: %s <driver.sys> [options]{RESET}\n", Exe);
        Logger::Log("{WHT}Options:{RESET}\n");
        Logger::Log("  --diag                  Enable diagnostic hooks (slow){RESET}\n");
        Logger::Log("  --no-seh                Disable SEH dispatch{RESET}\n");
        Logger::Log("  --modreads               Enable module read logging{RESET}\n");
        Logger::Log("  --intel                 (no-op) coherent Intel CPU profile is always active{RESET}\n");
        Logger::Log("  --seed <n>              Deterministic seed for TSC jitter (default fixed){RESET}\n");
        Logger::Log("  --vgk-override          Alias: adds 0xC0000022->0 and 0xC000007A->0 to the status override map{RESET}\n");
        Logger::Log("  --devirt                Enable devirtualization testing{RESET}\n");
        Logger::Log("  --strict-exports        Unhandled exports return STATUS_NOT_IMPLEMENTED instead of 0{RESET}\n");
        Logger::Log("  --provenance            Trace branch decisions + API results for rejection paths{RESET}\n");
        Logger::Log("  --trace <file>          Record deterministic execution trace{RESET}\n");
        Logger::Log("  --check <file>          Replay trace; report first divergence{RESET}\n");
        Logger::Log("  --no-pause              Skip final pause; exit ~5s after a no-thread run (automation){RESET}\n");
        Logger::Log("  --workers-deep          Worker threads use the extended emulation loop (SSE-fault dispatch + INSN_INVALID retry); default is raw uc_emu_start vendor parity{RESET}\n");
        Logger::Log("  --eac-service-emu       Create host-side EAC service IPC objects (Global\\EasyAntiCheat_EOSBin section + EventDriver/Game/Module) before DriverEntry{RESET}\n");
        Logger::Log("  --inject-hypervideo      Expose synthetic Hyper-V video module for targets that require it{RESET}\n");
        Logger::Log("  --vtil-rva <rva>        Lift a bounded AMD64 region into optimized VTIL{RESET}\n");
        Logger::Log("  --vtil-size <bytes>     Bytes available to the VTIL lifter (default: 0x5000){RESET}\n");
        Logger::Log("  --target-compat          Enable exact-version status normalization for analysis{RESET}\n");
        Logger::Log("  --gate-bypass            Analysis: neutralize a DriverEntry guard wrapper so the real initializer runs{RESET}\n");
        Logger::Log("  --no-target-compat       Disable exact-version target continuation hooks{RESET}\n");
        Logger::Log("  --vtil-out <file>       VTIL serialization path (default: executable directory){RESET}\n");
        Logger::Log("  --max-insns <n>         Stop DriverEntry after n instructions and report RIP{RESET}\n");
        Logger::Log("  --profile <name|build>  Select a built-in Windows build profile{RESET}\n");
        Logger::Log("  --profile-json <file>  Load a validated build-profile override{RESET}\n");
        Logger::Log("  --selftest              Run the ke_* semantics self-test and exit (no driver){RESET}\n");
        Logger::Log("  --module <path>          Map an additional companion kernel module{RESET}\n");
        Logger::Log("  --afl-bitmap <file>     Write 65536-byte AFL coverage bitmap after emulation{RESET}\n");
        Logger::Log("  --coverage-out <file>   Persist edge coverage snapshot after emulation{RESET}\n");
        Logger::Log("  --coverage-base <file>  Load baseline snapshot; report new edges vs baseline{RESET}\n");
        Logger::Log("  --eos-pipe              Create real named pipe for EOS_AntiCheat_Server NtCreateFile calls{RESET}\n");
        Logger::Log("  --override-status <from>=<to>  Override NTSTATUS after DriverEntry (hex, repeatable; e.g. 0xC0000022=0x0){RESET}\n");
    };

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    Logger::Log("{GRN}Process priority: HIGH, Thread priority: HIGHEST{RESET}\n");

    Logger::Log("{GRY}Downloading NTDLL Symbol...{RESET}");

    symparser::download_symbols("c:\\Windows\\System32\\ntdll.dll");

    Logger::Log("{GRY}Downloading NTOSKRNL Symbol...{RESET}");

    symparser::download_symbols("c:\\Windows\\System32\\ntoskrnl.exe");

    Logger::Log("{GRN}Downloaded Symbols{RESET}");

    if (!UnicornEmu::Initialize()) {
        Logger::Log("{RED}Failed to initialize Unicorn engine{RESET}\n");
        return 1;
    }

    Logger::Log("{GRN}Initialized.{RESET}");


    Logger::Log("{CYN}Loading driver module{RESET}\n");

    std::string DriverPath;
    uint64_t VtilRva = 0;
    uint64_t VtilSize = 0x5000;
    std::string VtilOutputPath;
    bool VtilRequested = false;
    std::string ClientScript;
    int ClientDelay = 120;
    std::string JsonOutPath;

    std::vector<std::string> AdditionalModules;
    for (int I = 1; I < Argc; I++) {
        std::string Arg = Argv[I];
        if (Arg.rfind("--", 0) == 0) {
            if (Arg == "--vgk-override") {
                g_StatusOverrides[0xC0000022u] = 0;
                g_StatusOverrides[0xC000007Au] = 0;
                Logger::Log("{CYN}VGK override: added 0xC0000022->0 and 0xC000007A->0 to status override map{RESET}\n");
            } else if (Arg == "--diag") {
                UnicornEmu::DiagnosticHooksEnabled = true;
                if (!DiagCenter::Instance().IsEnabled())
                    DiagCenter::Instance().Initialize();
                Logger::Log("{YEL}Diagnostic hooks ENABLED (slow mode){RESET}\n");
            } else if (Arg.rfind("--module", 0) == 0) {
                std::string Val = (Arg.size() > 8 && Arg[8] == '=')
                    ? Arg.substr(9) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) {
                    Logger::Log("{RED}--module requires a module path{RESET}\n");
                    return 1;
                }
                AdditionalModules.push_back(std::move(Val));
            } else if (Arg == "--no-seh") {
                UnicornEmu::SehDispatchEnabled = false;
                Logger::Log("{YEL}SEH dispatch DISABLED{RESET}\n");
            } else if (Arg == "--modreads") {
                UnicornEmu::ModuleReadLoggingEnabled = true;
                Logger::Log("{CYN}Module read logging ENABLED{RESET}\n");
            } else if (Arg == "--intel") {
                UnicornEmu::IntelCpuSpoofEnabled = true;
                Logger::Log("{CYN}--intel is a no-op: coherent Intel CPU profile is always active{RESET}\n");
            } else if (Arg.rfind("--profile-json", 0) == 0) {
                std::string Val = (Arg.size() > 14 && Arg[14] == '=')
                    ? Arg.substr(15) : (I + 1 < Argc ? Argv[++I] : "");
                std::ifstream ProfileFile(Val, std::ios::binary);
                if (!ProfileFile) {
                    Logger::Log("{RED}--profile-json cannot open %s{RESET}\n", Val.c_str());
                    return 1;
                }
                std::string Json((std::istreambuf_iterator<char>(ProfileFile)),
                    std::istreambuf_iterator<char>());
                Kevlar::Profile::ValidationResult Validation;
                if (!Kevlar::Profile::ActivateOverride(Json, &Validation)) {
                    for (const auto& Diagnostic : Validation.Diagnostics) {
                        Logger::Log("{RED}Profile %s: %s{RESET}\n",
                            Diagnostic.Path.c_str(), Diagnostic.Message.c_str());
                    }
                    return 1;
                }
            } else if (Arg.rfind("--profile", 0) == 0) {
                std::string Val = (Arg.size() > 9 && Arg[9] == '=')
                    ? Arg.substr(10) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) {
                    Logger::Log("{RED}--profile requires a name or build number{RESET}\n");
                    return 1;
                }
                char* End = nullptr;
                unsigned long Build = strtoul(Val.c_str(), &End, 0);
                Kevlar::Profile::ValidationResult Validation;
                bool Activated = (End && *End == '\\0')
                    ? Kevlar::Profile::ActivateBuild((uint32_t)Build, &Validation)
                    : Kevlar::Profile::ActivateName(Val, &Validation);
                if (!Activated) {
                    Logger::Log("{RED}Unknown or invalid profile: %s{RESET}\n", Val.c_str());
                    return 1;
                }
            } else if (Arg.rfind("--seed", 0) == 0) {
                std::string Val = (Arg.size() > 6 && Arg[6] == '=')
                    ? Arg.substr(7) : (I + 1 < Argc ? Argv[++I] : "");
                if (!Val.empty()) {
                    TimingSeed = strtoull(Val.c_str(), nullptr, 0);
                    Logger::Log("{CYN}Timing seed set to 0x%llx{RESET}\n", TimingSeed);
                } else {
                    Logger::Log("{RED}--seed requires a value (e.g. --seed 0x1234){RESET}\n");
                }
            } else if (Arg.rfind("--devirt", 0) == 0) {
                UnicornEmu::DevirtualizationTest = true;
                Logger::Log("{CYN}Devirtualization Testing ENABLED{RESET}\n");
            } else if (Arg == "--strict-exports") {
                UnicornEmu::StrictExportsEnabled = true;
                Logger::Log("{CYN}Strict exports ENABLED (unhandled -> STATUS_NOT_IMPLEMENTED){RESET}\n");
            } else if (Arg.rfind("--vtil-rva", 0) == 0) {
                std::string Val = (Arg.size() > 10 && Arg[10] == '=')
                    ? Arg.substr(11) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) {
                    Logger::Log("{RED}--vtil-rva requires an RVA{RESET}\n");
                    return 1;
                }
                VtilRva = strtoull(Val.c_str(), nullptr, 0);
                VtilRequested = true;
            } else if (Arg.rfind("--vtil-size", 0) == 0) {
                std::string Val = (Arg.size() > 11 && Arg[11] == '=')
                    ? Arg.substr(12) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) {
                    Logger::Log("{RED}--vtil-size requires a byte count{RESET}\n");
                    return 1;
                }
                VtilSize = strtoull(Val.c_str(), nullptr, 0);
                if (!VtilSize) {
                    Logger::Log("{RED}--vtil-size must be greater than zero{RESET}\n");
                    return 1;
                }
            } else if (Arg.rfind("--vtil-out", 0) == 0) {
                std::string Val = (Arg.size() > 10 && Arg[10] == '=')
                    ? Arg.substr(11) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) {
                    Logger::Log("{RED}--vtil-out requires a file path{RESET}\n");
                    return 1;
                }
                VtilOutputPath = std::move(Val);
            } else if (Arg == "--provenance") {
                UnicornEmu::ProvenanceEnabled = true;
                if (!DiagCenter::Instance().IsEnabled())
                    DiagCenter::Instance().Initialize();
                Logger::Log("{CYN}Provenance tracing ENABLED (branch decisions + API results){RESET}\n");
            } else if (Arg.rfind("--trace", 0) == 0) {
                std::string Val = (Arg.size() > 7 && Arg[7] == '=')
                    ? Arg.substr(8) : (I + 1 < Argc ? Argv[++I] : "");
                if (!Val.empty()) {
                    UnicornEmu::TraceRecordPath = Val;
                    Logger::Log("{CYN}Trace recording to %s{RESET}\n", Val.c_str());
                } else {
                    Logger::Log("{RED}--trace requires a file path{RESET}\n");
                }
            } else if (Arg.rfind("--check", 0) == 0) {
                std::string Val = (Arg.size() > 7 && Arg[7] == '=')
                    ? Arg.substr(8) : (I + 1 < Argc ? Argv[++I] : "");
                if (!Val.empty()) {
                    UnicornEmu::TraceCheckPath = Val;
                    Logger::Log("{CYN}Trace check against %s (differential validation){RESET}\n", Val.c_str());
                } else {
                    Logger::Log("{RED}--check requires a file path{RESET}\n");
                }
            } else if (Arg.rfind("--client-delay", 0) == 0) {
                std::string Val = (Arg.size() > 14 && Arg[14] == '=')
                    ? Arg.substr(15) : (I + 1 < Argc ? Argv[++I] : "");
                ClientDelay = Val.empty() ? 120 : atoi(Val.c_str());
            } else if (Arg.rfind("--client", 0) == 0) {
                std::string Val = (Arg.size() > 8 && Arg[8] == '=')
                    ? Arg.substr(9) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) {
                    Logger::Log("{RED}--client requires a script path{RESET}\n");
                    return 1;
                }
                ClientScript = std::move(Val);
            } else if (Arg == "--target-compat") {
                TargetCompatEnabled = true;
            } else if (Arg == "--gate-bypass") {
                DriverEntryGateBypassEnabled = true;
                Logger::Log("{CYN}DriverEntry gate bypass ENABLED (analysis: neutralizes the entry guard){RESET}\n");
            } else if (Arg.rfind("--poke", 0) == 0) {
                std::string Val = (Arg.size() > 6 && Arg[6] == '=')
                    ? Arg.substr(7) : (I + 1 < Argc ? Argv[++I] : "");
                const auto Eq = Val.find('=');
                if (Val.empty() || Eq == std::string::npos) {
                    Logger::Log("{RED}--poke requires <rva>=<hex64>{RESET}\n");
                    return 1;
                }
                const uint64_t PokeRva = strtoull(Val.substr(0, Eq).c_str(), nullptr, 0);
                const uint64_t PokeVal = strtoull(Val.substr(Eq + 1).c_str(), nullptr, 0);
                g_Pokes.emplace_back(PokeRva, PokeVal);
                Logger::Log("{CYN}Poke queued: drv+0x%llx = 0x%llx{RESET}\n",
                    (unsigned long long)PokeRva, (unsigned long long)PokeVal);
            } else if (Arg.rfind("--watch-rva", 0) == 0) {
                std::string Val = (Arg.size() > 11 && Arg[11] == '=')
                    ? Arg.substr(12) : (I + 1 < Argc ? Argv[++I] : "");
                size_t Start = 0;
                while (Start <= Val.size()) {
                    const size_t Comma = Val.find(',', Start);
                    const std::string Piece = Val.substr(Start, Comma == std::string::npos ? std::string::npos : Comma - Start);
                    if (!Piece.empty()) {
                        g_WatchRvas.push_back(strtoull(Piece.c_str(), nullptr, 0));
                        g_WatchHits.push_back(0);
                    }
                    if (Comma == std::string::npos) break;
                    Start = Comma + 1;
                }
                Logger::Log("{CYN}Watch queued for %zu RVA(s){RESET}\n", g_WatchRvas.size());
            } else if (Arg == "--no-pause") {
                NoPause = true;
            } else if (Arg == "--workers-deep") {
                UnicornEmu::WorkersDeepMode = true;
                Logger::Log("{CYN}Worker deep-mode: extended emulation loop for worker threads{RESET}\n");
            } else if (Arg == "--eac-service-emu") {
                EacServiceEmu = true;
            } else if (Arg.rfind("--json-out", 0) == 0) {
                std::string Val = (Arg.size() > 10 && Arg[10] == '=')
                    ? Arg.substr(11) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) {
                    Logger::Log("{RED}--json-out requires a file path{RESET}\n");
                    return 1;
                }
                JsonOutPath = std::move(Val);
            } else if (Arg == "--no-target-compat") {
                TargetCompatEnabled = false;
            } else if (Arg == "--inject-hypervideo") {
                UnicornEmu::HyperVideoInjectionEnabled = true;
            } else if (Arg.rfind("--max-insns", 0) == 0) {
                std::string Val = (Arg.size() > 11 && Arg[11] == '=')
                    ? Arg.substr(12) : (I + 1 < Argc ? Argv[++I] : "");
                if (!Val.empty()) {
                    UnicornEmu::ExecutionInstructionLimit = strtoull(Val.c_str(), nullptr, 0);
                    if (UnicornEmu::ExecutionInstructionLimit) {
                        Logger::Log("{CYN}DriverEntry instruction limit: %llu{RESET}\n",
                            UnicornEmu::ExecutionInstructionLimit);
                    } else {
                        Logger::Log("{RED}--max-insns must be greater than zero{RESET}\n");
                        return 1;
                    }
                } else {
                    Logger::Log("{RED}--max-insns requires a value{RESET}\n");
                    return 1;
                }
            } else if (Arg.rfind("--afl-bitmap", 0) == 0) {
                std::string Val = (Arg.size() > 12 && Arg[12] == '=')
                    ? Arg.substr(13) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) { Logger::Log("{RED}--afl-bitmap requires a file path{RESET}\n"); return 1; }
                AflBitmapPath = std::move(Val);
            } else if (Arg.rfind("--coverage-base", 0) == 0) {
                std::string Val = (Arg.size() > 15 && Arg[15] == '=')
                    ? Arg.substr(16) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) { Logger::Log("{RED}--coverage-base requires a file path{RESET}\n"); return 1; }
                CoverageBasePath = std::move(Val);
            } else if (Arg.rfind("--coverage-out", 0) == 0) {
                std::string Val = (Arg.size() > 14 && Arg[14] == '=')
                    ? Arg.substr(15) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) { Logger::Log("{RED}--coverage-out requires a file path{RESET}\n"); return 1; }
                CoverageOutPath = std::move(Val);
            } else if (Arg.rfind("--pid-map", 0) == 0) {
                std::string Val = (Arg.size() > 9 && Arg[9] == '=') ? Arg.substr(10) : (I+1<Argc?Argv[++I]:"");
                auto Eq = Val.find('=');
                if (Eq == std::string::npos) { Logger::Log("{RED}--pid-map requires pid=name{RESET}\n"); return 1; }
                uint64_t Pid = strtoull(Val.c_str(), nullptr, 0);
                std::string Name = Val.substr(Eq + 1);
                PsCallbacks::RegisterPidName(Pid, Name);
                Logger::Log("{CYN}--pid-map: PID %llu -> %s{RESET}\n", Pid, Name.c_str());
            } else if (Arg == "--selftest") {
                SelfTest = true;
            } else if (Arg == "--pause")
            {
               system("pause");
            } else if (Arg == "--eos-pipe") {
                g_EosServerPipeEnabled = true;
                Logger::Log("{CYN}EOS AntiCheat_Server pipe emulation ENABLED{RESET}\n");
            } else if (Arg.rfind("--override-status", 0) == 0) {
                std::string Val = (Arg.size() > 17 && Arg[17] == '=')
                    ? Arg.substr(18) : (I + 1 < Argc ? Argv[++I] : "");
                if (Val.empty()) {
                    Logger::Log("{RED}--override-status requires <from>=<to> (e.g. 0xC0000022=0x0){RESET}\n");
                    return 1;
                }
                auto Sep = Val.find('=');
                if (Sep == std::string::npos) {
                    Logger::Log("{RED}--override-status: expected <from>=<to>, got: %s{RESET}\n", Val.c_str());
                    return 1;
                }
                uint32_t From = (uint32_t)strtoul(Val.substr(0, Sep).c_str(), nullptr, 0);
                uint32_t To   = (uint32_t)strtoul(Val.substr(Sep + 1).c_str(), nullptr, 0);
                g_StatusOverrides[From] = To;
                Logger::Log("{CYN}[STATUS OVERRIDE] registered: 0x%08x -> 0x%08x{RESET}\n", From, To);
            } else {
                Logger::Log("{RED}Unknown option: %s{RESET}\n", Arg.c_str());
                PrintUsage(Argv[0]);
                return 1;
            }
        } else {
            if (DriverPath.empty()) {
                DriverPath = Arg;
            } else {
                Logger::Log("{RED}Multiple driver paths specified: %s and %s{RESET}\n", DriverPath.c_str(), Arg.c_str());
                PrintUsage(Argv[0]);
                return 1;
            }
        }
    }
    if (!DriverPath.empty()
        && _stricmp(std::filesystem::path(DriverPath).filename().string().c_str(),
            "FACEIT_AC.sys") == 0) {
        const std::string Companion = "C:\\Windows\\System32\\drivers\\FACEIT_IOMMU.sys";
        if (std::filesystem::exists(Companion)
            && std::find(AdditionalModules.begin(), AdditionalModules.end(), Companion)
                == AdditionalModules.end()) {
            AdditionalModules.push_back(Companion);
        }
    }
    Logger::Log("{CYN}Build profile: %s build=%u fingerprint=%s{RESET}\n",
        Kevlar::Profile::Active().Name.c_str(),
        Kevlar::Profile::Active().BuildNumber,
        Kevlar::Profile::FingerprintHex(Kevlar::Profile::Active()).c_str());
    UnicornEmu::InitTimingSpoofing();
    Kevlar::Hardware::ResetActiveHardware(TimingSeed, 0);
    Kevlar::Memory::ResetGuestMemory(TimingSeed);

    auto ContractCatalog = std::filesystem::path(KevlarGlobal::ExeDir)
        .parent_path().parent_path().parent_path() / "generated" / "export_contracts_26200.json";
    auto ContractLoad = Kevlar::Host::Contracts::LoadActiveCatalog(ContractCatalog);
    if (!ContractLoad.Ok()) {
        Logger::Log("{RED}Failed to load export contracts: %s (%zu diagnostic(s)){RESET}\n",
            ContractCatalog.string().c_str(), ContractLoad.Diagnostics.size());
        return 1;
    }
    Logger::Log("{CYN}Loaded %zu export contracts from %s{RESET}\n",
        ContractLoad.ContractsAdded, ContractCatalog.string().c_str());

    Environment::InitializeSystemModules();
    ntoskrnl_provider::Initialize();
    for (const auto& ModulePath : AdditionalModules) {
        if (!Environment::AddModuleFromFile(ModulePath, L"")) {
            Logger::Log("{RED}Failed to map companion module: %s{RESET}\n", ModulePath.c_str());
            return 1;
        }
    }
    ntoskrnl_export::Initialize();
    usermode_provider::Initialize();

    UnicornEmu::PatchSystemModuleExports();
    UnicornEmu::BuildSysModFuncCache();

    if (SelfTest) {
        int SelfResult = RunSelfTest();
        // ExitProcess bypasses the global-destructor teardown that crashes on the
        // no-driver exit path (pre-existing: a std::string holds a stale guest pointer).
        // Flush first -- ExitProcess skips stdio flushing, which drops redirected output.
        fflush(stdout);
        fflush(stderr);
        ExitProcess((UINT)SelfResult);
    }

    if (DriverPath.empty()) {
        PrintUsage(Argv[0]);
        return 1;
    }

    Logger::Log("{CYN}[ARGS] driver=%s diag=%d overrides=%zu eos_pipe=%d{RESET}\n",
        DriverPath.c_str(),
        UnicornEmu::DiagnosticHooksEnabled ? 1 : 0,
        g_StatusOverrides.size(),
        g_EosServerPipeEnabled ? 1 : 0);

    Logger::Log("{GRY}Opening File...{RESET}");

    bool IsACE = false;
    {
        
    }
    auto MainModule = PEFile::Open(DriverPath, "MyDriver");
    if (!MainModule) {
        Logger::Log("{RED}Failed to open driver: {WHT}%s{RESET}\n", DriverPath.c_str());
        return 1;
    }
    Logger::Log("{GRN}File opened. {GRY}MappedBase={WHT}0x%llx {GRY}VirtSize={WHT}0x%llx {GRY}EP={WHT}0x%llx{RESET}\n",
        MainModule->GetMappedImageBase(), MainModule->GetVirtualSize(), MainModule->GetEP());
    const bool DllMainMode = MainModule->IsDll()
        && MainModule->GetSubsystem() != IMAGE_SUBSYSTEM_NATIVE;
    const bool FaceitTarget = _stricmp(
        std::filesystem::path(DriverPath).filename().string().c_str(),
        "FACEIT_AC.sys") == 0;
    if (DllMainMode) {
        Logger::Log("{YEL}PE mode: user-mode DLL; invoking DllMain(HINSTANCE, DLL_PROCESS_ATTACH, nullptr){RESET}\n");
    }
    if (VtilRequested) {
        if (VtilOutputPath.empty()) {
            char FileName[64];
            snprintf(FileName, sizeof(FileName), "vtil-rva-%llx.vtil", VtilRva);
            VtilOutputPath = KevlarGlobal::ExeDir + FileName;
        }

        const VtilAnalysis::Options VtilOptions = {
            .Rva = VtilRva,
            .Size = VtilSize,
            .InputPath = DriverPath,
            .OutputPath = VtilOutputPath,
        };
        if (!VtilAnalysis::LiftImageRegion(
                (const uint8_t*)MainModule->GetMappedImageBase(),
                (size_t)MainModule->GetVirtualSize(),
                VtilOptions)) {
            return 1;
        }
        return 0;
    }

    {
        std::string Fname = DriverPath;
        auto Slash = Fname.find_last_of("\\/");
        std::string BaseNameStr = (Slash != std::string::npos) ? Fname.substr(Slash + 1) : Fname;

        int WideLen = MultiByteToWideChar(CP_ACP, 0, BaseNameStr.c_str(), -1, NULL, 0);
        DriverBaseName.resize(WideLen - 1);
        MultiByteToWideChar(CP_ACP, 0, BaseNameStr.c_str(), -1, &DriverBaseName[0], WideLen);

        DriverFullPath = L"\\SystemRoot\\system32\\drivers\\" + DriverBaseName;

        std::string SvcName = BaseNameStr;
        auto Dot = SvcName.find_last_of('.');
        if (Dot != std::string::npos)
            SvcName = SvcName.substr(0, Dot);

        static std::wstring WDriverName;
        static std::wstring WRegistryBuffer;
        int Len2 = MultiByteToWideChar(CP_ACP, 0, SvcName.c_str(), -1, NULL, 0);
        std::wstring WideSvc(Len2 - 1, 0);
        MultiByteToWideChar(CP_ACP, 0, SvcName.c_str(), -1, &WideSvc[0], Len2);

        WDriverName = L"\\Driver\\" + WideSvc;
        WRegistryBuffer = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\" + WideSvc;
        DriverName = WDriverName.c_str();
        RegistryBuffer = WRegistryBuffer.c_str();

        VirtualFs::Initialize(KevlarGlobal::ExeDir, std::string(BaseNameStr.begin(), BaseNameStr.end()));
        {
            std::wstring SvcRegPath = VirtualFs::GetVregRoot() + L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\" + WideSvc;
            std::wstring SwRegPath = VirtualFs::GetVregRoot() + L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\" + WideSvc;

            std::wstring ImagePath = L"\\SystemRoot\\system32\\drivers\\" + DriverBaseName;
            VirtualReg::WriteValueToFile(SvcRegPath, L"ImagePath", 2, ImagePath.c_str(), (ULONG)((ImagePath.size() + 1) * sizeof(wchar_t)));

            uint32_t StartType = 0;
            VirtualReg::WriteValueToFile(SvcRegPath, L"Start", 4, &StartType, sizeof(StartType));

            uint32_t SvcType = 1;
            VirtualReg::WriteValueToFile(SvcRegPath, L"Type", 4, &SvcType, sizeof(SvcType));

            uint32_t ErrorControl = 1;
            VirtualReg::WriteValueToFile(SvcRegPath, L"ErrorControl", 4, &ErrorControl, sizeof(ErrorControl));

            VirtualReg::WriteValueToFile(SvcRegPath, L"DisplayName", 1, WideSvc.c_str(), (ULONG)((WideSvc.size() + 1) * sizeof(wchar_t)));

            std::error_code RegEc;
            std::filesystem::create_directories(std::filesystem::path(SwRegPath), RegEc);
        }
    }

    if (!UnicornEmu::MapDriverImage(MainModule, DRIVER_BASE_UC)) {
        Logger::Log("{RED}Failed to map driver image into Unicorn{RESET}\n");
        return 1;
    }
    Logger::Log("{GRN}Driver mapped. {GRY}Resolving imports.{RESET}\n");

    Logger::Log("{GRY}Resolving Imports...{RESET}");
    MainModule->ResolveImport();
    Logger::Log("{GRN}Imports Resolved.{RESET}\n");

    UnicornEmu::BuildSentinelIat(MainModule);

    PopulateKernelStructs();
    SetupDriverLdrEntry(MainModule);

    drvObj.DriverStart = (PVOID)DRIVER_BASE_UC;
    drvObj.DriverSize = (ULONG)MainModule->GetVirtualSize();
    drvObj.DriverInit = (decltype(drvObj.DriverInit))(DRIVER_BASE_UC + MainModule->GetEP());

    {
        uint64_t ExtSize = sizeof(_DRIVER_EXTENSION) + 0x200;
        uint64_t ExtUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, ExtSize, "DriverExtension");
        auto ExtHost = (_DRIVER_EXTENSION*)UnicornMem::UcToHost(ExtUcAddr);
        memset(ExtHost, 0, ExtSize);
        ExtHost->DriverObject = (_DRIVER_OBJECT*)DRIVER_OBJ_BASE_UC;

        size_t SvcNameOff = sizeof(_DRIVER_EXTENSION);
        SvcNameOff = (SvcNameOff + 0xF) & ~0xFULL;
        size_t SvcBytes = (wcslen(RegistryBuffer) + 1) * sizeof(wchar_t);
        if (SvcNameOff + SvcBytes < ExtSize) {
            memcpy((uint8_t*)ExtHost + SvcNameOff, RegistryBuffer, SvcBytes);
            ExtHost->ServiceKeyName.Buffer = (WCHAR*)(ExtUcAddr + SvcNameOff);
            ExtHost->ServiceKeyName.Length = (USHORT)(wcslen(RegistryBuffer) * sizeof(wchar_t));
            ExtHost->ServiceKeyName.MaximumLength = ExtHost->ServiceKeyName.Length + sizeof(wchar_t);
        }

        drvObj.DriverExtension = (_DRIVER_EXTENSION*)ExtUcAddr;
        Logger::Log("{GRY}DriverExtension at UC {WHT}0x%llx{RESET}\n", ExtUcAddr);
    }

    {
        static const wchar_t* HwDbPath = L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\System";
        uint64_t HwDbSize = sizeof(UNICODE_STRING) + 0x100;
        uint64_t HwDbUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, HwDbSize, "HardwareDatabase");
        auto HwDbHost = (UNICODE_STRING*)UnicornMem::UcToHost(HwDbUcAddr);
        memset(HwDbHost, 0, HwDbSize);

        size_t StrOff = sizeof(UNICODE_STRING);
        StrOff = (StrOff + 0xF) & ~0xFULL;
        size_t StrBytes = (wcslen(HwDbPath) + 1) * sizeof(wchar_t);
        memcpy((uint8_t*)HwDbHost + StrOff, HwDbPath, StrBytes);
        HwDbHost->Buffer = (WCHAR*)(HwDbUcAddr + StrOff);
        HwDbHost->Length = (USHORT)(wcslen(HwDbPath) * sizeof(wchar_t));
        HwDbHost->MaximumLength = HwDbHost->Length + sizeof(wchar_t);

        drvObj.HardwareDatabase = (_PRIMITIVE_UNICODE_STRING*)HwDbUcAddr;
    }

    Logger::Log("{CYN}DRIVER_OBJECT: {WHT}Start={GRY}0x%llx {WHT}Size={GRY}0x%x {WHT}Section={GRY}0x%llx {WHT}Init={GRY}0x%llx {WHT}Ext={GRY}0x%llx{RESET}\n",
        (uint64_t)drvObj.DriverStart, drvObj.DriverSize,
        (uint64_t)drvObj.DriverSection, (uint64_t)drvObj.DriverInit,
        (uint64_t)drvObj.DriverExtension);

    // --- Driver-entry gate bypass -------------------------------------------------
    // Many protected drivers compile DriverEntry as a guard wrapper that branches to
    // its real initializer only when the value the wrapper computed survives a check
    // like `test eax,eax / je skip / cmp eax,<tag> / je skip / jmp <init>`; the tag is
    // the driver's own "self-test failed" sentinel (vgk.sys: 0xD4494E49). The wrapper
    // computes that value from obfuscated state the emulator cannot reproduce, so the
    // guard always takes the skip branch and DriverEntry returns the sentinel after
    // zero real work. Rewrite the guard's two conditional jumps into unconditional
    // jumps to the same target as the wrapper's dispatch so the real initializer runs.
    // This is pattern-driven and only rewrites a short local window at the entry.
    if (DriverEntryGateBypassEnabled) {
        const size_t GateScan = 0x80;
        const uint64_t EpUc = DRIVER_BASE_UC + MainModule->GetEP();
        uint8_t Gate[GateScan] = {};
        if (uc_mem_read(UnicornEmu::PrimaryEngine, EpUc, Gate, GateScan) == UC_ERR_OK) {
            // Find the 32-bit immediate of `cmp eax, imm32` (3D imm32) inside the guard.
            int CmpOff = -1;
            uint32_t Sentinel = 0;
            for (int I = 0; I + 5 <= (int)GateScan; ++I) {
                if (Gate[I] != 0x3D)
                    continue;
                memcpy(&Sentinel, Gate + I + 1, sizeof(Sentinel));
                if (Sentinel != 0)
                    CmpOff = I;
            }
            if (CmpOff >= 0) {
                // The guard is `test eax,eax; je <skip>` then `cmp eax,<tag>; je <skip>`;
                // <skip> is the wrapper's early `pop rbx; ret`. Identify the skip target
                // from the first je and neutralize only jumps that land on it, so the
                // sentinel compare and the real dispatch stay untouched.
                int Patched = 0;
                // The guard is `test eax,eax; je exit` followed by `cmp eax,imm32;
                // je exit`, so the second je lies *after* the 4-byte immediate -
                // scan a little past CmpOff rather than stopping at it.
                const int ScanEnd = (int)GateScan - 2;
                for (int I = 0; I <= ScanEnd; ) {
                    // Short form: 74 rel8 (2 bytes). Near form: 0F 84 rel32 (6 bytes).
                    int Len = 0;
                    int64_t Target = -1;
                    if (Gate[I] == 0x74) {
                        Len = 2;
                        Target = (int64_t)I + 2 + (int8_t)Gate[I + 1];
                    } else if (Gate[I] == 0x0F && Gate[I + 1] == 0x84 && I + 6 <= (int)GateScan) {
                        int32_t Rel = 0;
                        memcpy(&Rel, Gate + I + 2, sizeof(Rel));
                        Len = 6;
                        Target = (int64_t)I + 6 + Rel;
                    }
                    if (Len == 0 || Target < 0 || Target >= (int64_t)GateScan) {
                        ++I;
                        continue;
                    }
                    // Only neutralize jumps that land on the wrapper's early exit
                    // (`pop rbx` then `ret`), never the dispatch path itself.
                    if (Gate[Target] != 0x5B || Gate[Target + 1] != 0xC3) {
                        ++I;
                        continue;
                    }
                    uint8_t Nops[6] = { 0x90, 0x90, 0x0F, 0x1F, 0x44, 0x00 };
                    uc_mem_write(UnicornEmu::PrimaryEngine, EpUc + I, Nops, (size_t)Len);
                    ++Patched;
                    I += Len;
                }
                Logger::Log("{MAG}DriverEntry gate: guard at RVA 0x%llx compares against 0x%08x; "
                            "neutralized %d guard jump(s){RESET}\n",
                    (unsigned long long)(MainModule->GetEP() + CmpOff), Sentinel, Patched);
            }
        }
    }

    UnicornEmu::MapKernelStructs();
    UnicornEmu::MapKuserSharedData();

    // Apply analysis pre-seeds to the mapped (relocated) driver image. Done after the
    // image is mapped and relocated so a seeded pointer stays meaningful.
    for (const auto& Poke : g_Pokes) {
        const uint64_t PokeUc = DRIVER_BASE_UC + Poke.first;
        if (uc_mem_write(UnicornEmu::PrimaryEngine, PokeUc, &Poke.second, sizeof(Poke.second)) == UC_ERR_OK) {
            Logger::Log("{MAG}Poke applied: drv+0x%llx = 0x%llx{RESET}\n",
                (unsigned long long)Poke.first, (unsigned long long)Poke.second);
        } else {
            Logger::Log("{RED}Poke failed at drv+0x%llx (unmapped){RESET}\n",
                (unsigned long long)Poke.first);
        }
    }

    UnicornEmu::InstallWatchpoints(UnicornEmu::PrimaryEngine, MainModule);
    if (!g_WatchRvas.empty()) {
        UnicornEmu::InstallRvaWatch(UnicornEmu::PrimaryEngine, g_WatchRvas.data(),
            (int)g_WatchRvas.size());
    }
    if (FaceitTarget && TargetCompatEnabled) {
        TargetCompat::InstallFaceitAc20260908(
            UnicornEmu::PrimaryEngine, DRIVER_BASE_UC, MainModule->GetVirtualSize());
    }

    if (!UnicornEmu::TraceRecordPath.empty() || !UnicornEmu::TraceCheckPath.empty() || UnicornEmu::ProvenanceEnabled) {
        UnicornEmu::InstallTraceCapture(UnicornEmu::PrimaryEngine, DRIVER_BASE_UC, MainModule->GetVirtualSize());
    }

    if (UnicornEmu::DevirtualizationTest) {
        UnicornEmu::InstallFocusedTrace(UnicornEmu::PrimaryEngine,
            DRIVER_BASE_UC + 0x2680F00, DRIVER_BASE_UC + 0x2680F00);
        UnicornEmu::InstallVmStepTrace(UnicornEmu::PrimaryEngine,
            DRIVER_BASE_UC, MainModule->GetVirtualSize(), DRIVER_BASE_UC + 0x2680F00, 1024);
        constexpr uint64_t kLoopRva = 0x2680000;
        constexpr uint64_t kLoopSpan = 0x5000;
        UnicornEmu::InstallProtectedCodeWriteWatch(UnicornEmu::PrimaryEngine,
            DRIVER_BASE_UC + kLoopRva, kLoopSpan);
    }

    if (!AflBitmapPath.empty() || !CoverageOutPath.empty() || !CoverageBasePath.empty()) {
        UnicornEmu::InstallEdgeCoverage(
            UnicornEmu::PrimaryEngine, DRIVER_BASE_UC, MainModule->GetVirtualSize());
    }

    //UnicornEmu::InstallStackWriteWatch(UnicornEmu::PrimaryEngine,
    //    STACK_BASE_UC + 0x3FC80, 0x80);

    {
        Logger::Log("{CYN}=== PsLoadedModuleList validation ==={RESET}\n");
        uint64_t ListHead = (uint64_t)Environment::PsLoadedModuleList;
        Logger::Log("{GRY}PsLoadedModuleList sentinel at UC {WHT}0x%llx{RESET}\n", ListHead);

        auto SentinelHost = (LIST_ENTRY*)UnicornMem::UcToHost(ListHead);
        if (SentinelHost) {
            uint64_t CurrentUc = (uint64_t)SentinelHost->Flink;
            int ModCount = 0;
            while (CurrentUc && CurrentUc != ListHead && ModCount < 300) {
                auto CurrentHost = (KLDR_DATA_TABLE_ENTRY*)UnicornMem::UcToHost(CurrentUc);
                if (!CurrentHost) {
                    Logger::Log("{RED}  [%d] UC 0x%llx -> HOST NULL (broken link!){RESET}\n", ModCount, CurrentUc);
                    break;
                }

                uint64_t DllBaseVal = (uint64_t)CurrentHost->DllBase;

                wchar_t NameBuf[256] = { 0 };
                if (CurrentHost->BaseDllName.Buffer && CurrentHost->BaseDllName.Length > 0) {
                    auto NameHost = (wchar_t*)UnicornMem::UcToHost((uint64_t)CurrentHost->BaseDllName.Buffer);
                    if (NameHost) {
                        size_t CopyLen = CurrentHost->BaseDllName.Length / sizeof(wchar_t);
                        if (CopyLen > 255) CopyLen = 255;
                        memcpy(NameBuf, NameHost, CopyLen * sizeof(wchar_t));
                    }
                }

                if (DllBaseVal != 0) {
                    Logger::Log("{GRY}  [%d] UC {WHT}0x%llx{GRY}: DllBase={WHT}0x%llx {GRY}Size={WHT}0x%x {GRY}Name={WHT}%ws{RESET}\n",
                        ModCount, CurrentUc, DllBaseVal, CurrentHost->SizeOfImage, NameBuf);
                }

                CurrentUc = (uint64_t)CurrentHost->InLoadOrderLinks.Flink;
                ModCount++;
            }
            Logger::Log("{CYN}=== %d modules in list ==={RESET}\n", ModCount);
        } else {
            Logger::Log("{RED}PsLoadedModuleList sentinel host lookup FAILED{RESET}\n");
        }
    }

    if (EacServiceEmu) {
        // Emulate the EasyAntiCheat_EOS service side of the IPC contract with
        // NAMESPACE ISOLATION: objects are created UNNAMED on the host and
        // served to the guest through NamedObjectRegistry, so a live EAC
        // install's Global\EasyAntiCheat_EOS* objects are never touched.
        // Live-system ground truth (binread of the real section while Apex was
        // running): 28-byte header (service sub_424030 values) followed at
        // +0x1C by the FULL on-disk driver image (sha 5149a978... == file).
        PSECURITY_DESCRIPTOR EacSd = nullptr;
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;OICI;GA;;;BG)(A;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)",
            1, &EacSd, nullptr);
        SECURITY_ATTRIBUTES EacSa = { sizeof(EacSa), EacSd, FALSE };
        HANDLE BinSection = CreateFileMappingW(INVALID_HANDLE_VALUE, &EacSa, PAGE_READWRITE, 0, 0x6000000, nullptr);
        bool Populated = false;
        if (BinSection) {
            auto* View = (uint8_t*)MapViewOfFile(BinSection, FILE_MAP_ALL_ACCESS, 0, 0, 0);
            if (View) {
                *(uint32_t*)(View + 0) = 1;
                *(uint32_t*)(View + 4) = 0x06000000u;
                *(uint32_t*)(View + 8) = 0x00080000u;
                *(uint32_t*)(View + 12) = 0x00010005u;
                *(uint32_t*)(View + 16) = 0;
                *(uint32_t*)(View + 20) = 0;
                *(uint32_t*)(View + 24) = 0;
                FILE* DrvFile = nullptr;
                fopen_s(&DrvFile, DriverPath.c_str(), "rb");
                if (DrvFile) {
                    size_t Got = fread(View + 0x1C, 1, 0x6000000u - 0x1C, DrvFile);
                    fclose(DrvFile);
                    Populated = Got > 0x1000;
                    Logger::Log("{GRN}EAC service-emu: section populated with driver image (%zu bytes at +0x1C){RESET}\n", Got);
                }
            }
            NamedObjectRegistry::Register(L"Global\\EasyAntiCheat_EOSBin", BinSection);
            NamedObjectRegistry::Register(L"\\BaseNamedObjects\\EasyAntiCheat_EOSBin", BinSection);
        }
        HANDLE EvModule = CreateEventW(&EacSa, TRUE, FALSE, nullptr);
        HANDLE EvDriver = CreateEventW(&EacSa, TRUE, FALSE, nullptr);
        HANDLE EvGame = CreateEventW(&EacSa, TRUE, FALSE, nullptr);
        if (EvModule) {
            NamedObjectRegistry::Register(L"Global\\EasyAntiCheat_EOSEventModule", EvModule);
            NamedObjectRegistry::Register(L"\\BaseNamedObjects\\EasyAntiCheat_EOSEventModule", EvModule);
        }
        if (EvDriver) {
            NamedObjectRegistry::Register(L"Global\\EasyAntiCheat_EOSEventDriver", EvDriver);
            NamedObjectRegistry::Register(L"\\BaseNamedObjects\\EasyAntiCheat_EOSEventDriver", EvDriver);
        }
        if (EvGame) {
            NamedObjectRegistry::Register(L"Global\\EasyAntiCheat_EOSEventGame", EvGame);
            NamedObjectRegistry::Register(L"\\BaseNamedObjects\\EasyAntiCheat_EOSEventGame", EvGame);
        }
        Logger::Log("{GRN}EAC service-emu(isolated): bin=%p populated=%d events=%p/%p/%p{RESET}\n",
            BinSection, Populated ? 1 : 0, EvModule, EvDriver, EvGame);
        if (EacSd) LocalFree(EacSd);
    }

    Logger::Log("{CYN}Starting %s at RVA {WHT}0x%llx{RESET}\n",
        DllMainMode ? "DllMain" : "DriverEntry", MainModule->GetEP());

    bool Result = UnicornEmu::StartEmulation(
        UnicornEmu::PrimaryEngine, DRIVER_BASE_UC + MainModule->GetEP(), DllMainMode);

    if (!g_StatusOverrides.empty()) {
        uint64_t Rax = 0;
        uc_reg_read(UnicornEmu::PrimaryEngine, UC_X86_REG_RAX, &Rax);
        auto It = g_StatusOverrides.find((uint32_t)Rax);
        if (It != g_StatusOverrides.end()) {
            Logger::Log("{GRN}[STATUS OVERRIDE] 0x%08x -> 0x%08x{RESET}\n", It->first, It->second);
            uint64_t NewRax = It->second;
            uc_reg_write(UnicornEmu::PrimaryEngine, UC_X86_REG_RAX, &NewRax);
            if (It->second == 0) Result = true;
        }
    }

    if (Kevlar::Coverage::g_EdgeCoverage) {
        if (!AflBitmapPath.empty()) {
            if (!Kevlar::Coverage::g_EdgeCoverage->WriteBitmap(AflBitmapPath))
                Logger::Log("{RED}Coverage: failed to write AFL bitmap to %s{RESET}\n", AflBitmapPath.c_str());
            else
                Logger::Log("{GRN}Coverage: AFL bitmap written to %s{RESET}\n", AflBitmapPath.c_str());
        }
        if (!CoverageOutPath.empty()) {
            if (!Kevlar::Coverage::g_EdgeCoverage->SaveSnapshot(CoverageOutPath))
                Logger::Log("{RED}Coverage: failed to save snapshot to %s{RESET}\n", CoverageOutPath.c_str());
            else
                Logger::Log("{GRN}Coverage: snapshot saved to %s{RESET}\n", CoverageOutPath.c_str());
        }
        if (!CoverageBasePath.empty()) {
            auto Base = Kevlar::Coverage::EdgeCoverage::LoadSnapshot(CoverageBasePath);
            if (Base) {
                auto NewEdges = Kevlar::Coverage::g_EdgeCoverage->NewEdgesComparedTo(*Base);
                Logger::Log("{CYN}Coverage: %zu new edges vs baseline %s{RESET}\n",
                    NewEdges.size(), CoverageBasePath.c_str());
            } else {
                Logger::Log("{RED}Coverage: failed to load baseline from %s{RESET}\n", CoverageBasePath.c_str());
            }
        }
    }


    {
        auto GuestDriver = reinterpret_cast<_DRIVER_OBJECT*>(
            UnicornMem::UcToHost(DRIVER_OBJ_BASE_UC));
        size_t DispatchCount = 0;
        uint64_t AddDevice = 0;
        uint64_t Unload = 0;
        uint64_t DeviceObject = 0;
        if (GuestDriver) {
            for (const auto Routine : GuestDriver->MajorFunction) {
                if (Routine) ++DispatchCount;
            }
            Unload = reinterpret_cast<uint64_t>(GuestDriver->DriverUnload);
            DeviceObject = reinterpret_cast<uint64_t>(GuestDriver->DeviceObject);
            if (GuestDriver->DriverExtension) {
                auto Extension = reinterpret_cast<_DRIVER_EXTENSION*>(
                    UnicornMem::UcToHost(reinterpret_cast<uint64_t>(GuestDriver->DriverExtension)));
                if (Extension)
                    AddDevice = reinterpret_cast<uint64_t>(Extension->AddDevice);
            }
        }
        Logger::Log("{CYN}[LIFECYCLE] add_device=0x%llx unload=0x%llx device=0x%llx dispatch=%zu tracked_devices=%zu ps=%zu/%zu/%zu ob=%zu cm=%zu flt=%zu{RESET}\n",
            AddDevice, Unload, DeviceObject, DispatchCount, DeviceTracker::GetCount(),
            PsCallbacks::ProcessCallbackCount(), PsCallbacks::ThreadCallbackCount(),
            PsCallbacks::ImageCallbackCount(), ObCallbacks::RegisteredCount(),
            CmCallbacks::RegisteredCount(), FltCallbacks::RegisteredCount());
    }
    if (Result)
        Logger::Log(DllMainMode
            ? "{GRN}DllMain completed successfully{RESET}\n"
            : "{GRN}DriverEntry completed successfully{RESET}\n");
    else
        Logger::Log(DllMainMode
            ? "{RED}DllMain failed or was stopped{RESET}\n"
            : "{RED}DriverEntry failed or was stopped{RESET}\n");

    if (!JsonOutPath.empty() && DiagCenter::Instance().IsEnabled())
        DiagCenter::Instance().DumpJson(JsonOutPath);

    if (!ClientScript.empty()) {
        std::string ScriptCopy = ClientScript;
        int Delay = ClientDelay;
        std::thread([ScriptCopy, Delay]() {
            UsermodeClient::RunScript(ScriptCopy, Delay);
        }).detach();
        Logger::Log("{CYN}User-mode client armed (script=%s delay=%ds){RESET}\n", ClientScript.c_str(), ClientDelay);
    }

    Logger::Log("{MAG}Waiting for spawned threads (will keep alive up to 3600s for deferred work)...{RESET}\n");

    {
        LARGE_INTEGER WaitStart;
        QueryPerformanceCounter(&WaitStart);
        LARGE_INTEGER WaitFreq;
        QueryPerformanceFrequency(&WaitFreq);
        const double MaxWaitSeconds = 3600.0;
        int LastReportSec = 0;
        bool EverHadThreads = false;
        int IdleCycles = 0;

        while (true) {
            bool AnyRunning = false;
            int TotalThreads = 0;
            int RunningThreads = 0;
            {
                std::lock_guard<std::mutex> Lock(UnicornThread::ThreadLock);
                TotalThreads = (int)UnicornThread::ThreadMap.size();
                for (auto& [Id, Ctx] : UnicornThread::ThreadMap) {
                    if (Ctx->Running) {
                        RunningThreads++;
                        AnyRunning = true;
                    }
                }
            }

            if (AnyRunning) {
                EverHadThreads = true;
                IdleCycles = 0;
            }

            LARGE_INTEGER Now;
            QueryPerformanceCounter(&Now);
            double Elapsed = (double)(Now.QuadPart - WaitStart.QuadPart) / (double)WaitFreq.QuadPart;
            int ElapsedSec = (int)Elapsed;

            if (ElapsedSec >= LastReportSec + 10) {
                LastReportSec = ElapsedSec;
                Logger::Log("{GRY}[ALIVE %.0fs] threads: %d total, %d running%s{RESET}\n",
                    Elapsed, TotalThreads, RunningThreads,
                    EverHadThreads ? "" : " (waiting for first thread)");
            }

            if (EverHadThreads && !AnyRunning) {
                IdleCycles++;
                if (IdleCycles > 50) {
                    Logger::Log("{CYN}All spawned threads finished after %.1fs{RESET}\n", Elapsed);
                    break;
                }
            }

            double NoThreadTimeout = NoPause ? 5.0 : MaxWaitSeconds;
            if (!EverHadThreads && Elapsed >= NoThreadTimeout) {
                Logger::Log("{YEL}No threads spawned after %.0fs — giving up{RESET}\n", Elapsed);
                break;
            }

            if (NoPause && Elapsed >= MaxWaitSeconds) {
                // automation mode: honor the documented 3600s cap even while
                // driver threads are still running (EAC keeps a scanner alive
                // forever); interactive default is unchanged.
                Logger::Log("{YEL}Wait cap %.0fs reached (%d thread(s) still running) - shutting down{RESET}\n",
                    Elapsed, RunningThreads);
                break;
            }

            Sleep(100);
        }
    }

    Logger::Log("{GRN}Done. Press any key to exit.{RESET}\n");
    if (!NoPause)
        system("pause");

    UnicornEmu::Shutdown();
    Logger::MarkThreadEnd("main");

    return 0;
}
