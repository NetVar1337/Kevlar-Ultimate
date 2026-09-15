#include "core/process/unicorn_threading.h"
#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/memory/unicorn_memory.h"
#include "host/providers/ntoskrnl_provider.h"
#include "include/ntoskrnl_struct.h"
#include "include/kernel_layout_consume.h"
#include "core/loader/environment.h"
#include <Logger/Logger.h>
#include <malloc.h>
#include <cstdio>

namespace UnicornThread {
    std::unordered_map<DWORD, ThreadContext*> ThreadMap;
    std::mutex ThreadLock;
    uint64_t NextThreadId = 0x100;
    uint64_t NextEthreadAddr = 0xFFFFF80600000000ULL;
    uint64_t NextStackAddr = 0xFFFFF71000000000ULL;
}

static thread_local ThreadContext* TlsContext = nullptr;

// Real ntoskrnl's KiInitializePcrLockQueues publishes a self-referential
// KSPIN_LOCK_QUEUE array at KPRCB.LockQueue and stores its base in KPCR.LockArray
// (gs:[0x28]). Worker contexts that take a queued spin lock dereference that
// pointer, so a per-thread KPCR needs the same array instead of a NULL LockArray.
static void SeedPerThreadLockQueues(uint8_t* PerThreadKpcr, uint64_t ThreadKpcrAddr) {
    // KSPIN_LOCK_QUEUE is 16 bytes (Next + Lock); the kernel array spans
    // KPRCB.LockQueue..KPRCB.PPLookasideList.
    constexpr uint64_t kLockQueueStride = 16;
    constexpr uint64_t kQueueCount =
        (GEN__KPRCB_PPLookasideList - GEN__KPRCB_LockQueue) / kLockQueueStride;
    const uint64_t QueueBase = ThreadKpcrAddr + KPCR_PRCB_OFFSET + GEN__KPRCB_LockQueue;
    for (uint64_t Index = 0; Index < kQueueCount; ++Index) {
        uint64_t* Entry = (uint64_t*)(PerThreadKpcr + KPCR_PRCB_OFFSET + GEN__KPRCB_LockQueue +
                                      Index * kLockQueueStride);
        Entry[0] = QueueBase + Index * kLockQueueStride;   // Next -> &this queue
        Entry[1] = 0;                                      // Lock -> 0 (unowned)
    }
    // gs:[0x28] itself points at a dedicated zeroed per-CPU scratch page, so a
    // driver reading it never aliases live lock state through a truncated pointer.
    *(uint64_t*)(PerThreadKpcr + 0x28) = KPCR_LOCK_ARRAY_UC;
}

bool TlsHasGuestContext() { return TlsContext != nullptr; }

static DWORD ThreadEntryCore(ThreadStartInfo* Info) {
    auto Ctx = Info->Context;
    char ThreadReason[128] = {};
    snprintf(ThreadReason, sizeof(ThreadReason), "worker_tid=%llu start=0x%llx", Ctx->ThreadId, Info->StartRoutine);
    Logger::MarkThreadStart(ThreadReason);

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    TlsContext = Ctx;

    {
        std::lock_guard<std::mutex> Lock(UnicornThread::ThreadLock);
        UnicornThread::ThreadMap[GetCurrentThreadId()] = Ctx;
    }

    uint64_t Rcx = Info->StartContext;
    uc_reg_write(Info->Engine, UC_X86_REG_RCX, &Rcx);

    if (Info->NumArgs >= 2) {
        uc_reg_write(Info->Engine, UC_X86_REG_RDX, &Info->Arg2);
    }
    if (Info->NumArgs >= 3) {
        uc_reg_write(Info->Engine, UC_X86_REG_R8, &Info->Arg3);
    }
    if (Info->NumArgs >= 4) {
        uc_reg_write(Info->Engine, UC_X86_REG_R9, &Info->Arg4);
    }

    uint64_t Rsp = Ctx->StackBase + Ctx->StackSize - 0x100;
    uint64_t RetAddr = SENTINEL_RET_ADDR;
    Rsp -= 8;
    uc_mem_write(Info->Engine, Rsp, &RetAddr, 8);
    uc_reg_write(Info->Engine, UC_X86_REG_RSP, &Rsp);

    if (Info->UseArg5) {
        // 5th __fastcall arg at [RSP+0x28] (entry RSP = StackBase+StackSize-0x108).
        uint64_t Arg5Slot = Rsp + 0x28;
        uc_mem_write(Info->Engine, Arg5Slot, &Info->Arg5, 8);
    }

    Logger::Log("{MAG}Thread %llu starting at 0x%llx{RESET}\n", Ctx->ThreadId, Info->StartRoutine);

    Ctx->Running = true;
    uc_err Err = UC_ERR_OK;
    if (UnicornEmu::WorkersDeepMode) {
        // Opt-in (--workers-deep): extended loop with SSE-fault dispatch and
        // INSN_INVALID TryEmulate retry. Default below stays raw for vendor parity.
        auto LR = RunEmulationLoop(Info->Engine, Info->StartRoutine);
        if (!LR.Ok)
            Err = LR.HostCrash ? UC_ERR_EXCEPTION : UC_ERR_INSN_INVALID;
    } else {
        // Vendor-parity: raw engine run; workers are short-lived decoys whose quick exit
        // the driver's init state machine expects (extended TryEmulate retry here stalls
        // the DriverEntry completion-wait spin at drv+0x1edd75).
        Err = uc_emu_start(Info->Engine, Info->StartRoutine, SENTINEL_RET_ADDR, 0, 0);
    }
    Ctx->Running = false;

    if (UnicornEmu::ProbeEnginesOnly) {
        Logger::Log("{MAG}Thread %llu icount=%llu{RESET}\n", Ctx->ThreadId,
            (unsigned long long)UnicornEmu::GetInstrCount(Info->Engine));
    }

    if (Err != UC_ERR_OK) {
        uint64_t CrashRip = 0;
        uc_reg_read(Info->Engine, UC_X86_REG_RIP, &CrashRip);
        Logger::Log("{RED}Thread %llu emulation error at RIP=0x%llx: %s{RESET}\n", Ctx->ThreadId, CrashRip, uc_strerror(Err));
    }

    uint64_t Rax;
    uc_reg_read(Info->Engine, UC_X86_REG_RAX, &Rax);
    Logger::Log("{MAG}Thread %llu finished with 0x%llx{RESET}\n", Ctx->ThreadId, Rax);
    Logger::MarkThreadEnd("worker_return");

    delete Info;
    return 0;
}

static DWORD WINAPI ThreadEntryPoint(LPVOID Param) {
    __try {
        return ThreadEntryCore((ThreadStartInfo*)Param);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}CRASH in worker thread! Exception code: 0x%08x{RESET}\n", GetExceptionCode());
    }
    return 0;
}

ThreadContext* UnicornThread::Create(uint64_t StartRoutine, uint64_t StartContext, PHANDLE OutHandle) {
    auto CallerEngine = GetCurrentEngine();
    std::lock_guard<std::mutex> Lock(ThreadLock);

    auto Ctx = new ThreadContext();
    Ctx->ThreadId = NextThreadId++;

    Logger::Log("{GRY}Thread::Create[%llu] step 1: allocating ETHREAD{RESET}\n", Ctx->ThreadId);

    Ctx->EthreadUcAddr = UnicornMem::AllocateVariable(CallerEngine, sizeof(_ETHREAD), "ETHREAD");
    Ctx->EthreadHostPtr = (_ETHREAD*)UnicornMem::UcToHost(Ctx->EthreadUcAddr);

    memset(Ctx->EthreadHostPtr, 0, sizeof(_ETHREAD));
    Ctx->EthreadHostPtr->Tcb.Process = (_KPROCESS*)EPROCESS_BASE_UC;
    Ctx->EthreadHostPtr->Tcb.ApcState.Process = (_KPROCESS*)EPROCESS_BASE_UC;
    EthreadCid(Ctx->EthreadHostPtr)->UniqueProcess = (void*)4;
    EthreadCid(Ctx->EthreadHostPtr)->UniqueThread = (void*)(uintptr_t)Ctx->ThreadId;
    Ctx->EthreadHostPtr->Tcb.PreviousMode = 0;
    Ctx->EthreadHostPtr->Tcb.State = 1;
    Ctx->EthreadHostPtr->Tcb.MiscFlags |= 0x400;

    uint64_t WlhUcAddr = Ctx->EthreadUcAddr + offsetof(_ETHREAD, Tcb.Header.WaitListHead);
    Ctx->EthreadHostPtr->Tcb.Header.WaitListHead.Flink = (PLIST_ENTRY)WlhUcAddr;
    Ctx->EthreadHostPtr->Tcb.Header.WaitListHead.Blink = (PLIST_ENTRY)WlhUcAddr;

    uint64_t ApcList0UcAddr = Ctx->EthreadUcAddr + offsetof(_ETHREAD, Tcb.ApcState.ApcListHead[0]);
    Ctx->EthreadHostPtr->Tcb.ApcState.ApcListHead[0].Flink = (PLIST_ENTRY)ApcList0UcAddr;
    Ctx->EthreadHostPtr->Tcb.ApcState.ApcListHead[0].Blink = (PLIST_ENTRY)ApcList0UcAddr;
    uint64_t ApcList1UcAddr = Ctx->EthreadUcAddr + offsetof(_ETHREAD, Tcb.ApcState.ApcListHead[1]);
    Ctx->EthreadHostPtr->Tcb.ApcState.ApcListHead[1].Flink = (PLIST_ENTRY)ApcList1UcAddr;
    Ctx->EthreadHostPtr->Tcb.ApcState.ApcListHead[1].Blink = (PLIST_ENTRY)ApcList1UcAddr;

    Logger::Log("{GRY}Thread::Create[%llu] step 2: allocating stack at 0x%llx{RESET}\n", Ctx->ThreadId, NextStackAddr);

    Ctx->StackBase = NextStackAddr;
    Ctx->StackSize = THREAD_STACK_SIZE_UC;
    NextStackAddr += THREAD_STACK_SIZE_UC + 0x1000;

    auto StackHost = (void*)_aligned_malloc((size_t)THREAD_STACK_SIZE_UC, 0x1000);
    if (!StackHost) {
        Logger::Log("{RED}Thread::Create[%llu] _aligned_malloc FAILED for stack{RESET}\n", Ctx->ThreadId);
        delete Ctx;
        return nullptr;
    }
    memset(StackHost, 0, (size_t)THREAD_STACK_SIZE_UC);
    uc_mem_map_ptr(UnicornEmu::PrimaryEngine, Ctx->StackBase, THREAD_STACK_SIZE_UC, UC_PROT_ALL, StackHost);

    UnicornMem::TrackExisting(Ctx->StackBase, StackHost, THREAD_STACK_SIZE_UC, "ThreadStack");
    {
        std::unique_lock<std::shared_mutex> RegGuard(UnicornEmu::RegionsLock);
        UnicornEmu::MappedRegions.push_back({Ctx->StackBase, THREAD_STACK_SIZE_UC, StackHost, "ThreadStack", UC_PROT_ALL});
    }

    Logger::Log("{GRY}Thread::Create[%llu] step 3: creating UC engine{RESET}\n", Ctx->ThreadId);

    Ctx->Engine = UnicornEmu::CreateEngine();
    if (!Ctx->Engine) {
        Logger::Log("{RED}Thread::Create[%llu] CreateEngine FAILED{RESET}\n", Ctx->ThreadId);
        delete Ctx;
        return nullptr;
    }

    Logger::Log("{GRY}Thread::Create[%llu] step 4: setting up per-thread KPCR{RESET}\n", Ctx->ThreadId);

    auto PerThreadKpcr = (uint8_t*)_aligned_malloc(0x10000, 0x1000);
    memset(PerThreadKpcr, 0, 0x10000);
    memcpy(PerThreadKpcr, &FakeKPCR, sizeof(_KPCR));
    Ctx->KpcrHostPtr = PerThreadKpcr;

    uint64_t ThreadKpcrAddr = NextEthreadAddr;
    NextEthreadAddr += 0x10000;
    auto MapErr = uc_mem_map_ptr(Ctx->Engine, ThreadKpcrAddr, 0x10000, UC_PROT_ALL, PerThreadKpcr);
    if (MapErr != UC_ERR_OK) {
        Logger::Log("{RED}Thread::Create[%llu] KPCR mapping FAILED at 0x%llx: %s{RESET}\n",
            Ctx->ThreadId, ThreadKpcrAddr, uc_strerror(MapErr));
    }

    uint64_t EthreadAddr = Ctx->EthreadUcAddr;
    memcpy(PerThreadKpcr + KPCR_PRCB_OFFSET + KPRCB_CURRENT_THREAD, &EthreadAddr, 8);

    memcpy(PerThreadKpcr + 0x18, &ThreadKpcrAddr, 8);

    uint64_t KprcbAddr = ThreadKpcrAddr + 0x180;
    memcpy(PerThreadKpcr + 0x20, &KprcbAddr, 8);

    uint64_t KprcbCurrentThreadOffset = KPCR_PRCB_OFFSET + KPRCB_CURRENT_THREAD;
    memcpy(PerThreadKpcr + KprcbCurrentThreadOffset, &EthreadAddr, 8);

    SeedPerThreadLockQueues(PerThreadKpcr, ThreadKpcrAddr);

    uc_reg_write(Ctx->Engine, UC_X86_REG_GS_BASE, &ThreadKpcrAddr);

    // The per-thread engine needs its own mapping of the zeroed LockArray scratch
    // page so the published gs:[0x28] value resolves in this engine too.
    if (LockArrayScratch) {
        uc_mem_map_ptr(Ctx->Engine, KPCR_LOCK_ARRAY_UC, 0x1000, UC_PROT_ALL, LockArrayScratch);
    }

    uint64_t VerifyGsBase = 0;
    uc_reg_read(Ctx->Engine, UC_X86_REG_GS_BASE, &VerifyGsBase);
    uint64_t VerifyPrcb = *(uint64_t*)(PerThreadKpcr + 0x20);
    Logger::Log("{GRY}Thread::Create[%llu] KPCR=0x%llx GS_BASE=0x%llx KPRCB=0x%llx host=%p{RESET}\n",
        Ctx->ThreadId, ThreadKpcrAddr, VerifyGsBase, VerifyPrcb, PerThreadKpcr);

    Ctx->EthreadHostPtr->Tcb.InitialStack = (void*)(Ctx->StackBase + Ctx->StackSize);
    Ctx->EthreadHostPtr->Tcb.StackBase = (void*)(Ctx->StackBase + Ctx->StackSize);
    Ctx->EthreadHostPtr->Tcb.StackLimit = (void*)Ctx->StackBase;

    auto StartInfo = new ThreadStartInfo();
    StartInfo->Engine = Ctx->Engine;
    StartInfo->StartRoutine = StartRoutine;
    StartInfo->StartContext = StartContext;
    StartInfo->Context = Ctx;
    StartInfo->Arg2 = 0;
    StartInfo->Arg3 = 0;
    StartInfo->Arg4 = 0;
    StartInfo->NumArgs = 1;

    Logger::Log("{GRY}Thread::Create[%llu] step 5: launching OS thread{RESET}\n", Ctx->ThreadId);

    Ctx->Running = false;
    Ctx->HostThread = CreateThread(nullptr, 0, ThreadEntryPoint, StartInfo, 0, nullptr);

    if (OutHandle) {
        auto HostOutHandle = (PHANDLE)UnicornMem::UcToHost((uint64_t)OutHandle);
        if (HostOutHandle)
            *HostOutHandle = (HANDLE)(uintptr_t)Ctx->ThreadId;
    }

    {
        std::lock_guard<std::mutex> TmGuard(Environment::ThreadManager::ThreadManagerLock);
        Environment::ThreadManager::environment_threads[(uintptr_t)Ctx->HostThread] = Ctx->EthreadHostPtr;
    }

    Logger::Log("{MAG}Created thread %llu: routine=0x%llx context=0x%llx ethread=0x%llx{RESET}\n",
        Ctx->ThreadId, StartRoutine, StartContext, Ctx->EthreadUcAddr);

    return Ctx;
}

static ThreadContext* CreateExImpl(uint64_t StartRoutine, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4, uint64_t Arg5, bool UseArg5, bool UserCaller, PHANDLE OutHandle) {
    auto CallerEngine = UnicornThread::GetCurrentEngine();
    std::lock_guard<std::mutex> Lock(UnicornThread::ThreadLock);

    auto Ctx = new ThreadContext();
    Ctx->ThreadId = UnicornThread::NextThreadId++;
    Ctx->WakeEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);  // manual reset; signaled by KeInsertQueueApc to interrupt waits

    Ctx->EthreadUcAddr = UnicornMem::AllocateVariable(CallerEngine, sizeof(_ETHREAD), "ETHREAD");
    Ctx->EthreadHostPtr = (_ETHREAD*)UnicornMem::UcToHost(Ctx->EthreadUcAddr);

    memset(Ctx->EthreadHostPtr, 0, sizeof(_ETHREAD));
    uint64_t ProcessUcAddr = EPROCESS_BASE_UC;
    if (UserCaller) {
        ProcessUcAddr = UnicornMem::AllocateVariable(CallerEngine, sizeof(_EPROCESS), "UserEPROCESS");
        auto* UserProc = (_EPROCESS*)UnicornMem::UcToHost(ProcessUcAddr);
        auto* SystemProc = (_EPROCESS*)UnicornMem::UcToHost(EPROCESS_BASE_UC);
        if (UserProc) {
            if (SystemProc) memcpy(UserProc, SystemProc, sizeof(_EPROCESS));
            else memset(UserProc, 0, sizeof(_EPROCESS));
            *EprocUniqueProcessId(UserProc) = (void*)0x1337;
            *EprocProtection(UserProc) = 0;
            *EprocWow64Process(UserProc) = nullptr;
            memset(EprocImageFileName(UserProc), 0, 15);
            memcpy(EprocImageFileName(UserProc), "r5apex.exe", 11);
        }
    }
    Ctx->EthreadHostPtr->Tcb.Process = (_KPROCESS*)ProcessUcAddr;
    Ctx->EthreadHostPtr->Tcb.ApcState.Process = (_KPROCESS*)ProcessUcAddr;
    EthreadCid(Ctx->EthreadHostPtr)->UniqueProcess = (void*)(uintptr_t)(UserCaller ? 0x1337 : 4);
    EthreadCid(Ctx->EthreadHostPtr)->UniqueThread = (void*)(uintptr_t)Ctx->ThreadId;
    Ctx->EthreadHostPtr->Tcb.PreviousMode = UserCaller ? 1 : 0;
    Ctx->EthreadHostPtr->Tcb.State = 1;
    if (!UserCaller)
        Ctx->EthreadHostPtr->Tcb.MiscFlags |= 0x400;

    {
        uint64_t WlhUcAddr2 = Ctx->EthreadUcAddr + offsetof(_ETHREAD, Tcb.Header.WaitListHead);
        Ctx->EthreadHostPtr->Tcb.Header.WaitListHead.Flink = (PLIST_ENTRY)WlhUcAddr2;
        Ctx->EthreadHostPtr->Tcb.Header.WaitListHead.Blink = (PLIST_ENTRY)WlhUcAddr2;

        uint64_t ApcList0Uc = Ctx->EthreadUcAddr + offsetof(_ETHREAD, Tcb.ApcState.ApcListHead[0]);
        Ctx->EthreadHostPtr->Tcb.ApcState.ApcListHead[0].Flink = (PLIST_ENTRY)ApcList0Uc;
        Ctx->EthreadHostPtr->Tcb.ApcState.ApcListHead[0].Blink = (PLIST_ENTRY)ApcList0Uc;
        uint64_t ApcList1Uc = Ctx->EthreadUcAddr + offsetof(_ETHREAD, Tcb.ApcState.ApcListHead[1]);
        Ctx->EthreadHostPtr->Tcb.ApcState.ApcListHead[1].Flink = (PLIST_ENTRY)ApcList1Uc;
        Ctx->EthreadHostPtr->Tcb.ApcState.ApcListHead[1].Blink = (PLIST_ENTRY)ApcList1Uc;
    }

    Ctx->StackBase = UnicornThread::NextStackAddr;
    Ctx->StackSize = THREAD_STACK_SIZE_UC;
    UnicornThread::NextStackAddr += THREAD_STACK_SIZE_UC + 0x1000;

    auto StackHost = (void*)_aligned_malloc((size_t)THREAD_STACK_SIZE_UC, 0x1000);
    memset(StackHost, 0, (size_t)THREAD_STACK_SIZE_UC);
    uc_mem_map_ptr(UnicornEmu::PrimaryEngine, Ctx->StackBase, THREAD_STACK_SIZE_UC, UC_PROT_ALL, StackHost);

    UnicornMem::TrackExisting(Ctx->StackBase, StackHost, THREAD_STACK_SIZE_UC, "ThreadStack");
    {
        std::unique_lock<std::shared_mutex> RegGuard(UnicornEmu::RegionsLock);
        UnicornEmu::MappedRegions.push_back({Ctx->StackBase, THREAD_STACK_SIZE_UC, StackHost, "ThreadStack", UC_PROT_ALL});
    }

    Ctx->Engine = UnicornEmu::CreateEngine();

    auto PerThreadKpcr = (uint8_t*)_aligned_malloc(0x10000, 0x1000);
    memset(PerThreadKpcr, 0, 0x10000);
    memcpy(PerThreadKpcr, &FakeKPCR, sizeof(_KPCR));
    Ctx->KpcrHostPtr = PerThreadKpcr;

    uint64_t ThreadKpcrAddr = UnicornThread::NextEthreadAddr;
    UnicornThread::NextEthreadAddr += 0x10000;
    uc_mem_map_ptr(Ctx->Engine, ThreadKpcrAddr, 0x10000, UC_PROT_ALL, PerThreadKpcr);

    uint64_t EthreadAddr = Ctx->EthreadUcAddr;
    memcpy(PerThreadKpcr + KPCR_PRCB_OFFSET + KPRCB_CURRENT_THREAD, &EthreadAddr, 8);
    memcpy(PerThreadKpcr + 0x18, &ThreadKpcrAddr, 8);

    uint64_t KprcbAddr = ThreadKpcrAddr + 0x180;
    memcpy(PerThreadKpcr + 0x20, &KprcbAddr, 8);

    uint64_t KprcbCurrentThreadOffset = KPCR_PRCB_OFFSET + KPRCB_CURRENT_THREAD;
    memcpy(PerThreadKpcr + KprcbCurrentThreadOffset, &EthreadAddr, 8);

    SeedPerThreadLockQueues(PerThreadKpcr, ThreadKpcrAddr);

    uc_reg_write(Ctx->Engine, UC_X86_REG_GS_BASE, &ThreadKpcrAddr);

    Ctx->EthreadHostPtr->Tcb.InitialStack = (void*)(Ctx->StackBase + Ctx->StackSize);
    Ctx->EthreadHostPtr->Tcb.StackBase = (void*)(Ctx->StackBase + Ctx->StackSize);
    Ctx->EthreadHostPtr->Tcb.StackLimit = (void*)Ctx->StackBase;

    auto StartInfo = new ThreadStartInfo();
    StartInfo->Engine = Ctx->Engine;
    StartInfo->StartRoutine = StartRoutine;
    StartInfo->StartContext = Arg1;
    StartInfo->Context = Ctx;
    StartInfo->Arg2 = Arg2;
    StartInfo->Arg3 = Arg3;
    StartInfo->Arg4 = Arg4;
    StartInfo->Arg5 = 0;
    StartInfo->UseArg5 = UseArg5;
    StartInfo->NumArgs = 4;

    Ctx->Running = false;
    Ctx->HostThread = CreateThread(nullptr, 0, ThreadEntryPoint, StartInfo, 0, nullptr);

    if (OutHandle) {
        auto HostOutHandle = (PHANDLE)UnicornMem::UcToHost((uint64_t)OutHandle);
        if (HostOutHandle)
            *HostOutHandle = (HANDLE)(uintptr_t)Ctx->ThreadId;
    }

    {
        std::lock_guard<std::mutex> TmGuard(Environment::ThreadManager::ThreadManagerLock);
        Environment::ThreadManager::environment_threads[(uintptr_t)Ctx->HostThread] = Ctx->EthreadHostPtr;
    }

    Logger::Log("{MAG}Created thread %llu (4-arg): routine=0x%llx args=(0x%llx, 0x%llx, 0x%llx, 0x%llx) ethread=0x%llx{RESET}\n",
        Ctx->ThreadId, StartRoutine, Arg1, Arg2, Arg3, Arg4, Ctx->EthreadUcAddr);

    return Ctx;
}

ThreadContext* UnicornThread::CreateEx(uint64_t StartRoutine, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4, PHANDLE OutHandle) {
    return CreateExImpl(StartRoutine, Arg1, Arg2, Arg3, Arg4, 0, false, false, OutHandle);
}

ThreadContext* UnicornThread::CreateUserEx(uint64_t StartRoutine, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4, PHANDLE OutHandle) {
    return CreateExImpl(StartRoutine, Arg1, Arg2, Arg3, Arg4, 0, false, true, OutHandle);
}

ThreadContext* UnicornThread::CreateEx5(uint64_t StartRoutine, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4, uint64_t Arg5, PHANDLE OutHandle) {
    return CreateExImpl(StartRoutine, Arg1, Arg2, Arg3, Arg4, Arg5, true, false, OutHandle);
}

void UnicornThread::Terminate(ThreadContext* Ctx, NTSTATUS ExitStatus) {
    if (Ctx->Running) {
        uc_emu_stop(Ctx->Engine);
    }

    WaitForSingleObject(Ctx->HostThread, 5000);
    if (Ctx->WakeEvent) CloseHandle(Ctx->WakeEvent);
    CloseHandle(Ctx->HostThread);
    uc_close(Ctx->Engine);

    std::lock_guard<std::mutex> Lock(ThreadLock);
    for (auto It = ThreadMap.begin(); It != ThreadMap.end(); ++It) {
        if (It->second == Ctx) {
            ThreadMap.erase(It);
            break;
        }
    }

    Logger::Log("{MAG}Terminated thread %llu with status 0x%lx{RESET}\n", Ctx->ThreadId, ExitStatus);

    delete Ctx;
}

ThreadContext* UnicornThread::GetCurrent() {
    if (TlsContext)
        return TlsContext;

    std::lock_guard<std::mutex> Lock(ThreadLock);
    auto OsThreadId = GetCurrentThreadId();
    auto It = ThreadMap.find(OsThreadId);
    if (It != ThreadMap.end())
        return It->second;

    return nullptr;
}

_ETHREAD* UnicornThread::GetCurrentEthread() {
    auto Ctx = GetCurrent();
    if (Ctx)
        return Ctx->EthreadHostPtr;

    return &FakeKernelThread;
}

void UnicornThread::SignalWake(_KTHREAD* Target) {
    if (!Target)
        return;
    std::lock_guard<std::mutex> Lock(ThreadLock);
    for (auto& [Id, Ctx] : ThreadMap) {
        if (Ctx && (uint64_t)Ctx->EthreadHostPtr == (uint64_t)Target && Ctx->WakeEvent) {
            SetEvent(Ctx->WakeEvent);
            return;
        }
    }
}

uc_engine* UnicornThread::GetCurrentEngine() {
    auto Ctx = GetCurrent();
    return Ctx ? Ctx->Engine : UnicornEmu::PrimaryEngine;
}

uint8_t* UnicornThread::GetCurrentKpcr() {
    auto Ctx = GetCurrent();
    if (Ctx && Ctx->KpcrHostPtr)
        return Ctx->KpcrHostPtr;
    if (KpcrBlock)
        return (uint8_t*)KpcrBlock;
    return (uint8_t*)&FakeKPCR;
}
