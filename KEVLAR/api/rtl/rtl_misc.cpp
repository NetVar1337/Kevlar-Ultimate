#include "include/common.h"
#include "rtl_misc.h"

uint64_t h_RtlRandomEx(unsigned long* seed) {
    auto HostSeed = UcPtr(seed);
    Logger::Log("  {GRY}Seed: {WHT}%llx{RESET}\n", *HostSeed);
    auto ret = __NtRoutine("RtlRandomEx", HostSeed);
    *HostSeed = ret;
    return ret;
}

NTSTATUS h_RtlGetVersion(RTL_OSVERSIONINFOW* lpVersionInformation) {
    auto HostInfo = UcPtr(lpVersionInformation);
    auto ret = __NtRoutine("RtlGetVersion", HostInfo);
    Logger::Log("  {GRY}%d.%d.%d{RESET}\n", HostInfo->dwMajorVersion, HostInfo->dwMinorVersion, HostInfo->dwBuildNumber);
    return ret;
}

void h_RtlTimeToTimeFields(PLARGE_INTEGER Time, PTIME_FIELDS TimeFields) {
    auto HostTime = UcPtr(Time);
    auto HostTf = UcPtr(TimeFields);
    LARGE_INTEGER LocalTime = *HostTime;
    TIME_FIELDS LocalTf = { 0 };
    typedef void(NTAPI* FnRtlTimeToTimeFields)(PLARGE_INTEGER, PTIME_FIELDS);
    static auto Fn = (FnRtlTimeToTimeFields)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlTimeToTimeFields");
    if (Fn)
        Fn(&LocalTime, &LocalTf);
    memcpy(HostTf, &LocalTf, sizeof(TIME_FIELDS));
}

BOOLEAN h_RtlTimeFieldsToTime(PTIME_FIELDS TimeFields, PLARGE_INTEGER Time) {
    auto HostTf = UcPtr(TimeFields);
    auto HostTime = UcPtr(Time);
    TIME_FIELDS LocalTf = *HostTf;
    LARGE_INTEGER LocalTime = { 0 };
    typedef BOOLEAN(NTAPI* FnRtlTimeFieldsToTime)(PTIME_FIELDS, PLARGE_INTEGER);
    static auto Fn = (FnRtlTimeFieldsToTime)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlTimeFieldsToTime");
    BOOLEAN Result = FALSE;
    if (Fn)
        Result = Fn(&LocalTf, &LocalTime);
    if (Result)
        *HostTime = LocalTime;
    Logger::Log("{GRY}\tRtlTimeFieldsToTime: %04d-%02d-%02d %02d:%02d:%02d -> %s{RESET}\n",
        LocalTf.Year, LocalTf.Month, LocalTf.Day, LocalTf.Hour, LocalTf.Minute, LocalTf.Second,
        Result ? "OK" : "FAIL");
    return Result;
}

PIMAGE_NT_HEADERS h_RtlImageNtHeader(PVOID ImageBase) {
    auto HostBase = (uint8_t*)UnicornMem::UcToHost((uint64_t)ImageBase);
    if (!HostBase) return nullptr;
    auto Dos = (PIMAGE_DOS_HEADER)HostBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto Nt = (PIMAGE_NT_HEADERS)(HostBase + Dos->e_lfanew);
    return (PIMAGE_NT_HEADERS)((uint64_t)ImageBase + Dos->e_lfanew);
}

// RtlPcToFileHeader resolves a control address to the image base of the owning
// module and, when given a non-NULL BaseOfImage output, to that module's
// KLDR_DATA_TABLE_ENTRY. The previous passthrough returned NULL for every PC,
// which made drivers that walk their own loader entry abort early.
PVOID h_RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage) {
    auto HostBase = UcPtr(BaseOfImage);
    if (!HostBase)
        return nullptr;

    const uint64_t Pc = (uint64_t)PcValue;

    // RtlPcToFileHeader returns the KLDR_DATA_TABLE_ENTRY published into
    // PsLoadedModuleList for the owning image (or NULL for an unknown PC), and
    // writes the image base through BaseOfImage.
    auto LdrEntryFor = [](uint64_t ImageBase) -> PVOID {
        if (ImageBase == DRIVER_BASE_UC)
            return (PVOID)UnicornEmu::DriverLdrEntryUc;
        for (auto& Mod : UnicornEmu::MappedSysMods) {
            if (Mod.UcBase == ImageBase)
                return (PVOID)Mod.LoaderEntry;
        }
        return nullptr;
    };

    if (Pc >= DRIVER_BASE_UC && Pc < DRIVER_BASE_UC + 0x10000000ULL) {
        *HostBase = (PVOID)DRIVER_BASE_UC;
        PVOID LdrEntry = LdrEntryFor(DRIVER_BASE_UC);
        Logger::Log("{GRY}\tRtlPcToFileHeader(0x%llx) -> driver base 0x%llx ldr=0x%llx{RESET}\n",
            Pc, (unsigned long long)DRIVER_BASE_UC, (unsigned long long)(uintptr_t)LdrEntry);
        return LdrEntry;
    }

    for (auto& Mod : UnicornEmu::MappedSysMods) {
        if (Pc >= Mod.UcBase && Pc < Mod.UcBase + Mod.Size) {
            *HostBase = (PVOID)Mod.UcBase;
            PVOID LdrEntry = LdrEntryFor(Mod.UcBase);
            Logger::Log("{GRY}\tRtlPcToFileHeader(0x%llx) -> %s base 0x%llx ldr=0x%llx{RESET}\n",
                Pc, Mod.Name.c_str(), (unsigned long long)Mod.UcBase,
                (unsigned long long)(uintptr_t)LdrEntry);
            return LdrEntry;
        }
    }

    *HostBase = nullptr;
    Logger::Log("{RED}\tRtlPcToFileHeader(0x%llx): no owning module{RESET}\n", Pc);
    return nullptr;
}

PRUNTIME_FUNCTION h_RtlLookupFunctionEntry(uint64_t ControlPc, uint64_t* ImageBase, PVOID HistoryTable) {
    auto HostImageBase = UcPtr(ImageBase);
    if (ControlPc >= DRIVER_BASE_UC && ControlPc < DRIVER_BASE_UC + 0x10000000ULL) {
        *HostImageBase = DRIVER_BASE_UC;
        auto HostDriverBase = (uint8_t*)UnicornMem::UcToHost(DRIVER_BASE_UC);
        if (HostDriverBase) {
            auto DosHdr = (PIMAGE_DOS_HEADER)HostDriverBase;
            auto NtHdr = (PIMAGE_NT_HEADERS)(HostDriverBase + DosHdr->e_lfanew);
            auto ExcDir = &NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (ExcDir->VirtualAddress && ExcDir->Size) {
                auto FuncTable = (PRUNTIME_FUNCTION)(HostDriverBase + ExcDir->VirtualAddress);
                DWORD Count = ExcDir->Size / sizeof(RUNTIME_FUNCTION);
                uint32_t Rva = (uint32_t)(ControlPc - DRIVER_BASE_UC);
                for (DWORD I = 0; I < Count; I++) {
                    if (Rva >= FuncTable[I].BeginAddress && Rva < FuncTable[I].EndAddress) {
                        return (PRUNTIME_FUNCTION)(DRIVER_BASE_UC + ExcDir->VirtualAddress + I * sizeof(RUNTIME_FUNCTION));
                    }
                }
            }
        }
    }
    Logger::Log("{RED}\tRtlLookupFunctionEntry: 0x%llx not found{RESET}\n", ControlPc);
    return nullptr;
}

PVOID h_RtlVirtualUnwind(DWORD HandlerType, uint64_t ImageBase, uint64_t ControlPc, PRUNTIME_FUNCTION FunctionEntry,
    PCONTEXT ContextRecord, PVOID* HandlerData, uint64_t* EstablisherFrame, PVOID ContextPointers) {
    Logger::Log("{CYN}\tRtlVirtualUnwind: ImageBase=0x%llx ControlPc=0x%llx{RESET}\n", ImageBase, ControlPc);
    auto HostCtx = UcPtr(ContextRecord);
    auto HostEstFrame = UcPtr(EstablisherFrame);
    if (HostEstFrame)
        *HostEstFrame = HostCtx->Rsp;
    HostCtx->Rip = *(uint64_t*)(UnicornMem::UcToHost(HostCtx->Rsp) ? UnicornMem::UcToHost(HostCtx->Rsp) : (void*)&HostCtx->Rsp);
    HostCtx->Rsp += 8;
    if (HandlerData) {
        auto HostHd = UcPtr(HandlerData);
        *HostHd = nullptr;
    }
    return nullptr;
}

void h_RtlCaptureContext(PCONTEXT ContextRecord) {
    auto HostCtx = UcPtr(ContextRecord);
    if (!HostCtx) return;
    memset(HostCtx, 0, sizeof(CONTEXT));
    HostCtx->ContextFlags = CONTEXT_FULL;
    uc_engine* Eng = UnicornThread::GetCurrentEngine();
    if (!Eng) Eng = UnicornEmu::PrimaryEngine;
    if (!Eng) return;
    uint64_t V = 0;
    uc_reg_read(Eng, UC_X86_REG_RIP, &V); HostCtx->Rip = V;
    uc_reg_read(Eng, UC_X86_REG_RSP, &V); HostCtx->Rsp = V;
    uc_reg_read(Eng, UC_X86_REG_RBP, &V); HostCtx->Rbp = V;
    uc_reg_read(Eng, UC_X86_REG_RAX, &V); HostCtx->Rax = V;
    uc_reg_read(Eng, UC_X86_REG_RBX, &V); HostCtx->Rbx = V;
    uc_reg_read(Eng, UC_X86_REG_RCX, &V); HostCtx->Rcx = V;
    uc_reg_read(Eng, UC_X86_REG_RDX, &V); HostCtx->Rdx = V;
    uc_reg_read(Eng, UC_X86_REG_RSI, &V); HostCtx->Rsi = V;
    uc_reg_read(Eng, UC_X86_REG_RDI, &V); HostCtx->Rdi = V;
    uc_reg_read(Eng, UC_X86_REG_R8, &V); HostCtx->R8 = V;
    uc_reg_read(Eng, UC_X86_REG_R9, &V); HostCtx->R9 = V;
    uc_reg_read(Eng, UC_X86_REG_R10, &V); HostCtx->R10 = V;
    uc_reg_read(Eng, UC_X86_REG_R11, &V); HostCtx->R11 = V;
    uc_reg_read(Eng, UC_X86_REG_R12, &V); HostCtx->R12 = V;
    uc_reg_read(Eng, UC_X86_REG_R13, &V); HostCtx->R13 = V;
    uc_reg_read(Eng, UC_X86_REG_R14, &V); HostCtx->R14 = V;
    uc_reg_read(Eng, UC_X86_REG_R15, &V); HostCtx->R15 = V;
    HostCtx->SegCs = 0x10;
    HostCtx->SegSs = 0x18;
    HostCtx->SegDs = 0x2B;
    HostCtx->SegEs = 0x2B;
    HostCtx->SegGs = 0x2B;
    HostCtx->MxCsr = 0x1F80;
    HostCtx->EFlags = 0x202;
}

ULONG h_RtlWalkFrameChain(PVOID* Callers, ULONG Count, ULONG Flags) {
    if (!Callers || Count == 0)
        return 0;
    if (Flags & 1)
        return 0;
    auto HostCallers = UcPtr(Callers);
    if (!HostCallers)
        return 0;
    uc_engine* Eng = UnicornThread::GetCurrentEngine();
    if (!Eng) Eng = UnicornEmu::PrimaryEngine;
    if (!Eng)
        return 0;
    uint64_t Rsp = 0;
    uint64_t Rip = 0;
    uc_reg_read(Eng, UC_X86_REG_RSP, &Rsp);
    uc_reg_read(Eng, UC_X86_REG_RIP, &Rip);
    ULONG Filled = 0;
    auto accept = [](uint64_t Addr) -> bool {
        if (Addr < 0xFFFF800000000000ULL)
            return false;
        if (Addr >= SENTINEL_BASE_UC && Addr < SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE)
            return false;
        if ((Addr & 0xFFFFFFFF00000000ULL) == 0xDEADC0DE00000000ULL)
            return false;
        return true;
    };
    if (accept(Rip) && Filled < Count)
        HostCallers[Filled++] = (PVOID)Rip;
    for (int I = 0; I < 96 && Filled < Count; I++) {
        void* Host = UnicornMem::UcToHost(Rsp + (uint64_t)I * 8ull);
        if (!Host)
            continue;
        uint64_t Slot = *(uint64_t*)Host;
        if (!accept(Slot))
            continue;
        if (Filled && (uint64_t)HostCallers[Filled - 1] == Slot)
            continue;
        HostCallers[Filled++] = (PVOID)Slot;
    }
    return Filled;
}

NTSTATUS h_RtlGUIDFromString(PUNICODE_STRING GuidString, GUID* Guid) {
    auto HostStr = UcPtr(GuidString);
    UNICODE_STRING LocalStr = *HostStr;
    LocalStr.Buffer = UcPtr(LocalStr.Buffer);
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe(Guid, LocalGuid);
    if (!HostGuid) return STATUS_INVALID_PARAMETER;
    NTSTATUS Status = (NTSTATUS)__NtRoutine("RtlGUIDFromString", &LocalStr, HostGuid);
    if (HostGuid == &LocalGuid && Status >= 0) {
        uc_mem_write((uc_engine*)0x1, (uint64_t)Guid, &LocalGuid, sizeof(GUID));
    }
    return Status;
}

NTSTATUS h_RtlStringFromGUID(GUID* Guid, PUNICODE_STRING GuidString) {
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe(Guid, LocalGuid);
    auto HostStr = UcPtr(GuidString);
    if (!HostGuid) return STATUS_INVALID_PARAMETER;
    return (NTSTATUS)__NtRoutine("RtlStringFromGUID", HostGuid, HostStr);
}
