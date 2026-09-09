#include "nt_memory.h"
#include <set>
#include <string>
#include <cwctype>
#include <unordered_map>

static std::mutex SectionHandleMutex;
static std::set<uint64_t> SectionHandleSet;
static uint64_t SectionHandleCounter = 0xBEEF0001;

static std::mutex PhysMapMutex;
static std::set<uint64_t> PhysicalMappedAddresses;

// Aliased host section views: guest VA -> { host view, size }. Populated when a
// real (host-handle) section is mapped: the host view is uc_mem_map_ptr'd into
// guest VA space so driver and host-side service emulators share one backing
// (zero-copy live IPC, e.g. Global\EasyAntiCheat_EOSBin).
static std::mutex AliasedViewMutex;
static std::unordered_map<uint64_t, std::pair<void*, uint64_t>> AliasedSectionViews;
static uint64_t NextSectionViewAddr = 0xFFFFB80000000000ULL;

// Private named-object registry: KEVLAR-created sections/events served to the
// guest WITHOUT touching the host's Global\ namespace (protects a live EAC
// install from interference). Names are matched case-insensitively on the full
// path and on the basename.
namespace {
    std::mutex NamedObjMutex;
    std::unordered_map<std::wstring, HANDLE> NamedObjects;

    std::wstring ToLowerW(const wchar_t* S) {
        std::wstring W(S);
        for (auto& C : W) C = (wchar_t)towlower(C);
        return W;
    }
    std::wstring BaseName(const std::wstring& W) {
        size_t P = W.find_last_of(L'\\');
        return (P == std::wstring::npos) ? W : W.substr(P + 1);
    }
}

void NamedObjectRegistry::Register(const wchar_t* Name, HANDLE HostHandle) {
    std::lock_guard<std::mutex> Lk(NamedObjMutex);
    NamedObjects[ToLowerW(Name)] = HostHandle;
    NamedObjects[BaseName(ToLowerW(Name))] = HostHandle;
}

bool NamedObjectRegistry::Find(const wchar_t* Name, HANDLE* Out) {
    std::lock_guard<std::mutex> Lk(NamedObjMutex);
    std::wstring Full = ToLowerW(Name);
    auto It = NamedObjects.find(Full);
    if (It == NamedObjects.end()) It = NamedObjects.find(BaseName(Full));
    if (It != NamedObjects.end() && It->second) {
        if (Out) *Out = It->second;
        return true;
    }
    return false;
}

bool NamedObjectRegistry::IsBlockedEacName(const wchar_t* Name) {
    if (!Name) return false;
    if (!wcsstr(Name, L"EasyAntiCheat") && !wcsstr(Name, L"easyanticheat")) return false;
    HANDLE H = nullptr;
    return !Find(Name, &H);
}

HANDLE SectionHandleManager::AllocateHandle() {
    std::lock_guard<std::mutex> Lock(SectionHandleMutex);
    uint64_t Handle = SectionHandleCounter++;
    SectionHandleSet.insert(Handle);
    return (HANDLE)Handle;
}

bool SectionHandleManager::IsSectionHandle(HANDLE Handle) {
    std::lock_guard<std::mutex> Lock(SectionHandleMutex);
    return SectionHandleSet.count((uint64_t)Handle) != 0;
}

void SectionHandleManager::FreeHandle(HANDLE Handle) {
    std::lock_guard<std::mutex> Lock(SectionHandleMutex);
    SectionHandleSet.erase((uint64_t)Handle);
}

NTSTATUS h_ZwMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    uint64_t ZeroBits, uint64_t CommitSize, PLARGE_INTEGER SectionOffset,
    uint64_t* ViewSize, uint32_t InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
    auto HostBaseAddress = UcPtr(BaseAddress);
    auto HostViewSize = UcPtr(ViewSize);

    // KEVLOBJ reference (from ObReferenceObjectByName): unwrap to host handle.
    {
        uint64_t Probe[2] = { 0, 0 };
        auto CurEng = UnicornThread::GetCurrentEngine();
        if (!CurEng) CurEng = UnicornEmu::PrimaryEngine;
        if (CurEng && uc_mem_read(CurEng, (uint64_t)SectionHandle, Probe, sizeof(Probe)) == UC_ERR_OK
            && Probe[0] == 0x4A56454B424A4FULL && Probe[1]) {
            Logger::Log("{GRN}\tZwMapViewOfSection: KEVLOBJ unwrap -> host handle %p{RESET}\n", (HANDLE)Probe[1]);
            SectionHandle = (HANDLE)Probe[1];
        }
    }

    if (SectionHandleManager::IsSectionHandle(SectionHandle)) {
        uint64_t MapSize = 0x1000;
        if (HostViewSize && *HostViewSize > 0)
            MapSize = *HostViewSize;
        if (MapSize > 0x100000)
            MapSize = 0x100000;

        auto Uc = UnicornThread::GetCurrentEngine();
        if (!Uc)
            Uc = UnicornEmu::PrimaryEngine;
        uint64_t UcAddr = UnicornMem::AllocatePoolWithTag(Uc, MapSize, 'PmVw');
        auto HostPtr = UnicornMem::UcToHost(UcAddr);
        if (HostPtr)
            memset(HostPtr, 0, MapSize);

        if (HostBaseAddress)
            *HostBaseAddress = (PVOID)UcAddr;
        if (HostViewSize)
            *HostViewSize = MapSize;

        {
            std::lock_guard<std::mutex> Lock(PhysMapMutex);
            PhysicalMappedAddresses.insert(UcAddr);
        }

        LARGE_INTEGER Offset = {};
        if (SectionOffset) {
            auto HostOffset = UcPtr(SectionOffset);
            Offset = *HostOffset;
        }
        Logger::Log("{BLU}\tZwMapViewOfSection: PhysMem offset=%llx size=%llx -> UC %llx{RESET}\n",
            Offset.QuadPart, MapSize, UcAddr);
        return STATUS_SUCCESS;
    }

    // Real host section handle: map the view into the KEVLAR host process, then
    // alias that view into guest VA space (shared backing, zero copy).
    {
        PVOID HostView = nullptr;
        uint64_t HostSideSize = HostViewSize ? *HostViewSize : 0;
        LARGE_INTEGER HostOffset = {};
        if (SectionOffset) {
            auto HostOff = UcPtr(SectionOffset);
            if (HostOff) HostOffset = *HostOff;
        }
        auto Ret = __NtRoutine("NtMapViewOfSection",
            SectionHandle, (HANDLE)(intptr_t)-1, &HostView,
            ZeroBits, CommitSize, &HostOffset,
            &HostSideSize, InheritDisposition, AllocationType, Win32Protect);
        Logger::Log("{BLU}\tZwMapViewOfSection: section=%p host view=%p size=%llx ret=%08x{RESET}\n",
            SectionHandle, HostView, HostSideSize, (unsigned)Ret);
        if (Ret != 0 || !HostView)
            return Ret;

        uint64_t Size = (HostSideSize + 0xFFFULL) & ~0xFFFULL;
        if (!Size) Size = 0x1000;
        uint64_t Guest = 0;
        {
            std::lock_guard<std::mutex> Lk(AliasedViewMutex);
            Guest = NextSectionViewAddr;
            NextSectionViewAddr += Size + 0x1000000ULL;
        }
        auto CurUc = UnicornThread::GetCurrentEngine();
        if (!CurUc) CurUc = UnicornEmu::PrimaryEngine;
        bool Mapped = false;
        if (uc_mem_map_ptr(CurUc, Guest, Size, UC_PROT_ALL, HostView) == UC_ERR_OK)
            Mapped = true;
        if (CurUc != UnicornEmu::PrimaryEngine)
            uc_mem_map_ptr(UnicornEmu::PrimaryEngine, Guest, Size, UC_PROT_ALL, HostView);
        if (!Mapped) {
            __NtRoutine("NtUnmapViewOfSection", (HANDLE)(intptr_t)-1, HostView);
            Logger::Log("{RED}\tZwMapViewOfSection: alias map FAILED for host view %p{RESET}\n", HostView);
            return (NTSTATUS)0xC0000018;
        }
        if (HostBaseAddress) *HostBaseAddress = (PVOID)Guest;
        if (HostViewSize) *HostViewSize = HostSideSize;
        UnicornMem::TrackExisting(Guest, HostView, Size, "SectionView");
        {
            std::unique_lock<std::shared_mutex> RegGuard(UnicornEmu::RegionsLock);
            UnicornEmu::MappedRegions.push_back({ Guest, Size, HostView, "SectionView", UC_PROT_ALL });
        }
        {
            std::lock_guard<std::mutex> Lk(AliasedViewMutex);
            AliasedSectionViews[Guest] = { HostView, Size };
        }
        Logger::Log("{GRN}\tZwMapViewOfSection: aliased host %p -> guest 0x%llx size=0x%llx{RESET}\n",
            HostView, (unsigned long long)Guest, (unsigned long long)Size);
        return STATUS_SUCCESS;
    }
}

NTSTATUS h_ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
    {
        std::lock_guard<std::mutex> Lock(PhysMapMutex);
        if (PhysicalMappedAddresses.count((uint64_t)BaseAddress)) {
            PhysicalMappedAddresses.erase((uint64_t)BaseAddress);
            auto Uc = UnicornThread::GetCurrentEngine();
            if (!Uc)
                Uc = UnicornEmu::PrimaryEngine;
            UnicornMem::FreePool(Uc, (uint64_t)BaseAddress);
            Logger::Log("{BLU}\tZwUnmapViewOfSection: freed PhysMem view %llx{RESET}\n", BaseAddress);
            return STATUS_SUCCESS;
        }
    }

    {
        std::lock_guard<std::mutex> Lk(AliasedViewMutex);
        auto It = AliasedSectionViews.find((uint64_t)BaseAddress);
        if (It != AliasedSectionViews.end()) {
            void* HostView = It->second.first;
            uint64_t Size = It->second.second;
            AliasedSectionViews.erase(It);
            auto Uc = UnicornThread::GetCurrentEngine();
            if (!Uc) Uc = UnicornEmu::PrimaryEngine;
            uc_mem_unmap(Uc, (uint64_t)BaseAddress, Size);
            if (Uc != UnicornEmu::PrimaryEngine)
                uc_mem_unmap(UnicornEmu::PrimaryEngine, (uint64_t)BaseAddress, Size);
            {
                std::unique_lock<std::shared_mutex> RegGuard(UnicornEmu::RegionsLock);
                auto& Regions = UnicornEmu::MappedRegions;
                for (auto R = Regions.begin(); R != Regions.end(); ) {
                    if (R->UcBase == (uint64_t)BaseAddress) R = Regions.erase(R);
                    else ++R;
                }
            }
            __NtRoutine("NtUnmapViewOfSection", (HANDLE)(intptr_t)-1, HostView);
            Logger::Log("{BLU}\tZwUnmapViewOfSection: unaliased guest 0x%llx{RESET}\n", (uint64_t)BaseAddress);
            return STATUS_SUCCESS;
        }
    }

    Logger::Log("{BLU}\tZwUnmapViewOfSection: process=%p base=%p passthrough{RESET}\n", ProcessHandle, BaseAddress);
    return __NtRoutine("NtUnmapViewOfSection", ProcessHandle, BaseAddress);
}

NTSTATUS h_ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    Logger::Log("{BLU}\tZwProtectVirtualMemory: handle=%p protect=%08x{RESET}\n", ProcessHandle, NewProtect);
    return __NtRoutine("NtProtectVirtualMemory",
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS h_ZwLockVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG MapType)
{
    Logger::Log("{BLU}\tZwLockVirtualMemory: handle=%p{RESET}\n", ProcessHandle);
    return 0;
}

NTSTATUS h_ZwUnlockVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG MapType)
{
    Logger::Log("{BLU}\tZwUnlockVirtualMemory: handle=%p{RESET}\n", ProcessHandle);
    return 0;
}

NTSTATUS h_ZwFlushInstructionCache(
    HANDLE ProcessHandle, void* BaseAddress, uint64_t Length)
{
    Logger::Log("{BLU}\tZwFlushInstructionCache: handle=%p base=%p{RESET}\n", ProcessHandle, BaseAddress);
    return 0;
}

NTSTATUS h_ZwAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t ZeroBits,
    uint64_t* RegionSize, ULONG AllocationType, ULONG Protect)
{
    Logger::Log("{BLU}\tZwAllocateVirtualMemory: handle=%p type=%08x protect=%08x{RESET}\n",
        ProcessHandle, AllocationType, Protect);
    return __NtRoutine("NtAllocateVirtualMemory",
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS h_ZwFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG FreeType)
{
    Logger::Log("{BLU}\tZwFreeVirtualMemory: handle=%p type=%08x{RESET}\n", ProcessHandle, FreeType);
    return __NtRoutine("NtFreeVirtualMemory",
        ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS h_ZwReadVirtualMemory(
    HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
    uint64_t BufferSize, uint64_t* NumberOfBytesRead)
{
    Logger::Log("{BLU}\tZwReadVirtualMemory: handle=%p base=%p size=%llu{RESET}\n",
        ProcessHandle, BaseAddress, BufferSize);
    return __NtRoutine("NtReadVirtualMemory",
        ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS h_ZwWriteVirtualMemory(
    HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
    uint64_t BufferSize, uint64_t* NumberOfBytesWritten)
{
    Logger::Log("{BLU}\tZwWriteVirtualMemory: handle=%p base=%p size=%llu{RESET}\n",
        ProcessHandle, BaseAddress, BufferSize);
    return __NtRoutine("NtWriteVirtualMemory",
        ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS h_ZwDuplicateObject(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
    Logger::Log("{CYN}\tZwDuplicateObject: src=%p dst=%p{RESET}\n", SourceHandle, TargetProcessHandle);
    return __NtRoutine("NtDuplicateObject",
        SourceProcessHandle, SourceHandle, TargetProcessHandle,
        TargetHandle, DesiredAccess, HandleAttributes, Options);
}
