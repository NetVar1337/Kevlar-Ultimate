#include "core/loader/environment.h"
#include "host/config/config.h"
#include "include/utils.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include <Logger/Logger.h>
#include <PEMapper/pefile.h>
#include <SymParser/symparser.hpp>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

struct KldrEntryInfo {
    KLDR_DATA_TABLE_ENTRY Entry;
    std::wstring FullDllNameStr;
    std::wstring BaseDllNameStr;
    uint64_t ModuleUcBase;
};

static std::string ResolveHostModulePath(const char* NtPath) {
    if (!NtPath) return {};
    std::string Path = NtPath;
    const std::string SystemRootPrefix = "\\SystemRoot\\";
    if (Path.rfind(SystemRootPrefix, 0) == 0) {
        char WindowsDirectory[MAX_PATH] = {};
        GetWindowsDirectoryA(WindowsDirectory, MAX_PATH);
        return std::string(WindowsDirectory) + "\\"
            + Path.substr(SystemRootPrefix.size());
    }
    if (Path.rfind("\\??\\", 0) == 0)
        return Path.substr(4);
    return Path;
}

static void PopulatePeIdentity(const std::string& Path, KLDR_DATA_TABLE_ENTRY& Entry) {
    std::ifstream File(Path, std::ios::binary);
    IMAGE_DOS_HEADER Dos = {};
    if (!File.read(reinterpret_cast<char*>(&Dos), sizeof(Dos))
        || Dos.e_magic != IMAGE_DOS_SIGNATURE || Dos.e_lfanew <= 0)
        return;
    File.seekg(Dos.e_lfanew);
    IMAGE_NT_HEADERS64 Nt = {};
    if (!File.read(reinterpret_cast<char*>(&Nt), sizeof(Nt))
        || Nt.Signature != IMAGE_NT_SIGNATURE
        || Nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return;
    Entry.TimeDateStamp = Nt.FileHeader.TimeDateStamp;
    Entry.CheckSum = Nt.OptionalHeader.CheckSum;
    if (Nt.OptionalHeader.SizeOfImage) {
        Entry.SizeOfImage = Nt.OptionalHeader.SizeOfImage;
        Entry.SizeOfImageNotRounded = Nt.OptionalHeader.SizeOfImage;
    }
}

void Environment::InitializeSystemModules() {
    auto pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) {
        Logger::Log("{RED}Failed to get NtQuerySystemInformation{RESET}\n");
        return;
    }

    ULONG Len = 0;
    NTSTATUS Ret = pNtQuerySystemInformation(0x0B, nullptr, 0, &Len);
    if (Ret != 0xC0000004 && Ret != 0) {
        Logger::Log("{RED}NtQuerySystemInformation length query failed: 0x%08x{RESET}\n", Ret);
        return;
    }

    PVOID Data = malloc(Len);
    if (!Data) {
        Logger::Log("{RED}Failed to allocate %lu bytes for system module info{RESET}\n", Len);
        return;
    }
    memset(Data, 0, Len);

    Ret = pNtQuerySystemInformation(0x0B, Data, Len, &Len);
    if (Ret != 0) {
        Logger::Log("{RED}NtQuerySystemInformation failed: 0x%08x{RESET}\n", Ret);
        free(Data);
        return;
    }

    auto Mods = (RTL_PROCESS_MODULES*)Data;
    ULONG NumMods = Mods->NumberOfModules;
    Logger::Log("{CYN}Found %u system modules{RESET}\n", NumMods);

    std::vector<std::string> BlacklistedModules = {
        "vmci.sys", "vsock.sys", "vmx86.sys", "vmnet.sys",
        "vmnetbridge.sys", "vmnetuserif.sys", "vm3dmp.sys",
        "vm3dmp-debug.sys", "vm3dmp-stats.sys", "vm3dmp_loader.sys",
        "vmhgfs.sys", "vmmouse.sys", "vmusbmouse.sys", "vmrawdsk.sys",
        "vmmemctl.sys", "vmxnet3.sys",
        "hcmon.sys", "vmnetadapter.sys", "vmnat.sys", "vmnetdhcp.sys",
        "vboxguest.sys", "vboxsf.sys", "vboxmouse.sys", "vboxvideo.sys",
        "vboxdrv.sys", "vboxnetadp.sys", "vboxnetflt.sys",
        "parsecvusba.sys", "droidcamvideo.sys", "droidcamaudio.sys",
        "iriuna0.sys", "vbaudio_cable64_win10.sys",
        "vmbus.sys", "vmsproxy.sys", "vmsproxyhnic.sys", "winhvr.sys",
        "vid.sys", "hypervideo.sys", "storvsp.sys", "netvsc.sys",
        "vmbkmclr.sys", "hvservice.sys", "vmstorfl.sys",
        "npcap.sys", "vigembus.sys",
        "faceit_ac.sys", "faceit_iommu.sys", "vgk.sys",
    };

    std::vector<KldrEntryInfo> Entries;
    int StubCount = 0;
    const int MaxStubs = 600;
    int TotalModules = 0;
    const int MaxTotalModules = 100;

    for (ULONG I = 0; I < NumMods && TotalModules < MaxTotalModules; I++) {
        auto& ModInfo = Mods->Modules[I];
        auto Filename = strrchr((const char*)ModInfo.FullPathName, '\\');
        if (!Filename) continue;
        Filename++;

        std::string CheckName = Filename;
        for (auto& C : CheckName) C = (char)tolower(C);
        bool IsBlacklisted = false;
        for (auto& Bl : BlacklistedModules) {
            if (CheckName == Bl) { IsBlacklisted = true; break; }
        }
        if (IsBlacklisted) {
            Logger::Log("{YEL}Filtering VM/virtual module: %s{RESET}\n", Filename);
            continue;
        }

        KldrEntryInfo Info{};
        auto& KldrEntry = Info.Entry;
        memset(&KldrEntry, 0, sizeof(KldrEntry));

        KldrEntry.Flags = ModInfo.Flags;
        KldrEntry.LoadCount = 1;
        KldrEntry.SizeOfImage = ModInfo.ImageSize;
        KldrEntry.SizeOfImageNotRounded = ModInfo.ImageSize;
        KldrEntry.TimeDateStamp = 0;
        KldrEntry.CheckSum = 0;
        KldrEntry.SectionPointer = nullptr;
        KldrEntry.ExceptionTable = nullptr;
        KldrEntry.ExceptionTableSize = 0;
        KldrEntry.GpValue = nullptr;
        KldrEntry.NonPagedDebugInfo = nullptr;
        KldrEntry.CoverageSection = nullptr;
        KldrEntry.CoverageSectionSize = 0;
        KldrEntry.LoadedImports = nullptr;
        KldrEntry.Spare = nullptr;

        std::string FilenameLower = Filename;
        for (auto& C : FilenameLower) C = (char)tolower(C);
        bool IsNtoskrnl = FilenameLower.find("ntoskrnl") != std::string::npos;
        bool IsHal = FilenameLower.find("hal.dll") != std::string::npos;
        bool IsCi = FilenameLower.find("ci.dll") != std::string::npos;

        if (IsNtoskrnl || IsHal || IsCi) {
            KldrEntry.u1.EntireField = 0x006C;
        } else {
            KldrEntry.u1.EntireField = 0x0026;
        }

        Info.FullDllNameStr = UtilWidestringFromString((const char*)ModInfo.FullPathName);
        Info.BaseDllNameStr = UtilWidestringFromString((const char*)ModInfo.FullPathName + ModInfo.OffsetToFileName);
        const std::string HostModulePath = ResolveHostModulePath((const char*)ModInfo.FullPathName);
        PopulatePeIdentity(HostModulePath, KldrEntry);

        RtlInitUnicodeString(&KldrEntry.FullDllName, Info.FullDllNameStr.c_str());
        RtlInitUnicodeString(&KldrEntry.BaseDllName, Info.BaseDllNameStr.c_str());

        const auto LocalOverride = KevlarGlobal::GetImportDir() + Filename;

        const bool UsingLocalOverride = fs::exists(LocalOverride);
        const std::string ImportFile = UsingLocalOverride
            ? LocalOverride : (fs::exists(HostModulePath) ? HostModulePath : std::string());
        bool ModuleLoaded = false;
        if (!ImportFile.empty()) {
            auto PeFile = PEFile::Open(ImportFile, Filename);
            if (PeFile) {
                uint64_t UcBase = UnicornEmu::MapSystemModule(PeFile, Filename);
                if (UcBase) {
                    Info.ModuleUcBase = UcBase;
                    KldrEntry.DllBase = (PVOID)UcBase;
                    KldrEntry.EntryPoint = (PVOID)(UcBase + PeFile->GetEP());

                    auto HostBase = (uint8_t*)PeFile->GetMappedImageBase();
                    auto Dos = (PIMAGE_DOS_HEADER)HostBase;
                    auto Nt = (PIMAGE_NT_HEADERS)(HostBase + Dos->e_lfanew);
                    auto& ExcDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                    if (ExcDir.VirtualAddress && ExcDir.Size) {
                        KldrEntry.ExceptionTable = (PVOID)(UcBase + ExcDir.VirtualAddress);
                        KldrEntry.ExceptionTableSize = ExcDir.Size;
                    }

                    if (UsingLocalOverride) {
                        Logger::Log("{CYN}PDB for %s{RESET}\n", ImportFile.c_str());
                        if (FilenameLower.find("ntoskrnl") == std::string::npos)
                            symparser::download_symbols(ImportFile);
                    }
                    ModuleLoaded = true;
                } else {
                    Logger::Log("{YEL}MapSystemModule returned 0 for %s, using stub{RESET}\n", Filename);
                }
            } else {
                Logger::Log("{YEL}PEFile::Open failed for %s, using stub{RESET}\n", Filename);
            }
        }

        if (!ModuleLoaded) {
            if (StubCount >= MaxStubs) {
                Logger::Log("{YEL}Skipping stub for %s (max %d stubs reached){RESET}\n", Filename, MaxStubs);
                continue;
            }
            uint64_t StubBase = UnicornEmu::MapStubModule(Filename, ModInfo.ImageSize);
            Info.ModuleUcBase = StubBase;
            KldrEntry.DllBase = (PVOID)StubBase;
            KldrEntry.EntryPoint = (PVOID)StubBase;
            KldrEntry.SizeOfImage = 0x2000;
            KldrEntry.SizeOfImageNotRounded = 0x2000;
            StubCount++;
        }

        TotalModules++;
        environment_module.insert(std::pair((uintptr_t)KldrEntry.DllBase, KldrEntry));
        Entries.push_back(std::move(Info));
    }

    free(Data);

    std::vector<uint64_t> UcLdrAddrs;

    for (auto& Info : Entries) {
        auto& KldrEntry = Info.Entry;
        uint64_t EntrySize = sizeof(KLDR_DATA_TABLE_ENTRY) + 0x400;
        std::string VarName = std::string("KldrEntry.") + UtilStringFromWidestring(Info.BaseDllNameStr);

        uint64_t UcAddr = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, EntrySize, VarName.c_str());
        auto TrackedEntry = (PKLDR_DATA_TABLE_ENTRY)UnicornMem::UcToHost(UcAddr);

        memcpy(TrackedEntry, &KldrEntry, sizeof(KldrEntry));

        if (KldrEntry.FullDllName.Buffer && KldrEntry.FullDllName.Length > 0) {
            size_t StrOff = sizeof(KLDR_DATA_TABLE_ENTRY);
            StrOff = (StrOff + 0xF) & ~0xFULL;
            size_t CopyLen = KldrEntry.FullDllName.MaximumLength;
            if (StrOff + CopyLen < EntrySize) {
                memcpy((uint8_t*)TrackedEntry + StrOff, Info.FullDllNameStr.c_str(), CopyLen);
                TrackedEntry->FullDllName.Buffer = (wchar_t*)(UcAddr + StrOff);
            }

            size_t BaseStrOff = StrOff + CopyLen;
            BaseStrOff = (BaseStrOff + 0xF) & ~0xFULL;
            if (KldrEntry.BaseDllName.Buffer && KldrEntry.BaseDllName.Length > 0) {
                size_t BaseCopyLen = KldrEntry.BaseDllName.MaximumLength;
                if (BaseStrOff + BaseCopyLen < EntrySize) {
                    memcpy((uint8_t*)TrackedEntry + BaseStrOff, Info.BaseDllNameStr.c_str(), BaseCopyLen);
                    TrackedEntry->BaseDllName.Buffer = (wchar_t*)(UcAddr + BaseStrOff);
                }
            }
        }

        TrackedEntry->DllBase = (PVOID)KldrEntry.DllBase;

        for (auto& Mod : UnicornEmu::MappedSysMods) {
            if (Mod.UcBase == (uint64_t)KldrEntry.DllBase) {
                Mod.LoaderEntry = UcAddr;
                break;
            }
        }

        UcLdrAddrs.push_back(UcAddr);
    }

    if (!UcLdrAddrs.empty()) {
        for (size_t I = 0; I < UcLdrAddrs.size(); I++) {
            uint64_t CurrentUc = UcLdrAddrs[I];
            uint64_t CurrentLinksUc = CurrentUc + offsetof(KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            uint64_t PrevIdx = (I == 0) ? UcLdrAddrs.size() - 1 : I - 1;
            uint64_t NextIdx = (I == UcLdrAddrs.size() - 1) ? 0 : I + 1;

            uint64_t PrevLinksUc = UcLdrAddrs[PrevIdx] + offsetof(KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            uint64_t NextLinksUc = UcLdrAddrs[NextIdx] + offsetof(KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            auto HostEntry = (PKLDR_DATA_TABLE_ENTRY)UnicornMem::UcToHost(CurrentUc);
            HostEntry->InLoadOrderLinks.Flink = (LIST_ENTRY*)NextLinksUc;
            HostEntry->InLoadOrderLinks.Blink = (LIST_ENTRY*)PrevLinksUc;
        }

        PsLoadedModuleList = (PKLDR_DATA_TABLE_ENTRY)UcLdrAddrs[0];

        for (size_t I = 0; I < Entries.size(); I++) {
            auto& BaseName = Entries[I].BaseDllNameStr;
            if (BaseName.find(L"ntoskrnl") != std::wstring::npos) {
                PsLoadedModuleList = (PKLDR_DATA_TABLE_ENTRY)UcLdrAddrs[I];
                break;
            }
        }
    }

}

void Environment::CheckPtr(uint64_t Ptr) {
    for (auto It = environment_module.begin(); It != environment_module.end(); It++) {
        uintptr_t Base = (uintptr_t)It->second.DllBase;

        if (Base <= Ptr && Ptr <= Base + It->second.SizeOfImage) {
            Logger::Log("{YEL}Trying to access not overriden module : %wZ at offset %llx{RESET}\n", It->second.FullDllName, Ptr - Base);
            break;
        }
    }
    return;
}

bool Environment::AddModuleFromFile(
    const std::string& Path, const std::wstring& GuestFullName) {
    std::filesystem::path FilePath(Path);
    if (!std::filesystem::exists(FilePath))
        return false;
    const std::string BaseName = FilePath.filename().string();
    auto Module = PEFile::Open(Path, BaseName);
    if (!Module)
        return false;
    const uint64_t ModuleBase = UnicornEmu::MapSystemModule(Module, BaseName.c_str());
    if (!ModuleBase)
        return false;

    const std::wstring FullName = GuestFullName.empty()
        ? (L"\\SystemRoot\\system32\\drivers\\" + FilePath.filename().wstring())
        : GuestFullName;
    const std::wstring WideBase = FilePath.filename().wstring();
    const size_t EntrySize = sizeof(KLDR_DATA_TABLE_ENTRY) + 0x400;
    const uint64_t EntryUc = UnicornMem::AllocateVariable(
        UnicornEmu::PrimaryEngine, EntrySize, ("KldrEntry." + BaseName).c_str());
    auto Entry = reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(
        UnicornMem::UcToHost(EntryUc));
    if (!Entry)
        return false;
    memset(Entry, 0, EntrySize);

    Entry->DllBase = reinterpret_cast<PVOID>(ModuleBase);
    Entry->EntryPoint = reinterpret_cast<PVOID>(ModuleBase + Module->GetEP());
    Entry->SizeOfImage = static_cast<ULONG>(Module->GetVirtualSize());
    Entry->SizeOfImageNotRounded = Entry->SizeOfImage;
    Entry->Flags = 0x20;
    Entry->LoadCount = 1;
    Entry->u1.EntireField = 0x26;

    auto HostBase = reinterpret_cast<uint8_t*>(Module->GetMappedImageBase());
    auto Dos = reinterpret_cast<PIMAGE_DOS_HEADER>(HostBase);
    auto Nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(HostBase + Dos->e_lfanew);
    Entry->CheckSum = Nt->OptionalHeader.CheckSum;
    Entry->TimeDateStamp = Nt->FileHeader.TimeDateStamp;
    const auto& Exception = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (Exception.VirtualAddress && Exception.Size) {
        Entry->ExceptionTable = reinterpret_cast<PVOID>(ModuleBase + Exception.VirtualAddress);
        Entry->ExceptionTableSize = Exception.Size;
    }

    size_t Offset = (sizeof(KLDR_DATA_TABLE_ENTRY) + 0xF) & ~size_t(0xF);
    const size_t FullBytes = (FullName.size() + 1) * sizeof(wchar_t);
    const size_t BaseOffset = (Offset + FullBytes + 0xF) & ~size_t(0xF);
    const size_t BaseBytes = (WideBase.size() + 1) * sizeof(wchar_t);
    if (BaseOffset + BaseBytes > EntrySize)
        return false;
    memcpy(reinterpret_cast<uint8_t*>(Entry) + Offset, FullName.c_str(), FullBytes);
    memcpy(reinterpret_cast<uint8_t*>(Entry) + BaseOffset, WideBase.c_str(), BaseBytes);
    Entry->FullDllName = {
        static_cast<USHORT>(FullName.size() * sizeof(wchar_t)),
        static_cast<USHORT>(FullBytes),
        reinterpret_cast<PWCH>(EntryUc + Offset),
    };
    Entry->BaseDllName = {
        static_cast<USHORT>(WideBase.size() * sizeof(wchar_t)),
        static_cast<USHORT>(BaseBytes),
        reinterpret_cast<PWCH>(EntryUc + BaseOffset),
    };

    const uint64_t HeadUc = reinterpret_cast<uint64_t>(PsLoadedModuleList);
    auto Head = reinterpret_cast<PLIST_ENTRY>(UnicornMem::UcToHost(HeadUc));
    if (!Head)
        return false;
    const uint64_t LastUc = reinterpret_cast<uint64_t>(Head->Blink);
    auto Last = reinterpret_cast<PLIST_ENTRY>(UnicornMem::UcToHost(LastUc));
    Entry->InLoadOrderLinks.Flink = reinterpret_cast<PLIST_ENTRY>(HeadUc);
    Entry->InLoadOrderLinks.Blink = reinterpret_cast<PLIST_ENTRY>(LastUc);
    if (Last)
        Last->Flink = reinterpret_cast<PLIST_ENTRY>(EntryUc);
    Head->Blink = reinterpret_cast<PLIST_ENTRY>(EntryUc);

    Entry->SectionPointer = reinterpret_cast<PVOID>(EntryUc);
    environment_module[ModuleBase] = *Entry;
    for (auto& Mod : UnicornEmu::MappedSysMods) {
        if (Mod.UcBase == ModuleBase) {
            Mod.LoaderEntry = EntryUc;
            break;
        }
    }
    Logger::Log("{CYN}Added companion module %s at UC 0x%llx size=0x%x{RESET}\n",
        BaseName.c_str(), ModuleBase, Entry->SizeOfImage);
    return true;
}