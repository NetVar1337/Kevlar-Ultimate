#include "pefile.h"
#include <Logger/Logger.h>
#include <SymParser\symparser.hpp>
#include "../../KEVLAR/config.h"
#include <algorithm>
#include <vector>

namespace {

bool IsFileRangeValid(size_t Offset, size_t Length, size_t FileSize) {
    return Offset <= FileSize && Length <= FileSize - Offset;
}

unsigned char* MapRawPeImage(const std::string& Filename) {
    const auto Fail = [&](const char* Reason) {
        Logger::Log("{RED}Raw PE map failed for %s: %s{RESET}\n", Filename.c_str(), Reason);
        return static_cast<unsigned char*>(nullptr);
    };

    std::ifstream RawFile(Filename, std::ios::binary | std::ios::ate);
    if (!RawFile)
        return Fail("open");

    const auto RawSize = RawFile.tellg();
    if (RawSize <= 0 || static_cast<uintmax_t>(RawSize) > SIZE_MAX)
        return Fail("file size");

    std::vector<unsigned char> Raw(static_cast<size_t>(RawSize));
    RawFile.seekg(0);
    if (!RawFile.read(reinterpret_cast<char*>(Raw.data()), RawSize))
        return Fail("read");

    if (Raw.size() < sizeof(IMAGE_DOS_HEADER))
        return Fail("DOS header");

    const auto Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(Raw.data());
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE || Dos->e_lfanew < 0)
        return Fail("DOS signature");

    const auto NtOffset = static_cast<size_t>(Dos->e_lfanew);
    if (!IsFileRangeValid(NtOffset, sizeof(IMAGE_NT_HEADERS64), Raw.size()))
        return Fail("NT header range");

    const auto Nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Raw.data() + NtOffset);
    if (Nt->Signature != IMAGE_NT_SIGNATURE
        || Nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
        || Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
        || Nt->OptionalHeader.SizeOfImage == 0)
        return Fail("NT header");

    const auto ImageSize = static_cast<size_t>(Nt->OptionalHeader.SizeOfImage);
    if (ImageSize > SIZE_MAX)
        return Fail("image size");

    const auto SectionOffset = NtOffset + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader)
        + Nt->FileHeader.SizeOfOptionalHeader;
    if (SectionOffset < NtOffset
        || Nt->FileHeader.NumberOfSections > (Raw.size() - (std::min)(SectionOffset, Raw.size())) / sizeof(IMAGE_SECTION_HEADER)
        || !IsFileRangeValid(SectionOffset,
            static_cast<size_t>(Nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER), Raw.size()))
        return Fail("section table");

    auto Image = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!Image)
        return Fail("allocation");

    const auto HeaderSize = (std::min)((std::min)(static_cast<size_t>(Nt->OptionalHeader.SizeOfHeaders), Raw.size()), ImageSize);
    memcpy(Image, Raw.data(), HeaderSize);

    const auto Sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(Raw.data() + SectionOffset);
    for (uint16_t I = 0; I < Nt->FileHeader.NumberOfSections; ++I) {
        const auto& Section = Sections[I];
        const auto SectionSize = (std::max)(Section.Misc.VirtualSize, Section.SizeOfRawData);
        if (Section.VirtualAddress > ImageSize || SectionSize > ImageSize - Section.VirtualAddress) {
            VirtualFree(Image, 0, MEM_RELEASE);
            return Fail("section virtual range");
        }

        const auto AvailableRaw = Section.PointerToRawData < Raw.size()
            ? (std::min)(static_cast<size_t>(Section.SizeOfRawData), Raw.size() - Section.PointerToRawData)
            : 0;
        if (AvailableRaw < Section.SizeOfRawData)
            Logger::Log("{YEL}Raw PE map: section %u is truncated; zero-filling 0x%llx bytes{RESET}\n",
                I, static_cast<uint64_t>(Section.SizeOfRawData) - AvailableRaw);
        if (AvailableRaw)
            memcpy(Image + Section.VirtualAddress, Raw.data() + Section.PointerToRawData, AvailableRaw);
    }

    return Image;
}


} // namespace
bool PEFile::IsRawMapped() const {
    return raw_mapped;
}



std::unordered_map<std::string, PEFile*> PEFile::moduleList_namekey;
std::vector<PEFile*> PEFile::LoadedModuleArray;

PEFile* PEFile::FindModule(uintptr_t ptr) {
    for (int i = 0; i < LoadedModuleArray.size(); i++)
        if (LoadedModuleArray[i]->GetMappedImageBase() <= ptr
            && ptr <= LoadedModuleArray[i]->GetMappedImageBase() + LoadedModuleArray[i]->GetVirtualSize())
            return LoadedModuleArray[i];
    return 0;
}

PEFile* PEFile::FindModule(std::string name) {

    for (auto& c : name)
        c = tolower(c);

    if (moduleList_namekey.contains(name)) {
        return moduleList_namekey[name];
    }
    return 0;
}

void PEFile::ParseHeader() {

    pDosHeader = (PIMAGE_DOS_HEADER)mapped_buffer;
    pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)mapped_buffer + pDosHeader->e_lfanew);
    pOptionalHeader = &pNtHeaders->OptionalHeader;
    pImageFileHeader = &pNtHeaders->FileHeader;
    pImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)pImageFileHeader + sizeof(IMAGE_FILE_HEADER) + pImageFileHeader->SizeOfOptionalHeader);

    virtual_size = pOptionalHeader->SizeOfImage;
    imagebase = pOptionalHeader->ImageBase;
    entrypoint = pOptionalHeader->AddressOfEntryPoint;
}

void PEFile::ParseSection() {

    sections.clear();

    for (int i = 0; i < pImageFileHeader->NumberOfSections; i++) {

        char RawName[32] = { 0 };
        strncpy_s(RawName, sizeof(RawName), (char*)pImageSectionHeader[i].Name, 8);

        SectionData data = { 0 };

        data.characteristics = pImageSectionHeader[i].Characteristics;
        data.virtual_address = pImageSectionHeader[i].VirtualAddress;
        data.virtual_size = pImageSectionHeader[i].Misc.VirtualSize;
        data.raw_size = pImageSectionHeader[i].SizeOfRawData;
        data.raw_address = pImageSectionHeader[i].PointerToRawData;

        if (RawName[0] == '\0') {
            sprintf_s(RawName, sizeof(RawName), ".sec%d", i);
        }

        std::string FinalName = RawName;
        int Suffix = 0;
        while (sections.contains(FinalName)) {
            Suffix++;
            FinalName = std::string(RawName) + std::to_string(Suffix);
        }

        sections.insert(std::pair(FinalName, data));
    }
}

void PEFile::ParseImport() {
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
        || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
        return;

    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor
        = makepointer<PIMAGE_IMPORT_DESCRIPTOR>(mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {

        PCHAR pDllName = makepointer<PCHAR>(mapped_buffer, pImageImportDescriptor->Name);

        // Original thunk
        PIMAGE_THUNK_DATA pOriginalThunk = NULL;
        if (pImageImportDescriptor->OriginalFirstThunk)
            pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->OriginalFirstThunk);
        else
            pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

        // IAT thunk
        PIMAGE_THUNK_DATA pIATThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

        for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
            FARPROC lpFunction = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {

            } else {
                ImportData id;
                PIMAGE_IMPORT_BY_NAME pImageImportByName = makepointer<PIMAGE_IMPORT_BY_NAME>(mapped_buffer, pOriginalThunk->u1.AddressOfData);

                id.library = pDllName;
                id.name = pImageImportByName->Name;
                id.rva = pIATThunk->u1.Function;

                imports_rvakey.insert(std::pair(id.rva, id));
                imports_namekey.insert(std::pair(id.name, id));
            }
        }
    }
}

void PEFile::ParseExport() {

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0
        || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
        return;

    PIMAGE_EXPORT_DIRECTORY pImageExportDescriptor
        = makepointer<PIMAGE_EXPORT_DIRECTORY>(mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImageExportDescriptor->NumberOfNames || !pImageExportDescriptor->AddressOfFunctions)
        return;

    uint32_t ExportDirRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    uint32_t ExportDirSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Every table read must be bounds-checked against the mapped image; a single
    // out-of-range name RVA used to construct a std::string key would corrupt the
    // export map and fault a later GetExport (the historical ResolveImport crash).
    auto Bounds = [&](uint64_t Rva, uint64_t Size) -> bool {
        return Rva < virtual_size && Size <= virtual_size - Rva;
    };

    if (!Bounds(pImageExportDescriptor->AddressOfFunctions, (uint64_t)pImageExportDescriptor->NumberOfFunctions * sizeof(DWORD))
        || !Bounds(pImageExportDescriptor->AddressOfNames, (uint64_t)pImageExportDescriptor->NumberOfNames * sizeof(DWORD))
        || !Bounds(pImageExportDescriptor->AddressOfNameOrdinals, (uint64_t)pImageExportDescriptor->NumberOfNames * sizeof(WORD)))
        return;

    PDWORD fAddr = (PDWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNames);
    PWORD fOrd = (PWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImageExportDescriptor->NumberOfNames; i++) {
        uint32_t NameRva = fNames[i];
        if (fOrd[i] >= pImageExportDescriptor->NumberOfFunctions || !Bounds(NameRva, 1))
            continue;
        // Name string must be NUL-terminated inside the image before it is copied.
        size_t NameLen = strnlen_s((const char*)((LPBYTE)mapped_buffer + NameRva), (size_t)(virtual_size - NameRva));
        if (NameLen == 0 || NameLen == virtual_size - NameRva)
            continue;
        uint32_t FuncRva = fAddr[fOrd[i]];
        if (FuncRva >= ExportDirRva && FuncRva < ExportDirRva + ExportDirSize)
            continue; // forwarded export, not resolvable here
        std::string FuncName((const char*)((LPBYTE)mapped_buffer + NameRva), NameLen);
        exports_namekey.insert(std::pair(FuncName, (uint64_t)FuncRva));
        exports_rvakey.insert(std::pair((uint64_t)FuncRva, std::move(FuncName)));
    }
}

PEFile::PEFile(std::string filename, std::string name, uintmax_t size) {
    if (!size)
        return;

    mapped_buffer = (unsigned char*)LoadLibraryExA(filename.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!mapped_buffer) {
        mapped_buffer = MapRawPeImage(filename);
        raw_mapped = true;
        if (!mapped_buffer) {
            Logger::Log("{RED}Failed to map PE image: %s{RESET}\n", filename.c_str());
            return;
        }
        Logger::Log("{YEL}LoadLibraryExA rejected %s; using bounded raw PE mapping{RESET}\n", filename.c_str());
    }

    this->isExecutable = false;
    this->filename = filename;
    this->name = name;

    ParseHeader();
    ParseSection();
    ParseImport();
    ParseExport();
}

void PEFile::ResolveImport() {

    if (!mapped_buffer)
        return;
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
        || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
        return;

    auto Bounds = [&](uint64_t Rva) -> bool { return Rva < virtual_size; };

    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor
        = makepointer<PIMAGE_IMPORT_DESCRIPTOR>(mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {

        if (!Bounds(pImageImportDescriptor->Name))
            break;
        PCHAR pDllName = makepointer<PCHAR>(mapped_buffer, pImageImportDescriptor->Name);

        PEFile* importModule = nullptr;
        char tmpName[256] = { 0 };
        strncpy_s(tmpName, sizeof(tmpName), pDllName, _TRUNCATE);
        for (int nl = 0; nl < (int)strlen(tmpName); nl++)
            tmpName[nl] = (char)tolower(tmpName[nl]);
        if (!moduleList_namekey.contains(tmpName)) {
            Logger::Log("{CYN}Loading %s...{RESET}\n", pDllName);
            importModule = PEFile::Open(KevlarGlobal::GetImportDir() + pDllName, pDllName);
        } else {
            importModule = moduleList_namekey[tmpName];
        }
        if (!importModule) {
            Logger::Log("{YEL}ResolveImport: cannot load %s, skipping its imports{RESET}\n", pDllName);
            continue;
        }
        auto modulebase = importModule->GetMappedImageBase();
        PIMAGE_THUNK_DATA pOriginalThunk = NULL;
        if (pImageImportDescriptor->OriginalFirstThunk)
            pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->OriginalFirstThunk);
        else
            pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

        PIMAGE_THUNK_DATA pIATThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);
        DWORD oldProtect = 0;
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(pIATThunk, &mbi, sizeof(mbi));
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect);
        for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
                // Ordinal imports are resolved by BuildSentinelIat; nothing to do here.
                continue;
            }

            uint32_t NameRva = (uint32_t)(pOriginalThunk->u1.AddressOfData & 0x7FFFFFFF);
            if (!Bounds(NameRva))
                continue;
            PIMAGE_IMPORT_BY_NAME pImageImportByName = makepointer<PIMAGE_IMPORT_BY_NAME>(mapped_buffer, NameRva);
            uint64_t ExportRva = importModule->GetExport(pImageImportByName->Name);
            if (ExportRva && modulebase) {
                // Note: this host-image IAT is not executed; UnicornEmu::BuildSentinelIat
                // rebuilds the guest IAT with sentinel stubs. Keep the write valid anyway.
                pIATThunk->u1.Function = modulebase + ExportRva;
            }
            //Logger::Log("Resolved %s::%s to %llx\n", pDllName, pImageImportByName->Name, pIATThunk->u1.Function);
        }
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
    }
}

uint64_t PEFile::GetImageBase() { return imagebase; }

uint64_t PEFile::GetMappedImageBase() { return (uint64_t)mapped_buffer; }
bool PEFile::IsMapped() const { return mapped_buffer != nullptr; }
uint16_t PEFile::GetSubsystem() const { return pOptionalHeader ? pOptionalHeader->Subsystem : 0; }
uint16_t PEFile::GetCharacteristics() const { return pImageFileHeader ? pImageFileHeader->Characteristics : 0; }
bool PEFile::IsDll() const { return (GetCharacteristics() & IMAGE_FILE_DLL) != 0; }



uint64_t PEFile::GetVirtualSize() { return virtual_size; }

ImportData* PEFile::GetImport(std::string name) {
    if (name.empty())
        return nullptr;
    auto It = imports_namekey.find(name);
    return It == imports_namekey.end() ? nullptr : &It->second;
}

ImportData* PEFile::GetImport(uint64_t rva) {
    auto It = imports_rvakey.find(rva);
    return It == imports_rvakey.end() ? nullptr : &It->second;
}

uint64_t PEFile::GetExport(std::string name) {
    if (name.empty())
        return 0;
    auto It = exports_namekey.find(name);
    return It == exports_namekey.end() ? 0 : It->second;
}

const char* PEFile::GetExport(uint64_t rva) {
    auto It = exports_rvakey.find(rva);
    return It == exports_rvakey.end() ? nullptr : It->second.c_str();
}

std::unordered_map<uint64_t, std::string> PEFile::GetAllExports() { return exports_rvakey; }

uintmax_t PEFile::GetEP() { return entrypoint; }

__forceinline uint64_t find_pattern(uint64_t start, size_t size, const uint8_t* binary, size_t len) {
    size_t bin_len = len;
    auto memory = (const uint8_t*)(start);

    for (size_t cur_offset = 0; cur_offset < (size - bin_len); cur_offset++) {
        auto has_match = true;
        for (size_t pos_offset = 0; pos_offset < bin_len; pos_offset++) {
            if (binary[pos_offset] != 0 && memory[cur_offset + pos_offset] != binary[pos_offset]) {
                has_match = false;
                break;
            }
        }

        if (has_match)
            return start + cur_offset;
    }

    return 0;
}

using RtlInsertInvertedFunctionTable = int(__fastcall*)(PVOID BaseAddress, uintmax_t uImageSize);

void PEFile::SetExecutable(bool isExecutable) {
    this->isExecutable = isExecutable;
    auto sym = symparser::find_symbol("c:\\Windows\\System32\\ntdll.dll", "RtlInsertInvertedFunctionTable");
    if (!sym || !sym->rva)
        __debugbreak();
    auto rtlinsert = reinterpret_cast<RtlInsertInvertedFunctionTable>((uint64_t)LoadLibraryA("ntdll.dll") + sym->rva);
    rtlinsert(mapped_buffer, virtual_size);
}

void PEFile::CreateShadowBuffer() {
    //MEMORY_BASIC_INFORMATION mbi;
    DWORD oldProtect = 0;
    shadow_buffer = (unsigned char*)_aligned_malloc(this->GetVirtualSize(), 0x10000);
    memcpy(shadow_buffer, mapped_buffer, this->GetVirtualSize());
    auto sections = this->sections;
    for (auto section = sections.begin(); section != sections.end(); section++) {
        auto sectionName = section->first;
        auto sectionData = section->second;
        if (sectionData.characteristics & 0x80000000 || sectionData.characteristics & 0x40000000) {
            if (sectionName != ".edata") {
                Logger::Log("{CYN}Hooking READ/WRITE %s of %s{RESET}\n", sectionName.c_str(), this->name.c_str());
                VirtualProtect(mapped_buffer + sectionData.virtual_address, sectionData.virtual_size, PAGE_NOACCESS, &oldProtect);
            }
        }

        if ((sectionData.characteristics & 0x20000000) || (sectionData.characteristics & 0x00000020)) {
            Logger::Log("{CYN}Hooking EXECUTE %s of %s{RESET}\n", sectionName.c_str(), this->name.c_str());
            VirtualProtect(mapped_buffer + sectionData.virtual_address, sectionData.virtual_size, PAGE_READONLY, &oldProtect);
        }
    }

    //Logger::Log("%llx\n", result);
}

uintptr_t PEFile::GetShadowBuffer() { return (uintptr_t)shadow_buffer; }
void PEFile::SetPermission() {
    for (int i = 0; i < LoadedModuleArray.size(); i++) {
        if (!LoadedModuleArray[i]->isExecutable) {
            LoadedModuleArray[i]->CreateShadowBuffer();
        }
    }
}

PEFile* PEFile::Open(std::string path, std::string name) {
    std::error_code Ec;
    auto size = std::filesystem::file_size(path, Ec);
    if (Ec || size == 0) {
        Logger::Log("{RED}Failed to get file size for: %s{RESET}\n", path.c_str());
        return 0;
    }

    auto loadedModule = new PEFile(path, name, size);
    if (!loadedModule->IsMapped()) {
        delete loadedModule;
        return nullptr;
    }
    loadedModule->isExecutable = false;
    LoadedModuleArray.push_back(loadedModule);

    for (auto& c : name)
        c = tolower(c);

    moduleList_namekey.insert(std::pair(name, loadedModule));

    return loadedModule;
}