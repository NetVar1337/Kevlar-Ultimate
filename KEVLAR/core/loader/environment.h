#pragma once
#include <unordered_map>
#include <mutex>
#include <windows.h>
#include "include/ntoskrnl_struct.h"
#include "include/utils.h"
#include <string>

namespace Environment {
    inline std::unordered_map<uintptr_t, KLDR_DATA_TABLE_ENTRY> environment_module{};
    inline PKLDR_DATA_TABLE_ENTRY PsLoadedModuleList;

    void InitializeSystemModules();
    bool AddModuleFromFile(const std::string& Path, const std::wstring& GuestFullName);
    void CheckPtr(uint64_t ptr);

    namespace ThreadManager {
        inline std::unordered_map<uintptr_t, _ETHREAD*> environment_threads{};
        inline std::mutex ThreadManagerLock;
    }
} 