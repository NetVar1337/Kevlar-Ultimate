#pragma once
#include "include/common.h"
#include <cstddef>
#include <string>

namespace CallbackRuntime {

uc_engine* SelectEngine(uc_engine* Engine);
bool ReadGuest(uc_engine* Engine, uint64_t Address, void* Buffer, size_t Size);
bool WriteGuest(uc_engine* Engine, uint64_t Address, const void* Buffer, size_t Size);
uint64_t AllocateGuestCopy(uc_engine* Engine, const void* Buffer, size_t Size, const char* Name);
uint64_t AllocateOpaqueHandle(uc_engine* Engine, uint64_t Magic, uint64_t Serial, const char* Name);
void FreeGuest(uc_engine* Engine, uint64_t Address);
bool InvokeGuest(uc_engine* Engine, uint64_t Function, const uint64_t* Arguments,
    size_t ArgumentCount, uint64_t* ReturnValue = nullptr);
bool ReadUnicodeString(uc_engine* Engine, uint64_t Address, std::wstring& Value);
bool AltitudePrecedes(const std::wstring& Left, const std::wstring& Right);

}

namespace CmCallbacks {

// Argument2 is a host-side byte buffer. It is copied into guest memory before
// callbacks run and copied back afterward so callback mutations are observable.
NTSTATUS Trigger(uc_engine* Engine, uint32_t NotifyClass, void* Argument2, size_t Argument2Size);
size_t RegisteredCount();

}

NTSTATUS h_CmRegisterCallbackEx(PVOID Function, PUNICODE_STRING Altitude, PVOID Driver, PVOID Context, PLARGE_INTEGER Cookie, PVOID Reserved);
NTSTATUS h_CmUnRegisterCallback(LARGE_INTEGER Cookie);
NTSTATUS h_CmRegisterCallback(PVOID Function, PVOID Context, PLARGE_INTEGER Cookie);
