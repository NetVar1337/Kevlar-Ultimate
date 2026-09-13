#include "include/common.h"
#include "ke_etw.h"
#include <unordered_map>
#include <cstdio>
#include <string>
#include <mutex>

// Map from fake REGHANDLE to registered provider GUID.
static std::unordered_map<uint64_t, GUID> g_EtwProviders;
static std::mutex g_EtwLock;
static uint64_t g_EtwNextHandle = 1;

static std::string GuidToString(const GUID& G) {
    char Buf[64];
    snprintf(Buf, sizeof(Buf),
        "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        G.Data1, G.Data2, G.Data3,
        G.Data4[0], G.Data4[1],
        G.Data4[2], G.Data4[3], G.Data4[4],
        G.Data4[5], G.Data4[6], G.Data4[7]);
    return Buf;
}

NTSTATUS h_EtwRegister(const GUID* ProviderId, void* EnableCallback, void* CallbackContext, REGHANDLE* RegHandle) {
    if (!ProviderId || !RegHandle)
        return STATUS_INVALID_PARAMETER;

    auto HostGuid   = UcPtr(ProviderId);
    auto HostHandle = UcPtr(RegHandle);

    GUID GuidCopy = *HostGuid;
    uint64_t Handle;
    {
        std::lock_guard<std::mutex> Guard(g_EtwLock);
        Handle = g_EtwNextHandle++;
        g_EtwProviders[Handle] = GuidCopy;
    }

    *HostHandle = (REGHANDLE)Handle;
    Logger::Log("{CYN}[ETW] EtwRegister: provider %s -> handle 0x%llx{RESET}\n",
        GuidToString(GuidCopy).c_str(), Handle);
    return STATUS_SUCCESS;
}

NTSTATUS h_EtwUnregister(REGHANDLE RegHandle) {
    uint64_t Handle = (uint64_t)RegHandle;
    {
        std::lock_guard<std::mutex> Guard(g_EtwLock);
        auto It = g_EtwProviders.find(Handle);
        if (It != g_EtwProviders.end()) {
            Logger::Log("{CYN}[ETW] EtwUnregister: handle 0x%llx (provider %s){RESET}\n",
                Handle, GuidToString(It->second).c_str());
            g_EtwProviders.erase(It);
        } else {
            Logger::Log("{YEL}[ETW] EtwUnregister: unknown handle 0x%llx{RESET}\n", Handle);
        }
    }
    return STATUS_SUCCESS;
}

// EVENT_DESCRIPTOR layout (first 3 bytes): Id(2), Version(1)
static void LogEtwWrite(const char* Func, REGHANDLE RegHandle, void* EventDescriptor) {
    uint64_t Handle = (uint64_t)RegHandle;
    std::string ProviderStr = "<unknown>";
    {
        std::lock_guard<std::mutex> Guard(g_EtwLock);
        auto It = g_EtwProviders.find(Handle);
        if (It != g_EtwProviders.end())
            ProviderStr = GuidToString(It->second);
    }
    uint16_t EventId = 0;
    uint8_t  EventVersion = 0;
    if (EventDescriptor) {
        auto HostDesc = UcPtr((uint8_t*)EventDescriptor);
        if (HostDesc) {
            memcpy(&EventId, HostDesc, sizeof(uint16_t));
            memcpy(&EventVersion, HostDesc + 2, sizeof(uint8_t));
        }
    }
    Logger::Log("{CYN}[ETW] %s: provider %s handle=0x%llx eventId=%u version=%u{RESET}\n",
        Func, ProviderStr.c_str(), Handle, (unsigned)EventId, (unsigned)EventVersion);
}

NTSTATUS h_EtwWrite(REGHANDLE RegHandle, void* EventDescriptor, ULONG UserDataCount, void* UserData) {
    LogEtwWrite("EtwWrite", RegHandle, EventDescriptor);
    return STATUS_SUCCESS;
}

NTSTATUS h_EtwWriteTransfer(REGHANDLE RegHandle, void* EventDescriptor, const GUID* ActivityId, const GUID* RelatedActivityId, ULONG UserDataCount, void* UserData) {
    LogEtwWrite("EtwWriteTransfer", RegHandle, EventDescriptor);
    return STATUS_SUCCESS;
}
