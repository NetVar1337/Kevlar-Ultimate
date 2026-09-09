#include "rtl_hash.h"

#include <Logger/Logger.h>
#include <mutex>
#include <unordered_set>

namespace {
std::mutex EnumeratorLock;
std::unordered_set<uint64_t> ActiveEnumerators;
}

BOOLEAN h_RtlInitWeakEnumerationHashTable(PVOID HashTable, PVOID Enumerator) {
    auto HostEnumerator = UcPtr(static_cast<uint8_t*>(Enumerator));
    if (!HashTable || !HostEnumerator)
        return FALSE;

    // RTL_DYNAMIC_HASH_TABLE_ENUMERATOR is opaque and build-specific. Zeroing
    // its public storage is the documented initial state; enumeration of the
    // synthetic empty table then terminates deterministically.
    memset(HostEnumerator, 0, 0x30);
    {
        std::lock_guard<std::mutex> Guard(EnumeratorLock);
        ActiveEnumerators.insert(reinterpret_cast<uint64_t>(Enumerator));
    }
    Logger::Log("{GRY}\tRtlInitWeakEnumerationHashTable: table=%p enum=%p{RESET}\n", HashTable, Enumerator);
    return TRUE;
}

PVOID h_RtlWeaklyEnumerateEntryHashTable(PVOID HashTable, PVOID Enumerator) {
    std::lock_guard<std::mutex> Guard(EnumeratorLock);
    if (!HashTable || !ActiveEnumerators.contains(reinterpret_cast<uint64_t>(Enumerator)))
        return nullptr;
    return nullptr;
}

void h_RtlEndWeakEnumerationHashTable(PVOID HashTable, PVOID Enumerator) {
    std::lock_guard<std::mutex> Guard(EnumeratorLock);
    ActiveEnumerators.erase(reinterpret_cast<uint64_t>(Enumerator));
    Logger::Log("{GRY}\tRtlEndWeakEnumerationHashTable: table=%p enum=%p{RESET}\n", HashTable, Enumerator);
}
