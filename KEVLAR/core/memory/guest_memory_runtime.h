#pragma once

#include "core/memory/physical_memory.h"

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>

namespace Kevlar::Memory {

struct GuestMemoryRuntimeSnapshot {
    PhysicalMemorySnapshot Physical;
    std::map<std::uint64_t, PageFrameNumber> VirtualPages;
};

void ResetGuestMemory(std::uint64_t Seed = 0x4B45564C4152ULL);
GuestPhysicalAddress TranslateOrMapGuestAddress(std::uint64_t GuestVirtualAddress);
bool RegisterGuestRange(std::uint64_t GuestVirtualAddress, std::uint64_t Size, bool Contiguous);
void UnregisterGuestRange(std::uint64_t GuestVirtualAddress, std::uint64_t Size);
GuestMemoryRuntimeSnapshot SnapshotGuestMemory();
bool RestoreGuestMemory(const GuestMemoryRuntimeSnapshot& Snapshot);
PhysicalMemory& ActivePhysicalMemory();

} // namespace Kevlar::Memory
