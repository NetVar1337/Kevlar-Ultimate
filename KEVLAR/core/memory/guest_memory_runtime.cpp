#include "core/memory/guest_memory_runtime.h"

#include <limits>
#include <memory>

namespace Kevlar::Memory {
namespace {
std::mutex RuntimeLock;
std::unique_ptr<PhysicalMemory> Physical = std::make_unique<PhysicalMemory>(0x4B45564C4152ULL);
std::map<std::uint64_t, PageFrameNumber> VirtualPages;

bool CheckedPages(std::uint64_t Address, std::uint64_t Size,
                  std::uint64_t& FirstPage, std::uint64_t& PageCount) {
    if (!Size || Address > std::numeric_limits<std::uint64_t>::max() - (Size - 1))
        return false;
    FirstPage = Address / PageSize;
    const auto LastPage = (Address + Size - 1) / PageSize;
    PageCount = LastPage - FirstPage + 1;
    return PageCount <= 0x100000;
}
}

void ResetGuestMemory(std::uint64_t Seed) {
    auto Replacement = std::make_unique<PhysicalMemory>(Seed);
    std::lock_guard<std::mutex> Guard(RuntimeLock);
    Physical = std::move(Replacement);
    VirtualPages.clear();
}

GuestPhysicalAddress TranslateOrMapGuestAddress(std::uint64_t GuestVirtualAddress) {
    std::lock_guard<std::mutex> Guard(RuntimeLock);
    const std::uint64_t VirtualPage = GuestVirtualAddress / PageSize;
    auto It = VirtualPages.find(VirtualPage);
    if (It == VirtualPages.end()) {
        auto Allocation = Physical->AllocatePage();
        if (!Allocation)
            return 0;
        It = VirtualPages.emplace(VirtualPage, Allocation.FirstPfn).first;
    }
    return It->second * PageSize + (GuestVirtualAddress & (PageSize - 1));
}

bool RegisterGuestRange(std::uint64_t GuestVirtualAddress, std::uint64_t Size, bool Contiguous) {
    std::uint64_t FirstPage = 0, Count = 0;
    if (!CheckedPages(GuestVirtualAddress, Size, FirstPage, Count))
        return false;
    std::lock_guard<std::mutex> Guard(RuntimeLock);
    for (std::uint64_t Index = 0; Index < Count; ++Index) {
        if (VirtualPages.contains(FirstPage + Index))
            return false;
    }
    auto Allocation = Contiguous
        ? Physical->AllocateContiguous(static_cast<std::size_t>(Count))
        : Physical->AllocateContiguous(static_cast<std::size_t>(Count));
    if (!Allocation)
        return false;
    for (std::uint64_t Index = 0; Index < Count; ++Index)
        VirtualPages.emplace(FirstPage + Index, Allocation.FirstPfn + Index);
    return true;
}

void UnregisterGuestRange(std::uint64_t GuestVirtualAddress, std::uint64_t Size) {
    std::uint64_t FirstPage = 0, Count = 0;
    if (!CheckedPages(GuestVirtualAddress, Size, FirstPage, Count))
        return;
    std::lock_guard<std::mutex> Guard(RuntimeLock);
    for (std::uint64_t Index = 0; Index < Count; ++Index) {
        auto It = VirtualPages.find(FirstPage + Index);
        if (It == VirtualPages.end())
            continue;
        Physical->FreePage(It->second);
        VirtualPages.erase(It);
    }
}

GuestMemoryRuntimeSnapshot SnapshotGuestMemory() {
    std::lock_guard<std::mutex> Guard(RuntimeLock);
    return { Physical->Snapshot(), VirtualPages };
}

bool RestoreGuestMemory(const GuestMemoryRuntimeSnapshot& Snapshot) {
    auto Replacement = std::make_unique<PhysicalMemory>(Snapshot.Physical.Seed, Snapshot.Physical.FirstPfn);
    if (!Replacement->Restore(Snapshot.Physical))
        return false;
    std::lock_guard<std::mutex> Guard(RuntimeLock);
    Physical = std::move(Replacement);
    VirtualPages = Snapshot.VirtualPages;
    return true;
}

PhysicalMemory& ActivePhysicalMemory() {
    return *Physical;
}

} // namespace Kevlar::Memory
