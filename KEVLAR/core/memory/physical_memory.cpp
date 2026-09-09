#include "core/memory/physical_memory.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <set>
#include <type_traits>

namespace Kevlar::Memory {
namespace {

constexpr std::array<std::byte, 4> PhysicalMagic{
    std::byte{'K'}, std::byte{'V'}, std::byte{'P'}, std::byte{'M'}};
constexpr std::uint32_t SnapshotVersion = 1;
constexpr PageFrameNumber MaximumPfn =
    std::numeric_limits<GuestPhysicalAddress>::max() / PageSize;

template <typename T>
void AppendInteger(std::vector<std::byte>& Output, T Value) {
    using Unsigned = std::make_unsigned_t<T>;
    Unsigned Bits = static_cast<Unsigned>(Value);
    for (std::size_t Index = 0; Index < sizeof(T); ++Index) {
        Output.push_back(static_cast<std::byte>((Bits >> (Index * 8)) & 0xff));
    }
}

template <typename T>
bool ReadInteger(std::span<const std::byte> Input, std::size_t& Offset, T& Value) {
    if (Offset > Input.size() || Input.size() - Offset < sizeof(T)) {
        return false;
    }

    using Unsigned = std::make_unsigned_t<T>;
    Unsigned Bits = 0;
    for (std::size_t Index = 0; Index < sizeof(T); ++Index) {
        Bits |= static_cast<Unsigned>(std::to_integer<unsigned char>(Input[Offset + Index]))
            << (Index * 8);
    }
    Offset += sizeof(T);
    Value = static_cast<T>(Bits);
    return true;
}

bool CheckedEnd(std::uint64_t Address, std::size_t Size, std::uint64_t& End) {
    if (Size > std::numeric_limits<std::uint64_t>::max() - Address) {
        return false;
    }
    End = Address + static_cast<std::uint64_t>(Size);
    return true;
}

bool HasDuplicates(std::span<const PageFrameNumber> Pfns) {
    std::set<PageFrameNumber> Seen;
    for (const auto Pfn : Pfns) {
        if (!Seen.insert(Pfn).second) {
            return true;
        }
    }
    return false;
}

} // namespace

GuestPhysicalAddress PhysicalAllocation::GuestAddress() const noexcept {
    if (!Ok() || FirstPfn > MaximumPfn) {
        return 0;
    }
    return FirstPfn * PageSize;
}

PhysicalMemory::PhysicalMemory(std::uint64_t Seed, PageFrameNumber FirstPfn)
    : seed_(Seed),
      firstPfn_(FirstPfn),
      nextPfn_(FirstPfn) {
    if (firstPfn_ == 0 || firstPfn_ > MaximumPfn) {
        firstPfn_ = 1;
        nextPfn_ = 1;
    }
}

std::uint64_t PhysicalMemory::Seed() const noexcept {
    return seed_;
}

bool PhysicalMemory::Contains(PageFrameNumber Pfn) const {
    std::shared_lock Lock(mutex_);
    return pages_.contains(Pfn);
}

std::size_t PhysicalMemory::PageCount() const {
    std::shared_lock Lock(mutex_);
    return pages_.size();
}

PhysicalAllocation PhysicalMemory::AllocatePage(CacheType Cache) {
    return AllocateContiguous(1, Cache);
}

PhysicalAllocation PhysicalMemory::AllocateContiguous(std::size_t Count, CacheType Cache) {
    if (Count == 0 || !IsValidCacheType(Cache)) {
        return {MemoryFault::InvalidArgument, 0, 0};
    }
    if (Count > MaximumPfn || firstPfn_ > MaximumPfn - (Count - 1)) {
        return {MemoryFault::AddressOverflow, 0, 0};
    }

    std::unique_lock Lock(mutex_);
    const auto First = FindContiguousRun(Count);
    if (!First) {
        return {MemoryFault::AllocationFailure, 0, 0};
    }

    std::vector<PageFrameNumber> Inserted;
    try {
        Inserted.reserve(Count);
        for (std::size_t Index = 0; Index < Count; ++Index) {
            const auto Pfn = *First + static_cast<PageFrameNumber>(Index);
            auto [Iterator, WasInserted] = pages_.try_emplace(Pfn, Page{});
            if (!WasInserted) {
                for (const auto Added : Inserted) {
                    pages_.erase(Added);
                }
                return {MemoryFault::AllocationFailure, 0, 0};
            }
            Iterator->second.Cache = Cache;
            Inserted.push_back(Pfn);
        }
    } catch (const std::bad_alloc&) {
        for (const auto Added : Inserted) {
            pages_.erase(Added);
        }
        return {MemoryFault::AllocationFailure, 0, 0};
    }

    const auto End = *First + static_cast<PageFrameNumber>(Count);
    if (End > nextPfn_) {
        nextPfn_ = End;
    }
    return {MemoryFault::None, *First, Count};
}

MemoryResult PhysicalMemory::FreePage(PageFrameNumber Pfn) {
    return FreePages(std::span<const PageFrameNumber>(&Pfn, 1));
}

MemoryResult PhysicalMemory::FreePages(std::span<const PageFrameNumber> Pfns) {
    if (Pfns.empty() || HasDuplicates(Pfns)) {
        return {MemoryFault::InvalidArgument, 0, 0};
    }

    std::unique_lock Lock(mutex_);
    for (const auto Pfn : Pfns) {
        const auto Iterator = pages_.find(Pfn);
        if (Iterator == pages_.end()) {
            return {MemoryFault::PageMissing, Pfn * PageSize, 0};
        }
        if (Iterator->second.PinCount != 0) {
            return {MemoryFault::PagePinned, Pfn * PageSize, 0};
        }
    }
    for (const auto Pfn : Pfns) {
        pages_.erase(Pfn);
    }
    return {};
}

MemoryResult PhysicalMemory::Read(
    GuestPhysicalAddress Address,
    std::span<std::byte> Destination) const {
    if (Destination.empty()) {
        return {};
    }
    std::uint64_t End = 0;
    if (!CheckedEnd(Address, Destination.size(), End)) {
        return {MemoryFault::AddressOverflow, Address, 0};
    }
    (void)End;

    std::shared_lock Lock(mutex_);
    std::size_t Completed = 0;
    while (Completed < Destination.size()) {
        const auto Current = Address + static_cast<std::uint64_t>(Completed);
        const auto Pfn = Current / PageSize;
        const auto Offset = static_cast<std::size_t>(Current % PageSize);
        const auto Iterator = pages_.find(Pfn);
        if (Iterator == pages_.end()) {
            return {MemoryFault::PageMissing, Current, Completed};
        }
        const auto Chunk = std::min<std::size_t>(PageSize - Offset, Destination.size() - Completed);
        std::memcpy(Destination.data() + Completed, Iterator->second.Data.data() + Offset, Chunk);
        Completed += Chunk;
    }
    return {MemoryFault::None, 0, Completed};
}

MemoryResult PhysicalMemory::Write(
    GuestPhysicalAddress Address,
    std::span<const std::byte> Source) {
    if (Source.empty()) {
        return {};
    }
    std::uint64_t End = 0;
    if (!CheckedEnd(Address, Source.size(), End)) {
        return {MemoryFault::AddressOverflow, Address, 0};
    }
    (void)End;

    std::unique_lock Lock(mutex_);
    std::size_t Completed = 0;
    while (Completed < Source.size()) {
        const auto Current = Address + static_cast<std::uint64_t>(Completed);
        const auto Pfn = Current / PageSize;
        const auto Offset = static_cast<std::size_t>(Current % PageSize);
        const auto Iterator = pages_.find(Pfn);
        if (Iterator == pages_.end()) {
            return {MemoryFault::PageMissing, Current, Completed};
        }
        const auto Chunk = std::min<std::size_t>(PageSize - Offset, Source.size() - Completed);
        std::memcpy(Iterator->second.Data.data() + Offset, Source.data() + Completed, Chunk);
        Iterator->second.Dirty = true;
        Completed += Chunk;
    }
    return {MemoryFault::None, 0, Completed};
}

MemoryResult PhysicalMemory::PinPages(std::span<const PageFrameNumber> Pfns) {
    if (Pfns.empty() || HasDuplicates(Pfns)) {
        return {MemoryFault::InvalidArgument, 0, 0};
    }

    std::unique_lock Lock(mutex_);
    for (const auto Pfn : Pfns) {
        const auto Iterator = pages_.find(Pfn);
        if (Iterator == pages_.end()) {
            return {MemoryFault::PageMissing, Pfn * PageSize, 0};
        }
        if (Iterator->second.PinCount == std::numeric_limits<std::uint32_t>::max()) {
            return {MemoryFault::PinOverflow, Pfn * PageSize, 0};
        }
    }
    for (const auto Pfn : Pfns) {
        ++pages_.at(Pfn).PinCount;
    }
    return {};
}

MemoryResult PhysicalMemory::UnpinPages(std::span<const PageFrameNumber> Pfns) {
    if (Pfns.empty() || HasDuplicates(Pfns)) {
        return {MemoryFault::InvalidArgument, 0, 0};
    }

    std::unique_lock Lock(mutex_);
    for (const auto Pfn : Pfns) {
        const auto Iterator = pages_.find(Pfn);
        if (Iterator == pages_.end()) {
            return {MemoryFault::PageMissing, Pfn * PageSize, 0};
        }
        if (Iterator->second.PinCount == 0) {
            return {MemoryFault::PinUnderflow, Pfn * PageSize, 0};
        }
    }
    for (const auto Pfn : Pfns) {
        --pages_.at(Pfn).PinCount;
    }
    return {};
}

MemoryResult PhysicalMemory::SetCacheType(PageFrameNumber Pfn, CacheType Cache) {
    if (!IsValidCacheType(Cache)) {
        return {MemoryFault::InvalidArgument, Pfn * PageSize, 0};
    }
    std::unique_lock Lock(mutex_);
    const auto Iterator = pages_.find(Pfn);
    if (Iterator == pages_.end()) {
        return {MemoryFault::PageMissing, Pfn * PageSize, 0};
    }
    Iterator->second.Cache = Cache;
    return {};
}

std::optional<PhysicalPageInfo> PhysicalMemory::GetPageInfo(PageFrameNumber Pfn) const {
    std::shared_lock Lock(mutex_);
    const auto Iterator = pages_.find(Pfn);
    if (Iterator == pages_.end()) {
        return std::nullopt;
    }
    GuestPhysicalAddress Base = 0;
    if (!TryPhysicalBase(Pfn, Base)) {
        return std::nullopt;
    }
    return PhysicalPageInfo{Pfn, Base, Iterator->second.Cache,
        Iterator->second.PinCount, Iterator->second.Dirty};
}

std::vector<PageFrameNumber> PhysicalMemory::DirtyPfns() const {
    std::shared_lock Lock(mutex_);
    std::vector<PageFrameNumber> Result;
    Result.reserve(pages_.size());
    for (const auto& [Pfn, Page] : pages_) {
        if (Page.Dirty) {
            Result.push_back(Pfn);
        }
    }
    return Result;
}

void PhysicalMemory::ClearDirty(std::span<const PageFrameNumber> Pfns) {
    std::unique_lock Lock(mutex_);
    for (const auto Pfn : Pfns) {
        const auto Iterator = pages_.find(Pfn);
        if (Iterator != pages_.end()) {
            Iterator->second.Dirty = false;
        }
    }
}

void PhysicalMemory::ClearAllDirty() {
    std::unique_lock Lock(mutex_);
    for (auto& [Pfn, Page] : pages_) {
        (void)Pfn;
        Page.Dirty = false;
    }
}

PhysicalMemorySnapshot PhysicalMemory::Snapshot() const {
    std::shared_lock Lock(mutex_);
    PhysicalMemorySnapshot Result;
    Result.Seed = seed_;
    Result.FirstPfn = firstPfn_;
    Result.NextPfn = nextPfn_;
    Result.Pages.reserve(pages_.size());
    for (const auto& [Pfn, Source] : pages_) {
        PhysicalPageSnapshot Page;
        Page.Pfn = Pfn;
        Page.Cache = Source.Cache;
        Page.PinCount = Source.PinCount;
        Page.Dirty = Source.Dirty;
        Page.Data = Source.Data;
        Result.Pages.push_back(std::move(Page));
    }
    return Result;
}

MemoryResult PhysicalMemory::Restore(const PhysicalMemorySnapshot& Snapshot) {
    if (Snapshot.Seed != seed_ || Snapshot.FirstPfn == 0 ||
        Snapshot.FirstPfn > MaximumPfn || Snapshot.NextPfn < Snapshot.FirstPfn ||
        Snapshot.NextPfn > MaximumPfn + 1) {
        return {MemoryFault::CorruptSnapshot, 0, 0};
    }

    std::map<PageFrameNumber, Page> Replacement;
    try {
        for (const auto& Source : Snapshot.Pages) {
            if (Source.Pfn < Snapshot.FirstPfn || Source.Pfn >= Snapshot.NextPfn ||
                Source.Pfn > MaximumPfn || !IsValidCacheType(Source.Cache)) {
                return {MemoryFault::CorruptSnapshot, Source.Pfn * PageSize, 0};
            }
            Page Destination;
            Destination.Data = Source.Data;
            Destination.Cache = Source.Cache;
            Destination.PinCount = Source.PinCount;
            Destination.Dirty = Source.Dirty;
            if (!Replacement.emplace(Source.Pfn, std::move(Destination)).second) {
                return {MemoryFault::CorruptSnapshot, Source.Pfn * PageSize, 0};
            }
        }
    } catch (const std::bad_alloc&) {
        return {MemoryFault::AllocationFailure, 0, 0};
    }

    std::unique_lock Lock(mutex_);
    firstPfn_ = Snapshot.FirstPfn;
    nextPfn_ = Snapshot.NextPfn;
    pages_.swap(Replacement);
    return {};
}

std::vector<std::byte> PhysicalMemory::SerializeSnapshot(
    const PhysicalMemorySnapshot& Snapshot) {
    std::vector<std::byte> Output;
    constexpr std::size_t HeaderSize = 4 + 4 + 8 + 8 + 8 + 8;
    constexpr std::size_t RecordSize = 8 + 1 + 1 + 4 + PageSize;
    if (Snapshot.Pages.size() >
        (std::numeric_limits<std::size_t>::max() - HeaderSize) / RecordSize) {
        return {};
    }
    try {
        Output.reserve(HeaderSize + Snapshot.Pages.size() * RecordSize);
        Output.insert(Output.end(), PhysicalMagic.begin(), PhysicalMagic.end());
        AppendInteger(Output, SnapshotVersion);
        AppendInteger(Output, Snapshot.Seed);
        AppendInteger(Output, Snapshot.FirstPfn);
        AppendInteger(Output, Snapshot.NextPfn);
        AppendInteger(Output, static_cast<std::uint64_t>(Snapshot.Pages.size()));
        for (const auto& Page : Snapshot.Pages) {
            AppendInteger(Output, Page.Pfn);
            AppendInteger(Output, static_cast<std::uint8_t>(Page.Cache));
            AppendInteger(Output, static_cast<std::uint8_t>(Page.Dirty ? 1 : 0));
            AppendInteger(Output, Page.PinCount);
            Output.insert(Output.end(), Page.Data.begin(), Page.Data.end());
        }
    } catch (const std::bad_alloc&) {
        return {};
    }
    return Output;
}

std::optional<PhysicalMemorySnapshot> PhysicalMemory::DeserializeSnapshot(
    std::span<const std::byte> Bytes) {
    if (Bytes.size() < PhysicalMagic.size() ||
        !std::equal(PhysicalMagic.begin(), PhysicalMagic.end(), Bytes.begin())) {
        return std::nullopt;
    }

    std::size_t Offset = PhysicalMagic.size();
    std::uint32_t Version = 0;
    PhysicalMemorySnapshot Result;
    std::uint64_t Count = 0;
    if (!ReadInteger(Bytes, Offset, Version) || Version != SnapshotVersion ||
        !ReadInteger(Bytes, Offset, Result.Seed) ||
        !ReadInteger(Bytes, Offset, Result.FirstPfn) ||
        !ReadInteger(Bytes, Offset, Result.NextPfn) ||
        !ReadInteger(Bytes, Offset, Count)) {
        return std::nullopt;
    }

    constexpr std::size_t RecordSize = 8 + 1 + 1 + 4 + PageSize;
    if (Count > (Bytes.size() - Offset) / RecordSize ||
        Count != (Bytes.size() - Offset) / RecordSize ||
        (Bytes.size() - Offset) % RecordSize != 0) {
        return std::nullopt;
    }

    try {
        Result.Pages.reserve(static_cast<std::size_t>(Count));
        for (std::uint64_t Index = 0; Index < Count; ++Index) {
            PhysicalPageSnapshot Page;
            std::uint8_t Cache = 0;
            std::uint8_t Dirty = 0;
            if (!ReadInteger(Bytes, Offset, Page.Pfn) ||
                !ReadInteger(Bytes, Offset, Cache) ||
                !ReadInteger(Bytes, Offset, Dirty) ||
                !ReadInteger(Bytes, Offset, Page.PinCount) || Dirty > 1) {
                return std::nullopt;
            }
            Page.Cache = static_cast<CacheType>(Cache);
            Page.Dirty = Dirty != 0;
            if (!IsValidCacheType(Page.Cache) || Bytes.size() - Offset < PageSize) {
                return std::nullopt;
            }
            std::copy_n(Bytes.begin() + static_cast<std::ptrdiff_t>(Offset),
                PageSize, Page.Data.begin());
            Offset += PageSize;
            Result.Pages.push_back(std::move(Page));
        }
    } catch (const std::bad_alloc&) {
        return std::nullopt;
    }

    return Result;
}

bool PhysicalMemory::IsValidCacheType(CacheType Cache) noexcept {
    switch (Cache) {
    case CacheType::WriteBack:
    case CacheType::WriteThrough:
    case CacheType::Uncached:
    case CacheType::WriteCombined:
        return true;
    }
    return false;
}

bool PhysicalMemory::TryPhysicalBase(
    PageFrameNumber Pfn,
    GuestPhysicalAddress& Address) noexcept {
    if (Pfn > MaximumPfn) {
        return false;
    }
    Address = Pfn * PageSize;
    return true;
}

std::optional<PageFrameNumber> PhysicalMemory::FindContiguousRun(std::size_t Count) const {
    if (Count == 0 || Count > MaximumPfn) {
        return std::nullopt;
    }

    PageFrameNumber Candidate = firstPfn_;
    const auto Count64 = static_cast<PageFrameNumber>(Count);
    for (const auto& [Pfn, Page] : pages_) {
        (void)Page;
        if (Pfn < Candidate) {
            continue;
        }
        if (Candidate <= MaximumPfn - (Count64 - 1) && Pfn - Candidate >= Count64) {
            return Candidate;
        }
        if (Pfn == MaximumPfn) {
            return std::nullopt;
        }
        Candidate = Pfn + 1;
    }
    if (Candidate <= MaximumPfn - (Count64 - 1)) {
        return Candidate;
    }
    return std::nullopt;
}

} // namespace Kevlar::Memory
