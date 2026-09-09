#include "core/memory/virtual_address_space.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <set>
#include <type_traits>

namespace Kevlar::Memory {
namespace {
constexpr std::array<std::byte, 4> Magic{std::byte{'K'}, std::byte{'V'}, std::byte{'V'}, std::byte{'A'}};
constexpr std::uint32_t Version = 1;
constexpr std::uint8_t ProtectionMask = 0x0f;

std::uint64_t Mix(std::uint64_t Value) {
    Value += 0x9e3779b97f4a7c15ull;
    Value = (Value ^ (Value >> 30)) * 0xbf58476d1ce4e5b9ull;
    Value = (Value ^ (Value >> 27)) * 0x94d049bb133111ebull;
    return Value ^ (Value >> 31);
}

template <typename T> void Append(std::vector<std::byte>& Out, T Value) {
    using U = std::make_unsigned_t<T>;
    U Bits = static_cast<U>(Value);
    for (std::size_t I = 0; I < sizeof(T); ++I) Out.push_back(static_cast<std::byte>((Bits >> (I * 8)) & 0xff));
}
template <typename T> bool Take(std::span<const std::byte> In, std::size_t& Off, T& Value) {
    if (Off > In.size() || In.size() - Off < sizeof(T)) return false;
    using U = std::make_unsigned_t<T>; U Bits = 0;
    for (std::size_t I = 0; I < sizeof(T); ++I)
        Bits |= static_cast<U>(std::to_integer<unsigned char>(In[Off + I])) << (I * 8);
    Off += sizeof(T); Value = static_cast<T>(Bits); return true;
}

Protection RequiredProtection(AccessType Access) {
    switch (Access) {
    case AccessType::Read: return Protection::Read;
    case AccessType::Write: return Protection::Write;
    case AccessType::Execute: return Protection::Execute;
    }
    return Protection::None;
}
} // namespace

VirtualAddressSpace::VirtualAddressSpace(std::shared_ptr<PhysicalMemory> Physical,
    std::uint64_t ProcessId, std::uint64_t Seed, std::uint64_t MinimumAddress,
    std::uint64_t MaximumAddressExclusive)
    : physical_(std::move(Physical)), processId_(ProcessId), seed_(Seed),
      minimumAddress_((MinimumAddress + PageSize - 1) & ~(PageSize - 1)),
      maximumAddressExclusive_(MaximumAddressExclusive & ~(PageSize - 1)),
      allocationCursor_(minimumAddress_) {
    if (maximumAddressExclusive_ > minimumAddress_) {
        const auto Pages = (maximumAddressExclusive_ - minimumAddress_) / PageSize;
        const auto Window = std::min<std::uint64_t>(Pages, 4096);
        allocationCursor_ += (Window == 0 ? 0 : Mix(seed_ ^ processId_) % Window) * PageSize;
    }
}

std::uint64_t VirtualAddressSpace::ProcessId() const noexcept { return processId_; }
std::uint64_t VirtualAddressSpace::Seed() const noexcept { return seed_; }

VirtualAllocation VirtualAddressSpace::Allocate(std::uint64_t Size, Protection Access,
    CacheType Cache, std::optional<std::uint64_t> PreferredAddress) {
    if (!physical_ || Size == 0 || !IsValidProtection(Access) || Size > UINT64_MAX - (PageSize - 1))
        return {MemoryFault::InvalidArgument};
    const auto AlignedSize = (Size + PageSize - 1) & ~(PageSize - 1);
    const auto Count = AlignedSize / PageSize;

    std::unique_lock Lock(mutex_);
    std::optional<std::uint64_t> Base;
    if (PreferredAddress) {
        if ((*PreferredAddress % PageSize) != 0 || !RangeInBounds(*PreferredAddress / PageSize, Count))
            return {MemoryFault::InvalidAlignment};
        bool Free = true;
        for (std::uint64_t I = 0; I < Count; ++I) Free &= !mappings_.contains(*PreferredAddress / PageSize + I);
        if (!Free) return {MemoryFault::AlreadyMapped, *PreferredAddress};
        Base = *PreferredAddress;
    } else {
        Base = FindFreeRange(Count);
        if (!Base) return {MemoryFault::OutOfRange};
    }

    const auto Physical = physical_->AllocateContiguous(static_cast<std::size_t>(Count), Cache);
    if (!Physical) return {Physical.Fault};
    VirtualAllocation Result;
    Result.Address = *Base; Result.Size = AlignedSize;
    try {
        Result.Pfns.reserve(static_cast<std::size_t>(Count));
        for (std::uint64_t I = 0; I < Count; ++I) {
            const auto Pfn = Physical.FirstPfn + I;
            mappings_.emplace(*Base / PageSize + I, Mapping{Pfn, Access, false});
            Result.Pfns.push_back(Pfn);
        }
    } catch (const std::bad_alloc&) {
        for (std::uint64_t I = 0; I < Count; ++I) mappings_.erase(*Base / PageSize + I);
        std::vector<PageFrameNumber> Pfns;
        for (std::uint64_t I = 0; I < Count; ++I) Pfns.push_back(Physical.FirstPfn + I);
        (void)physical_->FreePages(Pfns);
        return {MemoryFault::AllocationFailure};
    }
    allocationCursor_ = *Base + AlignedSize;
    if (allocationCursor_ >= maximumAddressExclusive_) allocationCursor_ = minimumAddress_;
    return Result;
}

MemoryResult VirtualAddressSpace::Map(std::uint64_t Address, std::span<const PageFrameNumber> Pfns,
    Protection Access, bool CopyOnWrite) {
    if (!physical_ || Pfns.empty() || Address % PageSize || !IsValidProtection(Access) ||
        (CopyOnWrite && !HasProtection(Access, Protection::Write))) return {MemoryFault::InvalidArgument, Address};
    std::unique_lock Lock(mutex_);
    const auto First = Address / PageSize;
    if (!RangeInBounds(First, Pfns.size())) return {MemoryFault::OutOfRange, Address};
    for (std::size_t I = 0; I < Pfns.size(); ++I) {
        if (!physical_->Contains(Pfns[I])) return {MemoryFault::PageMissing, Address + I * PageSize};
        if (mappings_.contains(First + I)) return {MemoryFault::AlreadyMapped, Address + I * PageSize};
    }
    try {
        for (std::size_t I = 0; I < Pfns.size(); ++I)
            mappings_.emplace(First + I, Mapping{Pfns[I], Access, CopyOnWrite});
    } catch (const std::bad_alloc&) {
        for (std::size_t I = 0; I < Pfns.size(); ++I) mappings_.erase(First + I);
        return {MemoryFault::AllocationFailure, Address};
    }
    return {};
}

MemoryResult VirtualAddressSpace::Unmap(std::uint64_t Address, std::uint64_t Size) {
    std::uint64_t First = 0, Count = 0;
    if (!CheckedPageRange(Address, Size, First, Count)) return {MemoryFault::InvalidAlignment, Address};
    std::unique_lock Lock(mutex_);
    if (!RangeInBounds(First, Count)) return {MemoryFault::OutOfRange, Address};
    for (std::uint64_t I = 0; I < Count; ++I)
        if (!mappings_.contains(First + I)) return {MemoryFault::Unmapped, (First + I) * PageSize};
    for (std::uint64_t I = 0; I < Count; ++I) mappings_.erase(First + I);
    return {};
}

MemoryResult VirtualAddressSpace::Protect(std::uint64_t Address, std::uint64_t Size, Protection Access) {
    std::uint64_t First = 0, Count = 0;
    if (!CheckedPageRange(Address, Size, First, Count) || !IsValidProtection(Access))
        return {MemoryFault::InvalidArgument, Address};
    std::unique_lock Lock(mutex_);
    if (!RangeInBounds(First, Count)) return {MemoryFault::OutOfRange, Address};
    for (std::uint64_t I = 0; I < Count; ++I)
        if (!mappings_.contains(First + I)) return {MemoryFault::Unmapped, (First + I) * PageSize};
    for (std::uint64_t I = 0; I < Count; ++I) {
        auto& Entry = mappings_.at(First + I); Entry.Access = Access;
        if (!HasProtection(Access, Protection::Write)) Entry.CopyOnWrite = false;
    }
    return {};
}

TranslationResult VirtualAddressSpace::Translate(std::uint64_t Address, AccessType Access, bool UserMode) const {
    std::shared_lock Lock(mutex_); return TranslateLocked(Address, Access, UserMode);
}

TranslationResult VirtualAddressSpace::TranslateLocked(std::uint64_t Address, AccessType Access, bool UserMode) const {
    if (Address < minimumAddress_ || Address >= maximumAddressExclusive_) return {MemoryFault::OutOfRange, Address};
    const auto It = mappings_.find(Address / PageSize);
    if (It == mappings_.end()) return {MemoryFault::Unmapped, Address};
    const auto Required = RequiredProtection(Access);
    if (!HasProtection(It->second.Access, Required) || (UserMode && !HasProtection(It->second.Access, Protection::User)))
        return {MemoryFault::ProtectionViolation, Address};
    const auto Info = physical_->GetPageInfo(It->second.Pfn);
    if (!Info) return {MemoryFault::PageMissing, Address};
    const auto Offset = static_cast<std::uint16_t>(Address % PageSize);
    return {MemoryFault::None, 0, Info->GuestBase + Offset, It->second.Pfn, Offset,
        It->second.Access, Info->Cache, It->second.CopyOnWrite};
}

MemoryResult VirtualAddressSpace::Read(std::uint64_t Address, std::span<std::byte> Destination, bool UserMode) const {
    if (Destination.empty()) return {};
    if (Destination.size() > UINT64_MAX - Address) return {MemoryFault::AddressOverflow, Address};
    std::shared_lock Lock(mutex_); std::size_t Done = 0;
    while (Done < Destination.size()) {
        const auto Current = Address + Done; const auto Translation = TranslateLocked(Current, AccessType::Read, UserMode);
        if (!Translation) return {Translation.Fault, Current, Done};
        const auto Chunk = std::min<std::size_t>(PageSize - Translation.PageOffset, Destination.size() - Done);
        const auto Result = physical_->Read(Translation.PhysicalAddress, Destination.subspan(Done, Chunk));
        if (!Result) return {Result.Fault, Current + Result.BytesCompleted, Done + Result.BytesCompleted};
        Done += Chunk;
    }
    return {MemoryFault::None, 0, Done};
}

MemoryResult VirtualAddressSpace::Write(std::uint64_t Address, std::span<const std::byte> Source, bool UserMode) {
    if (Source.empty()) return {};
    if (Source.size() > UINT64_MAX - Address) return {MemoryFault::AddressOverflow, Address};
    std::unique_lock Lock(mutex_); std::size_t Done = 0;
    while (Done < Source.size()) {
        const auto Current = Address + Done; auto Translation = TranslateLocked(Current, AccessType::Write, UserMode);
        if (!Translation) return {Translation.Fault, Current, Done};
        auto& Mapping = mappings_.at(Current / PageSize);
        if (Mapping.CopyOnWrite) {
            const auto NewPage = physical_->AllocatePage(Translation.Cache);
            if (!NewPage) return {NewPage.Fault, Current, Done};
            std::array<std::byte, PageSize> Copy{};
            auto Result = physical_->Read(Mapping.Pfn * PageSize, Copy);
            if (!Result || !(Result = physical_->Write(NewPage.GuestAddress(), Copy))) {
                (void)physical_->FreePage(NewPage.FirstPfn); return {Result.Fault, Current, Done};
            }
            Mapping.Pfn = NewPage.FirstPfn; Mapping.CopyOnWrite = false;
            Translation = TranslateLocked(Current, AccessType::Write, UserMode);
        }
        const auto Chunk = std::min<std::size_t>(PageSize - Translation.PageOffset, Source.size() - Done);
        const auto Result = physical_->Write(Translation.PhysicalAddress, Source.subspan(Done, Chunk));
        if (!Result) return {Result.Fault, Current + Result.BytesCompleted, Done + Result.BytesCompleted};
        Done += Chunk;
    }
    return {MemoryFault::None, 0, Done};
}

MemoryResult VirtualAddressSpace::Pin(std::uint64_t Address, std::uint64_t Size, std::vector<PageFrameNumber>* PinnedPfns) {
    if (Size == 0 || Size > UINT64_MAX - Address) return {MemoryFault::InvalidArgument, Address};
    const auto First = Address / PageSize, Last = (Address + Size - 1) / PageSize;
    std::shared_lock Lock(mutex_); std::vector<PageFrameNumber> Pfns;
    try { Pfns.reserve(static_cast<std::size_t>(Last - First + 1)); } catch (...) { return {MemoryFault::AllocationFailure}; }
    for (auto Page = First; Page <= Last; ++Page) {
        const auto It = mappings_.find(Page); if (It == mappings_.end()) return {MemoryFault::Unmapped, Page * PageSize};
        Pfns.push_back(It->second.Pfn);
    }
    std::sort(Pfns.begin(), Pfns.end()); Pfns.erase(std::unique(Pfns.begin(), Pfns.end()), Pfns.end());
    const auto Result = physical_->PinPages(Pfns); if (Result && PinnedPfns) *PinnedPfns = Pfns; return Result;
}
MemoryResult VirtualAddressSpace::Unpin(std::span<const PageFrameNumber> Pfns) { return physical_->UnpinPages(Pfns); }

std::vector<std::uint64_t> VirtualAddressSpace::DirtyVirtualPages() const {
    const auto Dirty = physical_->DirtyPfns(); std::set<PageFrameNumber> Set(Dirty.begin(), Dirty.end());
    std::shared_lock Lock(mutex_); std::vector<std::uint64_t> Result;
    for (const auto& [Vpn, Mapping] : mappings_) if (Set.contains(Mapping.Pfn)) Result.push_back(Vpn * PageSize);
    return Result;
}

std::unique_ptr<VirtualAddressSpace> VirtualAddressSpace::CloneCopyOnWrite(std::uint64_t ChildProcessId, std::uint64_t ChildSeed) {
    std::unique_lock Lock(mutex_);
    auto Child = std::make_unique<VirtualAddressSpace>(physical_, ChildProcessId, ChildSeed, minimumAddress_, maximumAddressExclusive_);
    Child->allocationCursor_ = allocationCursor_; Child->mappings_ = mappings_;
    for (auto& [Vpn, Mapping] : mappings_) {
        if (HasProtection(Mapping.Access, Protection::Write)) {
            Mapping.CopyOnWrite = true; Child->mappings_.at(Vpn).CopyOnWrite = true;
        }
    }
    return Child;
}

VirtualAddressSpaceSnapshot VirtualAddressSpace::Snapshot() const {
    std::shared_lock Lock(mutex_); VirtualAddressSpaceSnapshot Result{processId_, seed_, minimumAddress_, maximumAddressExclusive_, allocationCursor_};
    Result.Mappings.reserve(mappings_.size());
    for (const auto& [Vpn, Mapping] : mappings_) Result.Mappings.push_back({Vpn, Mapping.Pfn, Mapping.Access, Mapping.CopyOnWrite});
    return Result;
}

MemoryResult VirtualAddressSpace::Restore(const VirtualAddressSpaceSnapshot& Snapshot) {
    if (Snapshot.ProcessId != processId_ || Snapshot.Seed != seed_ || Snapshot.MinimumAddress != minimumAddress_ ||
        Snapshot.MaximumAddressExclusive != maximumAddressExclusive_ || Snapshot.AllocationCursor % PageSize ||
        Snapshot.AllocationCursor < minimumAddress_ || Snapshot.AllocationCursor >= maximumAddressExclusive_)
        return {MemoryFault::CorruptSnapshot};
    std::map<std::uint64_t, Mapping> Replacement;
    try {
        for (const auto& Item : Snapshot.Mappings) {
            if (!RangeInBounds(Item.VirtualPage, 1) || !physical_->Contains(Item.Pfn) || !IsValidProtection(Item.Access) ||
                (Item.CopyOnWrite && !HasProtection(Item.Access, Protection::Write)) ||
                !Replacement.emplace(Item.VirtualPage, Mapping{Item.Pfn, Item.Access, Item.CopyOnWrite}).second)
                return {MemoryFault::CorruptSnapshot, Item.VirtualPage * PageSize};
        }
    } catch (...) { return {MemoryFault::AllocationFailure}; }
    std::unique_lock Lock(mutex_); mappings_.swap(Replacement); allocationCursor_ = Snapshot.AllocationCursor; return {};
}

std::vector<std::byte> VirtualAddressSpace::SerializeSnapshot(const VirtualAddressSpaceSnapshot& Snapshot) {
    std::vector<std::byte> Out;
    try {
        Out.insert(Out.end(), Magic.begin(), Magic.end()); Append(Out, Version); Append(Out, Snapshot.ProcessId); Append(Out, Snapshot.Seed);
        Append(Out, Snapshot.MinimumAddress); Append(Out, Snapshot.MaximumAddressExclusive); Append(Out, Snapshot.AllocationCursor);
        Append(Out, static_cast<std::uint64_t>(Snapshot.Mappings.size()));
        for (const auto& M : Snapshot.Mappings) { Append(Out, M.VirtualPage); Append(Out, M.Pfn); Append(Out, static_cast<std::uint8_t>(M.Access)); Append(Out, static_cast<std::uint8_t>(M.CopyOnWrite)); }
    } catch (...) { return {}; }
    return Out;
}

std::optional<VirtualAddressSpaceSnapshot> VirtualAddressSpace::DeserializeSnapshot(std::span<const std::byte> Bytes) {
    if (Bytes.size() < Magic.size() || !std::equal(Magic.begin(), Magic.end(), Bytes.begin())) return std::nullopt;
    std::size_t Off = Magic.size(); std::uint32_t Ver = 0; std::uint64_t Count = 0; VirtualAddressSpaceSnapshot Result;
    if (!Take(Bytes, Off, Ver) || Ver != Version || !Take(Bytes, Off, Result.ProcessId) || !Take(Bytes, Off, Result.Seed) ||
        !Take(Bytes, Off, Result.MinimumAddress) || !Take(Bytes, Off, Result.MaximumAddressExclusive) ||
        !Take(Bytes, Off, Result.AllocationCursor) || !Take(Bytes, Off, Count)) return std::nullopt;
    constexpr std::size_t Record = 18;
    if (Count != (Bytes.size() - Off) / Record || (Bytes.size() - Off) % Record) return std::nullopt;
    try {
        Result.Mappings.reserve(static_cast<std::size_t>(Count));
        for (std::uint64_t I = 0; I < Count; ++I) {
            VirtualMappingSnapshot M; std::uint8_t Access = 0, Cow = 0;
            if (!Take(Bytes, Off, M.VirtualPage) || !Take(Bytes, Off, M.Pfn) || !Take(Bytes, Off, Access) || !Take(Bytes, Off, Cow) || Cow > 1 || (Access & ~ProtectionMask)) return std::nullopt;
            M.Access = static_cast<Protection>(Access); M.CopyOnWrite = Cow != 0; Result.Mappings.push_back(M);
        }
    } catch (...) { return std::nullopt; }
    return Result;
}

bool VirtualAddressSpace::CheckedPageRange(std::uint64_t Address, std::uint64_t Size, std::uint64_t& First, std::uint64_t& Count) noexcept {
    if (!Size || Address % PageSize || Size % PageSize || Size > UINT64_MAX - Address) return false;
    First = Address / PageSize; Count = Size / PageSize; return Count != 0;
}
bool VirtualAddressSpace::IsValidProtection(Protection Access) noexcept { return (static_cast<std::uint8_t>(Access) & ~ProtectionMask) == 0; }
bool VirtualAddressSpace::RangeInBounds(std::uint64_t First, std::uint64_t Count) const noexcept {
    if (!Count || maximumAddressExclusive_ <= minimumAddress_) return false;
    const auto Min = minimumAddress_ / PageSize, Max = maximumAddressExclusive_ / PageSize;
    return First >= Min && First < Max && Count <= Max - First;
}
std::optional<std::uint64_t> VirtualAddressSpace::FindFreeRange(std::uint64_t Count) const {
    const auto Min = minimumAddress_ / PageSize, Max = maximumAddressExclusive_ / PageSize;
    auto Search = [&](std::uint64_t Start, std::uint64_t End) -> std::optional<std::uint64_t> {
        if (Start >= End || Count > End - Start) return std::nullopt;
        auto Candidate = Start; auto It = mappings_.lower_bound(Start);
        while (Candidate <= End - Count) {
            while (It != mappings_.end() && It->first < Candidate) ++It;
            if (It == mappings_.end() || It->first >= Candidate + Count) return Candidate * PageSize;
            Candidate = It->first + 1; ++It;
        }
        return std::nullopt;
    };
    const auto Cursor = std::clamp(allocationCursor_ / PageSize, Min, Max);
    if (auto Result = Search(Cursor, Max)) return Result;
    return Search(Min, Cursor);
}

} // namespace Kevlar::Memory
