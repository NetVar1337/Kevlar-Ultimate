#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <shared_mutex>
#include <span>
#include <vector>

namespace Kevlar::Memory {

inline constexpr std::uint64_t PageSize = 0x1000;
using PageFrameNumber = std::uint64_t;
using GuestPhysicalAddress = std::uint64_t;

enum class CacheType : std::uint8_t {
    WriteBack = 0,
    WriteThrough = 1,
    Uncached = 2,
    WriteCombined = 3,
};

enum class MemoryFault : std::uint8_t {
    None = 0,
    InvalidArgument,
    InvalidAlignment,
    AddressOverflow,
    OutOfRange,
    Unmapped,
    ProtectionViolation,
    AlreadyMapped,
    PageMissing,
    PagePinned,
    PinUnderflow,
    PinOverflow,
    AllocationFailure,
    CorruptSnapshot,
};

struct MemoryResult {
    MemoryFault Fault = MemoryFault::None;
    std::uint64_t FaultAddress = 0;
    std::size_t BytesCompleted = 0;

    [[nodiscard]] bool Ok() const noexcept { return Fault == MemoryFault::None; }
    [[nodiscard]] explicit operator bool() const noexcept { return Ok(); }
};

struct PhysicalAllocation {
    MemoryFault Fault = MemoryFault::None;
    PageFrameNumber FirstPfn = 0;
    std::size_t PageCount = 0;

    [[nodiscard]] bool Ok() const noexcept { return Fault == MemoryFault::None; }
    [[nodiscard]] explicit operator bool() const noexcept { return Ok(); }
    [[nodiscard]] GuestPhysicalAddress GuestAddress() const noexcept;
};

struct PhysicalPageInfo {
    PageFrameNumber Pfn = 0;
    GuestPhysicalAddress GuestBase = 0;
    CacheType Cache = CacheType::WriteBack;
    std::uint32_t PinCount = 0;
    bool Dirty = false;
};

struct PhysicalPageSnapshot {
    PageFrameNumber Pfn = 0;
    CacheType Cache = CacheType::WriteBack;
    std::uint32_t PinCount = 0;
    bool Dirty = false;
    std::array<std::byte, PageSize> Data{};
};

struct PhysicalMemorySnapshot {
    std::uint64_t Seed = 0;
    PageFrameNumber FirstPfn = 1;
    PageFrameNumber NextPfn = 1;
    std::vector<PhysicalPageSnapshot> Pages;
};

class PhysicalMemory final {
public:
    explicit PhysicalMemory(std::uint64_t Seed, PageFrameNumber FirstPfn = 1);

    PhysicalMemory(const PhysicalMemory&) = delete;
    PhysicalMemory& operator=(const PhysicalMemory&) = delete;

    [[nodiscard]] std::uint64_t Seed() const noexcept;
    [[nodiscard]] bool Contains(PageFrameNumber Pfn) const;
    [[nodiscard]] std::size_t PageCount() const;

    [[nodiscard]] PhysicalAllocation AllocatePage(CacheType Cache = CacheType::WriteBack);
    [[nodiscard]] PhysicalAllocation AllocateContiguous(
        std::size_t Count,
        CacheType Cache = CacheType::WriteBack);
    [[nodiscard]] MemoryResult FreePage(PageFrameNumber Pfn);
    [[nodiscard]] MemoryResult FreePages(std::span<const PageFrameNumber> Pfns);

    [[nodiscard]] MemoryResult Read(
        GuestPhysicalAddress Address,
        std::span<std::byte> Destination) const;
    [[nodiscard]] MemoryResult Write(
        GuestPhysicalAddress Address,
        std::span<const std::byte> Source);

    [[nodiscard]] MemoryResult PinPages(std::span<const PageFrameNumber> Pfns);
    [[nodiscard]] MemoryResult UnpinPages(std::span<const PageFrameNumber> Pfns);

    [[nodiscard]] MemoryResult SetCacheType(PageFrameNumber Pfn, CacheType Cache);
    [[nodiscard]] std::optional<PhysicalPageInfo> GetPageInfo(PageFrameNumber Pfn) const;
    [[nodiscard]] std::vector<PageFrameNumber> DirtyPfns() const;
    void ClearDirty(std::span<const PageFrameNumber> Pfns);
    void ClearAllDirty();

    [[nodiscard]] PhysicalMemorySnapshot Snapshot() const;
    [[nodiscard]] MemoryResult Restore(const PhysicalMemorySnapshot& Snapshot);

    [[nodiscard]] static std::vector<std::byte> SerializeSnapshot(
        const PhysicalMemorySnapshot& Snapshot);
    [[nodiscard]] static std::optional<PhysicalMemorySnapshot> DeserializeSnapshot(
        std::span<const std::byte> Bytes);

private:
    struct Page {
        std::array<std::byte, PageSize> Data{};
        CacheType Cache = CacheType::WriteBack;
        std::uint32_t PinCount = 0;
        bool Dirty = false;
    };

    [[nodiscard]] static bool IsValidCacheType(CacheType Cache) noexcept;
    [[nodiscard]] static bool TryPhysicalBase(
        PageFrameNumber Pfn,
        GuestPhysicalAddress& Address) noexcept;
    [[nodiscard]] std::optional<PageFrameNumber> FindContiguousRun(std::size_t Count) const;

    const std::uint64_t seed_;
    PageFrameNumber firstPfn_;
    PageFrameNumber nextPfn_;
    mutable std::shared_mutex mutex_;
    std::map<PageFrameNumber, Page> pages_;
};

} // namespace Kevlar::Memory
