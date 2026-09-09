#pragma once

#include "core/memory/physical_memory.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <vector>

namespace Kevlar::Memory {

enum class AccessType : std::uint8_t { Read, Write, Execute };

enum class Protection : std::uint8_t {
    None = 0,
    Read = 1 << 0,
    Write = 1 << 1,
    Execute = 1 << 2,
    User = 1 << 3,
};

constexpr Protection operator|(Protection Left, Protection Right) noexcept {
    return static_cast<Protection>(static_cast<std::uint8_t>(Left) |
        static_cast<std::uint8_t>(Right));
}
constexpr Protection operator&(Protection Left, Protection Right) noexcept {
    return static_cast<Protection>(static_cast<std::uint8_t>(Left) &
        static_cast<std::uint8_t>(Right));
}
constexpr bool HasProtection(Protection Value, Protection Required) noexcept {
    return (Value & Required) == Required;
}

struct TranslationResult {
    MemoryFault Fault = MemoryFault::None;
    std::uint64_t FaultAddress = 0;
    GuestPhysicalAddress PhysicalAddress = 0;
    PageFrameNumber Pfn = 0;
    std::uint16_t PageOffset = 0;
    Protection Access = Protection::None;
    CacheType Cache = CacheType::WriteBack;
    bool CopyOnWrite = false;

    [[nodiscard]] bool Ok() const noexcept { return Fault == MemoryFault::None; }
    [[nodiscard]] explicit operator bool() const noexcept { return Ok(); }
};

struct VirtualAllocation {
    MemoryFault Fault = MemoryFault::None;
    std::uint64_t Address = 0;
    std::uint64_t Size = 0;
    std::vector<PageFrameNumber> Pfns;

    [[nodiscard]] bool Ok() const noexcept { return Fault == MemoryFault::None; }
    [[nodiscard]] explicit operator bool() const noexcept { return Ok(); }
};

struct VirtualMappingSnapshot {
    std::uint64_t VirtualPage = 0;
    PageFrameNumber Pfn = 0;
    Protection Access = Protection::None;
    bool CopyOnWrite = false;
};

struct VirtualAddressSpaceSnapshot {
    std::uint64_t ProcessId = 0;
    std::uint64_t Seed = 0;
    std::uint64_t MinimumAddress = 0;
    std::uint64_t MaximumAddressExclusive = 0;
    std::uint64_t AllocationCursor = 0;
    std::vector<VirtualMappingSnapshot> Mappings;
};

class VirtualAddressSpace final {
public:
    VirtualAddressSpace(
        std::shared_ptr<PhysicalMemory> Physical,
        std::uint64_t ProcessId,
        std::uint64_t Seed,
        std::uint64_t MinimumAddress = 0x10000,
        std::uint64_t MaximumAddressExclusive = 0x0000800000000000ull);

    VirtualAddressSpace(const VirtualAddressSpace&) = delete;
    VirtualAddressSpace& operator=(const VirtualAddressSpace&) = delete;

    [[nodiscard]] std::uint64_t ProcessId() const noexcept;
    [[nodiscard]] std::uint64_t Seed() const noexcept;

    [[nodiscard]] VirtualAllocation Allocate(
        std::uint64_t Size,
        Protection Access,
        CacheType Cache = CacheType::WriteBack,
        std::optional<std::uint64_t> PreferredAddress = std::nullopt);
    [[nodiscard]] MemoryResult Map(
        std::uint64_t Address,
        std::span<const PageFrameNumber> Pfns,
        Protection Access,
        bool CopyOnWrite = false);
    [[nodiscard]] MemoryResult Unmap(std::uint64_t Address, std::uint64_t Size);
    [[nodiscard]] MemoryResult Protect(
        std::uint64_t Address,
        std::uint64_t Size,
        Protection Access);

    [[nodiscard]] TranslationResult Translate(
        std::uint64_t Address,
        AccessType Access,
        bool UserMode = false) const;
    [[nodiscard]] MemoryResult Read(
        std::uint64_t Address,
        std::span<std::byte> Destination,
        bool UserMode = false) const;
    [[nodiscard]] MemoryResult Write(
        std::uint64_t Address,
        std::span<const std::byte> Source,
        bool UserMode = false);

    [[nodiscard]] MemoryResult Pin(
        std::uint64_t Address,
        std::uint64_t Size,
        std::vector<PageFrameNumber>* PinnedPfns = nullptr);
    [[nodiscard]] MemoryResult Unpin(std::span<const PageFrameNumber> Pfns);

    [[nodiscard]] std::vector<std::uint64_t> DirtyVirtualPages() const;
    [[nodiscard]] std::unique_ptr<VirtualAddressSpace> CloneCopyOnWrite(
        std::uint64_t ChildProcessId,
        std::uint64_t ChildSeed);

    [[nodiscard]] VirtualAddressSpaceSnapshot Snapshot() const;
    [[nodiscard]] MemoryResult Restore(const VirtualAddressSpaceSnapshot& Snapshot);
    [[nodiscard]] static std::vector<std::byte> SerializeSnapshot(
        const VirtualAddressSpaceSnapshot& Snapshot);
    [[nodiscard]] static std::optional<VirtualAddressSpaceSnapshot> DeserializeSnapshot(
        std::span<const std::byte> Bytes);

private:
    struct Mapping {
        PageFrameNumber Pfn = 0;
        Protection Access = Protection::None;
        bool CopyOnWrite = false;
    };

    [[nodiscard]] static bool CheckedPageRange(
        std::uint64_t Address,
        std::uint64_t Size,
        std::uint64_t& FirstPage,
        std::uint64_t& PageCount) noexcept;
    [[nodiscard]] static bool IsValidProtection(Protection Access) noexcept;
    [[nodiscard]] bool RangeInBounds(std::uint64_t FirstPage, std::uint64_t PageCount) const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> FindFreeRange(std::uint64_t PageCount) const;
    [[nodiscard]] TranslationResult TranslateLocked(
        std::uint64_t Address,
        AccessType Access,
        bool UserMode) const;

    std::shared_ptr<PhysicalMemory> physical_;
    const std::uint64_t processId_;
    const std::uint64_t seed_;
    const std::uint64_t minimumAddress_;
    const std::uint64_t maximumAddressExclusive_;
    std::uint64_t allocationCursor_;
    mutable std::shared_mutex mutex_;
    std::map<std::uint64_t, Mapping> mappings_;
};

} // namespace Kevlar::Memory
