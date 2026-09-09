#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Kevlar::Snapshot {

inline constexpr std::size_t kSnapshotPageSize = 4096;
using SnapshotHash = std::array<std::uint8_t, 32>;
using AddressValidator = std::function<bool(std::uint64_t, std::size_t)>;
using MemoryReader = std::function<bool(std::uint64_t, std::span<std::uint8_t>)>;
using MemoryWriter = std::function<bool(std::uint64_t, std::span<const std::uint8_t>)>;

[[nodiscard]] SnapshotHash HashBytes(std::span<const std::uint8_t> Bytes) noexcept;

struct StateBlob {
    SnapshotHash Hash{};
    std::vector<std::uint8_t> Bytes;

    bool operator==(const StateBlob&) const = default;
};

struct DeduplicatedPage {
    SnapshotHash Hash{};
    std::array<std::uint8_t, kSnapshotPageSize> Bytes{};

    bool operator==(const DeduplicatedPage&) const = default;
};

struct MemoryMapping {
    std::uint64_t GuestBase = 0;
    std::uint64_t Size = 0;
    std::uint32_t Permissions = 0;
    std::vector<std::uint32_t> PageIndices;

    bool operator==(const MemoryMapping&) const = default;
};

struct SnapshotImage {
    std::uint64_t Seed = 0;
    std::uint64_t LogicalTime = 0;
    StateBlob CpuState;
    std::vector<DeduplicatedPage> Pages;
    std::vector<MemoryMapping> Mappings;
    StateBlob SchedulerState;
    StateBlob ObjectState;
    StateBlob DeviceState;

    bool operator==(const SnapshotImage&) const = default;
};

enum class SnapshotError : std::uint8_t {
    None = 0,
    InvalidArgument,
    InvalidAddress,
    ReadFailed,
    WriteFailed,
    OverlappingMapping,
    LimitExceeded,
    Truncated,
    BadMagic,
    UnsupportedVersion,
    SizeMismatch,
    HashMismatch,
    CorruptData,
};

struct SnapshotLimits {
    std::uint64_t MaximumSerializedBytes = 1ull << 30;
    std::uint64_t MaximumStateBlobBytes = 256ull << 20;
    std::uint32_t MaximumPages = 1u << 20;
    std::uint32_t MaximumMappings = 1u << 20;
};

struct SnapshotLoadResult {
    SnapshotError Error = SnapshotError::None;
    std::optional<SnapshotImage> Image;

    [[nodiscard]] bool Ok() const noexcept {
        return Error == SnapshotError::None && Image.has_value();
    }
};

class EmulatorSnapshot final {
public:
    EmulatorSnapshot();
    explicit EmulatorSnapshot(std::uint64_t Seed, std::uint64_t LogicalTime = 0);

    EmulatorSnapshot(const EmulatorSnapshot&) = delete;
    EmulatorSnapshot& operator=(const EmulatorSnapshot&) = delete;

    void SetSeed(std::uint64_t Seed);
    void SetLogicalTime(std::uint64_t LogicalTime);
    void SetCpuState(std::span<const std::uint8_t> Bytes);
    void SetSchedulerState(std::span<const std::uint8_t> Bytes);
    void SetObjectState(std::span<const std::uint8_t> Bytes);
    void SetDeviceState(std::span<const std::uint8_t> Bytes);

    [[nodiscard]] SnapshotError AddMappedMemory(
        std::uint64_t GuestBase,
        std::uint64_t Size,
        std::uint32_t Permissions,
        const AddressValidator& Validate,
        const MemoryReader& Read);
    [[nodiscard]] SnapshotError RestoreMappedMemory(
        const AddressValidator& Validate,
        const MemoryWriter& Write) const;

    [[nodiscard]] SnapshotImage Snapshot() const;
    [[nodiscard]] SnapshotError Restore(const SnapshotImage& Image);
    [[nodiscard]] std::vector<std::uint8_t> Serialize() const;
    [[nodiscard]] SnapshotError RestoreSerialized(
        std::span<const std::uint8_t> Bytes,
        const SnapshotLimits& Limits = {});

    [[nodiscard]] static bool Verify(
        const SnapshotImage& Image,
        const SnapshotLimits& Limits = {}) noexcept;
    [[nodiscard]] static std::vector<std::uint8_t> Serialize(const SnapshotImage& Image);
    [[nodiscard]] static SnapshotLoadResult Deserialize(
        std::span<const std::uint8_t> Bytes,
        const SnapshotLimits& Limits = {});

private:
    static StateBlob MakeBlob(std::span<const std::uint8_t> Bytes);

    mutable std::mutex Mutex_;
    SnapshotImage Image_;
};

} // namespace Kevlar::Snapshot
