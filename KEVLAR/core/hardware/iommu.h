#pragma once

#include "pci_bus.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace Kevlar::Hardware {

inline constexpr std::uint64_t kIommuPageSize = 4096;

enum class DmaAccess : std::uint8_t {
    Read = 1,
    Write = 2,
    ReadWrite = 3,
};

enum class IommuFaultReason : std::uint8_t {
    TranslationDisabled,
    InvalidRequest,
    DeviceNotAttached,
    Unmapped,
    PermissionDenied,
};

struct IommuMapping {
    std::uint32_t Domain = 0;
    std::uint64_t Iova = 0;
    std::uint64_t PhysicalAddress = 0;
    std::uint64_t Length = 0;
    DmaAccess Access = DmaAccess::ReadWrite;

    bool operator==(const IommuMapping&) const = default;
};

struct IommuAttachment {
    PciAddress Device;
    std::uint32_t Domain = 0;

    bool operator==(const IommuAttachment&) const = default;
};

struct IommuFault {
    std::uint64_t Sequence = 0;
    std::uint64_t VirtualTime = 0;
    PciAddress Device;
    std::uint32_t Domain = 0;
    std::uint64_t Iova = 0;
    std::uint64_t Length = 0;
    DmaAccess Access = DmaAccess::Read;
    IommuFaultReason Reason = IommuFaultReason::Unmapped;

    bool operator==(const IommuFault&) const = default;
};

struct IommuSnapshot {
    std::uint64_t Seed = 0;
    std::uint64_t VirtualTime = 0;
    std::uint64_t NextFaultSequence = 1;
    bool TranslationEnabled = true;
    std::vector<IommuAttachment> Attachments;
    std::vector<IommuMapping> Mappings;
    std::vector<IommuFault> Faults;

    bool operator==(const IommuSnapshot&) const = default;
};

class Iommu final {
public:
    explicit Iommu(std::uint64_t Seed, std::uint64_t InitialVirtualTime = 0);
    Iommu(const Iommu&) = delete;
    Iommu& operator=(const Iommu&) = delete;

    [[nodiscard]] bool AttachDevice(PciAddress Device, std::uint32_t Domain);
    [[nodiscard]] bool DetachDevice(PciAddress Device);
    [[nodiscard]] bool Map(const IommuMapping& Mapping);
    [[nodiscard]] bool Unmap(std::uint32_t Domain, std::uint64_t Iova, std::uint64_t Length);
    [[nodiscard]] std::optional<std::uint64_t> Translate(
        PciAddress Device, std::uint32_t Domain, std::uint64_t Iova,
        std::uint64_t Length, DmaAccess Access);

    void SetTranslationEnabled(bool Enabled);
    void SetVirtualTime(std::uint64_t VirtualTime);
    void ClearFaults();

    [[nodiscard]] bool TranslationEnabled() const;
    [[nodiscard]] std::uint64_t VirtualTime() const;
    [[nodiscard]] std::vector<IommuFault> FaultJournal() const;
    [[nodiscard]] IommuSnapshot Snapshot() const;
    [[nodiscard]] bool Restore(const IommuSnapshot& Snapshot);
    [[nodiscard]] std::vector<std::uint8_t> Serialize() const;
    [[nodiscard]] bool RestoreSerialized(std::span<const std::uint8_t> Bytes);
    [[nodiscard]] static std::optional<IommuSnapshot> Deserialize(
        std::span<const std::uint8_t> Bytes);

private:
    static bool IsValidAccess(DmaAccess Access) noexcept;
    static bool IsValidPageRange(std::uint64_t Address, std::uint64_t Length) noexcept;
    static bool RangesOverlap(std::uint64_t A, std::uint64_t ALength,
                              std::uint64_t B, std::uint64_t BLength) noexcept;
    void RecordFault(PciAddress Device, std::uint32_t Domain, std::uint64_t Iova,
                     std::uint64_t Length, DmaAccess Access, IommuFaultReason Reason);

    mutable std::mutex Mutex_;
    IommuSnapshot State_;
};

} // namespace Kevlar::Hardware
