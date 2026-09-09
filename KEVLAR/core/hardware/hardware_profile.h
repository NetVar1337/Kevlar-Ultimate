#pragma once

#include "iommu.h"
#include "pci_bus.h"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Kevlar::Hardware {

struct AcpiIdentity {
    std::string OemId;
    std::string OemTableId;
    std::uint32_t OemRevision = 0;
    std::uint32_t CreatorId = 0;
    std::uint32_t CreatorRevision = 0;
    bool operator==(const AcpiIdentity&) const = default;
};

struct SmbiosIdentity {
    std::string BiosVendor, BiosVersion, BiosDate;
    std::string SystemManufacturer, SystemProduct, SystemVersion, SystemSerial;
    std::string BaseboardManufacturer, BaseboardProduct, BaseboardSerial;
    std::array<std::uint8_t, 16> SystemUuid{};
    bool operator==(const SmbiosIdentity&) const = default;
};

struct UefiIdentity {
    std::string FirmwareVendor;
    std::uint32_t FirmwareRevision = 0;
    bool SecureBoot = true;
    std::array<std::uint8_t, 16> BootIdentifier{};
    bool operator==(const UefiIdentity&) const = default;
};

struct TpmIdentity {
    std::uint32_t ManufacturerId = 0;
    std::uint32_t FirmwareVersionMajor = 0;
    std::uint32_t FirmwareVersionMinor = 0;
    std::array<std::uint8_t, 32> EndorsementKeyDigest{};
    bool Enabled = true;
    bool operator==(const TpmIdentity&) const = default;
};

struct PlatformIdentity {
    std::string CpuVendor;
    std::string CpuBrand;
    std::uint32_t CpuSignature = 0;
    std::uint32_t LogicalProcessorCount = 0;
    AcpiIdentity Acpi;
    SmbiosIdentity Smbios;
    UefiIdentity Uefi;
    TpmIdentity Tpm;
    bool operator==(const PlatformIdentity&) const = default;
};

struct DmaAdapter {
    std::uint64_t Id = 0;
    PciAddress Device;
    std::uint32_t Domain = 0;
    std::uint64_t MaximumPhysicalAddress = 0;
    std::uint64_t Alignment = kIommuPageSize;
    std::uint64_t MaximumTransferLength = 0;
    std::uint32_t MaximumSegments = 0;
    bool operator==(const DmaAdapter&) const = default;
};

struct DmaCommonBuffer {
    std::uint64_t Id = 0;
    std::uint64_t AdapterId = 0;
    std::uint64_t Iova = 0;
    std::uint64_t PhysicalAddress = 0;
    std::uint64_t Length = 0;
    bool CacheEnabled = true;
    bool operator==(const DmaCommonBuffer&) const = default;
};

struct PhysicalRange {
    std::uint64_t Address = 0;
    std::uint64_t Length = 0;
    bool operator==(const PhysicalRange&) const = default;
};

struct DmaSegment {
    std::uint64_t Iova = 0;
    std::uint64_t PhysicalAddress = 0;
    std::uint64_t Length = 0;
    bool operator==(const DmaSegment&) const = default;
};

struct ScatterGatherList {
    std::uint64_t Id = 0;
    std::uint64_t AdapterId = 0;
    DmaAccess Access = DmaAccess::ReadWrite;
    std::vector<DmaSegment> Segments;
    bool operator==(const ScatterGatherList&) const = default;
};

struct HardwareProfileSnapshot {
    std::uint64_t Seed = 0;
    std::uint64_t VirtualTime = 0;
    std::uint64_t NextAdapterId = 1, NextAllocationId = 1;
    std::uint64_t NextPhysicalAddress = 0, NextIova = 0;
    PlatformIdentity Identity;
    PciBusSnapshot Pci;
    IommuSnapshot IommuState;
    std::vector<DmaAdapter> Adapters;
    std::vector<DmaCommonBuffer> CommonBuffers;
    std::vector<ScatterGatherList> ScatterGatherLists;
    bool operator==(const HardwareProfileSnapshot&) const = default;
};

class HardwareProfile final {
public:
    HardwareProfile(std::uint64_t Seed, std::uint64_t InitialVirtualTime);
    HardwareProfile(const HardwareProfile&) = delete;
    HardwareProfile& operator=(const HardwareProfile&) = delete;

    [[nodiscard]] static std::unique_ptr<HardwareProfile> CreateRaptorLake(
        std::uint64_t Seed, std::uint64_t InitialVirtualTime);

    [[nodiscard]] PciBus& Pci() noexcept { return Pci_; }
    [[nodiscard]] const PciBus& Pci() const noexcept { return Pci_; }
    [[nodiscard]] PlatformIdentity Identity() const;
    [[nodiscard]] std::uint64_t Seed() const noexcept { return Seed_; }
    [[nodiscard]] std::uint64_t VirtualTime() const;
    void SetVirtualTime(std::uint64_t VirtualTime);

    [[nodiscard]] std::optional<DmaAdapter> CreateDmaAdapter(
        PciAddress Device, std::uint64_t MaximumPhysicalAddress,
        std::uint64_t Alignment, std::uint64_t MaximumTransferLength,
        std::uint32_t MaximumSegments);
    [[nodiscard]] std::optional<DmaCommonBuffer> AllocateCommonBuffer(
        std::uint64_t AdapterId, std::uint64_t Length, std::uint64_t Alignment,
        bool CacheEnabled = true);
    [[nodiscard]] bool FreeCommonBuffer(std::uint64_t AllocationId);
    [[nodiscard]] std::optional<ScatterGatherList> AllocateScatterGather(
        std::uint64_t AdapterId, std::span<const PhysicalRange> Ranges,
        DmaAccess Access = DmaAccess::ReadWrite);
    [[nodiscard]] bool FreeScatterGather(std::uint64_t AllocationId);
    [[nodiscard]] std::optional<std::uint64_t> TranslateDma(
        std::uint64_t AdapterId, std::uint64_t Iova, std::uint64_t Length, DmaAccess Access);
    [[nodiscard]] std::vector<IommuFault> FaultJournal() const { return Iommu_.FaultJournal(); }

    [[nodiscard]] HardwareProfileSnapshot Snapshot() const;
    [[nodiscard]] bool Restore(const HardwareProfileSnapshot& Snapshot);

private:
    static std::uint64_t AlignUp(std::uint64_t Value, std::uint64_t Alignment) noexcept;
    static bool IsPowerOfTwo(std::uint64_t Value) noexcept;
    const DmaAdapter* FindAdapter(std::uint64_t Id) const noexcept;

    mutable std::mutex Mutex_;
    const std::uint64_t Seed_;
    std::uint64_t VirtualTime_;
    std::uint64_t NextAdapterId_ = 1, NextAllocationId_ = 1;
    std::uint64_t NextPhysicalAddress_, NextIova_;
    PlatformIdentity Identity_;
    PciBus Pci_;
    Iommu Iommu_;
    std::vector<DmaAdapter> Adapters_;
    std::vector<DmaCommonBuffer> CommonBuffers_;
    std::vector<ScatterGatherList> ScatterGatherLists_;
};

} // namespace Kevlar::Hardware
