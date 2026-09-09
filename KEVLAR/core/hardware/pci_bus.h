#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Kevlar::Hardware {

inline constexpr std::size_t kPciConfigSpaceSize = 4096;

struct PciAddress {
    std::uint16_t Segment = 0;
    std::uint8_t Bus = 0;
    std::uint8_t Device = 0;
    std::uint8_t Function = 0;

    [[nodiscard]] bool IsValid() const noexcept;
    auto operator<=>(const PciAddress&) const = default;
};

enum class PciBarType : std::uint8_t {
    Io,
    Mmio32,
    Mmio64,
};

struct PciBar {
    std::uint8_t Index = 0;
    PciBarType Type = PciBarType::Mmio32;
    std::uint64_t Address = 0;
    std::uint64_t Size = 0;
    bool Prefetchable = false;
    bool Enabled = true;

    bool operator==(const PciBar&) const = default;
};

struct MsiState {
    std::uint16_t CapabilityOffset = 0;
    std::uint16_t VectorCount = 1;
    std::uint64_t MessageAddress = 0;
    std::uint32_t MessageData = 0;
    bool Enabled = false;
    bool Is64Bit = true;

    bool operator==(const MsiState&) const = default;
};

struct MsixState {
    std::uint16_t CapabilityOffset = 0;
    std::uint16_t TableEntries = 0;
    std::uint8_t TableBar = 0;
    std::uint32_t TableOffset = 0;
    std::uint8_t PendingBitBar = 0;
    std::uint32_t PendingBitOffset = 0;
    bool Enabled = false;
    bool FunctionMask = false;

    bool operator==(const MsixState&) const = default;
};

struct PciDeviceDescriptor {
    PciAddress Address;
    std::uint16_t VendorId = 0;
    std::uint16_t DeviceId = 0;
    std::uint16_t SubsystemVendorId = 0;
    std::uint16_t SubsystemId = 0;
    std::uint8_t Revision = 0;
    std::uint8_t ClassCode = 0;
    std::uint8_t Subclass = 0;
    std::uint8_t ProgrammingInterface = 0;
    std::uint8_t HeaderType = 0;
    std::string Name;

    bool operator==(const PciDeviceDescriptor&) const = default;
};

struct PciDeviceSnapshot {
    PciDeviceDescriptor Descriptor;
    std::array<std::uint8_t, kPciConfigSpaceSize> Config{};
    std::vector<PciBar> Bars;
    std::optional<MsiState> Msi;
    std::optional<MsixState> Msix;

    bool operator==(const PciDeviceSnapshot&) const = default;
};

struct PciBusSnapshot {
    std::vector<PciDeviceSnapshot> Devices;

    bool operator==(const PciBusSnapshot&) const = default;
};

struct MmioRegion {
    PciAddress Device;
    std::uint8_t BarIndex = 0;
    std::uint64_t RegionBase = 0;
    std::uint64_t Offset = 0;
    std::uint64_t Length = 0;

    bool operator==(const MmioRegion&) const = default;
};

class PciBus final {
public:
    PciBus() = default;
    PciBus(const PciBus&) = delete;
    PciBus& operator=(const PciBus&) = delete;

    [[nodiscard]] bool AddDevice(const PciDeviceDescriptor& Descriptor);
    [[nodiscard]] bool RemoveDevice(PciAddress Address);
    [[nodiscard]] bool RegisterBar(PciAddress Address, const PciBar& Bar);
    [[nodiscard]] bool ConfigureMsi(PciAddress Address, const MsiState& State);
    [[nodiscard]] bool ConfigureMsix(PciAddress Address, const MsixState& State);

    [[nodiscard]] std::vector<PciAddress> Enumerate(
        std::optional<std::uint16_t> Segment = std::nullopt,
        std::optional<std::uint8_t> Bus = std::nullopt) const;
    [[nodiscard]] std::optional<PciDeviceSnapshot> Device(PciAddress Address) const;
    [[nodiscard]] std::optional<std::uint32_t> ReadConfig(
        PciAddress Address, std::uint16_t Offset, std::uint8_t Width) const;
    [[nodiscard]] bool WriteConfig(
        PciAddress Address, std::uint16_t Offset, std::uint8_t Width, std::uint32_t Value);
    [[nodiscard]] std::optional<MmioRegion> ResolveMmio(
        std::uint64_t Address, std::uint64_t Length = 1) const;

    [[nodiscard]] PciBusSnapshot Snapshot() const;
    [[nodiscard]] bool Restore(const PciBusSnapshot& Snapshot);
    [[nodiscard]] std::vector<std::uint8_t> Serialize() const;
    [[nodiscard]] bool RestoreSerialized(std::span<const std::uint8_t> Bytes);
    [[nodiscard]] static std::optional<PciBusSnapshot> Deserialize(
        std::span<const std::uint8_t> Bytes);

private:
    static bool IsValidBar(const PciBar& Bar) noexcept;
    static bool IsValidCapabilityOffset(std::uint16_t Offset, std::size_t Size) noexcept;
    static bool RangesOverlap(
        std::uint64_t LeftBase, std::uint64_t LeftLength,
        std::uint64_t RightBase, std::uint64_t RightLength) noexcept;
    static void RebuildCapabilityLinks(PciDeviceSnapshot& Device) noexcept;

    mutable std::mutex Mutex_;
    std::vector<PciDeviceSnapshot> Devices_;
};

} // namespace Kevlar::Hardware
