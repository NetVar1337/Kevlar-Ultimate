#include "pci_bus.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <tuple>
#include <type_traits>
#include <utility>

namespace Kevlar::Hardware {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'P', 'C', 'I'};
constexpr std::uint32_t kVersion = 1;
constexpr std::uint32_t kMaxSerializedDevices = 4096;
constexpr std::uint32_t kMaxSerializedBars = 6;
constexpr std::uint32_t kMaxSerializedString = 4096;

bool ValidWidth(std::uint8_t Width) noexcept {
    return Width == 1 || Width == 2 || Width == 4;
}

bool ValidRange(std::uint64_t Base, std::uint64_t Length) noexcept {
    return Length != 0 && Base <= std::numeric_limits<std::uint64_t>::max() - (Length - 1);
}

void Store16(std::array<std::uint8_t, kPciConfigSpaceSize>& Config,
             std::size_t Offset, std::uint16_t Value) noexcept {
    Config[Offset] = static_cast<std::uint8_t>(Value);
    Config[Offset + 1] = static_cast<std::uint8_t>(Value >> 8);
}

void Store32(std::array<std::uint8_t, kPciConfigSpaceSize>& Config,
             std::size_t Offset, std::uint32_t Value) noexcept {
    for (std::size_t Index = 0; Index != 4; ++Index) {
        Config[Offset + Index] = static_cast<std::uint8_t>(Value >> (Index * 8));
    }
}

class Writer {
public:
    template <typename T>
    void Integer(T Value) {
        using U = std::make_unsigned_t<T>;
        U Bits = static_cast<U>(Value);
        for (std::size_t Index = 0; Index != sizeof(T); ++Index) {
            Bytes_.push_back(static_cast<std::uint8_t>(Bits >> (Index * 8)));
        }
    }

    void Boolean(bool Value) { Integer<std::uint8_t>(Value ? 1 : 0); }

    void String(const std::string& Value) {
        Integer<std::uint32_t>(static_cast<std::uint32_t>(Value.size()));
        Bytes_.insert(Bytes_.end(), Value.begin(), Value.end());
    }

    void Raw(std::span<const std::uint8_t> Value) {
        Bytes_.insert(Bytes_.end(), Value.begin(), Value.end());
    }

    std::vector<std::uint8_t> Finish() && { return std::move(Bytes_); }

private:
    std::vector<std::uint8_t> Bytes_;
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> Bytes) : Bytes_(Bytes) {}

    template <typename T>
    bool Integer(T& Value) {
        if (Remaining() < sizeof(T)) return false;
        using U = std::make_unsigned_t<T>;
        U Bits = 0;
        for (std::size_t Index = 0; Index != sizeof(T); ++Index) {
            Bits |= static_cast<U>(Bytes_[Position_++]) << (Index * 8);
        }
        Value = static_cast<T>(Bits);
        return true;
    }

    bool Boolean(bool& Value) {
        std::uint8_t Byte = 0;
        if (!Integer(Byte) || Byte > 1) return false;
        Value = Byte != 0;
        return true;
    }

    bool String(std::string& Value) {
        std::uint32_t Size = 0;
        if (!Integer(Size) || Size > kMaxSerializedString || Remaining() < Size) return false;
        Value.assign(reinterpret_cast<const char*>(Bytes_.data() + Position_), Size);
        Position_ += Size;
        return true;
    }

    bool Raw(std::span<std::uint8_t> Value) {
        if (Remaining() < Value.size()) return false;
        std::memcpy(Value.data(), Bytes_.data() + Position_, Value.size());
        Position_ += Value.size();
        return true;
    }

    [[nodiscard]] std::size_t Remaining() const noexcept { return Bytes_.size() - Position_; }

private:
    std::span<const std::uint8_t> Bytes_;
    std::size_t Position_ = 0;
};

void WriteAddress(Writer& Output, const PciAddress& Address) {
    Output.Integer(Address.Segment);
    Output.Integer(Address.Bus);
    Output.Integer(Address.Device);
    Output.Integer(Address.Function);
}

bool ReadAddress(Reader& Input, PciAddress& Address) {
    return Input.Integer(Address.Segment) && Input.Integer(Address.Bus) &&
           Input.Integer(Address.Device) && Input.Integer(Address.Function);
}

} // namespace

bool PciAddress::IsValid() const noexcept {
    return Device < 32 && Function < 8;
}

bool PciBus::RangesOverlap(std::uint64_t LeftBase, std::uint64_t LeftLength,
                           std::uint64_t RightBase, std::uint64_t RightLength) noexcept {
    if (!ValidRange(LeftBase, LeftLength) || !ValidRange(RightBase, RightLength)) return true;
    return LeftBase < RightBase + RightLength && RightBase < LeftBase + LeftLength;
}

bool PciBus::IsValidBar(const PciBar& Bar) noexcept {
    if (Bar.Index >= 6 || !ValidRange(Bar.Address, Bar.Size) || !std::has_single_bit(Bar.Size) ||
        (Bar.Address & (Bar.Size - 1)) != 0) {
        return false;
    }
    if (Bar.Type == PciBarType::Mmio64 && Bar.Index == 5) return false;
    if ((Bar.Type == PciBarType::Io || Bar.Type == PciBarType::Mmio32) &&
        Bar.Address + Bar.Size - 1 > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    return true;
}

bool PciBus::IsValidCapabilityOffset(std::uint16_t Offset, std::size_t Size) noexcept {
    return Offset >= 0x40 && (Offset & 3) == 0 &&
           static_cast<std::size_t>(Offset) + Size <= 0x100;
}

void PciBus::RebuildCapabilityLinks(PciDeviceSnapshot& Device) noexcept {
    std::vector<std::uint16_t> Offsets;
    if (Device.Msi) Offsets.push_back(Device.Msi->CapabilityOffset);
    if (Device.Msix) Offsets.push_back(Device.Msix->CapabilityOffset);
    std::sort(Offsets.begin(), Offsets.end());
    Device.Config[0x34] = Offsets.empty() ? 0 : static_cast<std::uint8_t>(Offsets.front());
    if (Offsets.empty()) {
        Device.Config[0x06] &= static_cast<std::uint8_t>(~0x10u);
        return;
    }
    Device.Config[0x06] |= 0x10;
    for (std::size_t Index = 0; Index != Offsets.size(); ++Index) {
        Device.Config[Offsets[Index] + 1] = Index + 1 < Offsets.size()
            ? static_cast<std::uint8_t>(Offsets[Index + 1]) : 0;
    }
}

bool PciBus::AddDevice(const PciDeviceDescriptor& Descriptor) {
    if (!Descriptor.Address.IsValid() || Descriptor.VendorId == 0 || Descriptor.VendorId == 0xFFFF) {
        return false;
    }

    std::scoped_lock Lock(Mutex_);
    const auto Existing = std::lower_bound(Devices_.begin(), Devices_.end(), Descriptor.Address,
        [](const PciDeviceSnapshot& Device, const PciAddress& Address) {
            return Device.Descriptor.Address < Address;
        });
    if (Existing != Devices_.end() && Existing->Descriptor.Address == Descriptor.Address) return false;

    PciDeviceSnapshot Device;
    Device.Descriptor = Descriptor;
    Device.Config.fill(0);
    Store16(Device.Config, 0x00, Descriptor.VendorId);
    Store16(Device.Config, 0x02, Descriptor.DeviceId);
    Device.Config[0x08] = Descriptor.Revision;
    Device.Config[0x09] = Descriptor.ProgrammingInterface;
    Device.Config[0x0A] = Descriptor.Subclass;
    Device.Config[0x0B] = Descriptor.ClassCode;
    Device.Config[0x0E] = Descriptor.HeaderType;
    Store16(Device.Config, 0x2C, Descriptor.SubsystemVendorId);
    Store16(Device.Config, 0x2E, Descriptor.SubsystemId);
    Devices_.insert(Existing, std::move(Device));
    return true;
}

bool PciBus::RemoveDevice(PciAddress Address) {
    if (!Address.IsValid()) return false;
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(Devices_.begin(), Devices_.end(), Address,
        [](const PciDeviceSnapshot& Device, const PciAddress& Value) {
            return Device.Descriptor.Address < Value;
        });
    if (It == Devices_.end() || It->Descriptor.Address != Address) return false;
    Devices_.erase(It);
    return true;
}

bool PciBus::RegisterBar(PciAddress Address, const PciBar& Bar) {
    if (!Address.IsValid() || !IsValidBar(Bar)) return false;
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(Devices_.begin(), Devices_.end(), Address,
        [](const PciDeviceSnapshot& Device, const PciAddress& Value) {
            return Device.Descriptor.Address < Value;
        });
    if (It == Devices_.end() || It->Descriptor.Address != Address) return false;

    for (const auto& Existing : It->Bars) {
        const bool OccupiesRequested = Existing.Index == Bar.Index ||
            (Existing.Type == PciBarType::Mmio64 && Existing.Index + 1 == Bar.Index) ||
            (Bar.Type == PciBarType::Mmio64 && Bar.Index + 1 == Existing.Index);
        if (OccupiesRequested) return false;
    }
    if (Bar.Type != PciBarType::Io) {
        for (const auto& Device : Devices_) {
            for (const auto& Existing : Device.Bars) {
                if (Existing.Type != PciBarType::Io &&
                    RangesOverlap(Bar.Address, Bar.Size, Existing.Address, Existing.Size)) {
                    return false;
                }
            }
        }
    }

    It->Bars.push_back(Bar);
    std::sort(It->Bars.begin(), It->Bars.end(), [](const PciBar& Left, const PciBar& Right) {
        return Left.Index < Right.Index;
    });
    const std::size_t Offset = 0x10 + static_cast<std::size_t>(Bar.Index) * 4;
    if (Bar.Type == PciBarType::Io) {
        Store32(It->Config, Offset, static_cast<std::uint32_t>(Bar.Address) | 1u);
    } else {
        std::uint32_t Low = static_cast<std::uint32_t>(Bar.Address) & ~0xFu;
        if (Bar.Type == PciBarType::Mmio64) Low |= 4u;
        if (Bar.Prefetchable) Low |= 8u;
        Store32(It->Config, Offset, Low);
        if (Bar.Type == PciBarType::Mmio64) {
            Store32(It->Config, Offset + 4, static_cast<std::uint32_t>(Bar.Address >> 32));
        }
    }
    return true;
}

bool PciBus::ConfigureMsi(PciAddress Address, const MsiState& State) {
    const std::size_t Size = State.Is64Bit ? 14 : 10;
    if (!Address.IsValid() || !IsValidCapabilityOffset(State.CapabilityOffset, Size) ||
        State.VectorCount == 0 || State.VectorCount > 32 || !std::has_single_bit(State.VectorCount) ||
        (State.MessageAddress & 3) != 0) {
        return false;
    }
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(Devices_.begin(), Devices_.end(), Address,
        [](const PciDeviceSnapshot& Device, const PciAddress& Value) {
            return Device.Descriptor.Address < Value;
        });
    if (It == Devices_.end() || It->Descriptor.Address != Address) return false;
    if (It->Msix && RangesOverlap(State.CapabilityOffset, Size, It->Msix->CapabilityOffset, 12)) return false;

    It->Msi = State;
    auto& Config = It->Config;
    Config[State.CapabilityOffset] = 0x05;
    const auto MultipleMessageCapable = static_cast<std::uint16_t>(std::countr_zero(State.VectorCount));
    std::uint16_t Control = static_cast<std::uint16_t>((MultipleMessageCapable & 7u) << 1);
    if (State.Enabled) Control |= 1;
    if (State.Is64Bit) Control |= 1u << 7;
    Store16(Config, State.CapabilityOffset + 2, Control);
    Store32(Config, State.CapabilityOffset + 4, static_cast<std::uint32_t>(State.MessageAddress));
    std::size_t DataOffset = State.CapabilityOffset + 8;
    if (State.Is64Bit) {
        Store32(Config, State.CapabilityOffset + 8, static_cast<std::uint32_t>(State.MessageAddress >> 32));
        DataOffset += 4;
    }
    Store16(Config, DataOffset, static_cast<std::uint16_t>(State.MessageData));
    RebuildCapabilityLinks(*It);
    return true;
}

bool PciBus::ConfigureMsix(PciAddress Address, const MsixState& State) {
    if (!Address.IsValid() || !IsValidCapabilityOffset(State.CapabilityOffset, 12) ||
        State.TableEntries == 0 || State.TableEntries > 2048 || State.TableBar >= 6 ||
        State.PendingBitBar >= 6 || (State.TableOffset & 7) != 0 || (State.PendingBitOffset & 7) != 0) {
        return false;
    }
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(Devices_.begin(), Devices_.end(), Address,
        [](const PciDeviceSnapshot& Device, const PciAddress& Value) {
            return Device.Descriptor.Address < Value;
        });
    if (It == Devices_.end() || It->Descriptor.Address != Address) return false;
    if (It->Msi) {
        const std::size_t MsiSize = It->Msi->Is64Bit ? 14 : 10;
        if (RangesOverlap(State.CapabilityOffset, 12, It->Msi->CapabilityOffset, MsiSize)) return false;
    }
    const auto FindBar = [&](std::uint8_t Index) -> const PciBar* {
        const auto Bar = std::find_if(It->Bars.begin(), It->Bars.end(),
            [Index](const PciBar& Value) { return Value.Index == Index && Value.Type != PciBarType::Io; });
        return Bar == It->Bars.end() ? nullptr : &*Bar;
    };
    const PciBar* TableBar = FindBar(State.TableBar);
    const PciBar* PendingBar = FindBar(State.PendingBitBar);
    const std::uint64_t TableBytes = static_cast<std::uint64_t>(State.TableEntries) * 16;
    const std::uint64_t PendingBytes = ((static_cast<std::uint64_t>(State.TableEntries) + 63) / 64) * 8;
    if (!TableBar || !PendingBar || State.TableOffset > TableBar->Size ||
        TableBytes > TableBar->Size - State.TableOffset || State.PendingBitOffset > PendingBar->Size ||
        PendingBytes > PendingBar->Size - State.PendingBitOffset) {
        return false;
    }

    It->Msix = State;
    auto& Config = It->Config;
    Config[State.CapabilityOffset] = 0x11;
    std::uint16_t Control = static_cast<std::uint16_t>(State.TableEntries - 1);
    if (State.FunctionMask) Control |= 1u << 14;
    if (State.Enabled) Control |= 1u << 15;
    Store16(Config, State.CapabilityOffset + 2, Control);
    Store32(Config, State.CapabilityOffset + 4, (State.TableOffset & ~7u) | State.TableBar);
    Store32(Config, State.CapabilityOffset + 8, (State.PendingBitOffset & ~7u) | State.PendingBitBar);
    RebuildCapabilityLinks(*It);
    return true;
}

std::vector<PciAddress> PciBus::Enumerate(std::optional<std::uint16_t> Segment,
                                          std::optional<std::uint8_t> Bus) const {
    std::scoped_lock Lock(Mutex_);
    std::vector<PciAddress> Result;
    Result.reserve(Devices_.size());
    for (const auto& Device : Devices_) {
        const auto& Address = Device.Descriptor.Address;
        if ((!Segment || Address.Segment == *Segment) && (!Bus || Address.Bus == *Bus)) {
            Result.push_back(Address);
        }
    }
    return Result;
}

std::optional<PciDeviceSnapshot> PciBus::Device(PciAddress Address) const {
    if (!Address.IsValid()) return std::nullopt;
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(Devices_.begin(), Devices_.end(), Address,
        [](const PciDeviceSnapshot& Device, const PciAddress& Value) {
            return Device.Descriptor.Address < Value;
        });
    if (It == Devices_.end() || It->Descriptor.Address != Address) return std::nullopt;
    return *It;
}

std::optional<std::uint32_t> PciBus::ReadConfig(PciAddress Address, std::uint16_t Offset,
                                                std::uint8_t Width) const {
    if (!Address.IsValid() || !ValidWidth(Width) || (Offset & (Width - 1)) != 0 ||
        static_cast<std::size_t>(Offset) + Width > kPciConfigSpaceSize) {
        return std::nullopt;
    }
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(Devices_.begin(), Devices_.end(), Address,
        [](const PciDeviceSnapshot& Device, const PciAddress& Value) {
            return Device.Descriptor.Address < Value;
        });
    if (It == Devices_.end() || It->Descriptor.Address != Address) return std::nullopt;
    std::uint32_t Value = 0;
    for (std::uint8_t Index = 0; Index != Width; ++Index) {
        Value |= static_cast<std::uint32_t>(It->Config[Offset + Index]) << (Index * 8);
    }
    return Value;
}

bool PciBus::WriteConfig(PciAddress Address, std::uint16_t Offset, std::uint8_t Width,
                         std::uint32_t Value) {
    if (!Address.IsValid() || !ValidWidth(Width) || (Offset & (Width - 1)) != 0 ||
        static_cast<std::size_t>(Offset) + Width > kPciConfigSpaceSize || Offset < 4 ||
        RangesOverlap(Offset, Width, 0x10, 0x18)) {
        return false;
    }
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(Devices_.begin(), Devices_.end(), Address,
        [](const PciDeviceSnapshot& Device, const PciAddress& AddressValue) {
            return Device.Descriptor.Address < AddressValue;
        });
    if (It == Devices_.end() || It->Descriptor.Address != Address) return false;
    for (std::uint8_t Index = 0; Index != Width; ++Index) {
        It->Config[Offset + Index] = static_cast<std::uint8_t>(Value >> (Index * 8));
    }
    if (It->Msi) {
        const auto ControlOffset = static_cast<std::uint16_t>(It->Msi->CapabilityOffset + 2);
        if (RangesOverlap(Offset, Width, ControlOffset, 2)) {
            It->Msi->Enabled = (It->Config[ControlOffset] & 1) != 0;
        }
    }
    if (It->Msix) {
        const auto ControlOffset = static_cast<std::uint16_t>(It->Msix->CapabilityOffset + 2);
        if (RangesOverlap(Offset, Width, ControlOffset, 2)) {
            const std::uint16_t Control = static_cast<std::uint16_t>(It->Config[ControlOffset]) |
                static_cast<std::uint16_t>(It->Config[ControlOffset + 1]) << 8;
            It->Msix->FunctionMask = (Control & (1u << 14)) != 0;
            It->Msix->Enabled = (Control & (1u << 15)) != 0;
        }
    }
    return true;
}

std::optional<MmioRegion> PciBus::ResolveMmio(std::uint64_t Address, std::uint64_t Length) const {
    if (!ValidRange(Address, Length)) return std::nullopt;
    std::scoped_lock Lock(Mutex_);
    for (const auto& Device : Devices_) {
        for (const auto& Bar : Device.Bars) {
            if (!Bar.Enabled || Bar.Type == PciBarType::Io || Address < Bar.Address) continue;
            const std::uint64_t Offset = Address - Bar.Address;
            if (Offset <= Bar.Size && Length <= Bar.Size - Offset) {
                return MmioRegion{Device.Descriptor.Address, Bar.Index, Bar.Address, Offset, Length};
            }
        }
    }
    return std::nullopt;
}

PciBusSnapshot PciBus::Snapshot() const {
    std::scoped_lock Lock(Mutex_);
    return PciBusSnapshot{Devices_};
}

bool PciBus::Restore(const PciBusSnapshot& SnapshotValue) {
    if (SnapshotValue.Devices.size() > kMaxSerializedDevices) return false;
    auto Candidate = SnapshotValue.Devices;
    std::sort(Candidate.begin(), Candidate.end(), [](const auto& Left, const auto& Right) {
        return Left.Descriptor.Address < Right.Descriptor.Address;
    });
    for (std::size_t DeviceIndex = 0; DeviceIndex != Candidate.size(); ++DeviceIndex) {
        const auto& Device = Candidate[DeviceIndex];
        if (!Device.Descriptor.Address.IsValid() || Device.Descriptor.VendorId == 0 ||
            Device.Descriptor.VendorId == 0xFFFF || Device.Bars.size() > 6 ||
            (DeviceIndex != 0 && Candidate[DeviceIndex - 1].Descriptor.Address == Device.Descriptor.Address)) {
            return false;
        }
        const std::uint16_t ConfigVendor = static_cast<std::uint16_t>(Device.Config[0]) |
            static_cast<std::uint16_t>(Device.Config[1]) << 8;
        const std::uint16_t ConfigDevice = static_cast<std::uint16_t>(Device.Config[2]) |
            static_cast<std::uint16_t>(Device.Config[3]) << 8;
        if (ConfigVendor != Device.Descriptor.VendorId || ConfigDevice != Device.Descriptor.DeviceId) return false;
        std::array<bool, 6> Occupied{};
        for (const auto& Bar : Device.Bars) {
            if (!IsValidBar(Bar) || Occupied[Bar.Index]) return false;
            Occupied[Bar.Index] = true;
            if (Bar.Type == PciBarType::Mmio64) {
                if (Occupied[Bar.Index + 1]) return false;
                Occupied[Bar.Index + 1] = true;
            }
        }
        if (Device.Msi && (!IsValidCapabilityOffset(Device.Msi->CapabilityOffset, Device.Msi->Is64Bit ? 14 : 10) ||
            Device.Msi->VectorCount == 0 || Device.Msi->VectorCount > 32 ||
            !std::has_single_bit(Device.Msi->VectorCount) || (Device.Msi->MessageAddress & 3) != 0)) return false;
        if (Device.Msix && (!IsValidCapabilityOffset(Device.Msix->CapabilityOffset, 12) ||
            Device.Msix->TableEntries == 0 || Device.Msix->TableEntries > 2048)) return false;
    }
    for (std::size_t LeftDevice = 0; LeftDevice != Candidate.size(); ++LeftDevice) {
        for (const auto& LeftBar : Candidate[LeftDevice].Bars) {
            if (LeftBar.Type == PciBarType::Io) continue;
            for (std::size_t RightDevice = LeftDevice; RightDevice != Candidate.size(); ++RightDevice) {
                for (const auto& RightBar : Candidate[RightDevice].Bars) {
                    if (RightBar.Type == PciBarType::Io ||
                        (&LeftBar == &RightBar && LeftDevice == RightDevice)) continue;
                    if (RightDevice == LeftDevice && RightBar.Index <= LeftBar.Index) continue;
                    if (RangesOverlap(LeftBar.Address, LeftBar.Size, RightBar.Address, RightBar.Size)) return false;
                }
            }
        }
    }
    std::scoped_lock Lock(Mutex_);
    Devices_ = std::move(Candidate);
    return true;
}

std::vector<std::uint8_t> PciBus::Serialize() const {
    const auto State = Snapshot();
    Writer Output;
    Output.Raw(kMagic);
    Output.Integer(kVersion);
    Output.Integer<std::uint32_t>(static_cast<std::uint32_t>(State.Devices.size()));
    for (const auto& Device : State.Devices) {
        WriteAddress(Output, Device.Descriptor.Address);
        Output.Integer(Device.Descriptor.VendorId);
        Output.Integer(Device.Descriptor.DeviceId);
        Output.Integer(Device.Descriptor.SubsystemVendorId);
        Output.Integer(Device.Descriptor.SubsystemId);
        Output.Integer(Device.Descriptor.Revision);
        Output.Integer(Device.Descriptor.ClassCode);
        Output.Integer(Device.Descriptor.Subclass);
        Output.Integer(Device.Descriptor.ProgrammingInterface);
        Output.Integer(Device.Descriptor.HeaderType);
        Output.String(Device.Descriptor.Name);
        Output.Raw(Device.Config);
        Output.Integer<std::uint32_t>(static_cast<std::uint32_t>(Device.Bars.size()));
        for (const auto& Bar : Device.Bars) {
            Output.Integer(Bar.Index);
            Output.Integer(static_cast<std::uint8_t>(Bar.Type));
            Output.Integer(Bar.Address);
            Output.Integer(Bar.Size);
            Output.Boolean(Bar.Prefetchable);
            Output.Boolean(Bar.Enabled);
        }
        Output.Boolean(Device.Msi.has_value());
        if (Device.Msi) {
            Output.Integer(Device.Msi->CapabilityOffset);
            Output.Integer(Device.Msi->VectorCount);
            Output.Integer(Device.Msi->MessageAddress);
            Output.Integer(Device.Msi->MessageData);
            Output.Boolean(Device.Msi->Enabled);
            Output.Boolean(Device.Msi->Is64Bit);
        }
        Output.Boolean(Device.Msix.has_value());
        if (Device.Msix) {
            Output.Integer(Device.Msix->CapabilityOffset);
            Output.Integer(Device.Msix->TableEntries);
            Output.Integer(Device.Msix->TableBar);
            Output.Integer(Device.Msix->TableOffset);
            Output.Integer(Device.Msix->PendingBitBar);
            Output.Integer(Device.Msix->PendingBitOffset);
            Output.Boolean(Device.Msix->Enabled);
            Output.Boolean(Device.Msix->FunctionMask);
        }
    }
    return std::move(Output).Finish();
}

std::optional<PciBusSnapshot> PciBus::Deserialize(std::span<const std::uint8_t> Bytes) {
    Reader Input(Bytes);
    std::array<std::uint8_t, 4> Magic{};
    std::uint32_t Version = 0;
    std::uint32_t DeviceCount = 0;
    if (!Input.Raw(Magic) || Magic != kMagic || !Input.Integer(Version) || Version != kVersion ||
        !Input.Integer(DeviceCount) || DeviceCount > kMaxSerializedDevices) return std::nullopt;

    PciBusSnapshot State;
    State.Devices.resize(DeviceCount);
    for (auto& Device : State.Devices) {
        auto& Descriptor = Device.Descriptor;
        if (!ReadAddress(Input, Descriptor.Address) || !Input.Integer(Descriptor.VendorId) ||
            !Input.Integer(Descriptor.DeviceId) || !Input.Integer(Descriptor.SubsystemVendorId) ||
            !Input.Integer(Descriptor.SubsystemId) || !Input.Integer(Descriptor.Revision) ||
            !Input.Integer(Descriptor.ClassCode) || !Input.Integer(Descriptor.Subclass) ||
            !Input.Integer(Descriptor.ProgrammingInterface) || !Input.Integer(Descriptor.HeaderType) ||
            !Input.String(Descriptor.Name) || !Input.Raw(Device.Config)) return std::nullopt;
        std::uint32_t BarCount = 0;
        if (!Input.Integer(BarCount) || BarCount > kMaxSerializedBars) return std::nullopt;
        Device.Bars.resize(BarCount);
        for (auto& Bar : Device.Bars) {
            std::uint8_t Type = 0;
            if (!Input.Integer(Bar.Index) || !Input.Integer(Type) || Type > static_cast<std::uint8_t>(PciBarType::Mmio64) ||
                !Input.Integer(Bar.Address) || !Input.Integer(Bar.Size) ||
                !Input.Boolean(Bar.Prefetchable) || !Input.Boolean(Bar.Enabled)) return std::nullopt;
            Bar.Type = static_cast<PciBarType>(Type);
        }
        bool Present = false;
        if (!Input.Boolean(Present)) return std::nullopt;
        if (Present) {
            Device.Msi.emplace();
            if (!Input.Integer(Device.Msi->CapabilityOffset) || !Input.Integer(Device.Msi->VectorCount) ||
                !Input.Integer(Device.Msi->MessageAddress) || !Input.Integer(Device.Msi->MessageData) ||
                !Input.Boolean(Device.Msi->Enabled) || !Input.Boolean(Device.Msi->Is64Bit)) return std::nullopt;
        }
        if (!Input.Boolean(Present)) return std::nullopt;
        if (Present) {
            Device.Msix.emplace();
            if (!Input.Integer(Device.Msix->CapabilityOffset) || !Input.Integer(Device.Msix->TableEntries) ||
                !Input.Integer(Device.Msix->TableBar) || !Input.Integer(Device.Msix->TableOffset) ||
                !Input.Integer(Device.Msix->PendingBitBar) || !Input.Integer(Device.Msix->PendingBitOffset) ||
                !Input.Boolean(Device.Msix->Enabled) || !Input.Boolean(Device.Msix->FunctionMask)) return std::nullopt;
        }
    }
    if (Input.Remaining() != 0) return std::nullopt;
    PciBus Validator;
    if (!Validator.Restore(State)) return std::nullopt;
    return State;
}

bool PciBus::RestoreSerialized(std::span<const std::uint8_t> Bytes) {
    const auto State = Deserialize(Bytes);
    return State && Restore(*State);
}

} // namespace Kevlar::Hardware
