#include "hardware_profile.h"

#include <algorithm>
#include <bit>
#include <limits>

namespace Kevlar::Hardware {
namespace {

std::uint64_t SplitMix64(std::uint64_t& State) noexcept {
    std::uint64_t Value = (State += 0x9E3779B97F4A7C15ull);
    Value = (Value ^ (Value >> 30)) * 0xBF58476D1CE4E5B9ull;
    Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBull;
    return Value ^ (Value >> 31);
}

template <std::size_t N>
void FillSeeded(std::array<std::uint8_t, N>& Output, std::uint64_t& State) noexcept {
    for (std::size_t Offset = 0; Offset < N; Offset += 8) {
        const auto Value = SplitMix64(State);
        for (std::size_t Byte = 0; Byte < 8 && Offset + Byte < N; ++Byte)
            Output[Offset + Byte] = static_cast<std::uint8_t>(Value >> (Byte * 8));
    }
}

bool ValidRange(std::uint64_t Address, std::uint64_t Length) noexcept {
    return Length != 0 && Address <= std::numeric_limits<std::uint64_t>::max() - (Length - 1);
}

} // namespace

HardwareProfile::HardwareProfile(std::uint64_t Seed, std::uint64_t InitialVirtualTime)
    : Seed_(Seed), VirtualTime_(InitialVirtualTime),
      NextPhysicalAddress_(0x100000000ull + ((Seed & 0xFFFu) << 12)),
      NextIova_(0x10000000ull + ((Seed & 0xFFu) << 20)), Iommu_(Seed, InitialVirtualTime) {}

bool HardwareProfile::IsPowerOfTwo(std::uint64_t Value) noexcept { return std::has_single_bit(Value); }

std::uint64_t HardwareProfile::AlignUp(std::uint64_t Value, std::uint64_t Alignment) noexcept {
    if (!IsPowerOfTwo(Alignment) || Value > std::numeric_limits<std::uint64_t>::max() - (Alignment - 1)) return 0;
    return (Value + Alignment - 1) & ~(Alignment - 1);
}

std::unique_ptr<HardwareProfile> HardwareProfile::CreateRaptorLake(
    std::uint64_t Seed, std::uint64_t InitialVirtualTime) {
    auto Profile = std::make_unique<HardwareProfile>(Seed, InitialVirtualTime);
    auto& Identity = Profile->Identity_;
    Identity.CpuVendor = "GenuineIntel";
    Identity.CpuBrand = "13th Gen Intel(R) Core(TM) i9-13900K";
    Identity.CpuSignature = 0x000B0671;
    Identity.LogicalProcessorCount = 16;
    Identity.Acpi = {"ALASKA", "A M I ", 0x01072009, 0x4D534654, 0x00000097};
    Identity.Smbios.BiosVendor = "American Megatrends International, LLC.";
    Identity.Smbios.BiosVersion = "1801";
    Identity.Smbios.BiosDate = "12/22/2023";
    Identity.Smbios.SystemManufacturer = "ASUSTeK COMPUTER INC.";
    Identity.Smbios.SystemProduct = "PRIME Z790-P WIFI";
    Identity.Smbios.SystemVersion = "Rev 1.xx";
    Identity.Smbios.BaseboardManufacturer = "ASUSTeK COMPUTER INC.";
    Identity.Smbios.BaseboardProduct = "PRIME Z790-P WIFI";
    Identity.Uefi.FirmwareVendor = "American Megatrends";
    Identity.Uefi.FirmwareRevision = 0x00018001;
    Identity.Tpm.ManufacturerId = 0x49465800; // IFX\0
    Identity.Tpm.FirmwareVersionMajor = 7;
    Identity.Tpm.FirmwareVersionMinor = 85;
    std::uint64_t Random = Seed ^ 0x524150544F524C4Bull;
    FillSeeded(Identity.Smbios.SystemUuid, Random);
    FillSeeded(Identity.Uefi.BootIdentifier, Random);
    FillSeeded(Identity.Tpm.EndorsementKeyDigest, Random);
    const auto Serial = SplitMix64(Random);
    Identity.Smbios.SystemSerial = "RPL-" + std::to_string(Serial);
    Identity.Smbios.BaseboardSerial = "Z790-" + std::to_string(SplitMix64(Random));

    const auto Add = [&](PciAddress Address, std::uint16_t DeviceId, std::uint8_t Class,
                         std::uint8_t Subclass, std::uint8_t Interface, const char* Name) {
        return Profile->Pci_.AddDevice(PciDeviceDescriptor{Address, 0x8086, DeviceId, 0x1043,
            DeviceId, 0x11, Class, Subclass, Interface, 0, Name});
    };
    if (!Add({0, 0, 0, 0}, 0xA700, 0x06, 0x00, 0x00, "Raptor Lake Host Bridge") ||
        !Add({0, 0, 2, 0}, 0xA780, 0x03, 0x00, 0x00, "Raptor Lake UHD Graphics") ||
        !Add({0, 0, 20, 0}, 0x7A60, 0x0C, 0x03, 0x30, "Raptor Lake USB xHCI") ||
        !Add({0, 0, 31, 0}, 0x7A04, 0x06, 0x01, 0x00, "Z790 LPC Controller")) return nullptr;
    if (!Profile->Pci_.RegisterBar({0, 0, 2, 0}, {0, PciBarType::Mmio64, 0x0000008000000000ull, 0x10000000, true, true}) ||
        !Profile->Pci_.RegisterBar({0, 0, 20, 0}, {0, PciBarType::Mmio64, 0x00000000F6000000ull, 0x10000, false, true}) ||
        !Profile->Pci_.ConfigureMsi({0, 0, 20, 0}, {0x80, 8, 0xFEE00000, 0x40, false, true})) return nullptr;

    PciDeviceDescriptor Nvme{{0, 1, 0, 0}, 0x144D, 0xA80A, 0x144D, 0xA801, 1, 0x01, 0x08, 0x02, 0, "Samsung NVMe Controller"};
    if (!Profile->Pci_.AddDevice(Nvme) ||
        !Profile->Pci_.RegisterBar(Nvme.Address, {0, PciBarType::Mmio64, 0x00000000F5000000ull, 0x4000, false, true}) ||
        !Profile->Pci_.ConfigureMsix(Nvme.Address, {0x70, 65, 0, 0, 0, 0x2000, false, false})) return nullptr;
    return Profile;
}

PlatformIdentity HardwareProfile::Identity() const { std::scoped_lock Lock(Mutex_); return Identity_; }
std::uint64_t HardwareProfile::VirtualTime() const { std::scoped_lock Lock(Mutex_); return VirtualTime_; }
void HardwareProfile::SetVirtualTime(std::uint64_t Value) { std::scoped_lock Lock(Mutex_); VirtualTime_ = Value; Iommu_.SetVirtualTime(Value); }

const DmaAdapter* HardwareProfile::FindAdapter(std::uint64_t Id) const noexcept {
    const auto It = std::lower_bound(Adapters_.begin(), Adapters_.end(), Id,
        [](const DmaAdapter& Adapter, std::uint64_t Value) { return Adapter.Id < Value; });
    return It == Adapters_.end() || It->Id != Id ? nullptr : &*It;
}

std::optional<DmaAdapter> HardwareProfile::CreateDmaAdapter(PciAddress Device,
    std::uint64_t MaximumPhysicalAddress, std::uint64_t Alignment,
    std::uint64_t MaximumTransferLength, std::uint32_t MaximumSegments) {
    if (!Device.IsValid() || !IsPowerOfTwo(Alignment) || Alignment < kIommuPageSize ||
        MaximumTransferLength == 0 || MaximumSegments == 0 || !Pci_.Device(Device)) return std::nullopt;
    std::scoped_lock Lock(Mutex_);
    if (std::any_of(Adapters_.begin(), Adapters_.end(), [&](const auto& A) { return A.Device == Device; })) return std::nullopt;
    const std::uint64_t Id = NextAdapterId_;
    if (Id > std::numeric_limits<std::uint32_t>::max() || !Iommu_.AttachDevice(Device, static_cast<std::uint32_t>(Id))) return std::nullopt;
    ++NextAdapterId_;
    DmaAdapter Adapter{Id, Device, static_cast<std::uint32_t>(Id), MaximumPhysicalAddress,
        Alignment, MaximumTransferLength, MaximumSegments};
    Adapters_.push_back(Adapter);
    return Adapter;
}

std::optional<DmaCommonBuffer> HardwareProfile::AllocateCommonBuffer(
    std::uint64_t AdapterId, std::uint64_t Length, std::uint64_t Alignment, bool CacheEnabled) {
    std::scoped_lock Lock(Mutex_);
    const auto* Adapter = FindAdapter(AdapterId);
    if (!Adapter || Length == 0 || Length > Adapter->MaximumTransferLength || !IsPowerOfTwo(Alignment) ||
        Alignment < Adapter->Alignment) return std::nullopt;
    const auto MappedLength = AlignUp(Length, kIommuPageSize);
    const auto Physical = AlignUp(NextPhysicalAddress_, Alignment);
    const auto Iova = AlignUp(NextIova_, Alignment);
    if (!MappedLength || !Physical || !Iova || !ValidRange(Physical, MappedLength) || !ValidRange(Iova, MappedLength) ||
        Physical + MappedLength - 1 > Adapter->MaximumPhysicalAddress ||
        !Iommu_.Map({Adapter->Domain, Iova, Physical, MappedLength, DmaAccess::ReadWrite})) return std::nullopt;
    DmaCommonBuffer Buffer{NextAllocationId_++, AdapterId, Iova, Physical, MappedLength, CacheEnabled};
    CommonBuffers_.push_back(Buffer); NextPhysicalAddress_ = Physical + MappedLength; NextIova_ = Iova + MappedLength;
    return Buffer;
}

bool HardwareProfile::FreeCommonBuffer(std::uint64_t AllocationId) {
    std::scoped_lock Lock(Mutex_);
    const auto It = std::find_if(CommonBuffers_.begin(), CommonBuffers_.end(), [&](const auto& B) { return B.Id == AllocationId; });
    if (It == CommonBuffers_.end()) return false;
    const auto* Adapter = FindAdapter(It->AdapterId);
    if (!Adapter || !Iommu_.Unmap(Adapter->Domain, It->Iova, It->Length)) return false;
    CommonBuffers_.erase(It); return true;
}

std::optional<ScatterGatherList> HardwareProfile::AllocateScatterGather(
    std::uint64_t AdapterId, std::span<const PhysicalRange> Ranges, DmaAccess Access) {
    std::scoped_lock Lock(Mutex_); const auto* Adapter = FindAdapter(AdapterId);
    if (!Adapter || Ranges.empty() || Ranges.size() > Adapter->MaximumSegments ||
        static_cast<std::uint8_t>(Access) < 1 || static_cast<std::uint8_t>(Access) > 3) return std::nullopt;
    std::uint64_t Total = 0, Cursor = AlignUp(NextIova_, Adapter->Alignment);
    if (!Cursor) return std::nullopt;
    ScatterGatherList List{NextAllocationId_, AdapterId, Access, {}}; List.Segments.reserve(Ranges.size());
    for (const auto& Range : Ranges) {
        if (!ValidRange(Range.Address, Range.Length) || (Range.Address & (kIommuPageSize - 1)) ||
            (Range.Length & (kIommuPageSize - 1)) || Range.Address + Range.Length - 1 > Adapter->MaximumPhysicalAddress ||
            Range.Length > Adapter->MaximumTransferLength - Total ||
            !Iommu_.Map({Adapter->Domain, Cursor, Range.Address, Range.Length, Access})) {
            for (const auto& Segment : List.Segments) Iommu_.Unmap(Adapter->Domain, Segment.Iova, Segment.Length);
            return std::nullopt;
        }
        Total += Range.Length; List.Segments.push_back({Cursor, Range.Address, Range.Length}); Cursor += Range.Length;
    }
    ++NextAllocationId_; NextIova_ = Cursor; ScatterGatherLists_.push_back(List); return List;
}

bool HardwareProfile::FreeScatterGather(std::uint64_t AllocationId) {
    std::scoped_lock Lock(Mutex_);
    const auto It = std::find_if(ScatterGatherLists_.begin(), ScatterGatherLists_.end(), [&](const auto& L) { return L.Id == AllocationId; });
    if (It == ScatterGatherLists_.end()) return false; const auto* Adapter = FindAdapter(It->AdapterId); if (!Adapter) return false;
    for (const auto& Segment : It->Segments) if (!Iommu_.Unmap(Adapter->Domain, Segment.Iova, Segment.Length)) return false;
    ScatterGatherLists_.erase(It); return true;
}

std::optional<std::uint64_t> HardwareProfile::TranslateDma(
    std::uint64_t AdapterId, std::uint64_t Iova, std::uint64_t Length, DmaAccess Access) {
    std::scoped_lock Lock(Mutex_); const auto* Adapter = FindAdapter(AdapterId);
    if (!Adapter) return std::nullopt; return Iommu_.Translate(Adapter->Device, Adapter->Domain, Iova, Length, Access);
}

HardwareProfileSnapshot HardwareProfile::Snapshot() const {
    std::scoped_lock Lock(Mutex_);
    return {Seed_, VirtualTime_, NextAdapterId_, NextAllocationId_, NextPhysicalAddress_, NextIova_,
        Identity_, Pci_.Snapshot(), Iommu_.Snapshot(), Adapters_, CommonBuffers_, ScatterGatherLists_};
}

bool HardwareProfile::Restore(const HardwareProfileSnapshot& S) {
    if (S.Seed != Seed_ || S.NextAdapterId == 0 || S.NextAllocationId == 0 || !ValidRange(S.NextPhysicalAddress, 1) || !ValidRange(S.NextIova, 1)) return false;
    PciBus PciValidator; Iommu IommuValidator(S.Seed);
    if (!PciValidator.Restore(S.Pci) || !IommuValidator.Restore(S.IommuState) || S.IommuState.Seed != S.Seed || S.IommuState.VirtualTime != S.VirtualTime) return false;
    for (std::size_t I = 0; I != S.Adapters.size(); ++I) {
        const auto& A = S.Adapters[I];
        if (!A.Id || !A.Device.IsValid() || !IsPowerOfTwo(A.Alignment) || A.Alignment < kIommuPageSize ||
            !A.MaximumTransferLength || !A.MaximumSegments || !PciValidator.Device(A.Device) ||
            (I && S.Adapters[I - 1].Id >= A.Id)) return false;
    }
    std::scoped_lock Lock(Mutex_);
    if (!Pci_.Restore(S.Pci) || !Iommu_.Restore(S.IommuState)) return false;
    VirtualTime_ = S.VirtualTime; NextAdapterId_ = S.NextAdapterId; NextAllocationId_ = S.NextAllocationId;
    NextPhysicalAddress_ = S.NextPhysicalAddress; NextIova_ = S.NextIova; Identity_ = S.Identity;
    Adapters_ = S.Adapters; CommonBuffers_ = S.CommonBuffers; ScatterGatherLists_ = S.ScatterGatherLists;
    return true;
}

} // namespace Kevlar::Hardware
