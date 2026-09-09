#include "../../KEVLAR/core/hardware/hardware_profile.h"

#include <cassert>
#include <cstdint>
#include <cstdio>

using namespace Kevlar::Hardware;

namespace {

void PciFixture() {
    PciBus Bus;
    const PciDeviceDescriptor Device{{0, 2, 3, 1}, 0x1234, 0x5678, 0x1234, 1, 2, 1, 8, 2, 0, "fixture"};
    assert(Bus.AddDevice(Device));
    assert(!Bus.AddDevice(Device));
    assert(!Bus.AddDevice(PciDeviceDescriptor{{0, 0, 32, 0}, 1, 1}));
    assert(!Bus.RegisterBar(Device.Address, {0, PciBarType::Mmio64, 0x80001000, 0x4000}));
    assert(Bus.RegisterBar(Device.Address, {0, PciBarType::Mmio64, 0x80000000, 0x4000}));
    assert(!Bus.RegisterBar(Device.Address, {1, PciBarType::Mmio32, 0x90000000, 0x1000}));
    assert(Bus.ConfigureMsix(Device.Address, {0x70, 4, 0, 0, 0, 0x1000, true, false}));
    assert(Bus.Device(Device.Address)->Config.size() == kPciConfigSpaceSize);
    assert(Bus.ReadConfig(Device.Address, 0, 4) == 0x56781234u);
    assert(Bus.ResolveMmio(0x80000120, 8)->Offset == 0x120);

    const auto Before = Bus.Snapshot();
    const auto Bytes = Bus.Serialize();
    PciBus Restored;
    assert(Restored.RestoreSerialized(Bytes));
    assert(Restored.Snapshot() == Before);
}

void IommuFixture() {
    const PciAddress Device{0, 1, 0, 0};
    Iommu Unit(0x1234, 99);
    assert(Unit.AttachDevice(Device, 7));
    assert(!Unit.Map({7, 0x1001, 0x2000, 0x1000, DmaAccess::ReadWrite}));
    assert(Unit.Map({7, 0x1000, 0x4000, 0x2000, DmaAccess::Read}));
    assert(Unit.Translate(Device, 7, 0x1800, 8, DmaAccess::Read) == 0x4800);
    assert(!Unit.Translate(Device, 7, 0x1800, 8, DmaAccess::Write));
    assert(!Unit.Translate(Device, 7, 0x5000, 8, DmaAccess::Read));
    const auto Faults = Unit.FaultJournal();
    assert(Faults.size() == 2 && Faults[0].Sequence == 1 && Faults[1].Sequence == 2);
    assert(Faults[0].VirtualTime == 99 && Faults[0].Reason == IommuFaultReason::PermissionDenied);
    assert(Unit.Unmap(7, 0x1000, 0x2000));
    assert(!Unit.Translate(Device, 7, 0x1000, 1, DmaAccess::Read));

    const auto Before = Unit.Snapshot();
    Iommu Restored(0);
    assert(Restored.RestoreSerialized(Unit.Serialize()));
    assert(Restored.Snapshot() == Before);
}

void HardwareFixture() {
    auto Profile = HardwareProfile::CreateRaptorLake(0xC0FFEE, 123456);
    assert(Profile);
    assert(Profile->Identity().CpuSignature == 0x000B0671);
    assert(Profile->Identity().CpuBrand == "13th Gen Intel(R) Core(TM) i9-13900K");
    const auto Addresses = Profile->Pci().Enumerate(0, 0);
    assert(Addresses.size() == 4);

    const PciAddress Nvme{0, 1, 0, 0};
    const auto Adapter = Profile->CreateDmaAdapter(Nvme, 0x0000FFFFFFFFFFFFull,
        kIommuPageSize, 0x10000, 8);
    assert(Adapter);
    const auto Common = Profile->AllocateCommonBuffer(Adapter->Id, 0x1800, kIommuPageSize);
    assert(Common && Common->Length == 0x2000);
    assert(Profile->TranslateDma(Adapter->Id, Common->Iova + 0x100, 8, DmaAccess::Write) ==
        Common->PhysicalAddress + 0x100);
    assert(!Profile->TranslateDma(Adapter->Id, Common->Iova + Common->Length, 1, DmaAccess::Read));

    const PhysicalRange Ranges[]{{0x200000, 0x1000}, {0x300000, 0x2000}};
    const auto List = Profile->AllocateScatterGather(Adapter->Id, Ranges, DmaAccess::Read);
    assert(List && List->Segments.size() == 2);
    assert(!Profile->TranslateDma(Adapter->Id, List->Segments[0].Iova, 1, DmaAccess::Write));

    const auto Before = Profile->Snapshot();
    auto Restored = HardwareProfile::CreateRaptorLake(0xC0FFEE, 0);
    assert(Restored && Restored->Restore(Before));
    assert(Restored->Snapshot() == Before);
    assert(!HardwareProfile::CreateRaptorLake(1, 0)->Restore(Before));
}

} // namespace

int main() {
    PciFixture();
    IommuFixture();
    HardwareFixture();
    std::puts("hardware model fixtures OK");
    return 0;
}
