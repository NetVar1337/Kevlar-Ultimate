#include "core/memory/physical_memory.h"
#include "core/memory/virtual_address_space.h"

#include <array>
#include <cassert>
#include <memory>

using namespace Kevlar::Memory;

int main() {
    auto Physical = std::make_shared<PhysicalMemory>(0x12345678, 0x100);
    auto Contiguous = Physical->AllocateContiguous(3, CacheType::Uncached);
    assert(Contiguous && Contiguous.FirstPfn == 0x100 && Contiguous.GuestAddress() == 0x100000);

    VirtualAddressSpace Parent(Physical, 4, 0xabc);
    constexpr auto Rw = Protection::Read | Protection::Write | Protection::User;
    auto Allocation = Parent.Allocate(PageSize * 2, Rw, CacheType::WriteBack, 0x20000);
    assert(Allocation && Allocation.Pfns.size() == 2);

    std::array<std::byte, 4> Value{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    assert(Parent.Write(0x20ffe, Value, true));
    std::array<std::byte, 4> ReadBack{};
    assert(Parent.Read(0x20ffe, ReadBack, true) && ReadBack == Value);
    assert(Parent.DirtyVirtualPages().size() == 2);

    auto Child = Parent.CloneCopyOnWrite(5, 0xdef);
    const std::array<std::byte, 1> Changed{std::byte{9}};
    assert(Child->Write(0x20000, Changed, true));
    std::array<std::byte, 1> ParentByte{}, ChildByte{};
    assert(Parent.Read(0x20000, ParentByte, true));
    assert(Child->Read(0x20000, ChildByte, true));
    assert(ParentByte[0] == std::byte{0} && ChildByte[0] == std::byte{9});

    std::vector<PageFrameNumber> Pinned;
    assert(Parent.Pin(0x20000, PageSize * 2, &Pinned));
    assert(!Physical->FreePage(Pinned.front()));
    assert(Parent.Unpin(Pinned));

    const auto PhysicalState = Physical->Snapshot();
    const auto PhysicalBytes = PhysicalMemory::SerializeSnapshot(PhysicalState);
    const auto DecodedPhysical = PhysicalMemory::DeserializeSnapshot(PhysicalBytes);
    assert(DecodedPhysical);

    const auto AddressState = Parent.Snapshot();
    const auto AddressBytes = VirtualAddressSpace::SerializeSnapshot(AddressState);
    const auto DecodedAddress = VirtualAddressSpace::DeserializeSnapshot(AddressBytes);
    assert(DecodedAddress);
    assert(Parent.Protect(0x20000, PageSize, Protection::Read | Protection::User));
    assert(!Parent.Write(0x20000, Changed, true));
    assert(Parent.Restore(*DecodedAddress));
    assert(Physical->Restore(*DecodedPhysical));
    assert(Parent.Write(0x20000, Changed, true));

    return 0;
}
