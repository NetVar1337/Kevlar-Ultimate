#include "iommu.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <type_traits>
#include <utility>

namespace Kevlar::Hardware {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'I', 'O', 'M'};
constexpr std::uint32_t kVersion = 1;
constexpr std::uint32_t kMaxEntries = 1u << 20;

bool ValidRange(std::uint64_t Address, std::uint64_t Length) noexcept {
    return Length != 0 && Address <= std::numeric_limits<std::uint64_t>::max() - (Length - 1);
}

class Writer {
public:
    template <class T> void Put(T Value) {
        using U = std::make_unsigned_t<T>;
        U Bits = static_cast<U>(Value);
        for (std::size_t I = 0; I != sizeof(T); ++I) Bytes.push_back(static_cast<std::uint8_t>(Bits >> (I * 8)));
    }
    void Bool(bool Value) { Put<std::uint8_t>(Value ? 1 : 0); }
    void Raw(std::span<const std::uint8_t> Value) { Bytes.insert(Bytes.end(), Value.begin(), Value.end()); }
    std::vector<std::uint8_t> Bytes;
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> Value) : Bytes(Value) {}
    template <class T> bool Get(T& Value) {
        if (Bytes.size() - Position < sizeof(T)) return false;
        using U = std::make_unsigned_t<T>;
        U Bits = 0;
        for (std::size_t I = 0; I != sizeof(T); ++I) Bits |= static_cast<U>(Bytes[Position++]) << (I * 8);
        Value = static_cast<T>(Bits);
        return true;
    }
    bool Bool(bool& Value) { std::uint8_t V = 0; if (!Get(V) || V > 1) return false; Value = V != 0; return true; }
    bool Raw(std::span<std::uint8_t> Value) {
        if (Bytes.size() - Position < Value.size()) return false;
        std::memcpy(Value.data(), Bytes.data() + Position, Value.size()); Position += Value.size(); return true;
    }
    std::span<const std::uint8_t> Bytes;
    std::size_t Position = 0;
};

void PutAddress(Writer& W, PciAddress A) { W.Put(A.Segment); W.Put(A.Bus); W.Put(A.Device); W.Put(A.Function); }
bool GetAddress(Reader& R, PciAddress& A) { return R.Get(A.Segment) && R.Get(A.Bus) && R.Get(A.Device) && R.Get(A.Function); }

} // namespace

Iommu::Iommu(std::uint64_t Seed, std::uint64_t InitialVirtualTime) {
    State_.Seed = Seed;
    State_.VirtualTime = InitialVirtualTime;
}

bool Iommu::IsValidAccess(DmaAccess Access) noexcept {
    const auto Value = static_cast<std::uint8_t>(Access);
    return Value >= 1 && Value <= 3;
}

bool Iommu::IsValidPageRange(std::uint64_t Address, std::uint64_t Length) noexcept {
    return ValidRange(Address, Length) && (Address & (kIommuPageSize - 1)) == 0 &&
           (Length & (kIommuPageSize - 1)) == 0;
}

bool Iommu::RangesOverlap(std::uint64_t A, std::uint64_t ALength,
                          std::uint64_t B, std::uint64_t BLength) noexcept {
    return !ValidRange(A, ALength) || !ValidRange(B, BLength) || A < B + BLength && B < A + ALength;
}

bool Iommu::AttachDevice(PciAddress Device, std::uint32_t Domain) {
    if (!Device.IsValid()) return false;
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(State_.Attachments.begin(), State_.Attachments.end(), Device,
        [](const IommuAttachment& Value, const PciAddress& Address) { return Value.Device < Address; });
    if (It != State_.Attachments.end() && It->Device == Device) return It->Domain == Domain;
    State_.Attachments.insert(It, IommuAttachment{Device, Domain});
    return true;
}

bool Iommu::DetachDevice(PciAddress Device) {
    if (!Device.IsValid()) return false;
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(State_.Attachments.begin(), State_.Attachments.end(), Device,
        [](const IommuAttachment& Value, const PciAddress& Address) { return Value.Device < Address; });
    if (It == State_.Attachments.end() || It->Device != Device) return false;
    State_.Attachments.erase(It);
    return true;
}

bool Iommu::Map(const IommuMapping& Mapping) {
    if (!IsValidPageRange(Mapping.Iova, Mapping.Length) ||
        !IsValidPageRange(Mapping.PhysicalAddress, Mapping.Length) || !IsValidAccess(Mapping.Access)) return false;
    std::scoped_lock Lock(Mutex_);
    for (const auto& Existing : State_.Mappings) {
        if (Existing.Domain == Mapping.Domain && RangesOverlap(Existing.Iova, Existing.Length, Mapping.Iova, Mapping.Length)) return false;
    }
    State_.Mappings.push_back(Mapping);
    std::sort(State_.Mappings.begin(), State_.Mappings.end(), [](const auto& A, const auto& B) {
        return A.Domain < B.Domain || A.Domain == B.Domain && A.Iova < B.Iova;
    });
    return true;
}

bool Iommu::Unmap(std::uint32_t Domain, std::uint64_t Iova, std::uint64_t Length) {
    if (!IsValidPageRange(Iova, Length)) return false;
    std::scoped_lock Lock(Mutex_);
    const auto It = std::find_if(State_.Mappings.begin(), State_.Mappings.end(), [&](const auto& Mapping) {
        return Mapping.Domain == Domain && Mapping.Iova == Iova && Mapping.Length == Length;
    });
    if (It == State_.Mappings.end()) return false;
    State_.Mappings.erase(It);
    return true;
}

void Iommu::RecordFault(PciAddress Device, std::uint32_t Domain, std::uint64_t Iova,
                        std::uint64_t Length, DmaAccess Access, IommuFaultReason Reason) {
    State_.Faults.push_back(IommuFault{State_.NextFaultSequence++, State_.VirtualTime,
        Device, Domain, Iova, Length, Access, Reason});
}

std::optional<std::uint64_t> Iommu::Translate(PciAddress Device, std::uint32_t Domain,
                                              std::uint64_t Iova, std::uint64_t Length,
                                              DmaAccess Access) {
    std::scoped_lock Lock(Mutex_);
    if (!Device.IsValid() || !ValidRange(Iova, Length) || !IsValidAccess(Access)) {
        RecordFault(Device, Domain, Iova, Length, Access, IommuFaultReason::InvalidRequest); return std::nullopt;
    }
    if (!State_.TranslationEnabled) {
        RecordFault(Device, Domain, Iova, Length, Access, IommuFaultReason::TranslationDisabled); return std::nullopt;
    }
    const auto Attachment = std::lower_bound(State_.Attachments.begin(), State_.Attachments.end(), Device,
        [](const IommuAttachment& Value, const PciAddress& Address) { return Value.Device < Address; });
    if (Attachment == State_.Attachments.end() || Attachment->Device != Device || Attachment->Domain != Domain) {
        RecordFault(Device, Domain, Iova, Length, Access, IommuFaultReason::DeviceNotAttached); return std::nullopt;
    }
    const auto Mapping = std::find_if(State_.Mappings.begin(), State_.Mappings.end(), [&](const auto& Value) {
        if (Value.Domain != Domain || Iova < Value.Iova) return false;
        const auto Offset = Iova - Value.Iova;
        return Offset <= Value.Length && Length <= Value.Length - Offset;
    });
    if (Mapping == State_.Mappings.end()) {
        RecordFault(Device, Domain, Iova, Length, Access, IommuFaultReason::Unmapped); return std::nullopt;
    }
    const auto Requested = static_cast<std::uint8_t>(Access);
    const auto Granted = static_cast<std::uint8_t>(Mapping->Access);
    if ((Requested & Granted) != Requested) {
        RecordFault(Device, Domain, Iova, Length, Access, IommuFaultReason::PermissionDenied); return std::nullopt;
    }
    return Mapping->PhysicalAddress + (Iova - Mapping->Iova);
}

void Iommu::SetTranslationEnabled(bool Enabled) { std::scoped_lock Lock(Mutex_); State_.TranslationEnabled = Enabled; }
void Iommu::SetVirtualTime(std::uint64_t VirtualTime) { std::scoped_lock Lock(Mutex_); State_.VirtualTime = VirtualTime; }
void Iommu::ClearFaults() { std::scoped_lock Lock(Mutex_); State_.Faults.clear(); }
bool Iommu::TranslationEnabled() const { std::scoped_lock Lock(Mutex_); return State_.TranslationEnabled; }
std::uint64_t Iommu::VirtualTime() const { std::scoped_lock Lock(Mutex_); return State_.VirtualTime; }
std::vector<IommuFault> Iommu::FaultJournal() const { std::scoped_lock Lock(Mutex_); return State_.Faults; }
IommuSnapshot Iommu::Snapshot() const { std::scoped_lock Lock(Mutex_); return State_; }

bool Iommu::Restore(const IommuSnapshot& SnapshotValue) {
    if (SnapshotValue.Attachments.size() > kMaxEntries || SnapshotValue.Mappings.size() > kMaxEntries ||
        SnapshotValue.Faults.size() > kMaxEntries || SnapshotValue.NextFaultSequence == 0) return false;
    auto Candidate = SnapshotValue;
    std::sort(Candidate.Attachments.begin(), Candidate.Attachments.end(), [](const auto& A, const auto& B) { return A.Device < B.Device; });
    for (std::size_t I = 0; I != Candidate.Attachments.size(); ++I) {
        if (!Candidate.Attachments[I].Device.IsValid() || (I && Candidate.Attachments[I - 1].Device == Candidate.Attachments[I].Device)) return false;
    }
    std::sort(Candidate.Mappings.begin(), Candidate.Mappings.end(), [](const auto& A, const auto& B) {
        return A.Domain < B.Domain || A.Domain == B.Domain && A.Iova < B.Iova;
    });
    for (std::size_t I = 0; I != Candidate.Mappings.size(); ++I) {
        const auto& Mapping = Candidate.Mappings[I];
        if (!IsValidPageRange(Mapping.Iova, Mapping.Length) || !IsValidPageRange(Mapping.PhysicalAddress, Mapping.Length) ||
            !IsValidAccess(Mapping.Access) || (I && Candidate.Mappings[I - 1].Domain == Mapping.Domain &&
            RangesOverlap(Candidate.Mappings[I - 1].Iova, Candidate.Mappings[I - 1].Length, Mapping.Iova, Mapping.Length))) return false;
    }
    std::uint64_t LastSequence = 0;
    for (const auto& Fault : Candidate.Faults) {
        if (Fault.Sequence <= LastSequence || !Fault.Device.IsValid() || !IsValidAccess(Fault.Access) ||
            static_cast<std::uint8_t>(Fault.Reason) > static_cast<std::uint8_t>(IommuFaultReason::PermissionDenied)) return false;
        LastSequence = Fault.Sequence;
    }
    if (Candidate.NextFaultSequence <= LastSequence) return false;
    std::scoped_lock Lock(Mutex_); State_ = std::move(Candidate); return true;
}

std::vector<std::uint8_t> Iommu::Serialize() const {
    const auto State = Snapshot(); Writer W; W.Raw(kMagic); W.Put(kVersion); W.Put(State.Seed); W.Put(State.VirtualTime);
    W.Put(State.NextFaultSequence); W.Bool(State.TranslationEnabled);
    W.Put<std::uint32_t>(static_cast<std::uint32_t>(State.Attachments.size()));
    for (const auto& A : State.Attachments) { PutAddress(W, A.Device); W.Put(A.Domain); }
    W.Put<std::uint32_t>(static_cast<std::uint32_t>(State.Mappings.size()));
    for (const auto& M : State.Mappings) { W.Put(M.Domain); W.Put(M.Iova); W.Put(M.PhysicalAddress); W.Put(M.Length); W.Put(static_cast<std::uint8_t>(M.Access)); }
    W.Put<std::uint32_t>(static_cast<std::uint32_t>(State.Faults.size()));
    for (const auto& F : State.Faults) { W.Put(F.Sequence); W.Put(F.VirtualTime); PutAddress(W, F.Device); W.Put(F.Domain); W.Put(F.Iova); W.Put(F.Length); W.Put(static_cast<std::uint8_t>(F.Access)); W.Put(static_cast<std::uint8_t>(F.Reason)); }
    return std::move(W.Bytes);
}

std::optional<IommuSnapshot> Iommu::Deserialize(std::span<const std::uint8_t> Bytes) {
    Reader R(Bytes); std::array<std::uint8_t, 4> Magic{}; std::uint32_t Version = 0, Count = 0; IommuSnapshot S;
    if (!R.Raw(Magic) || Magic != kMagic || !R.Get(Version) || Version != kVersion || !R.Get(S.Seed) ||
        !R.Get(S.VirtualTime) || !R.Get(S.NextFaultSequence) || !R.Bool(S.TranslationEnabled) || !R.Get(Count) || Count > kMaxEntries) return std::nullopt;
    S.Attachments.resize(Count);
    for (auto& A : S.Attachments) if (!GetAddress(R, A.Device) || !R.Get(A.Domain)) return std::nullopt;
    if (!R.Get(Count) || Count > kMaxEntries) return std::nullopt; S.Mappings.resize(Count);
    for (auto& M : S.Mappings) { std::uint8_t Access = 0; if (!R.Get(M.Domain) || !R.Get(M.Iova) || !R.Get(M.PhysicalAddress) || !R.Get(M.Length) || !R.Get(Access)) return std::nullopt; M.Access = static_cast<DmaAccess>(Access); }
    if (!R.Get(Count) || Count > kMaxEntries) return std::nullopt; S.Faults.resize(Count);
    for (auto& F : S.Faults) { std::uint8_t Access = 0, Reason = 0; if (!R.Get(F.Sequence) || !R.Get(F.VirtualTime) || !GetAddress(R, F.Device) || !R.Get(F.Domain) || !R.Get(F.Iova) || !R.Get(F.Length) || !R.Get(Access) || !R.Get(Reason)) return std::nullopt; F.Access = static_cast<DmaAccess>(Access); F.Reason = static_cast<IommuFaultReason>(Reason); }
    if (R.Position != R.Bytes.size()) return std::nullopt; Iommu Validator(S.Seed); if (!Validator.Restore(S)) return std::nullopt; return S;
}

bool Iommu::RestoreSerialized(std::span<const std::uint8_t> Bytes) { const auto S = Deserialize(Bytes); return S && Restore(*S); }

} // namespace Kevlar::Hardware
