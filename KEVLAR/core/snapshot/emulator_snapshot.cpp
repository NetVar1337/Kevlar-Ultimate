#include "emulator_snapshot.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <type_traits>

namespace Kevlar::Snapshot {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'K', 'S', 'N', 'P'};
constexpr std::uint32_t kFormatVersion = 1;
constexpr std::size_t kHeaderSize = 4 + 4 + 8 + 32;
constexpr std::array<std::uint32_t, 64> kShaConstants{
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t RotateRight(std::uint32_t Value, unsigned Count) noexcept {
    return (Value >> Count) | (Value << (32 - Count));
}

void TransformSha(std::array<std::uint32_t, 8>& State, const std::uint8_t* Block) noexcept {
    std::array<std::uint32_t, 64> Words{};
    for (std::size_t I = 0; I != 16; ++I) {
        Words[I] = static_cast<std::uint32_t>(Block[I * 4]) << 24 |
                   static_cast<std::uint32_t>(Block[I * 4 + 1]) << 16 |
                   static_cast<std::uint32_t>(Block[I * 4 + 2]) << 8 |
                   static_cast<std::uint32_t>(Block[I * 4 + 3]);
    }
    for (std::size_t I = 16; I != Words.size(); ++I) {
        const auto S0 = RotateRight(Words[I - 15], 7) ^ RotateRight(Words[I - 15], 18) ^ (Words[I - 15] >> 3);
        const auto S1 = RotateRight(Words[I - 2], 17) ^ RotateRight(Words[I - 2], 19) ^ (Words[I - 2] >> 10);
        Words[I] = Words[I - 16] + S0 + Words[I - 7] + S1;
    }

    auto A = State[0]; auto B = State[1]; auto C = State[2]; auto D = State[3];
    auto E = State[4]; auto F = State[5]; auto G = State[6]; auto H = State[7];
    for (std::size_t I = 0; I != Words.size(); ++I) {
        const auto S1 = RotateRight(E, 6) ^ RotateRight(E, 11) ^ RotateRight(E, 25);
        const auto Choice = (E & F) ^ (~E & G);
        const auto T1 = H + S1 + Choice + kShaConstants[I] + Words[I];
        const auto S0 = RotateRight(A, 2) ^ RotateRight(A, 13) ^ RotateRight(A, 22);
        const auto Majority = (A & B) ^ (A & C) ^ (B & C);
        const auto T2 = S0 + Majority;
        H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
    }
    State[0] += A; State[1] += B; State[2] += C; State[3] += D;
    State[4] += E; State[5] += F; State[6] += G; State[7] += H;
}

class Writer final {
public:
    template <typename T>
    void Put(T Value) {
        using Unsigned = std::make_unsigned_t<T>;
        const auto Bits = static_cast<Unsigned>(Value);
        for (std::size_t I = 0; I != sizeof(T); ++I) {
            Bytes.push_back(static_cast<std::uint8_t>(Bits >> (I * 8)));
        }
    }

    void Raw(std::span<const std::uint8_t> Value) {
        Bytes.insert(Bytes.end(), Value.begin(), Value.end());
    }

    std::vector<std::uint8_t> Bytes;
};

class Reader final {
public:
    explicit Reader(std::span<const std::uint8_t> Bytes) : Bytes_(Bytes) {}

    template <typename T>
    bool Get(T& Value) noexcept {
        if (Remaining() < sizeof(T)) return false;
        using Unsigned = std::make_unsigned_t<T>;
        Unsigned Bits = 0;
        for (std::size_t I = 0; I != sizeof(T); ++I) {
            Bits |= static_cast<Unsigned>(Bytes_[Position_++]) << (I * 8);
        }
        Value = static_cast<T>(Bits);
        return true;
    }

    bool Raw(std::span<std::uint8_t> Destination) noexcept {
        if (Remaining() < Destination.size()) return false;
        if (!Destination.empty()) {
            std::memcpy(Destination.data(), Bytes_.data() + Position_, Destination.size());
        }
        Position_ += Destination.size();
        return true;
    }

    [[nodiscard]] std::size_t Remaining() const noexcept { return Bytes_.size() - Position_; }
    [[nodiscard]] bool Finished() const noexcept { return Position_ == Bytes_.size(); }

private:
    std::span<const std::uint8_t> Bytes_;
    std::size_t Position_ = 0;
};

bool ValidRange(std::uint64_t Base, std::uint64_t Size) noexcept {
    return Size != 0 && Base <= std::numeric_limits<std::uint64_t>::max() - (Size - 1);
}

bool Overlap(std::uint64_t LeftBase, std::uint64_t LeftSize,
             std::uint64_t RightBase, std::uint64_t RightSize) noexcept {
    return LeftBase < RightBase + RightSize && RightBase < LeftBase + LeftSize;
}

bool ValidBlob(const StateBlob& Blob, const SnapshotLimits& Limits) noexcept {
    return Blob.Bytes.size() <= Limits.MaximumStateBlobBytes && HashBytes(Blob.Bytes) == Blob.Hash;
}

void PutBlob(Writer& Output, const StateBlob& Blob) {
    Output.Put<std::uint64_t>(Blob.Bytes.size());
    Output.Raw(Blob.Hash);
    Output.Raw(Blob.Bytes);
}

SnapshotError GetBlob(Reader& Input, StateBlob& Blob, const SnapshotLimits& Limits) {
    std::uint64_t Size = 0;
    if (!Input.Get(Size)) return SnapshotError::Truncated;
    if (Size > Limits.MaximumStateBlobBytes || Size > Input.Remaining()) return SnapshotError::LimitExceeded;
    if (!Input.Raw(Blob.Hash)) return SnapshotError::Truncated;
    if (Size > Input.Remaining() || Size > std::numeric_limits<std::size_t>::max()) return SnapshotError::Truncated;
    Blob.Bytes.resize(static_cast<std::size_t>(Size));
    if (!Input.Raw(Blob.Bytes)) return SnapshotError::Truncated;
    return HashBytes(Blob.Bytes) == Blob.Hash ? SnapshotError::None : SnapshotError::HashMismatch;
}

} // namespace

SnapshotHash HashBytes(std::span<const std::uint8_t> Bytes) noexcept {
    std::array<std::uint32_t, 8> State{
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

    std::size_t Offset = 0;
    while (Bytes.size() - Offset >= 64) {
        TransformSha(State, Bytes.data() + Offset);
        Offset += 64;
    }

    std::array<std::uint8_t, 128> Tail{};
    const auto TailSize = Bytes.size() - Offset;
    if (TailSize != 0) std::memcpy(Tail.data(), Bytes.data() + Offset, TailSize);
    Tail[TailSize] = 0x80;
    const auto Blocks = TailSize < 56 ? 1u : 2u;
    const auto BitLength = static_cast<std::uint64_t>(Bytes.size()) * 8;
    const auto LengthOffset = Blocks * 64 - 8;
    for (std::size_t I = 0; I != 8; ++I) {
        Tail[LengthOffset + I] = static_cast<std::uint8_t>(BitLength >> ((7 - I) * 8));
    }
    TransformSha(State, Tail.data());
    if (Blocks == 2) TransformSha(State, Tail.data() + 64);

    SnapshotHash Result{};
    for (std::size_t I = 0; I != State.size(); ++I) {
        Result[I * 4] = static_cast<std::uint8_t>(State[I] >> 24);
        Result[I * 4 + 1] = static_cast<std::uint8_t>(State[I] >> 16);
        Result[I * 4 + 2] = static_cast<std::uint8_t>(State[I] >> 8);
        Result[I * 4 + 3] = static_cast<std::uint8_t>(State[I]);
    }
    return Result;
}

EmulatorSnapshot::EmulatorSnapshot() {
    Image_.CpuState = MakeBlob({});
    Image_.SchedulerState = MakeBlob({});
    Image_.ObjectState = MakeBlob({});
    Image_.DeviceState = MakeBlob({});
}

EmulatorSnapshot::EmulatorSnapshot(std::uint64_t Seed, std::uint64_t LogicalTime)
    : EmulatorSnapshot() {
    Image_.Seed = Seed;
    Image_.LogicalTime = LogicalTime;
}

StateBlob EmulatorSnapshot::MakeBlob(std::span<const std::uint8_t> Bytes) {
    StateBlob Result;
    Result.Bytes.assign(Bytes.begin(), Bytes.end());
    Result.Hash = HashBytes(Result.Bytes);
    return Result;
}

void EmulatorSnapshot::SetSeed(std::uint64_t Seed) {
    std::scoped_lock Lock(Mutex_);
    Image_.Seed = Seed;
}

void EmulatorSnapshot::SetLogicalTime(std::uint64_t LogicalTime) {
    std::scoped_lock Lock(Mutex_);
    Image_.LogicalTime = LogicalTime;
}

void EmulatorSnapshot::SetCpuState(std::span<const std::uint8_t> Bytes) {
    auto Blob = MakeBlob(Bytes);
    std::scoped_lock Lock(Mutex_);
    Image_.CpuState = std::move(Blob);
}

void EmulatorSnapshot::SetSchedulerState(std::span<const std::uint8_t> Bytes) {
    auto Blob = MakeBlob(Bytes);
    std::scoped_lock Lock(Mutex_);
    Image_.SchedulerState = std::move(Blob);
}

void EmulatorSnapshot::SetObjectState(std::span<const std::uint8_t> Bytes) {
    auto Blob = MakeBlob(Bytes);
    std::scoped_lock Lock(Mutex_);
    Image_.ObjectState = std::move(Blob);
}

void EmulatorSnapshot::SetDeviceState(std::span<const std::uint8_t> Bytes) {
    auto Blob = MakeBlob(Bytes);
    std::scoped_lock Lock(Mutex_);
    Image_.DeviceState = std::move(Blob);
}

SnapshotError EmulatorSnapshot::AddMappedMemory(
    std::uint64_t GuestBase,
    std::uint64_t Size,
    std::uint32_t Permissions,
    const AddressValidator& Validate,
    const MemoryReader& Read) {
    if (!Validate || !Read || !ValidRange(GuestBase, Size) || Permissions == 0 || (Permissions & ~7u) != 0) {
        return SnapshotError::InvalidArgument;
    }
    const auto PageCount64 = (Size - 1) / kSnapshotPageSize + 1;
    if (PageCount64 > std::numeric_limits<std::uint32_t>::max()) return SnapshotError::LimitExceeded;

    std::vector<DeduplicatedPage> ReadPages;
    ReadPages.reserve(static_cast<std::size_t>(PageCount64));
    std::uint64_t Completed = 0;
    while (Completed < Size) {
        const auto Remaining = Size - Completed;
        const auto Chunk = static_cast<std::size_t>(std::min<std::uint64_t>(Remaining, kSnapshotPageSize));
        const auto Address = GuestBase + Completed;
        if (!Validate(Address, Chunk)) return SnapshotError::InvalidAddress;
        DeduplicatedPage Page;
        if (!Read(Address, std::span<std::uint8_t>(Page.Bytes.data(), Chunk))) return SnapshotError::ReadFailed;
        Page.Hash = HashBytes(Page.Bytes);
        ReadPages.push_back(std::move(Page));
        Completed += Chunk;
    }

    std::scoped_lock Lock(Mutex_);
    for (const auto& Existing : Image_.Mappings) {
        if (Overlap(Existing.GuestBase, Existing.Size, GuestBase, Size)) return SnapshotError::OverlappingMapping;
    }

    MemoryMapping Mapping{GuestBase, Size, Permissions, {}};
    Mapping.PageIndices.reserve(ReadPages.size());
    for (const auto& Page : ReadPages) {
        const auto Existing = std::find_if(Image_.Pages.begin(), Image_.Pages.end(), [&](const DeduplicatedPage& Candidate) {
            return Candidate.Hash == Page.Hash && Candidate.Bytes == Page.Bytes;
        });
        if (Existing != Image_.Pages.end()) {
            Mapping.PageIndices.push_back(static_cast<std::uint32_t>(Existing - Image_.Pages.begin()));
        } else {
            if (Image_.Pages.size() == std::numeric_limits<std::uint32_t>::max()) return SnapshotError::LimitExceeded;
            Mapping.PageIndices.push_back(static_cast<std::uint32_t>(Image_.Pages.size()));
            Image_.Pages.push_back(Page);
        }
    }
    Image_.Mappings.push_back(std::move(Mapping));
    std::sort(Image_.Mappings.begin(), Image_.Mappings.end(), [](const MemoryMapping& Left, const MemoryMapping& Right) {
        return Left.GuestBase < Right.GuestBase;
    });
    return SnapshotError::None;
}

SnapshotError EmulatorSnapshot::RestoreMappedMemory(
    const AddressValidator& Validate,
    const MemoryWriter& Write) const {
    if (!Validate || !Write) return SnapshotError::InvalidArgument;
    const auto Image = Snapshot();
    if (!Verify(Image)) return SnapshotError::CorruptData;

    for (const auto& Mapping : Image.Mappings) {
        std::uint64_t Completed = 0;
        while (Completed < Mapping.Size) {
            const auto Chunk = static_cast<std::size_t>(std::min<std::uint64_t>(Mapping.Size - Completed, kSnapshotPageSize));
            if (!Validate(Mapping.GuestBase + Completed, Chunk)) return SnapshotError::InvalidAddress;
            Completed += Chunk;
        }
    }
    for (const auto& Mapping : Image.Mappings) {
        std::uint64_t Completed = 0;
        for (const auto PageIndex : Mapping.PageIndices) {
            const auto Chunk = static_cast<std::size_t>(std::min<std::uint64_t>(Mapping.Size - Completed, kSnapshotPageSize));
            const auto& Page = Image.Pages[PageIndex];
            if (!Write(Mapping.GuestBase + Completed, std::span<const std::uint8_t>(Page.Bytes.data(), Chunk))) {
                return SnapshotError::WriteFailed;
            }
            Completed += Chunk;
        }
    }
    return SnapshotError::None;
}

SnapshotImage EmulatorSnapshot::Snapshot() const {
    std::scoped_lock Lock(Mutex_);
    return Image_;
}

SnapshotError EmulatorSnapshot::Restore(const SnapshotImage& Image) {
    if (!Verify(Image)) return SnapshotError::CorruptData;
    std::scoped_lock Lock(Mutex_);
    Image_ = Image;
    return SnapshotError::None;
}

bool EmulatorSnapshot::Verify(const SnapshotImage& Image, const SnapshotLimits& Limits) noexcept {
    if (!ValidBlob(Image.CpuState, Limits) || !ValidBlob(Image.SchedulerState, Limits) ||
        !ValidBlob(Image.ObjectState, Limits) || !ValidBlob(Image.DeviceState, Limits) ||
        Image.Pages.size() > Limits.MaximumPages || Image.Mappings.size() > Limits.MaximumMappings) return false;

    for (std::size_t I = 0; I != Image.Pages.size(); ++I) {
        const auto& Page = Image.Pages[I];
        if (HashBytes(Page.Bytes) != Page.Hash) return false;
        for (std::size_t J = 0; J != I; ++J) {
            if (Image.Pages[J].Hash == Page.Hash && Image.Pages[J].Bytes == Page.Bytes) return false;
        }
    }
    std::uint64_t PreviousEnd = 0;
    bool HavePrevious = false;
    for (const auto& Mapping : Image.Mappings) {
        if (!ValidRange(Mapping.GuestBase, Mapping.Size) || Mapping.Permissions == 0 ||
            (Mapping.Permissions & ~7u) != 0) return false;
        const auto ExpectedPages = (Mapping.Size - 1) / kSnapshotPageSize + 1;
        if (ExpectedPages != Mapping.PageIndices.size()) return false;
        if (HavePrevious && Mapping.GuestBase < PreviousEnd) return false;
        PreviousEnd = Mapping.GuestBase + Mapping.Size;
        HavePrevious = true;
        for (const auto Index : Mapping.PageIndices) if (Index >= Image.Pages.size()) return false;
    }
    return true;
}

std::vector<std::uint8_t> EmulatorSnapshot::Serialize(const SnapshotImage& Image) {
    if (!Verify(Image)) return {};
    Writer Payload;
    Payload.Put(Image.Seed);
    Payload.Put(Image.LogicalTime);
    PutBlob(Payload, Image.CpuState);
    Payload.Put<std::uint32_t>(static_cast<std::uint32_t>(Image.Pages.size()));
    for (const auto& Page : Image.Pages) {
        Payload.Raw(Page.Hash);
        Payload.Raw(Page.Bytes);
    }
    Payload.Put<std::uint32_t>(static_cast<std::uint32_t>(Image.Mappings.size()));
    for (const auto& Mapping : Image.Mappings) {
        Payload.Put(Mapping.GuestBase);
        Payload.Put(Mapping.Size);
        Payload.Put(Mapping.Permissions);
        Payload.Put<std::uint32_t>(static_cast<std::uint32_t>(Mapping.PageIndices.size()));
        for (const auto PageIndex : Mapping.PageIndices) Payload.Put(PageIndex);
    }
    PutBlob(Payload, Image.SchedulerState);
    PutBlob(Payload, Image.ObjectState);
    PutBlob(Payload, Image.DeviceState);

    Writer Output;
    Output.Raw(kMagic);
    Output.Put(kFormatVersion);
    Output.Put<std::uint64_t>(Payload.Bytes.size());
    Output.Raw(HashBytes(Payload.Bytes));
    Output.Raw(Payload.Bytes);
    return std::move(Output.Bytes);
}

std::vector<std::uint8_t> EmulatorSnapshot::Serialize() const {
    return Serialize(Snapshot());
}

SnapshotLoadResult EmulatorSnapshot::Deserialize(
    std::span<const std::uint8_t> Bytes,
    const SnapshotLimits& Limits) {
    if (Bytes.size() > Limits.MaximumSerializedBytes) return {SnapshotError::LimitExceeded, std::nullopt};
    if (Bytes.size() < kHeaderSize) return {SnapshotError::Truncated, std::nullopt};

    Reader Header(Bytes);
    std::array<std::uint8_t, 4> Magic{};
    std::uint32_t Version = 0;
    std::uint64_t PayloadSize = 0;
    SnapshotHash PayloadHash{};
    if (!Header.Raw(Magic) || !Header.Get(Version) || !Header.Get(PayloadSize) || !Header.Raw(PayloadHash)) {
        return {SnapshotError::Truncated, std::nullopt};
    }
    if (Magic != kMagic) return {SnapshotError::BadMagic, std::nullopt};
    if (Version != kFormatVersion) return {SnapshotError::UnsupportedVersion, std::nullopt};
    if (PayloadSize != Header.Remaining()) return {SnapshotError::SizeMismatch, std::nullopt};
    const auto Payload = Bytes.subspan(kHeaderSize);
    if (HashBytes(Payload) != PayloadHash) return {SnapshotError::HashMismatch, std::nullopt};

    Reader Input(Payload);
    SnapshotImage Image;
    if (!Input.Get(Image.Seed) || !Input.Get(Image.LogicalTime)) return {SnapshotError::Truncated, std::nullopt};
    if (const auto Error = GetBlob(Input, Image.CpuState, Limits); Error != SnapshotError::None) return {Error, std::nullopt};

    std::uint32_t Count = 0;
    if (!Input.Get(Count)) return {SnapshotError::Truncated, std::nullopt};
    if (Count > Limits.MaximumPages || Count > Input.Remaining() / (32 + kSnapshotPageSize)) {
        return {SnapshotError::LimitExceeded, std::nullopt};
    }
    Image.Pages.resize(Count);
    for (auto& Page : Image.Pages) {
        if (!Input.Raw(Page.Hash) || !Input.Raw(Page.Bytes)) return {SnapshotError::Truncated, std::nullopt};
        if (HashBytes(Page.Bytes) != Page.Hash) return {SnapshotError::HashMismatch, std::nullopt};
    }

    if (!Input.Get(Count)) return {SnapshotError::Truncated, std::nullopt};
    if (Count > Limits.MaximumMappings || Count > Input.Remaining() / 24) return {SnapshotError::LimitExceeded, std::nullopt};
    Image.Mappings.resize(Count);
    for (auto& Mapping : Image.Mappings) {
        std::uint32_t PageCount = 0;
        if (!Input.Get(Mapping.GuestBase) || !Input.Get(Mapping.Size) ||
            !Input.Get(Mapping.Permissions) || !Input.Get(PageCount)) return {SnapshotError::Truncated, std::nullopt};
        if (PageCount > Limits.MaximumPages || PageCount > Input.Remaining() / sizeof(std::uint32_t)) {
            return {SnapshotError::LimitExceeded, std::nullopt};
        }
        Mapping.PageIndices.resize(PageCount);
        for (auto& Index : Mapping.PageIndices) if (!Input.Get(Index)) return {SnapshotError::Truncated, std::nullopt};
    }

    if (const auto Error = GetBlob(Input, Image.SchedulerState, Limits); Error != SnapshotError::None) return {Error, std::nullopt};
    if (const auto Error = GetBlob(Input, Image.ObjectState, Limits); Error != SnapshotError::None) return {Error, std::nullopt};
    if (const auto Error = GetBlob(Input, Image.DeviceState, Limits); Error != SnapshotError::None) return {Error, std::nullopt};
    if (!Input.Finished()) return {SnapshotError::SizeMismatch, std::nullopt};
    if (!Verify(Image, Limits)) return {SnapshotError::CorruptData, std::nullopt};
    return {SnapshotError::None, std::move(Image)};
}

SnapshotError EmulatorSnapshot::RestoreSerialized(
    std::span<const std::uint8_t> Bytes,
    const SnapshotLimits& Limits) {
    auto Loaded = Deserialize(Bytes, Limits);
    if (!Loaded.Ok()) return Loaded.Error;
    return Restore(*Loaded.Image);
}

} // namespace Kevlar::Snapshot
