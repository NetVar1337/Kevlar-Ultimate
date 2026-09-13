#include <algorithm>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>
#include "edge_coverage.h"

#include <limits>
#include <mutex>
#include <set>

namespace Kevlar::Coverage {

// Global pointer set by the engine; consumed post-run by the CLI.
EdgeCoverage* g_EdgeCoverage = nullptr;
namespace {

constexpr std::size_t kMaximumModuleIdentifierBytes = 4096;
constexpr std::uint64_t kFnvOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnvPrime = 1099511628211ull;

void HashByte(std::uint64_t& Hash, std::uint8_t Value) noexcept {
    Hash ^= Value;
    Hash *= kFnvPrime;
}

void HashU64(std::uint64_t& Hash, std::uint64_t Value) noexcept {
    for (std::size_t I = 0; I != sizeof(Value); ++I) {
        HashByte(Hash, static_cast<std::uint8_t>(Value >> (I * 8)));
    }
}

void HashLocation(std::uint64_t& Hash, const ModuleLocation& Location) noexcept {
    HashU64(Hash, Location.Module.size());
    for (const auto Character : Location.Module) HashByte(Hash, static_cast<std::uint8_t>(Character));
    HashU64(Hash, Location.Rva);
}

} // namespace

bool EdgeCoverage::IsValid(const ModuleLocation& Location) noexcept {
    return !Location.Module.empty() && Location.Module.size() <= kMaximumModuleIdentifierBytes;
}

bool EdgeCoverage::Record(const ModuleLocation& From, const ModuleLocation& To) {
    if (!IsValid(From) || !IsValid(To)) return false;
    const Edge Key{From, To};
    std::unique_lock Lock(Mutex_);
    const auto [Iterator, Inserted] = Edges_.try_emplace(Key, 0);
    if (Iterator->second != std::numeric_limits<std::uint64_t>::max()) ++Iterator->second;
    return Inserted;
}

std::optional<bool> EdgeCoverage::RecordAbsolute(
    std::uint64_t FromAddress,
    std::uint64_t ToAddress,
    const ModuleResolver& Resolve) {
    if (!Resolve) return std::nullopt;
    const auto From = Resolve(FromAddress);
    const auto To = Resolve(ToAddress);
    if (!From || !To || !IsValid(*From) || !IsValid(*To)) return std::nullopt;
    return Record(*From, *To);
}

bool EdgeCoverage::Contains(const Edge& Key) const {
    std::shared_lock Lock(Mutex_);
    return Edges_.contains(Key);
}

std::uint64_t EdgeCoverage::HitCount(const Edge& Key) const {
    std::shared_lock Lock(Mutex_);
    const auto Iterator = Edges_.find(Key);
    return Iterator == Edges_.end() ? 0 : Iterator->second;
}

std::size_t EdgeCoverage::EdgeCount() const {
    std::shared_lock Lock(Mutex_);
    return Edges_.size();
}

std::uint64_t EdgeCoverage::TotalHits() const {
    std::shared_lock Lock(Mutex_);
    std::uint64_t Total = 0;
    for (const auto& [Key, Hits] : Edges_) {
        (void)Key;
        if (Hits > std::numeric_limits<std::uint64_t>::max() - Total) return std::numeric_limits<std::uint64_t>::max();
        Total += Hits;
    }
    return Total;
}

bool EdgeCoverage::Empty() const {
    std::shared_lock Lock(Mutex_);
    return Edges_.empty();
}

void EdgeCoverage::Clear() {
    std::unique_lock Lock(Mutex_);
    Edges_.clear();
}

std::size_t EdgeCoverage::Merge(const CoverageSnapshot& Other) {
    std::map<Edge, std::uint64_t> Candidate;
    for (const auto& Record : Other.Edges) {
        if (!IsValid(Record.Key.From) || !IsValid(Record.Key.To) || Record.Hits == 0 || Candidate.contains(Record.Key)) {
            return 0;
        }
        Candidate.emplace(Record.Key, Record.Hits);
    }

    std::unique_lock Lock(Mutex_);
    std::size_t Added = 0;
    for (const auto& [Key, Hits] : Candidate) {
        const auto [Iterator, Inserted] = Edges_.try_emplace(Key, 0);
        if (Inserted) ++Added;
        if (Hits > std::numeric_limits<std::uint64_t>::max() - Iterator->second) {
            Iterator->second = std::numeric_limits<std::uint64_t>::max();
        } else {
            Iterator->second += Hits;
        }
    }
    return Added;
}

CoverageSnapshot EdgeCoverage::Snapshot() const {
    std::shared_lock Lock(Mutex_);
    CoverageSnapshot Result;
    Result.Edges.reserve(Edges_.size());
    for (const auto& [Key, Hits] : Edges_) Result.Edges.push_back({Key, Hits});
    return Result;
}

bool EdgeCoverage::Restore(const CoverageSnapshot& State) {
    std::map<Edge, std::uint64_t> Candidate;
    for (const auto& Record : State.Edges) {
        if (!IsValid(Record.Key.From) || !IsValid(Record.Key.To) || Record.Hits == 0 ||
            !Candidate.emplace(Record.Key, Record.Hits).second) return false;
    }
    std::unique_lock Lock(Mutex_);
    Edges_ = std::move(Candidate);
    return true;
}

std::vector<Edge> EdgeCoverage::NewEdgesComparedTo(const CoverageSnapshot& Baseline) const {
    std::set<Edge> Known;
    for (const auto& Record : Baseline.Edges) {
        if (Record.Hits != 0 && IsValid(Record.Key.From) && IsValid(Record.Key.To)) Known.insert(Record.Key);
    }
    std::shared_lock Lock(Mutex_);
    std::vector<Edge> Result;
    for (const auto& [Key, Hits] : Edges_) {
        (void)Hits;
        if (!Known.contains(Key)) Result.push_back(Key);
    }
    return Result;
}

std::uint64_t EdgeCoverage::StableEdgeId(const Edge& Key) noexcept {
    std::uint64_t Hash = kFnvOffset;
    HashLocation(Hash, Key.From);
    HashByte(Hash, 0xff);
    HashLocation(Hash, Key.To);
    return Hash;
}


bool EdgeCoverage::WriteBitmap(const std::string& Path) const {
    // 65536-byte AFL shared-memory bitmap: byte[StableEdgeId(e) % 65536] = min(hits, 255).
    std::uint8_t Bitmap[65536];
    std::memset(Bitmap, 0, sizeof(Bitmap));

    {
        std::shared_lock Lock(Mutex_);
        for (const auto& [Key, Hits] : Edges_) {
            const std::size_t Slot = static_cast<std::size_t>(StableEdgeId(Key) % 65536);
            const std::uint8_t Val = (Hits >= 255) ? 255u : static_cast<std::uint8_t>(Hits);
            if (Val > Bitmap[Slot]) Bitmap[Slot] = Val;
        }
    }

    std::FILE* F = nullptr;
    if (fopen_s(&F, Path.c_str(), "wb") != 0 || !F) return false;
    const bool Ok = (std::fwrite(Bitmap, 1, sizeof(Bitmap), F) == sizeof(Bitmap));
    std::fclose(F);
    return Ok;
}

bool EdgeCoverage::SaveSnapshot(const std::string& Path) const {
    std::ofstream Out(Path, std::ios::binary | std::ios::trunc);
    if (!Out) return false;

    std::shared_lock Lock(Mutex_);
    for (const auto& [Key, Hits] : Edges_) {
        Out << Key.From.Module << ':' << Key.From.Rva
            << "->" << Key.To.Module << ':' << Key.To.Rva
            << ':' << Hits << '\n';
        if (!Out) return false;
    }
    return true;
}

std::optional<CoverageSnapshot> EdgeCoverage::LoadSnapshot(const std::string& Path) {
    std::ifstream In(Path, std::ios::binary);
    if (!In) return std::nullopt;

    CoverageSnapshot Result;
    std::string Line;
    while (std::getline(In, Line)) {
        if (Line.empty()) continue;

        // Format: module_from:rva_from->module_to:rva_to:hits
        // Find the "->" separator by scanning from the left for the first occurrence.
        const auto ArrowPos = Line.find("->");
        if (ArrowPos == std::string::npos) return std::nullopt;

        const std::string FromPart = Line.substr(0, ArrowPos);
        const std::string ToPart   = Line.substr(ArrowPos + 2);

        // Split "module:rva" — the RVA is after the last ':'.
        auto SplitModuleRva = [](const std::string& Part, ModuleLocation& Out) -> bool {
            const auto ColonPos = Part.rfind(':');
            if (ColonPos == std::string::npos || ColonPos == 0) return false;
            Out.Module = Part.substr(0, ColonPos);
            const auto* Begin = Part.data() + ColonPos + 1;
            const auto* End   = Part.data() + Part.size();
            auto [Ptr, Ec] = std::from_chars(Begin, End, Out.Rva);
            return Ec == std::errc{} && Ptr == End;
        };

        // ToPart is "module_to:rva_to:hits" — split off trailing hits first.
        const auto HitsColonPos = ToPart.rfind(':');
        if (HitsColonPos == std::string::npos) return std::nullopt;
        const std::string ModuleRvaPart = ToPart.substr(0, HitsColonPos);
        const std::string HitsPart      = ToPart.substr(HitsColonPos + 1);

        EdgeRecord Rec;
        if (!SplitModuleRva(FromPart, Rec.Key.From)) return std::nullopt;
        if (!SplitModuleRva(ModuleRvaPart, Rec.Key.To)) return std::nullopt;
        if (!IsValid(Rec.Key.From) || !IsValid(Rec.Key.To)) return std::nullopt;

        const auto* HBegin = HitsPart.data();
        const auto* HEnd   = HitsPart.data() + HitsPart.size();
        auto [HPtr, HEc] = std::from_chars(HBegin, HEnd, Rec.Hits);
        if (HEc != std::errc{} || HPtr != HEnd || Rec.Hits == 0) return std::nullopt;

        Result.Edges.push_back(std::move(Rec));
    }
    return Result;
}

} // namespace Kevlar::Coverage
