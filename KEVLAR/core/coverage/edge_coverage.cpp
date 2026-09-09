#include "edge_coverage.h"

#include <limits>
#include <mutex>
#include <set>

namespace Kevlar::Coverage {
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

} // namespace Kevlar::Coverage
