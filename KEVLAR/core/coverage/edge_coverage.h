#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <cstdio>
#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace Kevlar::Coverage {

struct ModuleLocation {
    std::string Module;
    std::uint64_t Rva = 0;

    auto operator<=>(const ModuleLocation&) const = default;
};

struct Edge {
    ModuleLocation From;
    ModuleLocation To;

    auto operator<=>(const Edge&) const = default;
};

struct EdgeRecord {
    Edge Key;
    std::uint64_t Hits = 0;

    bool operator==(const EdgeRecord&) const = default;
};

struct CoverageSnapshot {
    std::vector<EdgeRecord> Edges;

    bool operator==(const CoverageSnapshot&) const = default;
};

using ModuleResolver = std::function<std::optional<ModuleLocation>(std::uint64_t)>;

class EdgeCoverage final {
public:
    EdgeCoverage() = default;
    EdgeCoverage(const EdgeCoverage&) = delete;
    EdgeCoverage& operator=(const EdgeCoverage&) = delete;

    [[nodiscard]] bool Record(const ModuleLocation& From, const ModuleLocation& To);
    [[nodiscard]] std::optional<bool> RecordAbsolute(
        std::uint64_t FromAddress,
        std::uint64_t ToAddress,
        const ModuleResolver& Resolve);
    [[nodiscard]] bool Contains(const Edge& Key) const;
    [[nodiscard]] std::uint64_t HitCount(const Edge& Key) const;
    [[nodiscard]] std::size_t EdgeCount() const;
    [[nodiscard]] std::uint64_t TotalHits() const;
    [[nodiscard]] bool Empty() const;

    void Clear();
    [[nodiscard]] std::vector<Edge> NewEdgesComparedTo(const CoverageSnapshot& Baseline) const;

    [[nodiscard]] bool WriteBitmap(const std::string& Path) const;
    [[nodiscard]] bool SaveSnapshot(const std::string& Path) const;
    [[nodiscard]] static std::optional<CoverageSnapshot> LoadSnapshot(const std::string& Path);

    [[nodiscard]] static bool IsValid(const ModuleLocation& Location) noexcept;
    [[nodiscard]] static std::uint64_t StableEdgeId(const Edge& Key) noexcept;

private:
    mutable std::shared_mutex Mutex_;
    std::map<Edge, std::uint64_t> Edges_;
};

// Global instance; set by the emulator loop, consumed by the CLI post-run.
extern EdgeCoverage* g_EdgeCoverage;

} // namespace Kevlar::Coverage
