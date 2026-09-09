#pragma once

#include "../coverage/edge_coverage.h"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Kevlar::Fuzz {

enum class InputKind : std::uint8_t {
    DeviceControl,
    InternalDeviceControl,
    Irp,
};

struct FuzzInput {
    InputKind Kind = InputKind::DeviceControl;
    std::uint32_t IoctlCode = 0;
    std::uint8_t MajorFunction = 0x0e;
    std::uint8_t MinorFunction = 0;
    std::uint32_t OutputBufferLength = 0;
    std::vector<std::uint8_t> Buffer;

    bool operator==(const FuzzInput&) const = default;
};

enum class ExecutionOutcome : std::uint8_t {
    Completed,
    Crash,
    Hang,
    Rejected,
};

struct CrashSignature {
    std::uint32_t ExceptionCode = 0;
    Coverage::ModuleLocation Fault;
    std::vector<Coverage::ModuleLocation> Stack;

    auto operator<=>(const CrashSignature&) const = default;
};

struct HangSignature {
    Coverage::ModuleLocation LastProgress;
    std::string WaitClass;
    std::uint64_t ProgressToken = 0;

    auto operator<=>(const HangSignature&) const = default;
};

struct ExecutionResult {
    ExecutionOutcome Outcome = ExecutionOutcome::Completed;
    Coverage::CoverageSnapshot Coverage;
    std::optional<CrashSignature> Crash;
    std::optional<HangSignature> Hang;

    bool operator==(const ExecutionResult&) const = default;
};

[[nodiscard]] std::uint64_t StableInputId(const FuzzInput& Input) noexcept;
[[nodiscard]] std::uint64_t StableCrashId(const CrashSignature& Signature) noexcept;
[[nodiscard]] std::uint64_t StableHangId(const HangSignature& Signature) noexcept;

enum class MutationStrategy : std::uint8_t {
    FlipBit,
    ReplaceByte,
    InterestingInteger,
    InsertBytes,
    EraseBytes,
    Splice,
    DictionaryOverwrite,
    MutateIoctlCode,
    MutateIrpFunction,
};

struct MutationRecord {
    MutationStrategy Strategy = MutationStrategy::FlipBit;
    std::uint64_t Offset = 0;
    std::uint64_t Length = 0;
    std::uint64_t Value = 0;
    std::vector<std::uint8_t> Payload;

    bool operator==(const MutationRecord&) const = default;
};

struct MutatedInput {
    FuzzInput Input;
    MutationRecord Mutation;

    bool operator==(const MutatedInput&) const = default;
};

struct MutatorSnapshot {
    std::uint64_t Seed = 0;
    std::uint64_t State = 0;
    std::size_t MaximumInputBytes = 0;
    std::vector<std::vector<std::uint8_t>> Dictionary;

    bool operator==(const MutatorSnapshot&) const = default;
};

class IoMutator final {
public:
    explicit IoMutator(
        std::uint64_t Seed,
        std::size_t MaximumInputBytes = 1u << 20,
        std::vector<std::vector<std::uint8_t>> Dictionary = {});

    IoMutator(const IoMutator&) = delete;
    IoMutator& operator=(const IoMutator&) = delete;

    [[nodiscard]] MutatedInput Mutate(
        const FuzzInput& Base,
        std::span<const FuzzInput> Donors = {});
    [[nodiscard]] MutatorSnapshot Snapshot() const;
    [[nodiscard]] bool Restore(const MutatorSnapshot& State);

    [[nodiscard]] static std::optional<FuzzInput> Replay(
        const FuzzInput& Base,
        const MutationRecord& Mutation,
        std::size_t MaximumInputBytes = 1u << 20);

private:
    [[nodiscard]] std::uint64_t Next() noexcept;
    [[nodiscard]] std::size_t Bounded(std::size_t Limit) noexcept;
    [[nodiscard]] MutationStrategy ChooseStrategy(
        const FuzzInput& Base,
        std::span<const FuzzInput> Donors) noexcept;

    mutable std::mutex Mutex_;
    std::uint64_t Seed_ = 0;
    std::uint64_t State_ = 0;
    std::size_t MaximumInputBytes_ = 0;
    std::vector<std::vector<std::uint8_t>> Dictionary_;
};

struct CorpusEntry {
    FuzzInput Input;
    ExecutionResult Result;
    std::uint64_t Sequence = 0;

    bool operator==(const CorpusEntry&) const = default;
};

struct CorpusSnapshot {
    std::vector<CorpusEntry> Entries;
    std::uint64_t NextSequence = 1;

    bool operator==(const CorpusSnapshot&) const = default;
};

struct AdmissionDecision {
    bool Admitted = false;
    bool NewCoverage = false;
    bool NewCrash = false;
    bool NewHang = false;
    bool Valid = true;
    std::size_t NewEdgeCount = 0;

    bool operator==(const AdmissionDecision&) const = default;
};

class FuzzCorpus final {
public:
    FuzzCorpus() = default;
    FuzzCorpus(const FuzzCorpus&) = delete;
    FuzzCorpus& operator=(const FuzzCorpus&) = delete;

    [[nodiscard]] AdmissionDecision Admit(const FuzzInput& Input, const ExecutionResult& Result);
    [[nodiscard]] std::vector<CorpusEntry> Entries() const;
    [[nodiscard]] std::size_t Size() const;
    [[nodiscard]] CorpusSnapshot Snapshot() const;
    [[nodiscard]] bool Restore(const CorpusSnapshot& State);
    [[nodiscard]] std::size_t Minimize();
    void Clear();

private:
    mutable std::mutex Mutex_;
    CorpusSnapshot State_;
};

using ExecutionCallback = std::function<ExecutionResult(const FuzzInput&, std::uint64_t)>;

struct CampaignIteration {
    std::uint64_t Iteration = 0;
    std::uint64_t SourceInputId = 0;
    MutatedInput Candidate;
    ExecutionResult Result;
    AdmissionDecision Admission;

    bool operator==(const CampaignIteration&) const = default;
};

struct CampaignReport {
    std::uint64_t Seed = 0;
    std::vector<CampaignIteration> Iterations;

    bool operator==(const CampaignReport&) const = default;
};

struct CampaignSnapshot {
    std::uint64_t Seed = 0;
    std::uint64_t NextIteration = 0;
    std::vector<FuzzInput> Seeds;
    MutatorSnapshot Mutator;
    CorpusSnapshot Corpus;

    bool operator==(const CampaignSnapshot&) const = default;
};

class IoFuzzCampaign final {
public:
    explicit IoFuzzCampaign(
        std::uint64_t Seed,
        std::vector<FuzzInput> Seeds,
        std::size_t MaximumInputBytes = 1u << 20,
        std::vector<std::vector<std::uint8_t>> Dictionary = {});

    IoFuzzCampaign(const IoFuzzCampaign&) = delete;
    IoFuzzCampaign& operator=(const IoFuzzCampaign&) = delete;

    [[nodiscard]] CampaignReport Run(std::size_t Iterations, const ExecutionCallback& Execute);
    [[nodiscard]] CampaignSnapshot Snapshot() const;
    [[nodiscard]] bool Restore(const CampaignSnapshot& State);
    [[nodiscard]] std::vector<CorpusEntry> CorpusEntries() const;

private:
    mutable std::mutex Mutex_;
    std::uint64_t Seed_ = 0;
    std::uint64_t NextIteration_ = 0;
    std::vector<FuzzInput> Seeds_;
    IoMutator Mutator_;
    FuzzCorpus Corpus_;
};

} // namespace Kevlar::Fuzz
