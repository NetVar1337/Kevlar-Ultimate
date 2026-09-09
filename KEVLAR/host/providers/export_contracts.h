#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace Kevlar::Host::Contracts {

inline constexpr std::uint32_t StatusNotImplemented = 0xC0000002u;

enum class ReturnPolicy {
    NtStatus,
    Boolean,
    Pointer,
    Void,
    UnsignedInteger,
};

enum class BufferDirection {
    Out,
    InOut,
};

enum class UnknownExportPolicy {
    ReturnStatusNotImplemented,
    RejectCall,
};

enum class DiagnosticSeverity {
    Error,
    Warning,
    Information,
};

enum class DiagnosticCode {
    CatalogIo,
    JsonSyntax,
    DuplicateJsonKey,
    UnknownJsonKey,
    MissingField,
    TypeMismatch,
    OutOfRange,
    InvalidValue,
    DuplicateContract,
    DuplicateSideEffect,
    DuplicateOutputRule,
    UnknownExport,
    ArgumentCountMismatch,
    IrqlViolation,
    NullOutputBuffer,
    OutputBufferTooSmall,
    ResultWithoutCall,
};

struct Diagnostic {
    DiagnosticSeverity Severity = DiagnosticSeverity::Error;
    DiagnosticCode Code = DiagnosticCode::InvalidValue;
    std::string Path;
    std::string Module;
    std::string Name;
    std::optional<std::size_t> ArgumentIndex;
    std::string Message;
};

struct OutputBufferRule {
    std::uint8_t ArgumentIndex = 0;
    std::optional<std::uint8_t> LengthArgumentIndex;
    std::uint64_t MinimumSize = 0;
    BufferDirection Direction = BufferDirection::Out;
    bool Nullable = false;
    bool WritesOnSuccessOnly = true;
};

struct ExportContract {
    std::string Module;
    std::string Name;
    std::uint8_t ArgumentCount = 0;
    std::uint8_t IrqlCeiling = 0;
    ReturnPolicy Return = ReturnPolicy::NtStatus;
    std::vector<OutputBufferRule> OutputBuffers;
    std::vector<std::string> SideEffects;
};

struct RegistryLimits {
    std::size_t MaximumCatalogBytes = 1024 * 1024;
    std::size_t MaximumJsonDepth = 16;
    std::size_t MaximumJsonNodes = 65536;
    std::size_t MaximumContracts = 4096;
    std::size_t MaximumStringBytes = 256;
    std::size_t MaximumSideEffectsPerContract = 32;
    std::size_t MaximumOutputRulesPerContract = 16;
    std::uint8_t MaximumArguments = 32;
};

struct RegistryOptions {
    std::uint64_t Seed = 0;
    std::uint64_t InitialVirtualTimeTicks = 0;
    UnknownExportPolicy UnknownPolicy = UnknownExportPolicy::ReturnStatusNotImplemented;
    RegistryLimits Limits;
};

struct OperationResult {
    std::vector<Diagnostic> Diagnostics;
    std::size_t ContractsAdded = 0;

    [[nodiscard]] bool Ok() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept;
};

struct CallContext {
    std::vector<std::uint64_t> Arguments;
    std::uint8_t CurrentIrql = 0;
    std::uint64_t VirtualTimeTicks = 0;
};

enum class CallDisposition {
    InvokeProvider,
    ReturnValue,
    Reject,
};

struct CallValidation {
    CallDisposition Disposition = CallDisposition::Reject;
    std::uint64_t ReturnValue = 0;
    std::vector<Diagnostic> Diagnostics;

    [[nodiscard]] bool Ok() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept;
};

struct ResultRecord {
    bool Recorded = false;
    bool Successful = false;
    std::vector<Diagnostic> Diagnostics;

    [[nodiscard]] bool Ok() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept;
};

struct ContractCoverage {
    std::string Module;
    std::string Name;
    std::uint64_t ValidatedCalls = 0;
    std::uint64_t ValidationFailures = 0;
    std::uint64_t RecordedResults = 0;
    std::uint64_t SuccessfulResults = 0;
    std::optional<std::uint64_t> LastReturnValue;
    std::optional<std::uint64_t> LastVirtualTimeTicks;
};

struct UnknownExportCoverage {
    std::string Module;
    std::string Name;
    std::uint64_t Calls = 0;
};

struct CoverageStatistics {
    std::uint64_t Seed = 0;
    std::uint64_t InitialVirtualTimeTicks = 0;
    std::size_t TotalContracts = 0;
    std::size_t ExercisedContracts = 0;
    std::size_t UnexercisedContracts = 0;
    std::uint64_t ValidatedCalls = 0;
    std::uint64_t ValidationFailures = 0;
    std::uint64_t RecordedResults = 0;
    std::uint64_t SuccessfulResults = 0;
    std::uint64_t UnknownExportCalls = 0;
    std::vector<ContractCoverage> Contracts;
    std::vector<UnknownExportCoverage> UnknownExports;
};

class ContractRegistry final {
public:
    explicit ContractRegistry(RegistryOptions Options = {});

    // Catalog loading is transactional. A malformed catalog or a duplicate with
    // an existing registration leaves the registry unchanged.
    [[nodiscard]] OperationResult LoadCatalog(const std::filesystem::path& Path);
    [[nodiscard]] OperationResult Register(ExportContract Contract);
    [[nodiscard]] std::optional<ExportContract> Find(
        std::string_view Module, std::string_view Name) const;

    // Argument values are guest scalar values/addresses only. The registry never
    // dereferences them or exposes host addresses to the emulated kernel.
    [[nodiscard]] CallValidation ValidateCall(
        std::string_view Module, std::string_view Name, const CallContext& Context);
    [[nodiscard]] ResultRecord RecordResult(
        std::string_view Module, std::string_view Name,
        std::uint64_t ReturnValue, std::uint64_t VirtualTimeTicks);
    [[nodiscard]] CoverageStatistics CoverageReport() const;

private:
    struct Entry {
        ExportContract Contract;
        std::uint64_t ValidatedCalls = 0;
        std::uint64_t ValidationFailures = 0;
        std::uint64_t RecordedResults = 0;
        std::uint64_t SuccessfulResults = 0;
        std::optional<std::uint64_t> LastReturnValue;
        std::optional<std::uint64_t> LastVirtualTimeTicks;
    };

    struct UnknownEntry {
        std::string Module;
        std::string Name;
        std::uint64_t Calls = 0;
    };

    using ContractKey = std::pair<std::string, std::string>;

    [[nodiscard]] static ContractKey MakeKey(
        std::string_view Module, std::string_view Name);
    [[nodiscard]] OperationResult ValidateContract(const ExportContract& Contract) const;

    RegistryOptions Options_;
    mutable std::shared_mutex Mutex_;
    std::map<ContractKey, Entry> Entries_;
    std::map<ContractKey, UnknownEntry> UnknownEntries_;
};

[[nodiscard]] std::string_view ToString(ReturnPolicy Policy) noexcept;
[[nodiscard]] std::string_view ToString(BufferDirection Direction) noexcept;
[[nodiscard]] std::string_view ToString(DiagnosticCode Code) noexcept;

} // namespace Kevlar::Host::Contracts
