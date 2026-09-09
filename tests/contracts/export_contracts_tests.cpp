#include "host/providers/export_contracts.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <string_view>

using namespace Kevlar::Host::Contracts;

namespace {

bool HasCode(const std::vector<Diagnostic>& Diagnostics, DiagnosticCode Code) {
    for (const Diagnostic& Item : Diagnostics) {
        if (Item.Code == Code)
            return true;
    }
    return false;
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::filesystem::path Fixtures = argv[1];

    RegistryOptions Options;
    Options.Seed = 0x26200;
    Options.InitialVirtualTimeTicks = 10'000;
    ContractRegistry Registry(Options);

    const OperationResult Loaded = Registry.LoadCatalog(Fixtures / "valid_catalog.json");
    assert(Loaded.Ok());
    assert(Loaded.ContractsAdded == 1);

    const auto Contract = Registry.Find("NTOSKRNL.EXE", "FixtureQuery");
    assert(Contract.has_value());
    assert(Contract->ArgumentCount == 3);
    assert(Contract->OutputBuffers.size() == 1);

    CallContext GoodCall;
    GoodCall.Arguments = { 0xFFFF800000001000ull, 8, 0 };
    GoodCall.CurrentIrql = 1;
    GoodCall.VirtualTimeTicks = 10'025;
    const CallValidation Good = Registry.ValidateCall("ntoskrnl.exe", "FixtureQuery", GoodCall);
    assert(Good.Ok());
    assert(Good.Disposition == CallDisposition::InvokeProvider);

    const ResultRecord Recorded = Registry.RecordResult(
        "ntoskrnl.exe", "FixtureQuery", 0, 10'030);
    assert(Recorded.Ok());
    assert(Recorded.Successful);

    CallContext ShortBuffer = GoodCall;
    ShortBuffer.Arguments[1] = 4;
    const CallValidation Short = Registry.ValidateCall(
        "ntoskrnl.exe", "FixtureQuery", ShortBuffer);
    assert(!Short.Ok());
    assert(HasCode(Short.Diagnostics, DiagnosticCode::OutputBufferTooSmall));

    CallContext HighIrql = GoodCall;
    HighIrql.CurrentIrql = 2;
    const CallValidation Irql = Registry.ValidateCall(
        "ntoskrnl.exe", "FixtureQuery", HighIrql);
    assert(!Irql.Ok());
    assert(HasCode(Irql.Diagnostics, DiagnosticCode::IrqlViolation));

    const CallValidation Unknown = Registry.ValidateCall(
        "ntoskrnl.exe", "DefinitelyMissing", {});
    assert(Unknown.Disposition == CallDisposition::ReturnValue);
    assert(Unknown.ReturnValue == StatusNotImplemented);
    assert(HasCode(Unknown.Diagnostics, DiagnosticCode::UnknownExport));

    const CoverageStatistics Coverage = Registry.CoverageReport();
    assert(Coverage.Seed == Options.Seed);
    assert(Coverage.InitialVirtualTimeTicks == Options.InitialVirtualTimeTicks);
    assert(Coverage.TotalContracts == 1);
    assert(Coverage.ExercisedContracts == 1);
    assert(Coverage.ValidatedCalls == 1);
    assert(Coverage.ValidationFailures == 2);
    assert(Coverage.RecordedResults == 1);
    assert(Coverage.SuccessfulResults == 1);
    assert(Coverage.UnknownExportCalls == 1);

    ContractRegistry DuplicateRegistry(Options);
    const OperationResult Duplicate = DuplicateRegistry.LoadCatalog(
        Fixtures / "duplicate_catalog.json");
    assert(!Duplicate.Ok());
    assert(Duplicate.ContractsAdded == 0);
    assert(HasCode(Duplicate.Diagnostics, DiagnosticCode::DuplicateContract));
    assert(DuplicateRegistry.CoverageReport().TotalContracts == 0);

    ContractRegistry MalformedRegistry(Options);
    const OperationResult Malformed = MalformedRegistry.LoadCatalog(
        Fixtures / "malformed_catalog.json");
    assert(!Malformed.Ok());
    assert(HasCode(Malformed.Diagnostics, DiagnosticCode::DuplicateJsonKey));
    assert(MalformedRegistry.CoverageReport().TotalContracts == 0);

    return 0;
}
