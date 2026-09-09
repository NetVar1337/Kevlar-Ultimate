#include "../../KEVLAR/core/profile/windows_build_profile.h"

#include <cassert>
#include <cstdint>
#include <string>

using namespace Kevlar::Profile;

namespace {

bool HasDiagnostic(const ValidationResult& Result, DiagnosticCode Code, const char* Path) {
    for (const auto& Diagnostic : Result.Diagnostics) {
        if (Diagnostic.Code == Code && Diagnostic.Path == Path) return true;
    }
    return false;
}

void BuiltInSelectionIsExactAndStable() {
    const WindowsBuildProfile* Current = SelectByBuild(26200);
    const WindowsBuildProfile* Legacy = SelectByBuild(26100);
    assert(Current != nullptr);
    assert(Legacy != nullptr);
    assert(SelectByName("windows-11-26200") == Current);
    assert(SelectByName("windows-11-26100") == Legacy);
    assert(SelectByBuild(26099) == nullptr);
    assert(SelectByName("WINDOWS-11-26200") == nullptr);

    assert(Validate(*Current).Ok());
    assert(Validate(*Legacy).Ok());
    assert(Current->Cpu.LogicalProcessorCount ==
        Current->Cpu.CoreCount * Current->Cpu.ThreadsPerCore);
    assert(Current->Structures.EprocessUniqueProcessId < Current->Structures.EprocessSize);
    assert(Current->KuserSharedData.NtBuildNumber < Current->KuserSharedData.PageSize);
    assert(Fingerprint(*Current) == Fingerprint(*Current));
    assert(FingerprintHex(*Current).size() == 16);
    assert(Fingerprint(*Current) != Fingerprint(*Legacy));
}

void ValidOverrideChangesOnlyNamedFields() {
    const auto Loaded = LoadOverride(R"json({
        "base": 26200,
        "name": "lab-26200",
        "cpu": {
            "logical_processors": 24,
            "cores": 12,
            "threads_per_core": 2
        },
        "firmware": {
            "boot_identifier": "00112233-4455-6677-8899-aabbccddeeff",
            "bios_version": "1904"
        },
        "policy": {
            "kernel_dma_protection": false
        }
    })json");
    assert(Loaded.Ok());
    assert(Loaded.Profile->Name == "lab-26200");
    assert(Loaded.Profile->Cpu.LogicalProcessorCount == 24);
    assert(Loaded.Profile->Cpu.CoreCount == 12);
    assert(Loaded.Profile->Cpu.ThreadsPerCore == 2);
    assert(Loaded.Profile->Firmware.BiosVersion == "1904");
    assert(Loaded.Profile->Structures.EprocessSize == SelectByBuild(26200)->Structures.EprocessSize);
    assert(Fingerprint(*Loaded.Profile) != Fingerprint(*SelectByBuild(26200)));
}

void ExplicitBaseFormWorksWithoutSelector() {
    const WindowsBuildProfile* Base = SelectByBuild(26100);
    assert(Base != nullptr);
    const auto Loaded = LoadOverride(*Base, R"json({
        "name": "legacy-lab",
        "pci_iommu": {
            "iommu_device_id": 18195,
            "iommu_revision": 17
        }
    })json");
    assert(Loaded.Ok());
    assert(Loaded.Profile->BuildNumber == 26100);
    assert(Loaded.Profile->PciIommu.IommuDeviceId == 18195);
    assert(Loaded.Profile->PciIommu.IommuRevision == 17);
}

void InvalidOverridesExposePreciseDiagnostics() {
    const auto Duplicate = LoadOverride(R"json({
        "base": 26200,
        "cpu": {"cores": 8, "cores": 12}
    })json");
    assert(!Duplicate.Ok());
    assert(HasDiagnostic(Duplicate.Validation, DiagnosticCode::DuplicateKey, "$.cpu.cores"));

    const auto Unknown = LoadOverride(R"json({
        "base": 26200,
        "cpu": {"host_passthrough": true}
    })json");
    assert(!Unknown.Ok());
    assert(HasDiagnostic(Unknown.Validation, DiagnosticCode::UnknownKey, "$.cpu.host_passthrough"));

    const auto Range = LoadOverride(R"json({
        "base": 26200,
        "pci_iommu": {"iommu_device": 32}
    })json");
    assert(!Range.Ok());
    assert(HasDiagnostic(Range.Validation, DiagnosticCode::OutOfRange, "$.pci_iommu.iommu_device"));

    const auto Topology = LoadOverride(R"json({
        "base": 26200,
        "cpu": {"logical_processors": 15, "cores": 8, "threads_per_core": 2}
    })json");
    assert(!Topology.Ok());
    assert(HasDiagnostic(Topology.Validation, DiagnosticCode::Incoherent, "$.cpu.logical_processors"));

    const auto MissingBase = LoadOverride(R"json({"name": "orphan"})json");
    assert(!MissingBase.Ok());
    assert(HasDiagnostic(MissingBase.Validation, DiagnosticCode::MissingKey, "$.base"));
}

void DirectValidationCatchesCrossSectionContradictions() {
    WindowsBuildProfile Profile = *SelectByBuild(26200);
    Profile.Policy.VirtualizationBasedSecurity = true;
    Profile.Policy.HypervisorPresent = false;
    Profile.Structures.EprocessPeb = Profile.Structures.EprocessSize;
    const ValidationResult Result = Validate(Profile);
    assert(!Result.Ok());
    assert(HasDiagnostic(Result, DiagnosticCode::Incoherent, "$.policy.virtualization_based_security"));
    assert(HasDiagnostic(Result, DiagnosticCode::OutOfRange, "$.structures.eprocess_peb"));
}

} // namespace

int main() {
    BuiltInSelectionIsExactAndStable();
    ValidOverrideChangesOnlyNamedFields();
    ExplicitBaseFormWorksWithoutSelector();
    InvalidOverridesExposePreciseDiagnostics();
    DirectValidationCatchesCrossSectionContradictions();
    return 0;
}
