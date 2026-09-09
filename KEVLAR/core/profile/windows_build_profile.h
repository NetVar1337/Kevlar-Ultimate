#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Kevlar::Profile {

struct CpuData {
    std::string Vendor;
    std::string Brand;
    std::uint32_t Signature = 0;
    std::uint32_t LogicalProcessorCount = 0;
    std::uint32_t CoreCount = 0;
    std::uint32_t ThreadsPerCore = 0;
    std::uint32_t BaseFrequencyMhz = 0;
    std::uint32_t MaximumFrequencyMhz = 0;
    std::uint32_t BusFrequencyMhz = 0;
    std::uint64_t CrystalFrequencyHz = 0;
    std::uint32_t TscNumerator = 0;
    std::uint32_t TscDenominator = 0;
    std::uint64_t TscFrequencyHz = 0;
    std::uint64_t InitialTsc = 0;
    std::uint64_t Xcr0Mask = 0;
    std::uint8_t PhysicalAddressBits = 0;
    std::uint8_t VirtualAddressBits = 0;
    std::uint32_t Leaf1Ecx = 0;
    std::uint32_t Leaf1Edx = 0;
    std::uint32_t Leaf7Ebx = 0;
    std::uint32_t Leaf7Ecx = 0;
    std::uint32_t Leaf7Edx = 0;
};

struct StructureOffsetData {
    std::uint32_t DriverObjectSize = 0;
    std::uint32_t DeviceObjectSize = 0;
    std::uint32_t EprocessSize = 0;
    std::uint32_t EthreadSize = 0;
    std::uint32_t KthreadSize = 0;

    std::uint32_t EprocessUniqueProcessId = 0;
    std::uint32_t EprocessActiveProcessLinks = 0;
    std::uint32_t EprocessCreateTime = 0;
    std::uint32_t EprocessToken = 0;
    std::uint32_t EprocessInheritedProcessId = 0;
    std::uint32_t EprocessPeb = 0;
    std::uint32_t EprocessObjectTable = 0;
    std::uint32_t EprocessWow64Process = 0;
    std::uint32_t EprocessImageFileName = 0;

    std::uint32_t EthreadStartAddress = 0;
    std::uint32_t EthreadClientId = 0;
    std::uint32_t KthreadApcState = 0;
    std::uint32_t KthreadKernelApcDisable = 0;
    std::uint32_t KthreadPreviousMode = 0;
};

struct KuserSharedDataProfile {
    std::uint64_t KernelAddress = 0;
    std::uint32_t PageSize = 0;
    std::uint32_t InterruptTime = 0;
    std::uint32_t SystemTime = 0;
    std::uint32_t NtBuildNumber = 0;
    std::uint32_t NtProductType = 0;
    std::uint32_t ProcessorArchitecture = 0;
    std::uint32_t NtMajorVersion = 0;
    std::uint32_t ActiveProcessorCount = 0;
    std::uint32_t ActiveGroupCount = 0;
    std::uint32_t PhysicalPageCount = 0;
    std::uint32_t TickCount = 0;
    std::uint32_t Cookie = 0;
    std::uint32_t ActiveProcessorCountDeprecated = 0;
    std::int64_t InitialSystemTime = 0;
};

struct FirmwareProfile {
    enum class Type : std::uint32_t {
        Unknown = 0,
        Bios = 1,
        Uefi = 2,
        Maximum = 3,
    };

    Type FirmwareType = Type::Unknown;
    std::array<std::uint8_t, 16> BootIdentifier{};
    std::uint64_t BootFlags = 0;
    std::string BiosVendor;
    std::string BiosVersion;
    std::string SystemManufacturer;
    std::string SystemProductName;
    std::string AcpiOemId;
    std::string AcpiOemTableId;
};

struct PciIommuProfile {
    std::uint16_t Segment = 0;
    std::uint8_t Bus = 0;
    std::uint8_t HostBridgeDevice = 0;
    std::uint8_t HostBridgeFunction = 0;
    std::uint16_t HostBridgeVendorId = 0;
    std::uint16_t HostBridgeDeviceId = 0;
    std::uint8_t HostBridgeRevision = 0;
    std::uint8_t IommuDevice = 0;
    std::uint8_t IommuFunction = 0;
    std::uint16_t IommuVendorId = 0;
    std::uint16_t IommuDeviceId = 0;
    std::uint8_t IommuRevision = 0;
    std::uint64_t IommuRegisterBase = 0;
    std::uint32_t IommuRegisterSize = 0;
    bool TranslationEnabled = false;
    bool InterruptRemapping = false;
    bool DmaRemapping = false;
};

struct PolicyProfile {
    std::uint32_t CodeIntegrityOptions = 0;
    std::uint32_t HvciOptions = 0;
    std::uint64_t CodeIntegrityPolicyVersion = 0;
    bool SecureBootEnabled = false;
    bool TestSigningEnabled = false;
    bool HypervisorPresent = false;
    bool VirtualizationBasedSecurity = false;
    bool KernelDmaProtection = false;
};

struct WindowsBuildProfile {
    std::string Name;
    std::uint32_t BuildNumber = 0;
    CpuData Cpu;
    StructureOffsetData Structures;
    KuserSharedDataProfile KuserSharedData;
    FirmwareProfile Firmware;
    PciIommuProfile PciIommu;
    PolicyProfile Policy;
};

enum class DiagnosticCode {
    Syntax,
    DuplicateKey,
    UnknownKey,
    MissingKey,
    TypeMismatch,
    OutOfRange,
    Incoherent,
};

struct ValidationDiagnostic {
    DiagnosticCode Code = DiagnosticCode::Syntax;
    std::string Path;
    std::string Message;
};

struct ValidationResult {
    std::vector<ValidationDiagnostic> Diagnostics;

    [[nodiscard]] bool Ok() const noexcept { return Diagnostics.empty(); }
    [[nodiscard]] explicit operator bool() const noexcept { return Ok(); }
};

struct OverrideResult {
    std::optional<WindowsBuildProfile> Profile;
    ValidationResult Validation;

    [[nodiscard]] bool Ok() const noexcept { return Profile.has_value() && Validation.Ok(); }
    [[nodiscard]] explicit operator bool() const noexcept { return Ok(); }
};

// Returned pointers refer to immutable process-lifetime built-ins.
[[nodiscard]] const WindowsBuildProfile* SelectByBuild(std::uint32_t BuildNumber) noexcept;
[[nodiscard]] const WindowsBuildProfile* SelectByName(std::string_view Name) noexcept;

// The one-argument form requires a top-level "base" key naming a built-in by
// canonical name or build number. The two-argument form applies the same
// constrained schema to an explicit base profile; a supplied "base" must
// identify that profile.
[[nodiscard]] OverrideResult LoadOverride(std::string_view JsonText);
[[nodiscard]] OverrideResult LoadOverride(const WindowsBuildProfile& Base, std::string_view JsonText);

[[nodiscard]] ValidationResult Validate(const WindowsBuildProfile& Profile);

// 64-bit FNV-1a over an explicitly encoded canonical field stream. It is
// independent of object layout, standard-library implementation, and process.
[[nodiscard]] std::uint64_t Fingerprint(const WindowsBuildProfile& Profile) noexcept;
[[nodiscard]] std::string FingerprintHex(const WindowsBuildProfile& Profile);

} // namespace Kevlar::Profile
