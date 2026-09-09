#include "core/profile/windows_build_profile.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdio>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <system_error>
#include <type_traits>
#include <utility>

namespace Kevlar::Profile {
namespace {

constexpr std::size_t kMaximumJsonBytes = 64 * 1024;
constexpr unsigned kMaximumJsonDepth = 16;

WindowsBuildProfile MakeBuiltIn(std::uint32_t Build, const char* Name, const char* BiosVersion) {
    WindowsBuildProfile Profile;
    Profile.Name = Name;
    Profile.BuildNumber = Build;

    Profile.Cpu.Vendor = "GenuineIntel";
    Profile.Cpu.Brand = "13th Gen Intel(R) Core(TM) i9-13900K";
    Profile.Cpu.Signature = 0x000B0671;
    Profile.Cpu.LogicalProcessorCount = 16;
    Profile.Cpu.CoreCount = 16;
    Profile.Cpu.ThreadsPerCore = 1;
    Profile.Cpu.BaseFrequencyMhz = 3000;
    Profile.Cpu.MaximumFrequencyMhz = 5800;
    Profile.Cpu.BusFrequencyMhz = 100;
    Profile.Cpu.CrystalFrequencyHz = 38400000;
    Profile.Cpu.TscNumerator = 168;
    Profile.Cpu.TscDenominator = 2;
    Profile.Cpu.TscFrequencyHz = 3225600000ULL;
    Profile.Cpu.InitialTsc = 0x1C0000000000ULL;
    Profile.Cpu.Xcr0Mask = 0x7;
    Profile.Cpu.PhysicalAddressBits = 46;
    Profile.Cpu.VirtualAddressBits = 48;
    Profile.Cpu.Leaf1Ecx = 0x7FFAB7FF;
    Profile.Cpu.Leaf1Edx = 0xBFEBFBFF;
    Profile.Cpu.Leaf7Ebx = 0x2000FFBB;
    Profile.Cpu.Leaf7Ecx = 0x04C05700;
    Profile.Cpu.Leaf7Edx = 0;

    Profile.Structures.DriverObjectSize = 0x150;
    Profile.Structures.DeviceObjectSize = 0x150;
    Profile.Structures.EprocessSize = 0x840;
    Profile.Structures.EthreadSize = 0x798;
    Profile.Structures.KthreadSize = 0x4C0;
    Profile.Structures.EprocessUniqueProcessId = 0x1D0;
    Profile.Structures.EprocessActiveProcessLinks = 0x1D8;
    Profile.Structures.EprocessCreateTime = 0x1F8;
    Profile.Structures.EprocessToken = 0x248;
    Profile.Structures.EprocessInheritedProcessId = 0x2D0;
    Profile.Structures.EprocessPeb = 0x2E0;
    Profile.Structures.EprocessObjectTable = 0x300;
    Profile.Structures.EprocessWow64Process = 0x310;
    Profile.Structures.EprocessImageFileName = 0x338;
    Profile.Structures.EthreadStartAddress = 0x4E0;
    Profile.Structures.EthreadClientId = 0x508;
    Profile.Structures.KthreadApcState = 0x98;
    Profile.Structures.KthreadKernelApcDisable = 0x1E4;
    Profile.Structures.KthreadPreviousMode = 0x232;

    Profile.KuserSharedData.KernelAddress = 0xFFFFF78000000000ULL;
    Profile.KuserSharedData.PageSize = 0x1000;
    Profile.KuserSharedData.InterruptTime = 0x08;
    Profile.KuserSharedData.SystemTime = 0x14;
    Profile.KuserSharedData.NtBuildNumber = 0x260;
    Profile.KuserSharedData.NtProductType = 0x264;
    Profile.KuserSharedData.ProcessorArchitecture = 0x26A;
    Profile.KuserSharedData.NtMajorVersion = 0x26C;
    Profile.KuserSharedData.ActiveProcessorCount = 0x2C0;
    Profile.KuserSharedData.ActiveGroupCount = 0x2C4;
    Profile.KuserSharedData.PhysicalPageCount = 0x2E8;
    Profile.KuserSharedData.TickCount = 0x320;
    Profile.KuserSharedData.Cookie = 0x330;
    Profile.KuserSharedData.ActiveProcessorCountDeprecated = 0x3C0;
    Profile.KuserSharedData.InitialSystemTime = 0x01DB2E7F4B7A0000LL;

    Profile.Firmware.FirmwareType = FirmwareProfile::Type::Uefi;
    Profile.Firmware.BootIdentifier = {
        0xB2, 0x9E, 0x3F, 0x5A, 0x1D, 0x4E, 0x8B, 0x42,
        0x2C, 0xA4, 0xB8, 0x5F, 0x1F, 0x8B, 0x67, 0x45,
    };
    Profile.Firmware.BootFlags = 1;
    Profile.Firmware.BiosVendor = "American Megatrends International, LLC.";
    Profile.Firmware.BiosVersion = BiosVersion;
    Profile.Firmware.SystemManufacturer = "ASUSTeK COMPUTER INC.";
    Profile.Firmware.SystemProductName = "PRIME Z790-P WIFI";
    Profile.Firmware.AcpiOemId = "INTEL ";
    Profile.Firmware.AcpiOemTableId = "ALASKA  ";

    Profile.PciIommu.Segment = 0;
    Profile.PciIommu.Bus = 0;
    Profile.PciIommu.HostBridgeDevice = 0;
    Profile.PciIommu.HostBridgeFunction = 0;
    Profile.PciIommu.HostBridgeVendorId = 0x8086;
    Profile.PciIommu.HostBridgeDeviceId = 0x3E1F;
    Profile.PciIommu.HostBridgeRevision = 0;
    Profile.PciIommu.IommuDevice = 0;
    Profile.PciIommu.IommuFunction = 2;
    Profile.PciIommu.IommuVendorId = 0x8086;
    Profile.PciIommu.IommuDeviceId = 0x4612;
    Profile.PciIommu.IommuRevision = 0x10;
    Profile.PciIommu.IommuRegisterBase = 0xFED90000ULL;
    Profile.PciIommu.IommuRegisterSize = 0x1000;
    Profile.PciIommu.TranslationEnabled = true;
    Profile.PciIommu.InterruptRemapping = true;
    Profile.PciIommu.DmaRemapping = true;

    Profile.Policy.CodeIntegrityOptions = 1;
    Profile.Policy.HvciOptions = 0;
    Profile.Policy.CodeIntegrityPolicyVersion = 0x0000000100000000ULL;
    Profile.Policy.SecureBootEnabled = true;
    Profile.Policy.TestSigningEnabled = false;
    Profile.Policy.HypervisorPresent = false;
    Profile.Policy.VirtualizationBasedSecurity = false;
    Profile.Policy.KernelDmaProtection = true;
    return Profile;
}

const std::array<WindowsBuildProfile, 2>& BuiltIns() {
    static const std::array<WindowsBuildProfile, 2> Profiles = {
        MakeBuiltIn(26200, "windows-11-26200", "1805"),
        MakeBuiltIn(26100, "windows-11-26100", "1802"),
    };
    return Profiles;
}

void AddDiagnostic(ValidationResult& Result, DiagnosticCode Code,
                   std::string Path, std::string Message) {
    Result.Diagnostics.push_back({Code, std::move(Path), std::move(Message)});
}

struct JsonValue {
    enum class Kind { Object, String, Number, Boolean, Null };
    using Member = std::pair<std::string, JsonValue>;

    Kind Type = Kind::Null;
    std::vector<Member> Object;
    std::string String;
    std::uint64_t Number = 0;
    bool Boolean = false;
};

class JsonParser {
public:
    JsonParser(std::string_view Text, ValidationResult& Result)
        : Text_(Text), Result_(Result) {}

    bool Parse(JsonValue& Out) {
        if (Text_.size() > kMaximumJsonBytes) {
            Error(DiagnosticCode::OutOfRange, "$", "JSON override exceeds 64 KiB");
            return false;
        }
        SkipWhitespace();
        if (!ParseValue(Out, "$", 0)) return false;
        SkipWhitespace();
        if (Position_ != Text_.size()) {
            Error(DiagnosticCode::Syntax, "$", "unexpected trailing input");
            return false;
        }
        return true;
    }

private:
    bool ParseValue(JsonValue& Out, const std::string& Path, unsigned Depth) {
        SkipWhitespace();
        if (Position_ >= Text_.size()) return Error(DiagnosticCode::Syntax, Path, "expected a value");
        const char Ch = Text_[Position_];
        if (Ch == '{') return ParseObject(Out, Path, Depth);
        if (Ch == '"') {
            Out.Type = JsonValue::Kind::String;
            return ParseString(Out.String, Path);
        }
        if (Ch >= '0' && Ch <= '9') return ParseNumber(Out, Path);
        if (ConsumeLiteral("true")) {
            Out.Type = JsonValue::Kind::Boolean;
            Out.Boolean = true;
            return true;
        }
        if (ConsumeLiteral("false")) {
            Out.Type = JsonValue::Kind::Boolean;
            Out.Boolean = false;
            return true;
        }
        if (ConsumeLiteral("null")) {
            Out.Type = JsonValue::Kind::Null;
            return true;
        }
        if (Ch == '[') return Error(DiagnosticCode::TypeMismatch, Path, "arrays are not supported by the profile schema");
        return Error(DiagnosticCode::Syntax, Path, "invalid JSON value");
    }

    bool ParseObject(JsonValue& Out, const std::string& Path, unsigned Depth) {
        if (Depth >= kMaximumJsonDepth)
            return Error(DiagnosticCode::OutOfRange, Path, "JSON nesting exceeds 16 levels");
        ++Position_;
        Out.Type = JsonValue::Kind::Object;
        SkipWhitespace();
        if (Consume('}')) return true;
        for (;;) {
            SkipWhitespace();
            std::string Key;
            if (!ParseString(Key, Path)) return false;
            const std::string ChildPath = Path + "." + Key;
            if (std::any_of(Out.Object.begin(), Out.Object.end(), [&](const JsonValue::Member& Member) {
                    return Member.first == Key;
                })) {
                return Error(DiagnosticCode::DuplicateKey, ChildPath, "duplicate object key");
            }
            SkipWhitespace();
            if (!Consume(':')) return Error(DiagnosticCode::Syntax, ChildPath, "expected ':' after key");
            JsonValue Child;
            if (!ParseValue(Child, ChildPath, Depth + 1)) return false;
            Out.Object.emplace_back(std::move(Key), std::move(Child));
            SkipWhitespace();
            if (Consume('}')) return true;
            if (!Consume(',')) return Error(DiagnosticCode::Syntax, Path, "expected ',' or '}'");
        }
    }

    bool ParseString(std::string& Out, const std::string& Path) {
        if (!Consume('"')) return Error(DiagnosticCode::Syntax, Path, "expected a JSON string");
        Out.clear();
        while (Position_ < Text_.size()) {
            const unsigned char Ch = static_cast<unsigned char>(Text_[Position_++]);
            if (Ch == '"') return true;
            if (Ch < 0x20) return Error(DiagnosticCode::Syntax, Path, "unescaped control character in string");
            if (Ch != '\\') {
                Out.push_back(static_cast<char>(Ch));
            } else {
                if (Position_ >= Text_.size()) return Error(DiagnosticCode::Syntax, Path, "unterminated escape sequence");
                switch (Text_[Position_++]) {
                case '"': Out.push_back('"'); break;
                case '\\': Out.push_back('\\'); break;
                case '/': Out.push_back('/'); break;
                case 'b': Out.push_back('\b'); break;
                case 'f': Out.push_back('\f'); break;
                case 'n': Out.push_back('\n'); break;
                case 'r': Out.push_back('\r'); break;
                case 't': Out.push_back('\t'); break;
                case 'u': return Error(DiagnosticCode::Syntax, Path, "Unicode escapes are not supported");
                default: return Error(DiagnosticCode::Syntax, Path, "invalid escape sequence");
                }
            }
            if (Out.size() > 256) return Error(DiagnosticCode::OutOfRange, Path, "string exceeds 256 bytes");
        }
        return Error(DiagnosticCode::Syntax, Path, "unterminated string");
    }

    bool ParseNumber(JsonValue& Out, const std::string& Path) {
        const std::size_t Start = Position_;
        if (Text_[Position_] == '0') {
            ++Position_;
            if (Position_ < Text_.size() && std::isdigit(static_cast<unsigned char>(Text_[Position_])))
                return Error(DiagnosticCode::Syntax, Path, "leading zero in number");
        } else {
            while (Position_ < Text_.size() && std::isdigit(static_cast<unsigned char>(Text_[Position_]))) ++Position_;
        }
        if (Position_ < Text_.size() && (Text_[Position_] == '.' || Text_[Position_] == 'e' || Text_[Position_] == 'E'))
            return Error(DiagnosticCode::TypeMismatch, Path, "profile numbers must be unsigned integers");
        const char* First = Text_.data() + Start;
        const char* Last = Text_.data() + Position_;
        const auto Converted = std::from_chars(First, Last, Out.Number, 10);
        if (Converted.ec != std::errc{} || Converted.ptr != Last)
            return Error(DiagnosticCode::OutOfRange, Path, "integer is outside the uint64 range");
        Out.Type = JsonValue::Kind::Number;
        return true;
    }

    bool Consume(char Expected) {
        if (Position_ < Text_.size() && Text_[Position_] == Expected) {
            ++Position_;
            return true;
        }
        return false;
    }

    bool ConsumeLiteral(std::string_view Literal) {
        if (Text_.substr(Position_, Literal.size()) == Literal) {
            Position_ += Literal.size();
            return true;
        }
        return false;
    }

    void SkipWhitespace() {
        while (Position_ < Text_.size()) {
            const char Ch = Text_[Position_];
            if (Ch != ' ' && Ch != '\t' && Ch != '\r' && Ch != '\n') break;
            ++Position_;
        }
    }

    bool Error(DiagnosticCode Code, const std::string& Path, const char* Message) {
        AddDiagnostic(Result_, Code, Path, Message);
        return false;
    }

    std::string_view Text_;
    std::size_t Position_ = 0;
    ValidationResult& Result_;
};

const JsonValue* Find(const JsonValue& Object, std::string_view Key) {
    if (Object.Type != JsonValue::Kind::Object) return nullptr;
    for (const auto& Member : Object.Object) {
        if (Member.first == Key) return &Member.second;
    }
    return nullptr;
}

bool IsAllowed(std::string_view Key, std::initializer_list<std::string_view> Allowed) {
    return std::find(Allowed.begin(), Allowed.end(), Key) != Allowed.end();
}

void RejectUnknown(const JsonValue& Object, const std::string& Path,
                   std::initializer_list<std::string_view> Allowed,
                   ValidationResult& Result) {
    if (Object.Type != JsonValue::Kind::Object) return;
    for (const auto& Member : Object.Object) {
        if (!IsAllowed(Member.first, Allowed))
            AddDiagnostic(Result, DiagnosticCode::UnknownKey, Path + "." + Member.first, "unknown profile key");
    }
}

bool RequireObject(const JsonValue* Value, const std::string& Path, ValidationResult& Result) {
    if (!Value || Value->Type == JsonValue::Kind::Object) return true;
    AddDiagnostic(Result, DiagnosticCode::TypeMismatch, Path, "expected an object");
    return false;
}

template <typename T>
void ApplyUnsigned(const JsonValue& Object, std::string_view Key, const std::string& Path,
                   T& Target, std::uint64_t Minimum, std::uint64_t Maximum,
                   ValidationResult& Result) {
    const JsonValue* Value = Find(Object, Key);
    if (!Value) return;
    const std::string FieldPath = Path + "." + std::string(Key);
    if (Value->Type != JsonValue::Kind::Number) {
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, FieldPath, "expected an unsigned integer");
    } else if (Value->Number < Minimum || Value->Number > Maximum) {
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, FieldPath, "integer is outside the allowed range");
    } else {
        Target = static_cast<T>(Value->Number);
    }
}

void ApplyString(const JsonValue& Object, std::string_view Key, const std::string& Path,
                 std::string& Target, ValidationResult& Result) {
    const JsonValue* Value = Find(Object, Key);
    if (!Value) return;
    const std::string FieldPath = Path + "." + std::string(Key);
    if (Value->Type != JsonValue::Kind::String)
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, FieldPath, "expected a string");
    else
        Target = Value->String;
}

void ApplyBoolean(const JsonValue& Object, std::string_view Key, const std::string& Path,
                  bool& Target, ValidationResult& Result) {
    const JsonValue* Value = Find(Object, Key);
    if (!Value) return;
    const std::string FieldPath = Path + "." + std::string(Key);
    if (Value->Type != JsonValue::Kind::Boolean)
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, FieldPath, "expected a boolean");
    else
        Target = Value->Boolean;
}

bool ParseGuid(std::string_view Text, std::array<std::uint8_t, 16>& Out) {
    if (Text.size() != 36 || Text[8] != '-' || Text[13] != '-' || Text[18] != '-' || Text[23] != '-') return false;
    auto Hex = [](char Ch) -> int {
        if (Ch >= '0' && Ch <= '9') return Ch - '0';
        if (Ch >= 'a' && Ch <= 'f') return Ch - 'a' + 10;
        if (Ch >= 'A' && Ch <= 'F') return Ch - 'A' + 10;
        return -1;
    };
    std::array<std::uint8_t, 16> Bytes{};
    std::size_t ByteIndex = 0;
    for (std::size_t I = 0; I < Text.size();) {
        if (Text[I] == '-') { ++I; continue; }
        if (I + 1 >= Text.size() || ByteIndex >= Bytes.size()) return false;
        const int High = Hex(Text[I]);
        const int Low = Hex(Text[I + 1]);
        if (High < 0 || Low < 0) return false;
        Bytes[ByteIndex++] = static_cast<std::uint8_t>((High << 4) | Low);
        I += 2;
    }
    if (ByteIndex != Bytes.size()) return false;
    Out = Bytes;
    return true;
}

void ApplyCpu(const JsonValue& Root, WindowsBuildProfile& Profile, ValidationResult& Result) {
    const JsonValue* Object = Find(Root, "cpu");
    if (!Object || !RequireObject(Object, "$.cpu", Result)) return;
    RejectUnknown(*Object, "$.cpu", {
        "vendor", "brand", "signature", "logical_processors", "cores", "threads_per_core",
        "base_frequency_mhz", "maximum_frequency_mhz", "bus_frequency_mhz", "crystal_frequency_hz",
        "tsc_numerator", "tsc_denominator", "tsc_frequency_hz", "initial_tsc", "xcr0_mask",
        "physical_address_bits", "virtual_address_bits", "leaf1_ecx", "leaf1_edx",
        "leaf7_ebx", "leaf7_ecx", "leaf7_edx"
    }, Result);
    CpuData& C = Profile.Cpu;
    ApplyString(*Object, "vendor", "$.cpu", C.Vendor, Result);
    ApplyString(*Object, "brand", "$.cpu", C.Brand, Result);
    ApplyUnsigned(*Object, "signature", "$.cpu", C.Signature, 1, UINT32_MAX, Result);
    ApplyUnsigned(*Object, "logical_processors", "$.cpu", C.LogicalProcessorCount, 1, 256, Result);
    ApplyUnsigned(*Object, "cores", "$.cpu", C.CoreCount, 1, 256, Result);
    ApplyUnsigned(*Object, "threads_per_core", "$.cpu", C.ThreadsPerCore, 1, 64, Result);
    ApplyUnsigned(*Object, "base_frequency_mhz", "$.cpu", C.BaseFrequencyMhz, 1, 20000, Result);
    ApplyUnsigned(*Object, "maximum_frequency_mhz", "$.cpu", C.MaximumFrequencyMhz, 1, 20000, Result);
    ApplyUnsigned(*Object, "bus_frequency_mhz", "$.cpu", C.BusFrequencyMhz, 1, 10000, Result);
    ApplyUnsigned(*Object, "crystal_frequency_hz", "$.cpu", C.CrystalFrequencyHz, 1, 1000000000ULL, Result);
    ApplyUnsigned(*Object, "tsc_numerator", "$.cpu", C.TscNumerator, 1, 4096, Result);
    ApplyUnsigned(*Object, "tsc_denominator", "$.cpu", C.TscDenominator, 1, 4096, Result);
    ApplyUnsigned(*Object, "tsc_frequency_hz", "$.cpu", C.TscFrequencyHz, 1, 20000000000ULL, Result);
    ApplyUnsigned(*Object, "initial_tsc", "$.cpu", C.InitialTsc, 1, UINT64_MAX, Result);
    ApplyUnsigned(*Object, "xcr0_mask", "$.cpu", C.Xcr0Mask, 1, UINT64_MAX, Result);
    ApplyUnsigned(*Object, "physical_address_bits", "$.cpu", C.PhysicalAddressBits, 32, 64, Result);
    ApplyUnsigned(*Object, "virtual_address_bits", "$.cpu", C.VirtualAddressBits, 32, 64, Result);
    ApplyUnsigned(*Object, "leaf1_ecx", "$.cpu", C.Leaf1Ecx, 0, UINT32_MAX, Result);
    ApplyUnsigned(*Object, "leaf1_edx", "$.cpu", C.Leaf1Edx, 0, UINT32_MAX, Result);
    ApplyUnsigned(*Object, "leaf7_ebx", "$.cpu", C.Leaf7Ebx, 0, UINT32_MAX, Result);
    ApplyUnsigned(*Object, "leaf7_ecx", "$.cpu", C.Leaf7Ecx, 0, UINT32_MAX, Result);
    ApplyUnsigned(*Object, "leaf7_edx", "$.cpu", C.Leaf7Edx, 0, UINT32_MAX, Result);
}

void ApplyStructures(const JsonValue& Root, WindowsBuildProfile& Profile, ValidationResult& Result) {
    const JsonValue* Object = Find(Root, "structures");
    if (!Object || !RequireObject(Object, "$.structures", Result)) return;
    RejectUnknown(*Object, "$.structures", {
        "driver_object_size", "device_object_size", "eprocess_size", "ethread_size", "kthread_size",
        "eprocess_unique_process_id", "eprocess_active_process_links", "eprocess_create_time",
        "eprocess_token", "eprocess_inherited_process_id", "eprocess_peb", "eprocess_object_table",
        "eprocess_wow64_process", "eprocess_image_file_name", "ethread_start_address",
        "ethread_client_id", "kthread_apc_state", "kthread_kernel_apc_disable", "kthread_previous_mode"
    }, Result);
    StructureOffsetData& S = Profile.Structures;
#define APPLY_STRUCTURE(Field, Key) ApplyUnsigned(*Object, Key, "$.structures", S.Field, 0, 0x10000, Result)
    APPLY_STRUCTURE(DriverObjectSize, "driver_object_size");
    APPLY_STRUCTURE(DeviceObjectSize, "device_object_size");
    APPLY_STRUCTURE(EprocessSize, "eprocess_size");
    APPLY_STRUCTURE(EthreadSize, "ethread_size");
    APPLY_STRUCTURE(KthreadSize, "kthread_size");
    APPLY_STRUCTURE(EprocessUniqueProcessId, "eprocess_unique_process_id");
    APPLY_STRUCTURE(EprocessActiveProcessLinks, "eprocess_active_process_links");
    APPLY_STRUCTURE(EprocessCreateTime, "eprocess_create_time");
    APPLY_STRUCTURE(EprocessToken, "eprocess_token");
    APPLY_STRUCTURE(EprocessInheritedProcessId, "eprocess_inherited_process_id");
    APPLY_STRUCTURE(EprocessPeb, "eprocess_peb");
    APPLY_STRUCTURE(EprocessObjectTable, "eprocess_object_table");
    APPLY_STRUCTURE(EprocessWow64Process, "eprocess_wow64_process");
    APPLY_STRUCTURE(EprocessImageFileName, "eprocess_image_file_name");
    APPLY_STRUCTURE(EthreadStartAddress, "ethread_start_address");
    APPLY_STRUCTURE(EthreadClientId, "ethread_client_id");
    APPLY_STRUCTURE(KthreadApcState, "kthread_apc_state");
    APPLY_STRUCTURE(KthreadKernelApcDisable, "kthread_kernel_apc_disable");
    APPLY_STRUCTURE(KthreadPreviousMode, "kthread_previous_mode");
#undef APPLY_STRUCTURE
}

void ApplyKuser(const JsonValue& Root, WindowsBuildProfile& Profile, ValidationResult& Result) {
    const JsonValue* Object = Find(Root, "kuser_shared_data");
    if (!Object || !RequireObject(Object, "$.kuser_shared_data", Result)) return;
    RejectUnknown(*Object, "$.kuser_shared_data", {
        "kernel_address", "page_size", "interrupt_time", "system_time", "nt_build_number",
        "nt_product_type", "processor_architecture", "nt_major_version", "active_processor_count",
        "active_group_count", "physical_page_count", "tick_count", "cookie",
        "active_processor_count_deprecated", "initial_system_time"
    }, Result);
    KuserSharedDataProfile& K = Profile.KuserSharedData;
    ApplyUnsigned(*Object, "kernel_address", "$.kuser_shared_data", K.KernelAddress, 1, UINT64_MAX, Result);
    ApplyUnsigned(*Object, "page_size", "$.kuser_shared_data", K.PageSize, 0x1000, 0x10000, Result);
#define APPLY_KUSER(Field, Key) ApplyUnsigned(*Object, Key, "$.kuser_shared_data", K.Field, 0, 0xFFFF, Result)
    APPLY_KUSER(InterruptTime, "interrupt_time");
    APPLY_KUSER(SystemTime, "system_time");
    APPLY_KUSER(NtBuildNumber, "nt_build_number");
    APPLY_KUSER(NtProductType, "nt_product_type");
    APPLY_KUSER(ProcessorArchitecture, "processor_architecture");
    APPLY_KUSER(NtMajorVersion, "nt_major_version");
    APPLY_KUSER(ActiveProcessorCount, "active_processor_count");
    APPLY_KUSER(ActiveGroupCount, "active_group_count");
    APPLY_KUSER(PhysicalPageCount, "physical_page_count");
    APPLY_KUSER(TickCount, "tick_count");
    APPLY_KUSER(Cookie, "cookie");
    APPLY_KUSER(ActiveProcessorCountDeprecated, "active_processor_count_deprecated");
#undef APPLY_KUSER
    const JsonValue* Initial = Find(*Object, "initial_system_time");
    if (Initial) {
        if (Initial->Type != JsonValue::Kind::Number || Initial->Number > static_cast<std::uint64_t>(INT64_MAX))
            AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.kuser_shared_data.initial_system_time", "expected a positive int64 value");
        else
            K.InitialSystemTime = static_cast<std::int64_t>(Initial->Number);
    }
}

void ApplyFirmware(const JsonValue& Root, WindowsBuildProfile& Profile, ValidationResult& Result) {
    const JsonValue* Object = Find(Root, "firmware");
    if (!Object || !RequireObject(Object, "$.firmware", Result)) return;
    RejectUnknown(*Object, "$.firmware", {
        "type", "boot_identifier", "boot_flags", "bios_vendor", "bios_version", "system_manufacturer",
        "system_product_name", "acpi_oem_id", "acpi_oem_table_id"
    }, Result);
    std::uint32_t Type = static_cast<std::uint32_t>(Profile.Firmware.FirmwareType);
    ApplyUnsigned(*Object, "type", "$.firmware", Type, 0, 2, Result);
    Profile.Firmware.FirmwareType = static_cast<FirmwareProfile::Type>(Type);
    ApplyUnsigned(*Object, "boot_flags", "$.firmware", Profile.Firmware.BootFlags, 0, UINT64_MAX, Result);
    ApplyString(*Object, "bios_vendor", "$.firmware", Profile.Firmware.BiosVendor, Result);
    ApplyString(*Object, "bios_version", "$.firmware", Profile.Firmware.BiosVersion, Result);
    ApplyString(*Object, "system_manufacturer", "$.firmware", Profile.Firmware.SystemManufacturer, Result);
    ApplyString(*Object, "system_product_name", "$.firmware", Profile.Firmware.SystemProductName, Result);
    ApplyString(*Object, "acpi_oem_id", "$.firmware", Profile.Firmware.AcpiOemId, Result);
    ApplyString(*Object, "acpi_oem_table_id", "$.firmware", Profile.Firmware.AcpiOemTableId, Result);
    if (const JsonValue* Guid = Find(*Object, "boot_identifier")) {
        if (Guid->Type != JsonValue::Kind::String)
            AddDiagnostic(Result, DiagnosticCode::TypeMismatch, "$.firmware.boot_identifier", "expected a canonical GUID string");
        else if (!ParseGuid(Guid->String, Profile.Firmware.BootIdentifier))
            AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.firmware.boot_identifier", "invalid canonical GUID string");
    }
}

void ApplyPci(const JsonValue& Root, WindowsBuildProfile& Profile, ValidationResult& Result) {
    const JsonValue* Object = Find(Root, "pci_iommu");
    if (!Object || !RequireObject(Object, "$.pci_iommu", Result)) return;
    RejectUnknown(*Object, "$.pci_iommu", {
        "segment", "bus", "host_bridge_device", "host_bridge_function", "host_bridge_vendor_id",
        "host_bridge_device_id", "host_bridge_revision", "iommu_device", "iommu_function",
        "iommu_vendor_id", "iommu_device_id", "iommu_revision", "iommu_register_base",
        "iommu_register_size", "translation_enabled", "interrupt_remapping", "dma_remapping"
    }, Result);
    PciIommuProfile& P = Profile.PciIommu;
    ApplyUnsigned(*Object, "segment", "$.pci_iommu", P.Segment, 0, UINT16_MAX, Result);
    ApplyUnsigned(*Object, "bus", "$.pci_iommu", P.Bus, 0, UINT8_MAX, Result);
    ApplyUnsigned(*Object, "host_bridge_device", "$.pci_iommu", P.HostBridgeDevice, 0, 31, Result);
    ApplyUnsigned(*Object, "host_bridge_function", "$.pci_iommu", P.HostBridgeFunction, 0, 7, Result);
    ApplyUnsigned(*Object, "host_bridge_vendor_id", "$.pci_iommu", P.HostBridgeVendorId, 1, 0xFFFE, Result);
    ApplyUnsigned(*Object, "host_bridge_device_id", "$.pci_iommu", P.HostBridgeDeviceId, 1, 0xFFFE, Result);
    ApplyUnsigned(*Object, "host_bridge_revision", "$.pci_iommu", P.HostBridgeRevision, 0, UINT8_MAX, Result);
    ApplyUnsigned(*Object, "iommu_device", "$.pci_iommu", P.IommuDevice, 0, 31, Result);
    ApplyUnsigned(*Object, "iommu_function", "$.pci_iommu", P.IommuFunction, 0, 7, Result);
    ApplyUnsigned(*Object, "iommu_vendor_id", "$.pci_iommu", P.IommuVendorId, 1, 0xFFFE, Result);
    ApplyUnsigned(*Object, "iommu_device_id", "$.pci_iommu", P.IommuDeviceId, 1, 0xFFFE, Result);
    ApplyUnsigned(*Object, "iommu_revision", "$.pci_iommu", P.IommuRevision, 0, UINT8_MAX, Result);
    ApplyUnsigned(*Object, "iommu_register_base", "$.pci_iommu", P.IommuRegisterBase, 0x1000, UINT64_MAX, Result);
    ApplyUnsigned(*Object, "iommu_register_size", "$.pci_iommu", P.IommuRegisterSize, 0x1000, 0x1000000, Result);
    ApplyBoolean(*Object, "translation_enabled", "$.pci_iommu", P.TranslationEnabled, Result);
    ApplyBoolean(*Object, "interrupt_remapping", "$.pci_iommu", P.InterruptRemapping, Result);
    ApplyBoolean(*Object, "dma_remapping", "$.pci_iommu", P.DmaRemapping, Result);
}

void ApplyPolicy(const JsonValue& Root, WindowsBuildProfile& Profile, ValidationResult& Result) {
    const JsonValue* Object = Find(Root, "policy");
    if (!Object || !RequireObject(Object, "$.policy", Result)) return;
    RejectUnknown(*Object, "$.policy", {
        "code_integrity_options", "hvci_options", "code_integrity_policy_version", "secure_boot_enabled",
        "test_signing_enabled", "hypervisor_present", "virtualization_based_security", "kernel_dma_protection"
    }, Result);
    PolicyProfile& P = Profile.Policy;
    ApplyUnsigned(*Object, "code_integrity_options", "$.policy", P.CodeIntegrityOptions, 0, UINT32_MAX, Result);
    ApplyUnsigned(*Object, "hvci_options", "$.policy", P.HvciOptions, 0, UINT32_MAX, Result);
    ApplyUnsigned(*Object, "code_integrity_policy_version", "$.policy", P.CodeIntegrityPolicyVersion, 0, UINT64_MAX, Result);
    ApplyBoolean(*Object, "secure_boot_enabled", "$.policy", P.SecureBootEnabled, Result);
    ApplyBoolean(*Object, "test_signing_enabled", "$.policy", P.TestSigningEnabled, Result);
    ApplyBoolean(*Object, "hypervisor_present", "$.policy", P.HypervisorPresent, Result);
    ApplyBoolean(*Object, "virtualization_based_security", "$.policy", P.VirtualizationBasedSecurity, Result);
    ApplyBoolean(*Object, "kernel_dma_protection", "$.policy", P.KernelDmaProtection, Result);
}

const WindowsBuildProfile* ResolveBase(const JsonValue& Root, ValidationResult& Result) {
    const JsonValue* Base = Find(Root, "base");
    if (!Base) {
        AddDiagnostic(Result, DiagnosticCode::MissingKey, "$.base", "a built-in base profile is required");
        return nullptr;
    }
    const WindowsBuildProfile* Selected = nullptr;
    if (Base->Type == JsonValue::Kind::String)
        Selected = SelectByName(Base->String);
    else if (Base->Type == JsonValue::Kind::Number && Base->Number <= UINT32_MAX)
        Selected = SelectByBuild(static_cast<std::uint32_t>(Base->Number));
    else
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, "$.base", "base must be a profile name or build number");
    if (!Selected && Result.Diagnostics.empty())
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.base", "unknown built-in profile");
    return Selected;
}

OverrideResult ApplyOverride(const WindowsBuildProfile& Base, const JsonValue& Root,
                             ValidationResult Result) {
    if (Root.Type != JsonValue::Kind::Object) {
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, "$", "profile override root must be an object");
        return {std::nullopt, std::move(Result)};
    }
    RejectUnknown(Root, "$", {"base", "name", "build", "cpu", "structures", "kuser_shared_data", "firmware", "pci_iommu", "policy"}, Result);

    if (const JsonValue* BaseSelector = Find(Root, "base")) {
        bool Matches = false;
        if (BaseSelector->Type == JsonValue::Kind::String) Matches = BaseSelector->String == Base.Name;
        else if (BaseSelector->Type == JsonValue::Kind::Number) Matches = BaseSelector->Number == Base.BuildNumber;
        else AddDiagnostic(Result, DiagnosticCode::TypeMismatch, "$.base", "base must be a profile name or build number");
        if (!Matches && (BaseSelector->Type == JsonValue::Kind::String || BaseSelector->Type == JsonValue::Kind::Number))
            AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.base", "base selector does not match the supplied base profile");
    }

    WindowsBuildProfile Profile = Base;
    ApplyString(Root, "name", "$", Profile.Name, Result);
    ApplyUnsigned(Root, "build", "$", Profile.BuildNumber, 10240, 99999, Result);
    ApplyCpu(Root, Profile, Result);
    ApplyStructures(Root, Profile, Result);
    ApplyKuser(Root, Profile, Result);
    ApplyFirmware(Root, Profile, Result);
    ApplyPci(Root, Profile, Result);
    ApplyPolicy(Root, Profile, Result);

    ValidationResult ModelValidation = Validate(Profile);
    Result.Diagnostics.insert(Result.Diagnostics.end(),
        std::make_move_iterator(ModelValidation.Diagnostics.begin()),
        std::make_move_iterator(ModelValidation.Diagnostics.end()));
    if (!Result.Ok()) return {std::nullopt, std::move(Result)};
    return {std::move(Profile), std::move(Result)};
}

bool IsProfileNameValid(std::string_view Name) {
    if (Name.empty() || Name.size() > 63) return false;
    return std::all_of(Name.begin(), Name.end(), [](unsigned char Ch) {
        return std::isalnum(Ch) || Ch == '-' || Ch == '_' || Ch == '.';
    });
}

void ValidateOffset(ValidationResult& Result, const char* Path,
                    std::uint32_t Offset, std::uint32_t Width, std::uint32_t Size) {
    if (Size == 0 || Offset >= Size || Width > Size - Offset)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, Path, "field extends beyond its containing structure");
}

class StableHasher {
public:
    void Bytes(const void* Data, std::size_t Size) noexcept {
        const auto* Current = static_cast<const std::uint8_t*>(Data);
        for (std::size_t I = 0; I < Size; ++I) {
            Value_ ^= Current[I];
            Value_ *= 1099511628211ULL;
        }
    }

    template <typename T>
    void Integer(T Value) noexcept {
        using U = std::make_unsigned_t<T>;
        U Encoded = static_cast<U>(Value);
        for (std::size_t I = 0; I < sizeof(U); ++I) {
            const std::uint8_t Byte = static_cast<std::uint8_t>(Encoded & 0xFF);
            Bytes(&Byte, 1);
            Encoded >>= 8;
        }
    }

    void Boolean(bool Value) noexcept { Integer<std::uint8_t>(Value ? 1 : 0); }

    void String(std::string_view Value) noexcept {
        Integer<std::uint64_t>(Value.size());
        Bytes(Value.data(), Value.size());
    }

    std::uint64_t Value() const noexcept { return Value_; }

private:
    std::uint64_t Value_ = 14695981039346656037ULL;
};

} // namespace

const WindowsBuildProfile* SelectByBuild(std::uint32_t BuildNumber) noexcept {
    for (const auto& Profile : BuiltIns()) {
        if (Profile.BuildNumber == BuildNumber) return &Profile;
    }
    return nullptr;
}

const WindowsBuildProfile* SelectByName(std::string_view Name) noexcept {
    for (const auto& Profile : BuiltIns()) {
        if (Profile.Name == Name) return &Profile;
    }
    return nullptr;
}

OverrideResult LoadOverride(std::string_view JsonText) {
    ValidationResult Result;
    JsonValue Root;
    JsonParser Parser(JsonText, Result);
    if (!Parser.Parse(Root)) return {std::nullopt, std::move(Result)};
    if (Root.Type != JsonValue::Kind::Object) {
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, "$", "profile override root must be an object");
        return {std::nullopt, std::move(Result)};
    }
    const WindowsBuildProfile* Base = ResolveBase(Root, Result);
    if (!Base) return {std::nullopt, std::move(Result)};
    return ApplyOverride(*Base, Root, std::move(Result));
}

OverrideResult LoadOverride(const WindowsBuildProfile& Base, std::string_view JsonText) {
    ValidationResult Result;
    JsonValue Root;
    JsonParser Parser(JsonText, Result);
    if (!Parser.Parse(Root)) return {std::nullopt, std::move(Result)};
    return ApplyOverride(Base, Root, std::move(Result));
}

ValidationResult Validate(const WindowsBuildProfile& Profile) {
    ValidationResult Result;
    if (!IsProfileNameValid(Profile.Name))
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.name", "name must be 1-63 ASCII letters, digits, '.', '_' or '-'");
    if (Profile.BuildNumber < 10240 || Profile.BuildNumber > 99999)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.build", "unsupported Windows build number range");

    const CpuData& C = Profile.Cpu;
    if (C.Vendor.size() != 12)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.cpu.vendor", "CPUID vendor must contain exactly 12 bytes");
    if (C.Brand.empty() || C.Brand.size() > 48)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.cpu.brand", "CPUID brand must contain 1-48 bytes");
    if (C.Signature == 0)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.cpu.signature", "CPU signature must be nonzero");
    if (C.CoreCount == 0 || C.ThreadsPerCore == 0 || C.LogicalProcessorCount == 0 ||
        static_cast<std::uint64_t>(C.CoreCount) * C.ThreadsPerCore != C.LogicalProcessorCount)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.cpu.logical_processors", "logical processor count must equal cores times threads_per_core");
    if (C.LogicalProcessorCount > 256 || C.CoreCount > 256 || C.ThreadsPerCore > 64)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.cpu.logical_processors", "CPU topology exceeds supported limits");
    if (C.BaseFrequencyMhz == 0 || C.MaximumFrequencyMhz < C.BaseFrequencyMhz || C.MaximumFrequencyMhz > 20000)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.cpu.maximum_frequency_mhz", "maximum frequency must be at least the nonzero base frequency");
    if (C.BusFrequencyMhz == 0 || C.BusFrequencyMhz > C.BaseFrequencyMhz)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.cpu.bus_frequency_mhz", "bus frequency must be nonzero and no greater than base frequency");
    if (C.CrystalFrequencyHz == 0 || C.CrystalFrequencyHz > 1000000000ULL ||
        C.TscNumerator == 0 || C.TscNumerator > 4096 || C.TscDenominator == 0 || C.TscDenominator > 4096) {
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.cpu.tsc_frequency_hz", "invalid TSC ratio inputs");
    } else {
        const std::uint64_t Product = C.CrystalFrequencyHz * C.TscNumerator;
        if (Product % C.TscDenominator != 0 || Product / C.TscDenominator != C.TscFrequencyHz)
            AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.cpu.tsc_frequency_hz", "TSC frequency does not match crystal frequency ratio");
    }
    if (C.InitialTsc == 0)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.cpu.initial_tsc", "initial TSC must be nonzero");
    if ((C.Xcr0Mask & 0x3) != 0x3)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.cpu.xcr0_mask", "XCR0 must enable x87 and SSE state");
    if (C.PhysicalAddressBits < 32 || C.PhysicalAddressBits > 64)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.cpu.physical_address_bits", "physical address width must be 32-64 bits");
    if (C.VirtualAddressBits < 32 || C.VirtualAddressBits > 64)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.cpu.virtual_address_bits", "virtual address width must be 32-64 bits");
    if ((C.Leaf1Ecx & (1u << 31)) != 0 && !Profile.Policy.HypervisorPresent)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.cpu.leaf1_ecx", "CPUID hypervisor bit conflicts with policy.hypervisor_present");

    const StructureOffsetData& S = Profile.Structures;
    auto ValidateSize = [&](const char* Path, std::uint32_t Size) {
        if (Size < 0x40 || Size > 0x10000 || (Size & 7) != 0)
            AddDiagnostic(Result, DiagnosticCode::OutOfRange, Path, "structure size must be 8-byte aligned and between 0x40 and 0x10000");
    };
    ValidateSize("$.structures.driver_object_size", S.DriverObjectSize);
    ValidateSize("$.structures.device_object_size", S.DeviceObjectSize);
    ValidateSize("$.structures.eprocess_size", S.EprocessSize);
    ValidateSize("$.structures.ethread_size", S.EthreadSize);
    ValidateSize("$.structures.kthread_size", S.KthreadSize);
    ValidateOffset(Result, "$.structures.eprocess_unique_process_id", S.EprocessUniqueProcessId, 8, S.EprocessSize);
    ValidateOffset(Result, "$.structures.eprocess_active_process_links", S.EprocessActiveProcessLinks, 16, S.EprocessSize);
    ValidateOffset(Result, "$.structures.eprocess_create_time", S.EprocessCreateTime, 8, S.EprocessSize);
    ValidateOffset(Result, "$.structures.eprocess_token", S.EprocessToken, 8, S.EprocessSize);
    ValidateOffset(Result, "$.structures.eprocess_inherited_process_id", S.EprocessInheritedProcessId, 8, S.EprocessSize);
    ValidateOffset(Result, "$.structures.eprocess_peb", S.EprocessPeb, 8, S.EprocessSize);
    ValidateOffset(Result, "$.structures.eprocess_object_table", S.EprocessObjectTable, 8, S.EprocessSize);
    ValidateOffset(Result, "$.structures.eprocess_wow64_process", S.EprocessWow64Process, 8, S.EprocessSize);
    ValidateOffset(Result, "$.structures.eprocess_image_file_name", S.EprocessImageFileName, 15, S.EprocessSize);
    ValidateOffset(Result, "$.structures.ethread_start_address", S.EthreadStartAddress, 8, S.EthreadSize);
    ValidateOffset(Result, "$.structures.ethread_client_id", S.EthreadClientId, 16, S.EthreadSize);
    ValidateOffset(Result, "$.structures.kthread_apc_state", S.KthreadApcState, 1, S.KthreadSize);
    ValidateOffset(Result, "$.structures.kthread_kernel_apc_disable", S.KthreadKernelApcDisable, 2, S.KthreadSize);
    ValidateOffset(Result, "$.structures.kthread_previous_mode", S.KthreadPreviousMode, 1, S.KthreadSize);
    if (S.KthreadSize > S.EthreadSize)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.structures.kthread_size", "KTHREAD cannot be larger than its containing ETHREAD");

    const KuserSharedDataProfile& K = Profile.KuserSharedData;
    if ((K.KernelAddress >> 48) != 0xFFFF || (K.KernelAddress & 0xFFF) != 0)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.kuser_shared_data.kernel_address", "KUSER address must be a page-aligned canonical kernel address");
    if (K.PageSize < 0x1000 || K.PageSize > 0x10000 || (K.PageSize & (K.PageSize - 1)) != 0)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.kuser_shared_data.page_size", "page size must be a power of two from 0x1000 through 0x10000");
    ValidateOffset(Result, "$.kuser_shared_data.interrupt_time", K.InterruptTime, 8, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.system_time", K.SystemTime, 8, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.nt_build_number", K.NtBuildNumber, 4, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.nt_product_type", K.NtProductType, 4, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.processor_architecture", K.ProcessorArchitecture, 2, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.nt_major_version", K.NtMajorVersion, 4, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.active_processor_count", K.ActiveProcessorCount, 4, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.active_group_count", K.ActiveGroupCount, 1, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.physical_page_count", K.PhysicalPageCount, 4, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.tick_count", K.TickCount, 12, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.cookie", K.Cookie, 4, K.PageSize);
    ValidateOffset(Result, "$.kuser_shared_data.active_processor_count_deprecated", K.ActiveProcessorCountDeprecated, 4, K.PageSize);
    if (K.InitialSystemTime <= 0)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.kuser_shared_data.initial_system_time", "initial system time must be positive");

    const FirmwareProfile& F = Profile.Firmware;
    if (static_cast<std::uint32_t>(F.FirmwareType) > 2)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.firmware.type", "firmware type is outside the Windows FIRMWARE_TYPE range");
    if (F.BiosVendor.empty() || F.BiosVendor.size() > 64 || F.BiosVersion.empty() || F.BiosVersion.size() > 64 ||
        F.SystemManufacturer.empty() || F.SystemManufacturer.size() > 64 ||
        F.SystemProductName.empty() || F.SystemProductName.size() > 64)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.firmware", "SMBIOS identity strings must contain 1-64 bytes");
    if (F.AcpiOemId.size() != 6)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.firmware.acpi_oem_id", "ACPI OEM ID must contain exactly 6 bytes");
    if (F.AcpiOemTableId.size() != 8)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.firmware.acpi_oem_table_id", "ACPI OEM table ID must contain exactly 8 bytes");

    const PciIommuProfile& P = Profile.PciIommu;
    if (P.HostBridgeDevice > 31 || P.IommuDevice > 31 || P.HostBridgeFunction > 7 || P.IommuFunction > 7)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.pci_iommu", "PCI device/function is outside configuration-space range");
    if (P.HostBridgeVendorId == 0 || P.HostBridgeVendorId == 0xFFFF || P.HostBridgeDeviceId == 0 || P.HostBridgeDeviceId == 0xFFFF ||
        P.IommuVendorId == 0 || P.IommuVendorId == 0xFFFF || P.IommuDeviceId == 0 || P.IommuDeviceId == 0xFFFF)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.pci_iommu", "PCI vendor and device IDs must describe present hardware");
    if ((P.IommuRegisterBase & 0xFFF) != 0 || P.IommuRegisterBase == 0 ||
        P.IommuRegisterSize < 0x1000 || (P.IommuRegisterSize & 0xFFF) != 0)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.pci_iommu.iommu_register_base", "IOMMU MMIO range must be nonzero and page aligned");
    if ((P.TranslationEnabled || P.InterruptRemapping) && !P.DmaRemapping)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.pci_iommu.dma_remapping", "translation features require DMA remapping");

    const PolicyProfile& Policy = Profile.Policy;
    if (Policy.TestSigningEnabled && Policy.SecureBootEnabled)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.policy.test_signing_enabled", "test signing cannot be enabled with secure boot");
    if (Policy.VirtualizationBasedSecurity && !Policy.HypervisorPresent)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.policy.virtualization_based_security", "VBS requires a visible hypervisor");
    if (Policy.HvciOptions != 0 && !Policy.VirtualizationBasedSecurity)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.policy.hvci_options", "nonzero HVCI options require VBS");
    if (Policy.KernelDmaProtection && !P.DmaRemapping)
        AddDiagnostic(Result, DiagnosticCode::Incoherent, "$.policy.kernel_dma_protection", "kernel DMA protection requires IOMMU DMA remapping");
    return Result;
}

std::uint64_t Fingerprint(const WindowsBuildProfile& Profile) noexcept {
    StableHasher H;
    H.String("kevlar.windows-build-profile.v1");
    H.String(Profile.Name);
    H.Integer(Profile.BuildNumber);
#define HASH_CPU(Field) H.Integer(Profile.Cpu.Field)
    H.String(Profile.Cpu.Vendor); H.String(Profile.Cpu.Brand);
    HASH_CPU(Signature); HASH_CPU(LogicalProcessorCount); HASH_CPU(CoreCount); HASH_CPU(ThreadsPerCore);
    HASH_CPU(BaseFrequencyMhz); HASH_CPU(MaximumFrequencyMhz); HASH_CPU(BusFrequencyMhz);
    HASH_CPU(CrystalFrequencyHz); HASH_CPU(TscNumerator); HASH_CPU(TscDenominator); HASH_CPU(TscFrequencyHz);
    HASH_CPU(InitialTsc); HASH_CPU(Xcr0Mask); HASH_CPU(PhysicalAddressBits); HASH_CPU(VirtualAddressBits);
    HASH_CPU(Leaf1Ecx); HASH_CPU(Leaf1Edx); HASH_CPU(Leaf7Ebx); HASH_CPU(Leaf7Ecx); HASH_CPU(Leaf7Edx);
#undef HASH_CPU
#define HASH_STRUCTURE(Field) H.Integer(Profile.Structures.Field)
    HASH_STRUCTURE(DriverObjectSize); HASH_STRUCTURE(DeviceObjectSize); HASH_STRUCTURE(EprocessSize);
    HASH_STRUCTURE(EthreadSize); HASH_STRUCTURE(KthreadSize); HASH_STRUCTURE(EprocessUniqueProcessId);
    HASH_STRUCTURE(EprocessActiveProcessLinks); HASH_STRUCTURE(EprocessCreateTime); HASH_STRUCTURE(EprocessToken);
    HASH_STRUCTURE(EprocessInheritedProcessId); HASH_STRUCTURE(EprocessPeb); HASH_STRUCTURE(EprocessObjectTable);
    HASH_STRUCTURE(EprocessWow64Process); HASH_STRUCTURE(EprocessImageFileName); HASH_STRUCTURE(EthreadStartAddress);
    HASH_STRUCTURE(EthreadClientId); HASH_STRUCTURE(KthreadApcState); HASH_STRUCTURE(KthreadKernelApcDisable);
    HASH_STRUCTURE(KthreadPreviousMode);
#undef HASH_STRUCTURE
#define HASH_KUSER(Field) H.Integer(Profile.KuserSharedData.Field)
    HASH_KUSER(KernelAddress); HASH_KUSER(PageSize); HASH_KUSER(InterruptTime); HASH_KUSER(SystemTime);
    HASH_KUSER(NtBuildNumber); HASH_KUSER(NtProductType); HASH_KUSER(ProcessorArchitecture); HASH_KUSER(NtMajorVersion);
    HASH_KUSER(ActiveProcessorCount); HASH_KUSER(ActiveGroupCount); HASH_KUSER(PhysicalPageCount);
    HASH_KUSER(TickCount); HASH_KUSER(Cookie); HASH_KUSER(ActiveProcessorCountDeprecated); HASH_KUSER(InitialSystemTime);
#undef HASH_KUSER
    H.Integer(static_cast<std::uint32_t>(Profile.Firmware.FirmwareType));
    H.Bytes(Profile.Firmware.BootIdentifier.data(), Profile.Firmware.BootIdentifier.size());
    H.Integer(Profile.Firmware.BootFlags); H.String(Profile.Firmware.BiosVendor); H.String(Profile.Firmware.BiosVersion);
    H.String(Profile.Firmware.SystemManufacturer); H.String(Profile.Firmware.SystemProductName);
    H.String(Profile.Firmware.AcpiOemId); H.String(Profile.Firmware.AcpiOemTableId);
#define HASH_PCI(Field) H.Integer(Profile.PciIommu.Field)
    HASH_PCI(Segment); HASH_PCI(Bus); HASH_PCI(HostBridgeDevice); HASH_PCI(HostBridgeFunction);
    HASH_PCI(HostBridgeVendorId); HASH_PCI(HostBridgeDeviceId); HASH_PCI(HostBridgeRevision);
    HASH_PCI(IommuDevice); HASH_PCI(IommuFunction); HASH_PCI(IommuVendorId); HASH_PCI(IommuDeviceId);
    HASH_PCI(IommuRevision); HASH_PCI(IommuRegisterBase); HASH_PCI(IommuRegisterSize);
#undef HASH_PCI
    H.Boolean(Profile.PciIommu.TranslationEnabled); H.Boolean(Profile.PciIommu.InterruptRemapping); H.Boolean(Profile.PciIommu.DmaRemapping);
    H.Integer(Profile.Policy.CodeIntegrityOptions); H.Integer(Profile.Policy.HvciOptions);
    H.Integer(Profile.Policy.CodeIntegrityPolicyVersion); H.Boolean(Profile.Policy.SecureBootEnabled);
    H.Boolean(Profile.Policy.TestSigningEnabled); H.Boolean(Profile.Policy.HypervisorPresent);
    H.Boolean(Profile.Policy.VirtualizationBasedSecurity); H.Boolean(Profile.Policy.KernelDmaProtection);
    return H.Value();
}

std::string FingerprintHex(const WindowsBuildProfile& Profile) {
    char Text[17]{};
    std::snprintf(Text, sizeof(Text), "%016llx", static_cast<unsigned long long>(Fingerprint(Profile)));
    return Text;
}

} // namespace Kevlar::Profile
