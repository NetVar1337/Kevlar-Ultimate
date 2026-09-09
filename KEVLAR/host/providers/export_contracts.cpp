#include "host/providers/export_contracts.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace Kevlar::Host::Contracts {
namespace {

struct JsonValue {
    enum class Kind { Null, Boolean, Number, String, Array, Object } Type = Kind::Null;
    bool Boolean = false;
    std::uint64_t Number = 0;
    std::string String;
    std::vector<JsonValue> Array;
    std::map<std::string, JsonValue> Object;
};

struct ParseFailure final : std::runtime_error {
    ParseFailure(DiagnosticCode CodeValue, std::size_t OffsetValue, std::string MessageValue)
        : std::runtime_error(std::move(MessageValue)), Code(CodeValue), Offset(OffsetValue) {}

    DiagnosticCode Code;
    std::size_t Offset;
};

class JsonParser final {
public:
    JsonParser(std::string_view Text, const RegistryLimits& Limits)
        : Text_(Text), Limits_(Limits) {}

    JsonValue Parse() {
        SkipWhitespace();
        JsonValue Result = ParseValue(0);
        SkipWhitespace();
        if (Position_ != Text_.size())
            Fail(DiagnosticCode::JsonSyntax, "trailing data after the root value");
        return Result;
    }

private:
    JsonValue ParseValue(std::size_t Depth) {
        if (Depth > Limits_.MaximumJsonDepth)
            Fail(DiagnosticCode::OutOfRange, "JSON nesting exceeds the configured limit");
        if (++Nodes_ > Limits_.MaximumJsonNodes)
            Fail(DiagnosticCode::OutOfRange, "JSON node count exceeds the configured limit");
        if (Position_ == Text_.size())
            Fail(DiagnosticCode::JsonSyntax, "unexpected end of input");

        switch (Text_[Position_]) {
        case '{': return ParseObject(Depth);
        case '[': return ParseArray(Depth);
        case '"': {
            JsonValue Value;
            Value.Type = JsonValue::Kind::String;
            Value.String = ParseString();
            return Value;
        }
        case 't': ConsumeLiteral("true"); return MakeBoolean(true);
        case 'f': ConsumeLiteral("false"); return MakeBoolean(false);
        case 'n': ConsumeLiteral("null"); return {};
        default:
            if (Text_[Position_] >= '0' && Text_[Position_] <= '9')
                return ParseNumber();
            Fail(DiagnosticCode::JsonSyntax, "expected a JSON value");
        }
    }

    JsonValue ParseObject(std::size_t Depth) {
        JsonValue Result;
        Result.Type = JsonValue::Kind::Object;
        ++Position_;
        SkipWhitespace();
        if (Consume('}'))
            return Result;

        while (true) {
            if (Position_ == Text_.size() || Text_[Position_] != '"')
                Fail(DiagnosticCode::JsonSyntax, "expected an object key");
            const std::size_t KeyOffset = Position_;
            std::string Key = ParseString();
            SkipWhitespace();
            if (!Consume(':'))
                Fail(DiagnosticCode::JsonSyntax, "expected ':' after an object key");
            SkipWhitespace();
            JsonValue Value = ParseValue(Depth + 1);
            if (!Result.Object.emplace(Key, std::move(Value)).second)
                throw ParseFailure(DiagnosticCode::DuplicateJsonKey, KeyOffset,
                    "duplicate object key '" + Key + "'");
            SkipWhitespace();
            if (Consume('}'))
                return Result;
            if (!Consume(','))
                Fail(DiagnosticCode::JsonSyntax, "expected ',' or '}' in object");
            SkipWhitespace();
        }
    }

    JsonValue ParseArray(std::size_t Depth) {
        JsonValue Result;
        Result.Type = JsonValue::Kind::Array;
        ++Position_;
        SkipWhitespace();
        if (Consume(']'))
            return Result;

        while (true) {
            Result.Array.push_back(ParseValue(Depth + 1));
            SkipWhitespace();
            if (Consume(']'))
                return Result;
            if (!Consume(','))
                Fail(DiagnosticCode::JsonSyntax, "expected ',' or ']' in array");
            SkipWhitespace();
        }
    }

    JsonValue ParseNumber() {
        const std::size_t Start = Position_;
        if (Text_[Position_] == '0') {
            ++Position_;
            if (Position_ < Text_.size() && std::isdigit(static_cast<unsigned char>(Text_[Position_])))
                Fail(DiagnosticCode::JsonSyntax, "leading zero in integer");
        } else {
            while (Position_ < Text_.size() && std::isdigit(static_cast<unsigned char>(Text_[Position_])) != 0)
                ++Position_;
        }
        if (Position_ < Text_.size() &&
            (Text_[Position_] == '.' || Text_[Position_] == 'e' || Text_[Position_] == 'E'))
            Fail(DiagnosticCode::TypeMismatch, "catalog numbers must be unsigned integers");

        std::uint64_t Number = 0;
        for (std::size_t Index = Start; Index < Position_; ++Index) {
            const unsigned Digit = static_cast<unsigned>(Text_[Index] - '0');
            if (Number > (std::numeric_limits<std::uint64_t>::max() - Digit) / 10)
                Fail(DiagnosticCode::OutOfRange, "integer exceeds uint64 range");
            Number = Number * 10 + Digit;
        }
        JsonValue Result;
        Result.Type = JsonValue::Kind::Number;
        Result.Number = Number;
        return Result;
    }

    std::string ParseString() {
        ++Position_;
        std::string Result;
        while (Position_ < Text_.size()) {
            const unsigned char Ch = static_cast<unsigned char>(Text_[Position_++]);
            if (Ch == '"') {
                if (Result.size() > Limits_.MaximumStringBytes)
                    Fail(DiagnosticCode::OutOfRange, "string exceeds the configured byte limit");
                return Result;
            }
            if (Ch < 0x20)
                Fail(DiagnosticCode::JsonSyntax, "unescaped control character in string");
            if (Ch != '\\') {
                Result.push_back(static_cast<char>(Ch));
                if (Result.size() > Limits_.MaximumStringBytes)
                    Fail(DiagnosticCode::OutOfRange, "string exceeds the configured byte limit");
                continue;
            }
            if (Position_ == Text_.size())
                Fail(DiagnosticCode::JsonSyntax, "unterminated string escape");
            const char Escape = Text_[Position_++];
            switch (Escape) {
            case '"': Result.push_back('"'); break;
            case '\\': Result.push_back('\\'); break;
            case '/': Result.push_back('/'); break;
            case 'b': Result.push_back('\b'); break;
            case 'f': Result.push_back('\f'); break;
            case 'n': Result.push_back('\n'); break;
            case 'r': Result.push_back('\r'); break;
            case 't': Result.push_back('\t'); break;
            case 'u': {
                if (Text_.size() - Position_ < 4)
                    Fail(DiagnosticCode::JsonSyntax, "incomplete Unicode escape");
                unsigned CodePoint = 0;
                for (unsigned Index = 0; Index < 4; ++Index) {
                    const char Hex = Text_[Position_++];
                    CodePoint <<= 4;
                    if (Hex >= '0' && Hex <= '9') CodePoint |= static_cast<unsigned>(Hex - '0');
                    else if (Hex >= 'a' && Hex <= 'f') CodePoint |= static_cast<unsigned>(Hex - 'a' + 10);
                    else if (Hex >= 'A' && Hex <= 'F') CodePoint |= static_cast<unsigned>(Hex - 'A' + 10);
                    else Fail(DiagnosticCode::JsonSyntax, "invalid Unicode escape");
                }
                if (CodePoint > 0x7F)
                    Fail(DiagnosticCode::InvalidValue, "catalog strings are restricted to ASCII");
                Result.push_back(static_cast<char>(CodePoint));
                break;
            }
            default:
                Fail(DiagnosticCode::JsonSyntax, "invalid string escape");
            }
            if (Result.size() > Limits_.MaximumStringBytes)
                Fail(DiagnosticCode::OutOfRange, "string exceeds the configured byte limit");
        }
        Fail(DiagnosticCode::JsonSyntax, "unterminated string");
    }

    static JsonValue MakeBoolean(bool Value) {
        JsonValue Result;
        Result.Type = JsonValue::Kind::Boolean;
        Result.Boolean = Value;
        return Result;
    }

    void ConsumeLiteral(std::string_view Literal) {
        if (Text_.substr(Position_, Literal.size()) != Literal)
            Fail(DiagnosticCode::JsonSyntax, "invalid JSON literal");
        Position_ += Literal.size();
    }

    bool Consume(char Ch) {
        if (Position_ < Text_.size() && Text_[Position_] == Ch) {
            ++Position_;
            return true;
        }
        return false;
    }

    void SkipWhitespace() {
        while (Position_ < Text_.size()) {
            const char Ch = Text_[Position_];
            if (Ch != ' ' && Ch != '\t' && Ch != '\r' && Ch != '\n')
                break;
            ++Position_;
        }
    }

    [[noreturn]] void Fail(DiagnosticCode Code, std::string Message) const {
        throw ParseFailure(Code, Position_, std::move(Message));
    }

    std::string_view Text_;
    const RegistryLimits& Limits_;
    std::size_t Position_ = 0;
    std::size_t Nodes_ = 0;
};

void AddDiagnostic(OperationResult& Result, DiagnosticCode Code, std::string Path,
    std::string Message, std::string Module = {}, std::string Name = {}) {
    Result.Diagnostics.push_back({ DiagnosticSeverity::Error, Code, std::move(Path),
        std::move(Module), std::move(Name), std::nullopt, std::move(Message) });
}

bool HasOnlyKeys(const JsonValue& Value, std::initializer_list<std::string_view> Allowed,
    std::string_view Path, OperationResult& Result) {
    bool Valid = true;
    for (const auto& [Key, Ignored] : Value.Object) {
        (void)Ignored;
        if (std::find(Allowed.begin(), Allowed.end(), Key) == Allowed.end()) {
            AddDiagnostic(Result, DiagnosticCode::UnknownJsonKey,
                std::string(Path) + "." + Key, "unknown field '" + Key + "'");
            Valid = false;
        }
    }
    return Valid;
}

const JsonValue* RequiredField(const JsonValue& Object, std::string_view Key,
    JsonValue::Kind Kind, std::string_view Path, OperationResult& Result) {
    const auto It = Object.Object.find(std::string(Key));
    if (It == Object.Object.end()) {
        AddDiagnostic(Result, DiagnosticCode::MissingField,
            std::string(Path) + "." + std::string(Key), "required field is missing");
        return nullptr;
    }
    if (It->second.Type != Kind) {
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch,
            std::string(Path) + "." + std::string(Key), "field has the wrong JSON type");
        return nullptr;
    }
    return &It->second;
}

const JsonValue* OptionalField(const JsonValue& Object, std::string_view Key) {
    const auto It = Object.Object.find(std::string(Key));
    return It == Object.Object.end() ? nullptr : &It->second;
}

std::optional<ReturnPolicy> ParseReturnPolicy(std::string_view Value) {
    if (Value == "ntstatus") return ReturnPolicy::NtStatus;
    if (Value == "boolean") return ReturnPolicy::Boolean;
    if (Value == "pointer") return ReturnPolicy::Pointer;
    if (Value == "void") return ReturnPolicy::Void;
    if (Value == "unsigned_integer") return ReturnPolicy::UnsignedInteger;
    return std::nullopt;
}

std::optional<BufferDirection> ParseBufferDirection(std::string_view Value) {
    if (Value == "out") return BufferDirection::Out;
    if (Value == "inout") return BufferDirection::InOut;
    return std::nullopt;
}

bool IsAsciiToken(std::string_view Value, bool SideEffect) {
    if (Value.empty())
        return false;
    for (const unsigned char Ch : Value) {
        if (std::isalnum(Ch) != 0 || Ch == '_' || Ch == '-' || Ch == '.')
            continue;
        if (!SideEffect && (Ch == '$' || Ch == '@' || Ch == '?'))
            continue;
        return false;
    }
    return true;
}

OperationResult ParseContract(const JsonValue& Value, std::size_t Index,
    const RegistryLimits& Limits, ExportContract& Contract) {
    OperationResult Result;
    const std::string Path = "$.contracts[" + std::to_string(Index) + "]";
    if (Value.Type != JsonValue::Kind::Object) {
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, Path, "contract must be an object");
        return Result;
    }
    HasOnlyKeys(Value, { "module", "name", "argument_count", "irql_ceiling",
        "return_policy", "output_buffers", "side_effects" }, Path, Result);

    const JsonValue* Module = RequiredField(Value, "module", JsonValue::Kind::String, Path, Result);
    const JsonValue* Name = RequiredField(Value, "name", JsonValue::Kind::String, Path, Result);
    const JsonValue* ArgumentCount = RequiredField(Value, "argument_count", JsonValue::Kind::Number, Path, Result);
    const JsonValue* IrqlCeiling = RequiredField(Value, "irql_ceiling", JsonValue::Kind::Number, Path, Result);
    const JsonValue* Return = RequiredField(Value, "return_policy", JsonValue::Kind::String, Path, Result);
    if (!Module || !Name || !ArgumentCount || !IrqlCeiling || !Return)
        return Result;

    Contract.Module = Module->String;
    Contract.Name = Name->String;
    if (ArgumentCount->Number > Limits.MaximumArguments) {
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, Path + ".argument_count",
            "argument count exceeds the configured limit");
    } else {
        Contract.ArgumentCount = static_cast<std::uint8_t>(ArgumentCount->Number);
    }
    if (IrqlCeiling->Number > 31) {
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, Path + ".irql_ceiling",
            "IRQL ceiling must be between 0 and 31");
    } else {
        Contract.IrqlCeiling = static_cast<std::uint8_t>(IrqlCeiling->Number);
    }
    const auto ParsedReturn = ParseReturnPolicy(Return->String);
    if (!ParsedReturn) {
        AddDiagnostic(Result, DiagnosticCode::InvalidValue, Path + ".return_policy",
            "unsupported return policy '" + Return->String + "'");
    } else {
        Contract.Return = *ParsedReturn;
    }

    if (const JsonValue* Effects = OptionalField(Value, "side_effects")) {
        if (Effects->Type != JsonValue::Kind::Array) {
            AddDiagnostic(Result, DiagnosticCode::TypeMismatch, Path + ".side_effects",
                "side_effects must be an array");
        } else if (Effects->Array.size() > Limits.MaximumSideEffectsPerContract) {
            AddDiagnostic(Result, DiagnosticCode::OutOfRange, Path + ".side_effects",
                "side effect count exceeds the configured limit");
        } else {
            for (std::size_t EffectIndex = 0; EffectIndex < Effects->Array.size(); ++EffectIndex) {
                const JsonValue& Effect = Effects->Array[EffectIndex];
                const std::string EffectPath = Path + ".side_effects[" + std::to_string(EffectIndex) + "]";
                if (Effect.Type != JsonValue::Kind::String) {
                    AddDiagnostic(Result, DiagnosticCode::TypeMismatch, EffectPath,
                        "side effect tag must be a string");
                } else {
                    Contract.SideEffects.push_back(Effect.String);
                }
            }
        }
    }

    if (const JsonValue* Rules = OptionalField(Value, "output_buffers")) {
        if (Rules->Type != JsonValue::Kind::Array) {
            AddDiagnostic(Result, DiagnosticCode::TypeMismatch, Path + ".output_buffers",
                "output_buffers must be an array");
        } else if (Rules->Array.size() > Limits.MaximumOutputRulesPerContract) {
            AddDiagnostic(Result, DiagnosticCode::OutOfRange, Path + ".output_buffers",
                "output rule count exceeds the configured limit");
        } else {
            for (std::size_t RuleIndex = 0; RuleIndex < Rules->Array.size(); ++RuleIndex) {
                const JsonValue& Rule = Rules->Array[RuleIndex];
                const std::string RulePath = Path + ".output_buffers[" + std::to_string(RuleIndex) + "]";
                if (Rule.Type != JsonValue::Kind::Object) {
                    AddDiagnostic(Result, DiagnosticCode::TypeMismatch, RulePath,
                        "output buffer rule must be an object");
                    continue;
                }
                HasOnlyKeys(Rule, { "argument", "length_argument", "minimum_size",
                    "direction", "nullable", "writes_on_success_only" }, RulePath, Result);
                const JsonValue* Argument = RequiredField(Rule, "argument", JsonValue::Kind::Number, RulePath, Result);
                const JsonValue* MinimumSize = RequiredField(Rule, "minimum_size", JsonValue::Kind::Number, RulePath, Result);
                const JsonValue* Direction = RequiredField(Rule, "direction", JsonValue::Kind::String, RulePath, Result);
                const JsonValue* Nullable = RequiredField(Rule, "nullable", JsonValue::Kind::Boolean, RulePath, Result);
                const JsonValue* WritesOnSuccess = RequiredField(Rule, "writes_on_success_only", JsonValue::Kind::Boolean, RulePath, Result);
                const JsonValue* LengthArgument = OptionalField(Rule, "length_argument");
                if (!Argument || !MinimumSize || !Direction || !Nullable || !WritesOnSuccess)
                    continue;

                OutputBufferRule ParsedRule;
                bool RuleValid = true;
                if (Argument->Number >= Contract.ArgumentCount) {
                    AddDiagnostic(Result, DiagnosticCode::OutOfRange, RulePath + ".argument",
                        "output buffer argument index is outside the call arguments");
                    RuleValid = false;
                } else {
                    ParsedRule.ArgumentIndex = static_cast<std::uint8_t>(Argument->Number);
                }
                if (LengthArgument && LengthArgument->Type != JsonValue::Kind::Null) {
                    if (LengthArgument->Type != JsonValue::Kind::Number) {
                        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, RulePath + ".length_argument",
                            "length_argument must be an integer or null");
                        RuleValid = false;
                    } else if (LengthArgument->Number >= Contract.ArgumentCount) {
                        AddDiagnostic(Result, DiagnosticCode::OutOfRange, RulePath + ".length_argument",
                            "length argument index is outside the call arguments");
                        RuleValid = false;
                    } else {
                        ParsedRule.LengthArgumentIndex = static_cast<std::uint8_t>(LengthArgument->Number);
                    }
                }
                ParsedRule.MinimumSize = MinimumSize->Number;
                const auto ParsedDirection = ParseBufferDirection(Direction->String);
                if (!ParsedDirection) {
                    AddDiagnostic(Result, DiagnosticCode::InvalidValue, RulePath + ".direction",
                        "direction must be 'out' or 'inout'");
                    RuleValid = false;
                } else {
                    ParsedRule.Direction = *ParsedDirection;
                }
                ParsedRule.Nullable = Nullable->Boolean;
                ParsedRule.WritesOnSuccessOnly = WritesOnSuccess->Boolean;
                if (RuleValid)
                    Contract.OutputBuffers.push_back(ParsedRule);
            }
        }
    }
    return Result;
}

bool IsSuccessful(ReturnPolicy Policy, std::uint64_t Value) {
    switch (Policy) {
    case ReturnPolicy::NtStatus:
        return static_cast<std::int32_t>(static_cast<std::uint32_t>(Value)) >= 0;
    case ReturnPolicy::Boolean:
    case ReturnPolicy::Pointer:
        return Value != 0;
    case ReturnPolicy::Void:
    case ReturnPolicy::UnsignedInteger:
        return true;
    }
    return false;
}

Diagnostic CallDiagnostic(DiagnosticCode Code, std::string_view Module,
    std::string_view Name, std::string Message,
    std::optional<std::size_t> ArgumentIndex = std::nullopt) {
    return { DiagnosticSeverity::Error, Code, {}, std::string(Module), std::string(Name),
        ArgumentIndex, std::move(Message) };
}

} // namespace

bool OperationResult::Ok() const noexcept {
    return std::none_of(Diagnostics.begin(), Diagnostics.end(),
        [](const Diagnostic& Value) { return Value.Severity == DiagnosticSeverity::Error; });
}

OperationResult::operator bool() const noexcept { return Ok(); }
bool CallValidation::Ok() const noexcept { return Disposition == CallDisposition::InvokeProvider; }
CallValidation::operator bool() const noexcept { return Ok(); }
bool ResultRecord::Ok() const noexcept { return Recorded && Diagnostics.empty(); }
ResultRecord::operator bool() const noexcept { return Ok(); }

ContractRegistry::ContractRegistry(RegistryOptions Options) : Options_(std::move(Options)) {
    if (Options_.Limits.MaximumCatalogBytes == 0 || Options_.Limits.MaximumJsonDepth == 0 ||
        Options_.Limits.MaximumJsonNodes == 0 || Options_.Limits.MaximumContracts == 0 ||
        Options_.Limits.MaximumStringBytes == 0 || Options_.Limits.MaximumArguments == 0)
        throw std::invalid_argument("contract registry limits must be nonzero");
}

ContractRegistry::ContractKey ContractRegistry::MakeKey(
    std::string_view Module, std::string_view Name) {
    std::string NormalizedModule(Module);
    std::transform(NormalizedModule.begin(), NormalizedModule.end(), NormalizedModule.begin(),
        [](unsigned char Ch) { return static_cast<char>(std::tolower(Ch)); });
    return { std::move(NormalizedModule), std::string(Name) };
}

OperationResult ContractRegistry::ValidateContract(const ExportContract& Contract) const {
    OperationResult Result;
    if (!IsAsciiToken(Contract.Module, false) || Contract.Module.size() > Options_.Limits.MaximumStringBytes)
        AddDiagnostic(Result, DiagnosticCode::InvalidValue, "$.module",
            "module must be a nonempty bounded ASCII token", Contract.Module, Contract.Name);
    if (!IsAsciiToken(Contract.Name, false) || Contract.Name.size() > Options_.Limits.MaximumStringBytes)
        AddDiagnostic(Result, DiagnosticCode::InvalidValue, "$.name",
            "name must be a nonempty bounded ASCII export token", Contract.Module, Contract.Name);
    if (Contract.ArgumentCount > Options_.Limits.MaximumArguments)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.argument_count",
            "argument count exceeds the configured limit", Contract.Module, Contract.Name);
    if (Contract.IrqlCeiling > 31)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.irql_ceiling",
            "IRQL ceiling must be between 0 and 31", Contract.Module, Contract.Name);
    if (Contract.SideEffects.size() > Options_.Limits.MaximumSideEffectsPerContract)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.side_effects",
            "side effect count exceeds the configured limit", Contract.Module, Contract.Name);
    if (Contract.OutputBuffers.size() > Options_.Limits.MaximumOutputRulesPerContract)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.output_buffers",
            "output rule count exceeds the configured limit", Contract.Module, Contract.Name);

    std::set<std::string> Effects;
    for (std::size_t Index = 0; Index < Contract.SideEffects.size(); ++Index) {
        const std::string& Effect = Contract.SideEffects[Index];
        if (!IsAsciiToken(Effect, true) || Effect.size() > Options_.Limits.MaximumStringBytes) {
            AddDiagnostic(Result, DiagnosticCode::InvalidValue,
                "$.side_effects[" + std::to_string(Index) + "]",
                "side effect must be a nonempty bounded ASCII token", Contract.Module, Contract.Name);
        } else if (!Effects.insert(Effect).second) {
            AddDiagnostic(Result, DiagnosticCode::DuplicateSideEffect,
                "$.side_effects[" + std::to_string(Index) + "]",
                "duplicate side effect '" + Effect + "'", Contract.Module, Contract.Name);
        }
    }

    std::set<std::uint8_t> OutputArguments;
    for (std::size_t Index = 0; Index < Contract.OutputBuffers.size(); ++Index) {
        const OutputBufferRule& Rule = Contract.OutputBuffers[Index];
        const std::string Path = "$.output_buffers[" + std::to_string(Index) + "]";
        if (Rule.ArgumentIndex >= Contract.ArgumentCount)
            AddDiagnostic(Result, DiagnosticCode::OutOfRange, Path + ".argument",
                "output buffer argument index is outside the call arguments", Contract.Module, Contract.Name);
        if (Rule.LengthArgumentIndex && *Rule.LengthArgumentIndex >= Contract.ArgumentCount)
            AddDiagnostic(Result, DiagnosticCode::OutOfRange, Path + ".length_argument",
                "length argument index is outside the call arguments", Contract.Module, Contract.Name);
        if (!OutputArguments.insert(Rule.ArgumentIndex).second)
            AddDiagnostic(Result, DiagnosticCode::DuplicateOutputRule, Path,
                "more than one output rule targets the same argument", Contract.Module, Contract.Name);
    }
    return Result;
}

OperationResult ContractRegistry::Register(ExportContract Contract) {
    OperationResult Result = ValidateContract(Contract);
    if (!Result)
        return Result;

    const ContractKey Key = MakeKey(Contract.Module, Contract.Name);
    std::unique_lock Lock(Mutex_);
    if (Entries_.contains(Key)) {
        AddDiagnostic(Result, DiagnosticCode::DuplicateContract, {},
            "contract is already registered", Contract.Module, Contract.Name);
        return Result;
    }
    Entries_.emplace(Key, Entry{ std::move(Contract) });
    Result.ContractsAdded = 1;
    return Result;
}

OperationResult ContractRegistry::LoadCatalog(const std::filesystem::path& Path) {
    OperationResult Result;
    std::ifstream Input(Path, std::ios::binary | std::ios::ate);
    if (!Input) {
        AddDiagnostic(Result, DiagnosticCode::CatalogIo, "$", "unable to open catalog");
        return Result;
    }
    const std::streamoff End = Input.tellg();
    if (End < 0 || static_cast<std::uint64_t>(End) > Options_.Limits.MaximumCatalogBytes) {
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$", "catalog exceeds the configured byte limit");
        return Result;
    }
    std::string Text(static_cast<std::size_t>(End), '\0');
    Input.seekg(0, std::ios::beg);
    if (!Text.empty() && !Input.read(Text.data(), static_cast<std::streamsize>(Text.size()))) {
        AddDiagnostic(Result, DiagnosticCode::CatalogIo, "$", "unable to read the complete catalog");
        return Result;
    }

    JsonValue Root;
    try {
        Root = JsonParser(Text, Options_.Limits).Parse();
    } catch (const ParseFailure& Failure) {
        AddDiagnostic(Result, Failure.Code, "$@" + std::to_string(Failure.Offset), Failure.what());
        return Result;
    }
    if (Root.Type != JsonValue::Kind::Object) {
        AddDiagnostic(Result, DiagnosticCode::TypeMismatch, "$", "catalog root must be an object");
        return Result;
    }
    HasOnlyKeys(Root, { "schema_version", "build", "contracts" }, "$", Result);
    const JsonValue* SchemaVersion = RequiredField(Root, "schema_version", JsonValue::Kind::Number, "$", Result);
    const JsonValue* Build = RequiredField(Root, "build", JsonValue::Kind::Number, "$", Result);
    const JsonValue* Contracts = RequiredField(Root, "contracts", JsonValue::Kind::Array, "$", Result);
    if (!SchemaVersion || !Build || !Contracts)
        return Result;
    if (SchemaVersion->Number != 1)
        AddDiagnostic(Result, DiagnosticCode::InvalidValue, "$.schema_version", "unsupported schema version");
    if (Build->Number > std::numeric_limits<std::uint32_t>::max())
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.build", "build exceeds uint32 range");
    if (Contracts->Array.size() > Options_.Limits.MaximumContracts)
        AddDiagnostic(Result, DiagnosticCode::OutOfRange, "$.contracts", "contract count exceeds the configured limit");
    if (!Result)
        return Result;

    std::map<ContractKey, Entry> ParsedEntries;
    for (std::size_t Index = 0; Index < Contracts->Array.size(); ++Index) {
        ExportContract Contract;
        OperationResult Parsed = ParseContract(Contracts->Array[Index], Index, Options_.Limits, Contract);
        Result.Diagnostics.insert(Result.Diagnostics.end(),
            std::make_move_iterator(Parsed.Diagnostics.begin()),
            std::make_move_iterator(Parsed.Diagnostics.end()));
        if (!Parsed)
            continue;
        OperationResult Validated = ValidateContract(Contract);
        for (Diagnostic& Item : Validated.Diagnostics) {
            if (!Item.Path.empty())
                Item.Path = "$.contracts[" + std::to_string(Index) + "]" + Item.Path.substr(1);
            Result.Diagnostics.push_back(std::move(Item));
        }
        if (!Validated)
            continue;
        ContractKey Key = MakeKey(Contract.Module, Contract.Name);
        if (!ParsedEntries.emplace(Key, Entry{ Contract }).second) {
            AddDiagnostic(Result, DiagnosticCode::DuplicateContract,
                "$.contracts[" + std::to_string(Index) + "]",
                "duplicate module/export contract", Contract.Module, Contract.Name);
        }
    }
    if (!Result)
        return Result;

    std::unique_lock Lock(Mutex_);
    for (const auto& [Key, EntryValue] : ParsedEntries) {
        if (Entries_.contains(Key)) {
            AddDiagnostic(Result, DiagnosticCode::DuplicateContract, {},
                "catalog duplicates an existing registration",
                EntryValue.Contract.Module, EntryValue.Contract.Name);
        }
    }
    if (!Result)
        return Result;
    for (auto& [Key, EntryValue] : ParsedEntries)
        Entries_.emplace(std::move(Key), std::move(EntryValue));
    Result.ContractsAdded = ParsedEntries.size();
    return Result;
}

std::optional<ExportContract> ContractRegistry::Find(
    std::string_view Module, std::string_view Name) const {
    const ContractKey Key = MakeKey(Module, Name);
    std::shared_lock Lock(Mutex_);
    const auto It = Entries_.find(Key);
    if (It == Entries_.end())
        return std::nullopt;
    return It->second.Contract;
}

CallValidation ContractRegistry::ValidateCall(
    std::string_view Module, std::string_view Name, const CallContext& Context) {
    CallValidation Result;
    const ContractKey Key = MakeKey(Module, Name);
    std::unique_lock Lock(Mutex_);
    const auto It = Entries_.find(Key);
    if (It == Entries_.end()) {
        UnknownEntry& Unknown = UnknownEntries_[Key];
        if (Unknown.Calls == 0) {
            Unknown.Module = std::string(Module);
            Unknown.Name = std::string(Name);
        }
        ++Unknown.Calls;
        Result.Diagnostics.push_back(CallDiagnostic(DiagnosticCode::UnknownExport,
            Module, Name, "no contract is registered for this export"));
        if (Options_.UnknownPolicy == UnknownExportPolicy::ReturnStatusNotImplemented) {
            Result.Disposition = CallDisposition::ReturnValue;
            Result.ReturnValue = StatusNotImplemented;
        } else {
            Result.Disposition = CallDisposition::Reject;
        }
        return Result;
    }

    Entry& Found = It->second;
    const ExportContract& Contract = Found.Contract;
    if (Context.Arguments.size() != Contract.ArgumentCount) {
        Result.Diagnostics.push_back(CallDiagnostic(DiagnosticCode::ArgumentCountMismatch,
            Module, Name, "expected " + std::to_string(Contract.ArgumentCount) +
            " arguments but received " + std::to_string(Context.Arguments.size())));
    }
    if (Context.CurrentIrql > Contract.IrqlCeiling) {
        Result.Diagnostics.push_back(CallDiagnostic(DiagnosticCode::IrqlViolation,
            Module, Name, "current IRQL exceeds the contract ceiling"));
    }
    if (Context.Arguments.size() == Contract.ArgumentCount) {
        for (const OutputBufferRule& Rule : Contract.OutputBuffers) {
            const std::uint64_t Address = Context.Arguments[Rule.ArgumentIndex];
            const std::uint64_t Length = Rule.LengthArgumentIndex
                ? Context.Arguments[*Rule.LengthArgumentIndex]
                : Rule.MinimumSize;
            if (Address == 0 && !(Rule.Nullable && Length == 0)) {
                Result.Diagnostics.push_back(CallDiagnostic(DiagnosticCode::NullOutputBuffer,
                    Module, Name, "required output buffer address is zero", Rule.ArgumentIndex));
            }
            if (Length < Rule.MinimumSize) {
                Result.Diagnostics.push_back(CallDiagnostic(DiagnosticCode::OutputBufferTooSmall,
                    Module, Name, "output buffer length is below the contract minimum",
                    Rule.ArgumentIndex));
            }
        }
    }

    if (!Result.Diagnostics.empty()) {
        ++Found.ValidationFailures;
        Result.Disposition = CallDisposition::Reject;
        return Result;
    }
    ++Found.ValidatedCalls;
    Found.LastVirtualTimeTicks = Context.VirtualTimeTicks;
    Result.Disposition = CallDisposition::InvokeProvider;
    return Result;
}

ResultRecord ContractRegistry::RecordResult(
    std::string_view Module, std::string_view Name,
    std::uint64_t ReturnValue, std::uint64_t VirtualTimeTicks) {
    ResultRecord Result;
    const ContractKey Key = MakeKey(Module, Name);
    std::unique_lock Lock(Mutex_);
    const auto It = Entries_.find(Key);
    if (It == Entries_.end()) {
        Result.Diagnostics.push_back(CallDiagnostic(DiagnosticCode::UnknownExport,
            Module, Name, "cannot record a result for an unknown export"));
        return Result;
    }
    Entry& Found = It->second;
    if (Found.RecordedResults >= Found.ValidatedCalls) {
        Result.Diagnostics.push_back(CallDiagnostic(DiagnosticCode::ResultWithoutCall,
            Module, Name, "no validated call is awaiting a result"));
        return Result;
    }

    Result.Successful = IsSuccessful(Found.Contract.Return, ReturnValue);
    Result.Recorded = true;
    ++Found.RecordedResults;
    if (Result.Successful)
        ++Found.SuccessfulResults;
    Found.LastReturnValue = ReturnValue;
    Found.LastVirtualTimeTicks = VirtualTimeTicks;
    return Result;
}

CoverageStatistics ContractRegistry::CoverageReport() const {
    CoverageStatistics Result;
    Result.Seed = Options_.Seed;
    Result.InitialVirtualTimeTicks = Options_.InitialVirtualTimeTicks;
    std::shared_lock Lock(Mutex_);
    Result.TotalContracts = Entries_.size();
    Result.Contracts.reserve(Entries_.size());
    for (const auto& [Key, EntryValue] : Entries_) {
        (void)Key;
        ContractCoverage Coverage;
        Coverage.Module = EntryValue.Contract.Module;
        Coverage.Name = EntryValue.Contract.Name;
        Coverage.ValidatedCalls = EntryValue.ValidatedCalls;
        Coverage.ValidationFailures = EntryValue.ValidationFailures;
        Coverage.RecordedResults = EntryValue.RecordedResults;
        Coverage.SuccessfulResults = EntryValue.SuccessfulResults;
        Coverage.LastReturnValue = EntryValue.LastReturnValue;
        Coverage.LastVirtualTimeTicks = EntryValue.LastVirtualTimeTicks;
        if (Coverage.ValidatedCalls != 0)
            ++Result.ExercisedContracts;
        Result.ValidatedCalls += Coverage.ValidatedCalls;
        Result.ValidationFailures += Coverage.ValidationFailures;
        Result.RecordedResults += Coverage.RecordedResults;
        Result.SuccessfulResults += Coverage.SuccessfulResults;
        Result.Contracts.push_back(std::move(Coverage));
    }
    Result.UnexercisedContracts = Result.TotalContracts - Result.ExercisedContracts;
    Result.UnknownExports.reserve(UnknownEntries_.size());
    for (const auto& [Key, Unknown] : UnknownEntries_) {
        (void)Key;
        Result.UnknownExportCalls += Unknown.Calls;
        Result.UnknownExports.push_back({ Unknown.Module, Unknown.Name, Unknown.Calls });
    }
    return Result;
}

std::string_view ToString(ReturnPolicy Policy) noexcept {
    switch (Policy) {
    case ReturnPolicy::NtStatus: return "ntstatus";
    case ReturnPolicy::Boolean: return "boolean";
    case ReturnPolicy::Pointer: return "pointer";
    case ReturnPolicy::Void: return "void";
    case ReturnPolicy::UnsignedInteger: return "unsigned_integer";
    }
    return "unknown";
}

std::string_view ToString(BufferDirection Direction) noexcept {
    switch (Direction) {
    case BufferDirection::Out: return "out";
    case BufferDirection::InOut: return "inout";
    }
    return "unknown";
}

std::string_view ToString(DiagnosticCode Code) noexcept {
    static constexpr std::array<std::string_view, 17> Names = {
        "catalog_io", "json_syntax", "duplicate_json_key", "unknown_json_key",
        "missing_field", "type_mismatch", "out_of_range", "invalid_value",
        "duplicate_contract", "duplicate_side_effect", "duplicate_output_rule",
        "unknown_export", "argument_count_mismatch", "irql_violation",
        "null_output_buffer", "output_buffer_too_small", "result_without_call"
    };
    const std::size_t Index = static_cast<std::size_t>(Code);
    return Index < Names.size() ? Names[Index] : "unknown";
}

} // namespace Kevlar::Host::Contracts
