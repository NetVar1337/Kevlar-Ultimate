#pragma once

#include "framework_provider.h"

#include <map>
#include <mutex>
#include <optional>

namespace Kevlar::Host::Frameworks {

enum class FltFilterState : std::uint8_t { Registered, Started };
enum class FltInstanceState : std::uint8_t { Created, Active };
enum class FltOperationState : std::uint8_t { PrePending, PostPending };

struct FltFilterCallbacks {
    CallbackDescriptor Unload{"FilterUnload", 0, 1};
    CallbackDescriptor InstanceSetup{"InstanceSetup", 0, 3};
    CallbackDescriptor InstanceTeardownStart{"InstanceTeardownStart", 0, 2};
    CallbackDescriptor InstanceTeardownComplete{"InstanceTeardownComplete", 0, 2};

    bool operator==(const FltFilterCallbacks&) const = default;
};

struct FltOperationCallbacks {
    CallbackDescriptor Pre{"PreOperation", 0, 3};
    CallbackDescriptor Post{"PostOperation", 0, 4};

    bool operator==(const FltOperationCallbacks&) const = default;
};

struct FltFilterSnapshot {
    GuestHandle Handle;
    GuestAddress DriverObject = 0;
    FltFilterState State = FltFilterState::Registered;
    FltFilterCallbacks Callbacks;
    std::map<std::uint8_t, FltOperationCallbacks> Operations;

    bool operator==(const FltFilterSnapshot&) const = default;
};

struct FltInstanceSnapshot {
    GuestHandle Handle;
    GuestHandle Filter;
    GuestAddress Volume = 0;
    FltInstanceState State = FltInstanceState::Created;

    bool operator==(const FltInstanceSnapshot&) const = default;
};

struct FltContextSnapshot {
    GuestHandle Handle;
    GuestHandle Owner;
    std::uint64_t TypeKey = 0;
    GuestAddress Address = 0;
    std::size_t Size = 0;
    CallbackDescriptor Cleanup{"ContextCleanup", 0, 2};

    bool operator==(const FltContextSnapshot&) const = default;
};

struct FltOperationSnapshot {
    GuestHandle Handle;
    GuestHandle Instance;
    std::uint8_t MajorFunction = 0;
    FltOperationState State = FltOperationState::PrePending;
    GuestAddress CallbackData = 0;
    GuestAddress RelatedObjects = 0;
    GuestAddress CompletionContext = 0;

    bool operator==(const FltOperationSnapshot&) const = default;
};

struct FltSnapshot {
    std::uint64_t NextHandleId = 1;
    std::uint64_t NextEventSequence = 1;
    std::map<GuestHandle, FltFilterSnapshot> Filters;
    std::map<GuestHandle, FltInstanceSnapshot> Instances;
    std::map<GuestHandle, FltContextSnapshot> Contexts;
    std::map<GuestHandle, FltOperationSnapshot> Operations;

    bool operator==(const FltSnapshot&) const = default;
};

struct FltBeginOperationResult {
    GuestHandle Operation;
    std::optional<CallbackInvocation> PreCallback;
};

class FltmgrProvider final : public FrameworkProvider {
public:
    explicit FltmgrProvider(GuestAddressValidator Validator);

    [[nodiscard]] std::string_view Name() const noexcept override;
    [[nodiscard]] CapabilityReport Capabilities() const override;
    [[nodiscard]] ProviderState CaptureState() const override;
    [[nodiscard]] Status ValidateState(const ProviderState& State) const override;
    [[nodiscard]] Status RestoreState(const ProviderState& State) override;
    void Reset() override;

    [[nodiscard]] Result<GuestHandle> RegisterFilter(
        GuestAddress DriverObject, FltFilterCallbacks Callbacks,
        std::map<std::uint8_t, FltOperationCallbacks> Operations);
    [[nodiscard]] Status StartFiltering(GuestHandle Filter);
    [[nodiscard]] Result<GuestHandle> CreateInstance(
        GuestHandle Filter, GuestAddress Volume);
    [[nodiscard]] Result<std::optional<CallbackInvocation>> ActivateInstance(
        GuestHandle Instance);
    [[nodiscard]] Result<GuestHandle> SetContext(
        GuestHandle Owner, std::uint64_t TypeKey, GuestAddress Address,
        std::size_t Size, CallbackDescriptor Cleanup = {"ContextCleanup", 0, 2});
    [[nodiscard]] Result<std::optional<CallbackInvocation>> DeleteContext(GuestHandle Context);

    [[nodiscard]] Result<FltBeginOperationResult> BeginOperation(
        GuestHandle Instance, std::uint8_t MajorFunction,
        GuestAddress CallbackData, GuestAddress RelatedObjects);
    [[nodiscard]] Status AcknowledgePreOperation(
        GuestHandle Operation, bool RequestPostCallback,
        GuestAddress CompletionContext = 0);
    [[nodiscard]] Result<std::optional<CallbackInvocation>> CompleteOperation(
        GuestHandle Operation, std::uint64_t OperationStatus);

    [[nodiscard]] Result<std::vector<CallbackInvocation>> DetachInstance(GuestHandle Instance);
    [[nodiscard]] Result<std::optional<CallbackInvocation>> UnregisterFilter(GuestHandle Filter);
    [[nodiscard]] Result<std::vector<CallbackInvocation>> Cleanup();

    [[nodiscard]] FltSnapshot Snapshot() const;
    [[nodiscard]] Status Restore(const FltSnapshot& Snapshot);

private:
    static constexpr std::uint16_t HandleTag = 0x464C;
    static constexpr std::uint32_t StateVersion = 1;

    [[nodiscard]] GuestHandle AllocateHandleLocked();
    [[nodiscard]] bool ValidateCallbacks(const FltFilterCallbacks& Callbacks) const;
    [[nodiscard]] bool ValidateCallbacks(const FltOperationCallbacks& Callbacks) const;
    [[nodiscard]] Status ValidateSnapshot(const FltSnapshot& Snapshot) const;
    [[nodiscard]] CallbackInvocation InvokeLocked(
        const CallbackDescriptor& Callback,
        std::initializer_list<GuestAddress> Arguments);
    void DeleteOwnedContextsLocked(
        GuestHandle Owner, std::vector<CallbackInvocation>& Events);

    GuestAddressValidator Validator_;
    mutable std::mutex Mutex_;
    FltSnapshot State_;
};

} // namespace Kevlar::Host::Frameworks
