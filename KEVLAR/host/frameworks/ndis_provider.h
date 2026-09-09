#pragma once

#include "framework_provider.h"

#include <map>
#include <mutex>
#include <optional>

namespace Kevlar::Host::Frameworks {

enum class NdisDriverKind : std::uint8_t { Miniport, Filter };
enum class NdisAdapterState : std::uint8_t {
    Initializing,
    Paused,
    Restarting,
    Running,
    Pausing,
};
enum class NdisOperationState : std::uint8_t { Dispatched, Completed, Cancelled };

struct NdisDriverCallbacks {
    CallbackDescriptor Initialize{"InitializeAdapter", 0, 4};
    CallbackDescriptor Halt{"HaltAdapter", 0, 2};
    CallbackDescriptor Pause{"PauseAdapter", 0, 2};
    CallbackDescriptor Restart{"RestartAdapter", 0, 2};
    CallbackDescriptor OidRequest{"OidRequest", 0, 3};
    CallbackDescriptor CancelOidRequest{"CancelOidRequest", 0, 2};
    CallbackDescriptor SendNetBufferLists{"SendNetBufferLists", 0, 4};
    CallbackDescriptor CancelSend{"CancelSend", 0, 2};
    CallbackDescriptor ReceiveNetBufferLists{"ReceiveNetBufferLists", 0, 5};
    CallbackDescriptor ReturnNetBufferLists{"ReturnNetBufferLists", 0, 3};

    bool operator==(const NdisDriverCallbacks&) const = default;
};

struct NdisRegistrationSnapshot {
    GuestHandle Handle;
    NdisDriverKind Kind = NdisDriverKind::Miniport;
    GuestAddress DriverObject = 0;
    NdisDriverCallbacks Callbacks;

    bool operator==(const NdisRegistrationSnapshot&) const = default;
};

struct NdisAdapterSnapshot {
    GuestHandle Handle;
    GuestHandle Registration;
    GuestAddress AdapterContext = 0;
    NdisAdapterState State = NdisAdapterState::Initializing;

    bool operator==(const NdisAdapterSnapshot&) const = default;
};

struct NdisOidRequestSnapshot {
    GuestHandle Handle;
    GuestHandle Adapter;
    std::uint64_t RequestId = 0;
    GuestAddress Request = 0;
    NdisOperationState State = NdisOperationState::Dispatched;
    std::uint64_t CompletionStatus = 0;

    bool operator==(const NdisOidRequestSnapshot&) const = default;
};

struct NdisSendSnapshot {
    GuestHandle Handle;
    GuestHandle Adapter;
    std::uint64_t CancelId = 0;
    GuestAddress NetBufferLists = 0;
    std::uint32_t PortNumber = 0;
    std::uint32_t SendFlags = 0;
    NdisOperationState State = NdisOperationState::Dispatched;
    std::uint64_t CompletionStatus = 0;

    bool operator==(const NdisSendSnapshot&) const = default;
};

struct NdisSnapshot {
    std::uint64_t NextHandleId = 1;
    std::uint64_t NextEventSequence = 1;
    std::map<GuestHandle, NdisRegistrationSnapshot> Registrations;
    std::map<GuestHandle, NdisAdapterSnapshot> Adapters;
    std::map<GuestHandle, NdisOidRequestSnapshot> OidRequests;
    std::map<GuestHandle, NdisSendSnapshot> Sends;

    bool operator==(const NdisSnapshot&) const = default;
};

struct NdisAdapterEventResult {
    GuestHandle Adapter;
    CallbackInvocation Callback;
};

struct NdisOperationEventResult {
    GuestHandle Operation;
    CallbackInvocation Callback;
};

class NdisProvider final : public FrameworkProvider {
public:
    explicit NdisProvider(GuestAddressValidator Validator);

    [[nodiscard]] std::string_view Name() const noexcept override;
    [[nodiscard]] CapabilityReport Capabilities() const override;
    [[nodiscard]] ProviderState CaptureState() const override;
    [[nodiscard]] Status ValidateState(const ProviderState& State) const override;
    [[nodiscard]] Status RestoreState(const ProviderState& State) override;
    void Reset() override;

    [[nodiscard]] Result<GuestHandle> RegisterMiniport(
        GuestAddress DriverObject, NdisDriverCallbacks Callbacks);
    [[nodiscard]] Result<GuestHandle> RegisterFilter(
        GuestAddress DriverObject, NdisDriverCallbacks Callbacks);
    [[nodiscard]] Status Unregister(GuestHandle Registration);

    [[nodiscard]] Result<NdisAdapterEventResult> BeginAdapterInitialization(
        GuestHandle Registration, GuestAddress AdapterContext,
        GuestAddress InitializationParameters);
    [[nodiscard]] Status CompleteAdapterInitialization(GuestHandle Adapter, bool Succeeded);
    [[nodiscard]] Result<CallbackInvocation> BeginRestartAdapter(
        GuestHandle Adapter, GuestAddress RestartParameters);
    [[nodiscard]] Status CompleteRestartAdapter(GuestHandle Adapter, bool Succeeded);
    [[nodiscard]] Result<CallbackInvocation> BeginPauseAdapter(
        GuestHandle Adapter, GuestAddress PauseParameters);
    [[nodiscard]] Status CompletePauseAdapter(GuestHandle Adapter);
    [[nodiscard]] Result<CallbackInvocation> HaltAdapter(
        GuestHandle Adapter, std::uint64_t HaltAction);

    [[nodiscard]] Result<NdisOperationEventResult> BeginOidRequest(
        GuestHandle Adapter, std::uint64_t RequestId, GuestAddress Request);
    [[nodiscard]] Status CompleteOidRequest(
        GuestHandle Operation, std::uint64_t CompletionStatus);
    [[nodiscard]] Result<CallbackInvocation> CancelOidRequest(GuestHandle Operation);

    [[nodiscard]] Result<NdisOperationEventResult> BeginSend(
        GuestHandle Adapter, std::uint64_t CancelId,
        GuestAddress NetBufferLists, std::uint32_t PortNumber,
        std::uint32_t SendFlags);
    [[nodiscard]] Status CompleteSend(
        GuestHandle Operation, std::uint64_t CompletionStatus);
    [[nodiscard]] Result<CallbackInvocation> CancelSend(GuestHandle Operation);
    [[nodiscard]] Result<CallbackInvocation> IndicateReceive(
        GuestHandle Adapter, GuestAddress NetBufferLists,
        std::uint32_t PortNumber, std::uint32_t NumberOfNetBufferLists,
        std::uint32_t ReceiveFlags);
    [[nodiscard]] Result<CallbackInvocation> ReturnReceive(
        GuestHandle Adapter, GuestAddress NetBufferLists,
        std::uint32_t ReturnFlags);

    [[nodiscard]] std::optional<NdisAdapterSnapshot> Adapter(GuestHandle Handle) const;
    [[nodiscard]] std::optional<NdisOidRequestSnapshot> OidRequest(GuestHandle Handle) const;
    [[nodiscard]] std::optional<NdisSendSnapshot> Send(GuestHandle Handle) const;
    [[nodiscard]] NdisSnapshot Snapshot() const;
    [[nodiscard]] Status Restore(const NdisSnapshot& Snapshot);

private:
    static constexpr std::uint16_t HandleTag = 0x4E44;
    static constexpr std::uint32_t StateVersion = 1;

    [[nodiscard]] Result<GuestHandle> Register(
        NdisDriverKind Kind, GuestAddress DriverObject,
        NdisDriverCallbacks Callbacks);
    [[nodiscard]] GuestHandle AllocateHandleLocked();
    [[nodiscard]] bool ValidateCallbacks(const NdisDriverCallbacks& Callbacks) const;
    [[nodiscard]] Status ValidateSnapshot(const NdisSnapshot& Snapshot) const;
    [[nodiscard]] CallbackInvocation InvokeLocked(
        const CallbackDescriptor& Callback,
        std::initializer_list<GuestAddress> Arguments);
    [[nodiscard]] bool HasOutstandingOperationsLocked(GuestHandle Adapter) const;
    void EraseAdapterHistoryLocked(GuestHandle Adapter);

    GuestAddressValidator Validator_;
    mutable std::mutex Mutex_;
    NdisSnapshot State_;
};

} // namespace Kevlar::Host::Frameworks
