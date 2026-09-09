#pragma once

#include "framework_provider.h"

#include <deque>
#include <map>
#include <mutex>
#include <optional>

namespace Kevlar::Host::Frameworks {

enum class StorportAdapterState : std::uint8_t {
    Discovering,
    Stopped,
    Starting,
    Started,
    Stopping,
    Resetting,
};
enum class StorportSrbState : std::uint8_t { Queued, Dispatched, Completed, Cancelled };

struct StorportMiniportCallbacks {
    CallbackDescriptor FindAdapter{"HwFindAdapter", 0, 4};
    CallbackDescriptor Initialize{"HwInitialize", 0, 1};
    CallbackDescriptor StartIo{"HwStartIo", 0, 2};
    CallbackDescriptor Interrupt{"HwInterrupt", 0, 1};
    CallbackDescriptor Dpc{"HwDpcRoutine", 0, 3};
    CallbackDescriptor ResetBus{"HwResetBus", 0, 2};
    CallbackDescriptor AdapterControl{"HwAdapterControl", 0, 3};
    CallbackDescriptor CancelSrb{"HwStorCancelCommand", 0, 2};

    bool operator==(const StorportMiniportCallbacks&) const = default;
};

struct StorportRegistrationSnapshot {
    GuestHandle Handle;
    GuestAddress DriverObject = 0;
    StorportMiniportCallbacks Callbacks;

    bool operator==(const StorportRegistrationSnapshot&) const = default;
};

struct StorportAdapterSnapshot {
    GuestHandle Handle;
    GuestHandle Registration;
    GuestAddress DeviceExtension = 0;
    StorportAdapterState State = StorportAdapterState::Discovering;
    std::deque<GuestHandle> PendingSrbs;

    bool operator==(const StorportAdapterSnapshot&) const = default;
};

struct StorportSrbSnapshot {
    GuestHandle Handle;
    GuestHandle Adapter;
    GuestAddress Srb = 0;
    std::uint32_t QueueTag = 0;
    StorportSrbState State = StorportSrbState::Queued;
    std::uint64_t CompletionStatus = 0;

    bool operator==(const StorportSrbSnapshot&) const = default;
};

struct StorportSnapshot {
    std::uint64_t NextHandleId = 1;
    std::uint64_t NextEventSequence = 1;
    std::map<GuestHandle, StorportRegistrationSnapshot> Registrations;
    std::map<GuestHandle, StorportAdapterSnapshot> Adapters;
    std::map<GuestHandle, StorportSrbSnapshot> Srbs;

    bool operator==(const StorportSnapshot&) const = default;
};

struct StorportAdapterEventResult {
    GuestHandle Adapter;
    CallbackInvocation Callback;
};

struct StorportSrbEventResult {
    GuestHandle Srb;
    CallbackInvocation Callback;
};

class StorportProvider final : public FrameworkProvider {
public:
    explicit StorportProvider(GuestAddressValidator Validator);

    [[nodiscard]] std::string_view Name() const noexcept override;
    [[nodiscard]] CapabilityReport Capabilities() const override;
    [[nodiscard]] ProviderState CaptureState() const override;
    [[nodiscard]] Status ValidateState(const ProviderState& State) const override;
    [[nodiscard]] Status RestoreState(const ProviderState& State) override;
    void Reset() override;

    [[nodiscard]] Result<GuestHandle> RegisterMiniport(
        GuestAddress DriverObject, StorportMiniportCallbacks Callbacks);
    [[nodiscard]] Status UnregisterMiniport(GuestHandle Registration);
    [[nodiscard]] Result<StorportAdapterEventResult> BeginAdapterDiscovery(
        GuestHandle Registration, GuestAddress DeviceExtension,
        GuestAddress ConfigurationInformation);
    [[nodiscard]] Status CompleteAdapterDiscovery(GuestHandle Adapter, bool Found);
    [[nodiscard]] Result<CallbackInvocation> BeginStartAdapter(GuestHandle Adapter);
    [[nodiscard]] Status CompleteStartAdapter(GuestHandle Adapter, bool Succeeded);
    [[nodiscard]] Result<CallbackInvocation> BeginStopAdapter(GuestHandle Adapter);
    [[nodiscard]] Status CompleteStopAdapter(GuestHandle Adapter);
    [[nodiscard]] Result<CallbackInvocation> BeginResetAdapter(
        GuestHandle Adapter, std::uint32_t PathId);
    [[nodiscard]] Status CompleteResetAdapter(GuestHandle Adapter, bool Succeeded);
    [[nodiscard]] Status RemoveAdapter(GuestHandle Adapter);

    [[nodiscard]] Result<GuestHandle> QueueSrb(
        GuestHandle Adapter, GuestAddress Srb, std::uint32_t QueueTag);
    [[nodiscard]] Result<StorportSrbEventResult> DispatchNextSrb(GuestHandle Adapter);
    [[nodiscard]] Status CompleteSrb(GuestHandle Srb, std::uint64_t CompletionStatus);
    [[nodiscard]] Result<std::optional<CallbackInvocation>> CancelSrb(GuestHandle Srb);
    [[nodiscard]] Result<CallbackInvocation> InvokeInterrupt(GuestHandle Adapter);
    [[nodiscard]] Result<CallbackInvocation> InvokeDpc(
        GuestHandle Adapter, GuestAddress SystemArgument1,
        GuestAddress SystemArgument2);

    [[nodiscard]] std::optional<StorportAdapterSnapshot> Adapter(GuestHandle Handle) const;
    [[nodiscard]] std::optional<StorportSrbSnapshot> Srb(GuestHandle Handle) const;
    [[nodiscard]] StorportSnapshot Snapshot() const;
    [[nodiscard]] Status Restore(const StorportSnapshot& Snapshot);

private:
    static constexpr std::uint16_t HandleTag = 0x5350;
    static constexpr std::uint32_t StateVersion = 1;

    [[nodiscard]] GuestHandle AllocateHandleLocked();
    [[nodiscard]] bool ValidateCallbacks(const StorportMiniportCallbacks& Callbacks) const;
    [[nodiscard]] Status ValidateSnapshot(const StorportSnapshot& Snapshot) const;
    [[nodiscard]] CallbackInvocation InvokeLocked(
        const CallbackDescriptor& Callback,
        std::initializer_list<GuestAddress> Arguments);
    [[nodiscard]] bool HasOutstandingSrbsLocked(GuestHandle Adapter) const;
    void EraseAdapterHistoryLocked(GuestHandle Adapter);

    GuestAddressValidator Validator_;
    mutable std::mutex Mutex_;
    StorportSnapshot State_;
};

} // namespace Kevlar::Host::Frameworks
