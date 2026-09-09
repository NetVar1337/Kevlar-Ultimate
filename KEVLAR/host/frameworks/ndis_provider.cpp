#include "ndis_provider.h"

#include <algorithm>
#include <set>

namespace Kevlar::Host::Frameworks {
namespace {

constexpr std::uint64_t IdMask = (std::uint64_t{1} << 48) - 1;

bool ValidDriverKind(NdisDriverKind Kind) {
    return Kind == NdisDriverKind::Miniport || Kind == NdisDriverKind::Filter;
}

bool ValidAdapterState(NdisAdapterState State) {
    return State >= NdisAdapterState::Initializing && State <= NdisAdapterState::Pausing;
}

bool ValidOperationState(NdisOperationState State) {
    return State >= NdisOperationState::Dispatched && State <= NdisOperationState::Cancelled;
}

} // namespace

NdisProvider::NdisProvider(GuestAddressValidator Validator)
    : Validator_(std::move(Validator)) {}

std::string_view NdisProvider::Name() const noexcept { return "ndis"; }

CapabilityReport NdisProvider::Capabilities() const {
    std::scoped_lock Lock(Mutex_);
    std::size_t Pending = 0;
    for (const auto& [Handle, Request] : State_.OidRequests) {
        (void)Handle;
        if (Request.State == NdisOperationState::Dispatched) ++Pending;
    }
    for (const auto& [Handle, Send] : State_.Sends) {
        (void)Handle;
        if (Send.State == NdisOperationState::Dispatched) ++Pending;
    }
    return {std::string(Name()), StateVersion,
        {"miniport-registration", "filter-registration", "adapter-lifecycle",
         "oid-requests", "send-receive", "cancellation", "snapshot"},
        State_.Registrations.size() + State_.Adapters.size(), Pending};
}

ProviderState NdisProvider::CaptureState() const {
    return {std::string(Name()), StateVersion, Snapshot()};
}

Status NdisProvider::ValidateState(const ProviderState& State) const {
    if (State.Provider != Name() || State.Version != StateVersion) return Status::CorruptSnapshot;
    const auto* Value = std::any_cast<NdisSnapshot>(&State.State);
    return Value ? ValidateSnapshot(*Value) : Status::CorruptSnapshot;
}

Status NdisProvider::RestoreState(const ProviderState& State) {
    if (State.Provider != Name() || State.Version != StateVersion) return Status::CorruptSnapshot;
    const auto* Value = std::any_cast<NdisSnapshot>(&State.State);
    return Value ? Restore(*Value) : Status::CorruptSnapshot;
}

void NdisProvider::Reset() {
    std::scoped_lock Lock(Mutex_);
    State_ = {};
}

GuestHandle NdisProvider::AllocateHandleLocked() {
    if (!State_.NextHandleId || State_.NextHandleId > IdMask) return {};
    return MakeHandle(HandleTag, State_.NextHandleId++);
}

bool NdisProvider::ValidateCallbacks(const NdisDriverCallbacks& Callbacks) const {
    const CallbackDescriptor* Values[] = {
        &Callbacks.Initialize, &Callbacks.Halt, &Callbacks.Pause, &Callbacks.Restart,
        &Callbacks.OidRequest, &Callbacks.CancelOidRequest,
        &Callbacks.SendNetBufferLists, &Callbacks.CancelSend,
        &Callbacks.ReceiveNetBufferLists, &Callbacks.ReturnNetBufferLists,
    };
    for (const CallbackDescriptor* Callback : Values) {
        if (Callback->ArgumentCount > 8 || !ValidateCallback(Validator_, *Callback)) return false;
    }
    return Callbacks.Initialize.Present() && Callbacks.Halt.Present() &&
        Callbacks.Pause.Present() && Callbacks.Restart.Present();
}

Result<GuestHandle> NdisProvider::Register(
    NdisDriverKind Kind, GuestAddress DriverObject,
    NdisDriverCallbacks Callbacks) {
    if (!ValidDriverKind(Kind) ||
        !ValidateGuestRange(Validator_, DriverObject, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    if (!ValidateCallbacks(Callbacks)) return {Status::InvalidArgument, {}};

    std::scoped_lock Lock(Mutex_);
    for (const auto& [Handle, Registration] : State_.Registrations) {
        (void)Handle;
        if (Registration.DriverObject == DriverObject) return {Status::Duplicate, {}};
    }
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Registrations.emplace(Handle,
        NdisRegistrationSnapshot{Handle, Kind, DriverObject, std::move(Callbacks)});
    return {Status::Success, Handle};
}

Result<GuestHandle> NdisProvider::RegisterMiniport(
    GuestAddress DriverObject, NdisDriverCallbacks Callbacks) {
    return Register(NdisDriverKind::Miniport, DriverObject, std::move(Callbacks));
}

Result<GuestHandle> NdisProvider::RegisterFilter(
    GuestAddress DriverObject, NdisDriverCallbacks Callbacks) {
    return Register(NdisDriverKind::Filter, DriverObject, std::move(Callbacks));
}

Status NdisProvider::Unregister(GuestHandle Registration) {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Registrations.find(Registration);
    if (It == State_.Registrations.end()) return Status::InvalidHandle;
    for (const auto& [Handle, Adapter] : State_.Adapters) {
        (void)Handle;
        if (Adapter.Registration == Registration) return Status::Busy;
    }
    State_.Registrations.erase(It);
    return Status::Success;
}

CallbackInvocation NdisProvider::InvokeLocked(
    const CallbackDescriptor& Callback,
    std::initializer_list<GuestAddress> Arguments) {
    return MakeInvocation(State_.NextEventSequence++, Callback, Arguments);
}

Result<NdisAdapterEventResult> NdisProvider::BeginAdapterInitialization(
    GuestHandle Registration, GuestAddress AdapterContext,
    GuestAddress InitializationParameters) {
    if (!ValidateGuestRange(Validator_, AdapterContext, 1, GuestAccess::Write) ||
        !ValidateGuestRange(Validator_, InitializationParameters, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};

    std::scoped_lock Lock(Mutex_);
    const auto RegistrationIt = State_.Registrations.find(Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidHandle, {}};
    for (const auto& [Handle, Adapter] : State_.Adapters) {
        (void)Handle;
        if (Adapter.Registration == Registration && Adapter.AdapterContext == AdapterContext)
            return {Status::Duplicate, {}};
    }
    const GuestHandle Adapter = AllocateHandleLocked();
    if (!Adapter) return {Status::Busy, {}};
    State_.Adapters.emplace(Adapter, NdisAdapterSnapshot{
        Adapter, Registration, AdapterContext, NdisAdapterState::Initializing});
    return {Status::Success, {Adapter,
        InvokeLocked(RegistrationIt->second.Callbacks.Initialize,
            {Registration.Value, Adapter.Value, AdapterContext, InitializationParameters})}};
}

Status NdisProvider::CompleteAdapterInitialization(GuestHandle Adapter, bool Succeeded) {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Adapters.find(Adapter);
    if (It == State_.Adapters.end()) return Status::InvalidHandle;
    if (It->second.State != NdisAdapterState::Initializing) return Status::InvalidState;
    if (!Succeeded) {
        State_.Adapters.erase(It);
        return Status::Success;
    }
    It->second.State = NdisAdapterState::Paused;
    return Status::Success;
}

Result<CallbackInvocation> NdisProvider::BeginRestartAdapter(
    GuestHandle Adapter, GuestAddress RestartParameters) {
    if (!ValidateGuestRange(Validator_, RestartParameters, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != NdisAdapterState::Paused) return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    AdapterIt->second.State = NdisAdapterState::Restarting;
    return {Status::Success, InvokeLocked(RegistrationIt->second.Callbacks.Restart,
        {AdapterIt->second.AdapterContext, RestartParameters})};
}

Status NdisProvider::CompleteRestartAdapter(GuestHandle Adapter, bool Succeeded) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Adapters.find(Adapter);
    if (It == State_.Adapters.end()) return Status::InvalidHandle;
    if (It->second.State != NdisAdapterState::Restarting) return Status::InvalidState;
    It->second.State = Succeeded ? NdisAdapterState::Running : NdisAdapterState::Paused;
    return Status::Success;
}

bool NdisProvider::HasOutstandingOperationsLocked(GuestHandle Adapter) const {
    for (const auto& [Handle, Request] : State_.OidRequests) {
        (void)Handle;
        if (Request.Adapter == Adapter && Request.State == NdisOperationState::Dispatched) return true;
    }
    for (const auto& [Handle, Send] : State_.Sends) {
        (void)Handle;
        if (Send.Adapter == Adapter && Send.State == NdisOperationState::Dispatched) return true;
    }
    return false;
}

Result<CallbackInvocation> NdisProvider::BeginPauseAdapter(
    GuestHandle Adapter, GuestAddress PauseParameters) {
    if (!ValidateGuestRange(Validator_, PauseParameters, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != NdisAdapterState::Running) return {Status::InvalidState, {}};
    if (HasOutstandingOperationsLocked(Adapter)) return {Status::Busy, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    AdapterIt->second.State = NdisAdapterState::Pausing;
    return {Status::Success, InvokeLocked(RegistrationIt->second.Callbacks.Pause,
        {AdapterIt->second.AdapterContext, PauseParameters})};
}

Status NdisProvider::CompletePauseAdapter(GuestHandle Adapter) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Adapters.find(Adapter);
    if (It == State_.Adapters.end()) return Status::InvalidHandle;
    if (It->second.State != NdisAdapterState::Pausing) return Status::InvalidState;
    It->second.State = NdisAdapterState::Paused;
    return Status::Success;
}

void NdisProvider::EraseAdapterHistoryLocked(GuestHandle Adapter) {
    for (auto It = State_.OidRequests.begin(); It != State_.OidRequests.end();) {
        if (It->second.Adapter == Adapter) It = State_.OidRequests.erase(It);
        else ++It;
    }
    for (auto It = State_.Sends.begin(); It != State_.Sends.end();) {
        if (It->second.Adapter == Adapter) It = State_.Sends.erase(It);
        else ++It;
    }
}

Result<CallbackInvocation> NdisProvider::HaltAdapter(
    GuestHandle Adapter, std::uint64_t HaltAction) {
    std::scoped_lock Lock(Mutex_);
    const auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != NdisAdapterState::Paused) return {Status::InvalidState, {}};
    if (HasOutstandingOperationsLocked(Adapter)) return {Status::Busy, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const CallbackInvocation Event = InvokeLocked(RegistrationIt->second.Callbacks.Halt,
        {AdapterIt->second.AdapterContext, HaltAction});
    EraseAdapterHistoryLocked(Adapter);
    State_.Adapters.erase(AdapterIt);
    return {Status::Success, Event};
}

Result<NdisOperationEventResult> NdisProvider::BeginOidRequest(
    GuestHandle Adapter, std::uint64_t RequestId, GuestAddress Request) {
    if (!RequestId || !ValidateGuestRange(Validator_, Request, 1, GuestAccess::Write))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    const auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != NdisAdapterState::Running) return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const auto& Callback = RegistrationIt->second.Callbacks.OidRequest;
    if (!Callback.Present()) return {Status::NotSupported, {}};
    for (const auto& [Handle, Existing] : State_.OidRequests) {
        (void)Handle;
        if (Existing.Adapter == Adapter && Existing.RequestId == RequestId &&
            Existing.State == NdisOperationState::Dispatched)
            return {Status::Duplicate, {}};
    }
    const GuestHandle Operation = AllocateHandleLocked();
    if (!Operation) return {Status::Busy, {}};
    State_.OidRequests.emplace(Operation, NdisOidRequestSnapshot{
        Operation, Adapter, RequestId, Request, NdisOperationState::Dispatched, 0});
    return {Status::Success, {Operation,
        InvokeLocked(Callback, {AdapterIt->second.AdapterContext, Request, RequestId})}};
}

Status NdisProvider::CompleteOidRequest(
    GuestHandle Operation, std::uint64_t CompletionStatus) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.OidRequests.find(Operation);
    if (It == State_.OidRequests.end()) return Status::InvalidHandle;
    if (It->second.State != NdisOperationState::Dispatched) return Status::InvalidState;
    It->second.State = NdisOperationState::Completed;
    It->second.CompletionStatus = CompletionStatus;
    return Status::Success;
}

Result<CallbackInvocation> NdisProvider::CancelOidRequest(GuestHandle Operation) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.OidRequests.find(Operation);
    if (It == State_.OidRequests.end()) return {Status::InvalidHandle, {}};
    if (It->second.State != NdisOperationState::Dispatched) return {Status::InvalidState, {}};
    const auto AdapterIt = State_.Adapters.find(It->second.Adapter);
    const auto RegistrationIt = AdapterIt == State_.Adapters.end()
        ? State_.Registrations.end() : State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const auto& Callback = RegistrationIt->second.Callbacks.CancelOidRequest;
    if (!Callback.Present()) return {Status::NotSupported, {}};
    It->second.State = NdisOperationState::Cancelled;
    return {Status::Success, InvokeLocked(Callback,
        {AdapterIt->second.AdapterContext, It->second.RequestId})};
}

Result<NdisOperationEventResult> NdisProvider::BeginSend(
    GuestHandle Adapter, std::uint64_t CancelId,
    GuestAddress NetBufferLists, std::uint32_t PortNumber,
    std::uint32_t SendFlags) {
    if (!ValidateGuestRange(Validator_, NetBufferLists, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    const auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != NdisAdapterState::Running) return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const auto& Callback = RegistrationIt->second.Callbacks.SendNetBufferLists;
    if (!Callback.Present()) return {Status::NotSupported, {}};
    const GuestHandle Operation = AllocateHandleLocked();
    if (!Operation) return {Status::Busy, {}};
    State_.Sends.emplace(Operation, NdisSendSnapshot{
        Operation, Adapter, CancelId, NetBufferLists, PortNumber, SendFlags,
        NdisOperationState::Dispatched, 0});
    return {Status::Success, {Operation, InvokeLocked(Callback,
        {AdapterIt->second.AdapterContext, NetBufferLists, PortNumber, SendFlags})}};
}

Status NdisProvider::CompleteSend(
    GuestHandle Operation, std::uint64_t CompletionStatus) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Sends.find(Operation);
    if (It == State_.Sends.end()) return Status::InvalidHandle;
    if (It->second.State != NdisOperationState::Dispatched) return Status::InvalidState;
    It->second.State = NdisOperationState::Completed;
    It->second.CompletionStatus = CompletionStatus;
    return Status::Success;
}

Result<CallbackInvocation> NdisProvider::CancelSend(GuestHandle Operation) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Sends.find(Operation);
    if (It == State_.Sends.end()) return {Status::InvalidHandle, {}};
    if (It->second.State != NdisOperationState::Dispatched) return {Status::InvalidState, {}};
    const auto AdapterIt = State_.Adapters.find(It->second.Adapter);
    const auto RegistrationIt = AdapterIt == State_.Adapters.end()
        ? State_.Registrations.end() : State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const auto& Callback = RegistrationIt->second.Callbacks.CancelSend;
    if (!Callback.Present()) return {Status::NotSupported, {}};
    It->second.State = NdisOperationState::Cancelled;
    return {Status::Success, InvokeLocked(Callback,
        {AdapterIt->second.AdapterContext, It->second.CancelId})};
}

Result<CallbackInvocation> NdisProvider::IndicateReceive(
    GuestHandle Adapter, GuestAddress NetBufferLists,
    std::uint32_t PortNumber, std::uint32_t NumberOfNetBufferLists,
    std::uint32_t ReceiveFlags) {
    if (!NumberOfNetBufferLists ||
        !ValidateGuestRange(Validator_, NetBufferLists, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    const auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != NdisAdapterState::Running) return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const auto& Callback = RegistrationIt->second.Callbacks.ReceiveNetBufferLists;
    if (!Callback.Present()) return {Status::NotSupported, {}};
    return {Status::Success, InvokeLocked(Callback,
        {AdapterIt->second.AdapterContext, NetBufferLists, PortNumber,
         NumberOfNetBufferLists, ReceiveFlags})};
}

Result<CallbackInvocation> NdisProvider::ReturnReceive(
    GuestHandle Adapter, GuestAddress NetBufferLists,
    std::uint32_t ReturnFlags) {
    if (!ValidateGuestRange(Validator_, NetBufferLists, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    const auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != NdisAdapterState::Running) return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const auto& Callback = RegistrationIt->second.Callbacks.ReturnNetBufferLists;
    if (!Callback.Present()) return {Status::NotSupported, {}};
    return {Status::Success, InvokeLocked(Callback,
        {AdapterIt->second.AdapterContext, NetBufferLists, ReturnFlags})};
}

std::optional<NdisAdapterSnapshot> NdisProvider::Adapter(GuestHandle Handle) const {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Adapters.find(Handle);
    return It == State_.Adapters.end() ? std::nullopt : std::optional(It->second);
}

std::optional<NdisOidRequestSnapshot> NdisProvider::OidRequest(GuestHandle Handle) const {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.OidRequests.find(Handle);
    return It == State_.OidRequests.end() ? std::nullopt : std::optional(It->second);
}

std::optional<NdisSendSnapshot> NdisProvider::Send(GuestHandle Handle) const {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Sends.find(Handle);
    return It == State_.Sends.end() ? std::nullopt : std::optional(It->second);
}

NdisSnapshot NdisProvider::Snapshot() const {
    std::scoped_lock Lock(Mutex_);
    return State_;
}

Status NdisProvider::ValidateSnapshot(const NdisSnapshot& SnapshotValue) const {
    if (!SnapshotValue.NextHandleId || SnapshotValue.NextHandleId > IdMask ||
        !SnapshotValue.NextEventSequence) return Status::CorruptSnapshot;

    std::uint64_t MaximumId = 0;
    std::set<GuestHandle> Handles;
    std::set<GuestAddress> Drivers;
    for (const auto& [Handle, Registration] : SnapshotValue.Registrations) {
        if (Handle != Registration.Handle || !HasHandleTag(Handle, HandleTag) ||
            !Handles.insert(Handle).second || !ValidDriverKind(Registration.Kind) ||
            !Drivers.insert(Registration.DriverObject).second ||
            !ValidateGuestRange(Validator_, Registration.DriverObject, 1, GuestAccess::Read) ||
            !ValidateCallbacks(Registration.Callbacks)) return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }

    std::set<std::pair<std::uint64_t, GuestAddress>> AdapterKeys;
    for (const auto& [Handle, Adapter] : SnapshotValue.Adapters) {
        if (Handle != Adapter.Handle || !HasHandleTag(Handle, HandleTag) ||
            !Handles.insert(Handle).second ||
            !SnapshotValue.Registrations.contains(Adapter.Registration) ||
            !ValidAdapterState(Adapter.State) ||
            !ValidateGuestRange(Validator_, Adapter.AdapterContext, 1, GuestAccess::Write) ||
            !AdapterKeys.emplace(Adapter.Registration.Value, Adapter.AdapterContext).second)
            return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }

    std::set<std::pair<std::uint64_t, std::uint64_t>> ActiveRequestIds;
    for (const auto& [Handle, Request] : SnapshotValue.OidRequests) {
        const auto AdapterIt = SnapshotValue.Adapters.find(Request.Adapter);
        if (Handle != Request.Handle || !HasHandleTag(Handle, HandleTag) ||
            !Handles.insert(Handle).second || AdapterIt == SnapshotValue.Adapters.end() ||
            !Request.RequestId || !ValidOperationState(Request.State) ||
            !ValidateGuestRange(Validator_, Request.Request, 1, GuestAccess::Write) ||
            (Request.State == NdisOperationState::Dispatched &&
             AdapterIt->second.State != NdisAdapterState::Running))
            return Status::CorruptSnapshot;
        if (Request.State == NdisOperationState::Dispatched &&
            !ActiveRequestIds.emplace(Request.Adapter.Value, Request.RequestId).second)
            return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }

    for (const auto& [Handle, Send] : SnapshotValue.Sends) {
        const auto AdapterIt = SnapshotValue.Adapters.find(Send.Adapter);
        if (Handle != Send.Handle || !HasHandleTag(Handle, HandleTag) ||
            !Handles.insert(Handle).second || AdapterIt == SnapshotValue.Adapters.end() ||
            !ValidOperationState(Send.State) ||
            !ValidateGuestRange(Validator_, Send.NetBufferLists, 1, GuestAccess::Read) ||
            (Send.State == NdisOperationState::Dispatched &&
             AdapterIt->second.State != NdisAdapterState::Running))
            return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    return SnapshotValue.NextHandleId <= MaximumId ? Status::CorruptSnapshot : Status::Success;
}

Status NdisProvider::Restore(const NdisSnapshot& SnapshotValue) {
    const Status Validation = ValidateSnapshot(SnapshotValue);
    if (Validation != Status::Success) return Validation;
    std::scoped_lock Lock(Mutex_);
    State_ = SnapshotValue;
    return Status::Success;
}

} // namespace Kevlar::Host::Frameworks
