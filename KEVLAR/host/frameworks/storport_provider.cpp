#include "storport_provider.h"

#include <algorithm>
#include <set>

namespace Kevlar::Host::Frameworks {
namespace {

constexpr std::uint64_t IdMask = (std::uint64_t{1} << 48) - 1;

bool ValidAdapterState(StorportAdapterState State) {
    return State >= StorportAdapterState::Discovering && State <= StorportAdapterState::Resetting;
}

bool ValidSrbState(StorportSrbState State) {
    return State >= StorportSrbState::Queued && State <= StorportSrbState::Cancelled;
}

} // namespace

StorportProvider::StorportProvider(GuestAddressValidator Validator)
    : Validator_(std::move(Validator)) {}

std::string_view StorportProvider::Name() const noexcept { return "storport"; }

CapabilityReport StorportProvider::Capabilities() const {
    std::scoped_lock Lock(Mutex_);
    std::size_t Pending = 0;
    for (const auto& [Handle, Srb] : State_.Srbs) {
        (void)Handle;
        if (Srb.State == StorportSrbState::Queued || Srb.State == StorportSrbState::Dispatched) ++Pending;
    }
    return {std::string(Name()), StateVersion,
        {"miniport-registration", "adapter-discovery", "adapter-lifecycle", "srb-queue",
         "interrupt-dpc", "reset", "cancellation", "snapshot"},
        State_.Registrations.size() + State_.Adapters.size(), Pending};
}

ProviderState StorportProvider::CaptureState() const {
    return {std::string(Name()), StateVersion, Snapshot()};
}

Status StorportProvider::ValidateState(const ProviderState& State) const {
    if (State.Provider != Name() || State.Version != StateVersion) return Status::CorruptSnapshot;
    const auto* Value = std::any_cast<StorportSnapshot>(&State.State);
    return Value ? ValidateSnapshot(*Value) : Status::CorruptSnapshot;
}

Status StorportProvider::RestoreState(const ProviderState& State) {
    if (State.Provider != Name() || State.Version != StateVersion) return Status::CorruptSnapshot;
    const auto* Value = std::any_cast<StorportSnapshot>(&State.State);
    return Value ? Restore(*Value) : Status::CorruptSnapshot;
}

void StorportProvider::Reset() {
    std::scoped_lock Lock(Mutex_);
    State_ = {};
}

GuestHandle StorportProvider::AllocateHandleLocked() {
    if (!State_.NextHandleId || State_.NextHandleId > IdMask) return {};
    return MakeHandle(HandleTag, State_.NextHandleId++);
}

bool StorportProvider::ValidateCallbacks(const StorportMiniportCallbacks& Callbacks) const {
    const CallbackDescriptor* Values[] = {&Callbacks.FindAdapter, &Callbacks.Initialize,
        &Callbacks.StartIo, &Callbacks.Interrupt, &Callbacks.Dpc, &Callbacks.ResetBus,
        &Callbacks.AdapterControl, &Callbacks.CancelSrb};
    for (const CallbackDescriptor* Callback : Values) {
        if (Callback->ArgumentCount > 8 || !ValidateCallback(Validator_, *Callback)) return false;
    }
    return Callbacks.FindAdapter.Present() && Callbacks.Initialize.Present() &&
        Callbacks.StartIo.Present() && Callbacks.ResetBus.Present() &&
        Callbacks.AdapterControl.Present();
}

Result<GuestHandle> StorportProvider::RegisterMiniport(
    GuestAddress DriverObject, StorportMiniportCallbacks Callbacks) {
    if (!ValidateGuestRange(Validator_, DriverObject, 1, GuestAccess::Read))
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
        StorportRegistrationSnapshot{Handle, DriverObject, std::move(Callbacks)});
    return {Status::Success, Handle};
}

Status StorportProvider::UnregisterMiniport(GuestHandle Registration) {
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

CallbackInvocation StorportProvider::InvokeLocked(
    const CallbackDescriptor& Callback,
    std::initializer_list<GuestAddress> Arguments) {
    return MakeInvocation(State_.NextEventSequence++, Callback, Arguments);
}

Result<StorportAdapterEventResult> StorportProvider::BeginAdapterDiscovery(
    GuestHandle Registration, GuestAddress DeviceExtension,
    GuestAddress ConfigurationInformation) {
    if (!ValidateGuestRange(Validator_, DeviceExtension, 1, GuestAccess::Write) ||
        !ValidateGuestRange(Validator_, ConfigurationInformation, 1, GuestAccess::Write))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    const auto RegistrationIt = State_.Registrations.find(Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidHandle, {}};
    for (const auto& [Handle, Adapter] : State_.Adapters) {
        (void)Handle;
        if (Adapter.Registration == Registration && Adapter.DeviceExtension == DeviceExtension)
            return {Status::Duplicate, {}};
    }
    const GuestHandle Adapter = AllocateHandleLocked();
    if (!Adapter) return {Status::Busy, {}};
    State_.Adapters.emplace(Adapter, StorportAdapterSnapshot{
        Adapter, Registration, DeviceExtension, StorportAdapterState::Discovering, {}});
    return {Status::Success, {Adapter, InvokeLocked(RegistrationIt->second.Callbacks.FindAdapter,
        {Registration.Value, Adapter.Value, DeviceExtension, ConfigurationInformation})}};
}

Status StorportProvider::CompleteAdapterDiscovery(GuestHandle Adapter, bool Found) {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Adapters.find(Adapter);
    if (It == State_.Adapters.end()) return Status::InvalidHandle;
    if (It->second.State != StorportAdapterState::Discovering) return Status::InvalidState;
    if (!Found) {
        State_.Adapters.erase(It);
        return Status::Success;
    }
    It->second.State = StorportAdapterState::Stopped;
    return Status::Success;
}

Result<CallbackInvocation> StorportProvider::BeginStartAdapter(GuestHandle Adapter) {
    std::scoped_lock Lock(Mutex_);
    auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != StorportAdapterState::Stopped) return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    AdapterIt->second.State = StorportAdapterState::Starting;
    return {Status::Success, InvokeLocked(RegistrationIt->second.Callbacks.Initialize,
        {AdapterIt->second.DeviceExtension})};
}

Status StorportProvider::CompleteStartAdapter(GuestHandle Adapter, bool Succeeded) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Adapters.find(Adapter);
    if (It == State_.Adapters.end()) return Status::InvalidHandle;
    if (It->second.State != StorportAdapterState::Starting) return Status::InvalidState;
    It->second.State = Succeeded ? StorportAdapterState::Started : StorportAdapterState::Stopped;
    return Status::Success;
}

bool StorportProvider::HasOutstandingSrbsLocked(GuestHandle Adapter) const {
    for (const auto& [Handle, Srb] : State_.Srbs) {
        (void)Handle;
        if (Srb.Adapter == Adapter &&
            (Srb.State == StorportSrbState::Queued || Srb.State == StorportSrbState::Dispatched))
            return true;
    }
    return false;
}

Result<CallbackInvocation> StorportProvider::BeginStopAdapter(GuestHandle Adapter) {
    std::scoped_lock Lock(Mutex_);
    auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != StorportAdapterState::Started) return {Status::InvalidState, {}};
    if (HasOutstandingSrbsLocked(Adapter)) return {Status::Busy, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    AdapterIt->second.State = StorportAdapterState::Stopping;
    return {Status::Success, InvokeLocked(RegistrationIt->second.Callbacks.AdapterControl,
        {AdapterIt->second.DeviceExtension, 1, 0})};
}

Status StorportProvider::CompleteStopAdapter(GuestHandle Adapter) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Adapters.find(Adapter);
    if (It == State_.Adapters.end()) return Status::InvalidHandle;
    if (It->second.State != StorportAdapterState::Stopping) return Status::InvalidState;
    It->second.State = StorportAdapterState::Stopped;
    return Status::Success;
}

Result<CallbackInvocation> StorportProvider::BeginResetAdapter(
    GuestHandle Adapter, std::uint32_t PathId) {
    std::scoped_lock Lock(Mutex_);
    auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != StorportAdapterState::Started) return {Status::InvalidState, {}};
    if (HasOutstandingSrbsLocked(Adapter)) return {Status::Busy, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    AdapterIt->second.State = StorportAdapterState::Resetting;
    return {Status::Success, InvokeLocked(RegistrationIt->second.Callbacks.ResetBus,
        {AdapterIt->second.DeviceExtension, PathId})};
}

Status StorportProvider::CompleteResetAdapter(GuestHandle Adapter, bool Succeeded) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Adapters.find(Adapter);
    if (It == State_.Adapters.end()) return Status::InvalidHandle;
    if (It->second.State != StorportAdapterState::Resetting) return Status::InvalidState;
    It->second.State = Succeeded ? StorportAdapterState::Started : StorportAdapterState::Stopped;
    return Status::Success;
}

void StorportProvider::EraseAdapterHistoryLocked(GuestHandle Adapter) {
    for (auto It = State_.Srbs.begin(); It != State_.Srbs.end();) {
        if (It->second.Adapter == Adapter) It = State_.Srbs.erase(It);
        else ++It;
    }
}

Status StorportProvider::RemoveAdapter(GuestHandle Adapter) {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Adapters.find(Adapter);
    if (It == State_.Adapters.end()) return Status::InvalidHandle;
    if (It->second.State != StorportAdapterState::Stopped) return Status::InvalidState;
    if (HasOutstandingSrbsLocked(Adapter)) return Status::Busy;
    EraseAdapterHistoryLocked(Adapter);
    State_.Adapters.erase(It);
    return Status::Success;
}

Result<GuestHandle> StorportProvider::QueueSrb(
    GuestHandle Adapter, GuestAddress Srb, std::uint32_t QueueTag) {
    if (!ValidateGuestRange(Validator_, Srb, 1, GuestAccess::Write))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != StorportAdapterState::Started) return {Status::InvalidState, {}};
    for (const auto& [Handle, Existing] : State_.Srbs) {
        (void)Handle;
        if (Existing.Adapter == Adapter && Existing.QueueTag == QueueTag &&
            (Existing.State == StorportSrbState::Queued || Existing.State == StorportSrbState::Dispatched))
            return {Status::Duplicate, {}};
    }
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Srbs.emplace(Handle, StorportSrbSnapshot{
        Handle, Adapter, Srb, QueueTag, StorportSrbState::Queued, 0});
    AdapterIt->second.PendingSrbs.push_back(Handle);
    return {Status::Success, Handle};
}

Result<StorportSrbEventResult> StorportProvider::DispatchNextSrb(GuestHandle Adapter) {
    std::scoped_lock Lock(Mutex_);
    auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != StorportAdapterState::Started) return {Status::InvalidState, {}};
    if (AdapterIt->second.PendingSrbs.empty()) return {Status::InvalidState, {}};
    const GuestHandle SrbHandle = AdapterIt->second.PendingSrbs.front();
    const auto SrbIt = State_.Srbs.find(SrbHandle);
    if (SrbIt == State_.Srbs.end() || SrbIt->second.State != StorportSrbState::Queued)
        return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    AdapterIt->second.PendingSrbs.pop_front();
    SrbIt->second.State = StorportSrbState::Dispatched;
    return {Status::Success, {SrbHandle, InvokeLocked(RegistrationIt->second.Callbacks.StartIo,
        {AdapterIt->second.DeviceExtension, SrbIt->second.Srb})}};
}

Status StorportProvider::CompleteSrb(GuestHandle Srb, std::uint64_t CompletionStatus) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Srbs.find(Srb);
    if (It == State_.Srbs.end()) return Status::InvalidHandle;
    if (It->second.State != StorportSrbState::Dispatched) return Status::InvalidState;
    It->second.State = StorportSrbState::Completed;
    It->second.CompletionStatus = CompletionStatus;
    return Status::Success;
}

Result<std::optional<CallbackInvocation>> StorportProvider::CancelSrb(GuestHandle Srb) {
    std::scoped_lock Lock(Mutex_);
    auto SrbIt = State_.Srbs.find(Srb);
    if (SrbIt == State_.Srbs.end()) return {Status::InvalidHandle, std::nullopt};
    if (SrbIt->second.State != StorportSrbState::Queued &&
        SrbIt->second.State != StorportSrbState::Dispatched)
        return {Status::InvalidState, std::nullopt};
    auto AdapterIt = State_.Adapters.find(SrbIt->second.Adapter);
    const auto RegistrationIt = AdapterIt == State_.Adapters.end()
        ? State_.Registrations.end() : State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, std::nullopt};
    if (SrbIt->second.State == StorportSrbState::Dispatched &&
        !RegistrationIt->second.Callbacks.CancelSrb.Present())
        return {Status::NotSupported, std::nullopt};
    auto& Pending = AdapterIt->second.PendingSrbs;
    Pending.erase(std::remove(Pending.begin(), Pending.end(), Srb), Pending.end());
    SrbIt->second.State = StorportSrbState::Cancelled;
    if (!RegistrationIt->second.Callbacks.CancelSrb.Present())
        return {Status::Success, std::nullopt};
    return {Status::Success, InvokeLocked(RegistrationIt->second.Callbacks.CancelSrb,
        {AdapterIt->second.DeviceExtension, SrbIt->second.Srb})};
}

Result<CallbackInvocation> StorportProvider::InvokeInterrupt(GuestHandle Adapter) {
    std::scoped_lock Lock(Mutex_);
    const auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != StorportAdapterState::Started) return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const auto& Callback = RegistrationIt->second.Callbacks.Interrupt;
    if (!Callback.Present()) return {Status::NotSupported, {}};
    return {Status::Success, InvokeLocked(Callback, {AdapterIt->second.DeviceExtension})};
}

Result<CallbackInvocation> StorportProvider::InvokeDpc(
    GuestHandle Adapter, GuestAddress SystemArgument1,
    GuestAddress SystemArgument2) {
    std::scoped_lock Lock(Mutex_);
    const auto AdapterIt = State_.Adapters.find(Adapter);
    if (AdapterIt == State_.Adapters.end()) return {Status::InvalidHandle, {}};
    if (AdapterIt->second.State != StorportAdapterState::Started) return {Status::InvalidState, {}};
    const auto RegistrationIt = State_.Registrations.find(AdapterIt->second.Registration);
    if (RegistrationIt == State_.Registrations.end()) return {Status::InvalidState, {}};
    const auto& Callback = RegistrationIt->second.Callbacks.Dpc;
    if (!Callback.Present()) return {Status::NotSupported, {}};
    return {Status::Success, InvokeLocked(Callback,
        {AdapterIt->second.DeviceExtension, SystemArgument1, SystemArgument2})};
}

std::optional<StorportAdapterSnapshot> StorportProvider::Adapter(GuestHandle Handle) const {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Adapters.find(Handle);
    return It == State_.Adapters.end() ? std::nullopt : std::optional(It->second);
}

std::optional<StorportSrbSnapshot> StorportProvider::Srb(GuestHandle Handle) const {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Srbs.find(Handle);
    return It == State_.Srbs.end() ? std::nullopt : std::optional(It->second);
}

StorportSnapshot StorportProvider::Snapshot() const {
    std::scoped_lock Lock(Mutex_);
    return State_;
}

Status StorportProvider::ValidateSnapshot(const StorportSnapshot& SnapshotValue) const {
    if (!SnapshotValue.NextHandleId || SnapshotValue.NextHandleId > IdMask ||
        !SnapshotValue.NextEventSequence) return Status::CorruptSnapshot;
    std::uint64_t MaximumId = 0;
    std::set<GuestHandle> Handles;
    std::set<GuestAddress> Drivers;
    for (const auto& [Handle, Registration] : SnapshotValue.Registrations) {
        if (Handle != Registration.Handle || !HasHandleTag(Handle, HandleTag) ||
            !Handles.insert(Handle).second || !Drivers.insert(Registration.DriverObject).second ||
            !ValidateGuestRange(Validator_, Registration.DriverObject, 1, GuestAccess::Read) ||
            !ValidateCallbacks(Registration.Callbacks)) return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    std::set<std::pair<std::uint64_t, GuestAddress>> AdapterKeys;
    std::set<GuestHandle> Queued;
    for (const auto& [Handle, Adapter] : SnapshotValue.Adapters) {
        if (Handle != Adapter.Handle || !HasHandleTag(Handle, HandleTag) ||
            !Handles.insert(Handle).second || !SnapshotValue.Registrations.contains(Adapter.Registration) ||
            !ValidAdapterState(Adapter.State) ||
            !ValidateGuestRange(Validator_, Adapter.DeviceExtension, 1, GuestAccess::Write) ||
            !AdapterKeys.emplace(Adapter.Registration.Value, Adapter.DeviceExtension).second)
            return Status::CorruptSnapshot;
        for (GuestHandle Srb : Adapter.PendingSrbs) {
            const auto SrbIt = SnapshotValue.Srbs.find(Srb);
            if (SrbIt == SnapshotValue.Srbs.end() || SrbIt->second.Adapter != Handle ||
                SrbIt->second.State != StorportSrbState::Queued || !Queued.insert(Srb).second)
                return Status::CorruptSnapshot;
        }
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    std::set<std::pair<std::uint64_t, std::uint32_t>> ActiveTags;
    for (const auto& [Handle, Srb] : SnapshotValue.Srbs) {
        const auto AdapterIt = SnapshotValue.Adapters.find(Srb.Adapter);
        if (Handle != Srb.Handle || !HasHandleTag(Handle, HandleTag) ||
            !Handles.insert(Handle).second || AdapterIt == SnapshotValue.Adapters.end() ||
            !ValidSrbState(Srb.State) ||
            !ValidateGuestRange(Validator_, Srb.Srb, 1, GuestAccess::Write) ||
            (Srb.State == StorportSrbState::Queued && !Queued.contains(Handle)) ||
            (Srb.State != StorportSrbState::Queued && Queued.contains(Handle)) ||
            ((Srb.State == StorportSrbState::Queued || Srb.State == StorportSrbState::Dispatched) &&
             AdapterIt->second.State != StorportAdapterState::Started))
            return Status::CorruptSnapshot;
        if ((Srb.State == StorportSrbState::Queued || Srb.State == StorportSrbState::Dispatched) &&
            !ActiveTags.emplace(Srb.Adapter.Value, Srb.QueueTag).second)
            return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    return SnapshotValue.NextHandleId <= MaximumId ? Status::CorruptSnapshot : Status::Success;
}

Status StorportProvider::Restore(const StorportSnapshot& SnapshotValue) {
    const Status Validation = ValidateSnapshot(SnapshotValue);
    if (Validation != Status::Success) return Validation;
    std::scoped_lock Lock(Mutex_);
    State_ = SnapshotValue;
    return Status::Success;
}

} // namespace Kevlar::Host::Frameworks
