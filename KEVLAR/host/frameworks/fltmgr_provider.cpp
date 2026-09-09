#include "fltmgr_provider.h"

#include <algorithm>
#include <set>

namespace Kevlar::Host::Frameworks {
namespace {
constexpr std::uint64_t IdMask = (std::uint64_t{1} << 48) - 1;

bool ValidFilterState(FltFilterState State) {
    return State == FltFilterState::Registered || State == FltFilterState::Started;
}
bool ValidInstanceState(FltInstanceState State) {
    return State == FltInstanceState::Created || State == FltInstanceState::Active;
}
bool ValidOperationState(FltOperationState State) {
    return State == FltOperationState::PrePending || State == FltOperationState::PostPending;
}
} // namespace

FltmgrProvider::FltmgrProvider(GuestAddressValidator Validator)
    : Validator_(std::move(Validator)) {}

std::string_view FltmgrProvider::Name() const noexcept { return "fltmgr"; }

CapabilityReport FltmgrProvider::Capabilities() const {
    std::scoped_lock Lock(Mutex_);
    return {std::string(Name()), StateVersion,
        {"filter-registration", "instances", "pre-post-operations", "typed-contexts", "snapshot"},
        State_.Filters.size() + State_.Instances.size() + State_.Contexts.size(),
        State_.Operations.size()};
}

ProviderState FltmgrProvider::CaptureState() const {
    return {std::string(Name()), StateVersion, Snapshot()};
}

Status FltmgrProvider::ValidateState(const ProviderState& State) const {
    if (State.Provider != Name() || State.Version != StateVersion) return Status::CorruptSnapshot;
    const auto* Value = std::any_cast<FltSnapshot>(&State.State);
    return Value ? ValidateSnapshot(*Value) : Status::CorruptSnapshot;
}

Status FltmgrProvider::RestoreState(const ProviderState& State) {
    if (State.Provider != Name() || State.Version != StateVersion) return Status::CorruptSnapshot;
    const auto* Value = std::any_cast<FltSnapshot>(&State.State);
    return Value ? Restore(*Value) : Status::CorruptSnapshot;
}

void FltmgrProvider::Reset() {
    std::scoped_lock Lock(Mutex_);
    State_ = {};
}

GuestHandle FltmgrProvider::AllocateHandleLocked() {
    if (!State_.NextHandleId || State_.NextHandleId > IdMask) return {};
    return MakeHandle(HandleTag, State_.NextHandleId++);
}

bool FltmgrProvider::ValidateCallbacks(const FltFilterCallbacks& Callbacks) const {
    const CallbackDescriptor* Values[] = {&Callbacks.Unload, &Callbacks.InstanceSetup,
        &Callbacks.InstanceTeardownStart, &Callbacks.InstanceTeardownComplete};
    for (const auto* Callback : Values)
        if (Callback->ArgumentCount > 8 || !ValidateCallback(Validator_, *Callback)) return false;
    return true;
}

bool FltmgrProvider::ValidateCallbacks(const FltOperationCallbacks& Callbacks) const {
    return Callbacks.Pre.ArgumentCount <= 8 && Callbacks.Post.ArgumentCount <= 8 &&
        ValidateCallback(Validator_, Callbacks.Pre) && ValidateCallback(Validator_, Callbacks.Post) &&
        (Callbacks.Pre.Present() || Callbacks.Post.Present());
}

Result<GuestHandle> FltmgrProvider::RegisterFilter(
    GuestAddress DriverObject, FltFilterCallbacks Callbacks,
    std::map<std::uint8_t, FltOperationCallbacks> Operations) {
    if (!ValidateGuestRange(Validator_, DriverObject, 1, GuestAccess::Read) ||
        !ValidateCallbacks(Callbacks) || Operations.empty())
        return {Status::InvalidArgument, {}};
    for (const auto& [Major, Operation] : Operations) {
        (void)Major;
        if (!ValidateCallbacks(Operation)) return {Status::AddressRejected, {}};
    }
    std::scoped_lock Lock(Mutex_);
    for (const auto& [Handle, Filter] : State_.Filters) {
        (void)Handle;
        if (Filter.DriverObject == DriverObject) return {Status::Duplicate, {}};
    }
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Filters.emplace(Handle, FltFilterSnapshot{
        Handle, DriverObject, FltFilterState::Registered,
        std::move(Callbacks), std::move(Operations)});
    return {Status::Success, Handle};
}

Status FltmgrProvider::StartFiltering(GuestHandle Filter) {
    std::scoped_lock Lock(Mutex_);
    auto It = State_.Filters.find(Filter);
    if (It == State_.Filters.end()) return Status::InvalidHandle;
    if (It->second.State != FltFilterState::Registered) return Status::InvalidState;
    It->second.State = FltFilterState::Started;
    return Status::Success;
}

Result<GuestHandle> FltmgrProvider::CreateInstance(
    GuestHandle Filter, GuestAddress Volume) {
    if (!ValidateGuestRange(Validator_, Volume, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    const auto FilterIt = State_.Filters.find(Filter);
    if (FilterIt == State_.Filters.end()) return {Status::InvalidHandle, {}};
    if (FilterIt->second.State != FltFilterState::Started) return {Status::InvalidState, {}};
    for (const auto& [Handle, Instance] : State_.Instances) {
        (void)Handle;
        if (Instance.Filter == Filter && Instance.Volume == Volume) return {Status::Duplicate, {}};
    }
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Instances.emplace(Handle,
        FltInstanceSnapshot{Handle, Filter, Volume, FltInstanceState::Created});
    return {Status::Success, Handle};
}

CallbackInvocation FltmgrProvider::InvokeLocked(
    const CallbackDescriptor& Callback,
    std::initializer_list<GuestAddress> Arguments) {
    return MakeInvocation(State_.NextEventSequence++, Callback, Arguments);
}

Result<std::optional<CallbackInvocation>> FltmgrProvider::ActivateInstance(GuestHandle Instance) {
    std::scoped_lock Lock(Mutex_);
    auto InstanceIt = State_.Instances.find(Instance);
    if (InstanceIt == State_.Instances.end()) return {Status::InvalidHandle, std::nullopt};
    if (InstanceIt->second.State != FltInstanceState::Created)
        return {Status::InvalidState, std::nullopt};
    const auto FilterIt = State_.Filters.find(InstanceIt->second.Filter);
    if (FilterIt == State_.Filters.end() || FilterIt->second.State != FltFilterState::Started)
        return {Status::InvalidState, std::nullopt};
    InstanceIt->second.State = FltInstanceState::Active;
    if (!FilterIt->second.Callbacks.InstanceSetup.Present())
        return {Status::Success, std::nullopt};
    return {Status::Success, InvokeLocked(FilterIt->second.Callbacks.InstanceSetup,
        {FilterIt->first.Value, Instance.Value, InstanceIt->second.Volume})};
}

Result<GuestHandle> FltmgrProvider::SetContext(
    GuestHandle Owner, std::uint64_t TypeKey, GuestAddress Address,
    std::size_t Size, CallbackDescriptor Cleanup) {
    if (!TypeKey || !ValidateGuestRange(Validator_, Address, Size, GuestAccess::Write) ||
        Cleanup.ArgumentCount > 8 || !ValidateCallback(Validator_, Cleanup))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    if (!State_.Filters.contains(Owner) && !State_.Instances.contains(Owner))
        return {Status::InvalidHandle, {}};
    for (const auto& [Handle, Context] : State_.Contexts) {
        (void)Handle;
        if (Context.Owner == Owner && Context.TypeKey == TypeKey) return {Status::Duplicate, {}};
    }
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Contexts.emplace(Handle,
        FltContextSnapshot{Handle, Owner, TypeKey, Address, Size, std::move(Cleanup)});
    return {Status::Success, Handle};
}

Result<std::optional<CallbackInvocation>> FltmgrProvider::DeleteContext(GuestHandle Context) {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Contexts.find(Context);
    if (It == State_.Contexts.end()) return {Status::InvalidHandle, std::nullopt};
    std::optional<CallbackInvocation> Event;
    if (It->second.Cleanup.Present())
        Event = InvokeLocked(It->second.Cleanup, {It->second.Owner.Value, It->second.Address});
    State_.Contexts.erase(It);
    return {Status::Success, std::move(Event)};
}

Result<FltBeginOperationResult> FltmgrProvider::BeginOperation(
    GuestHandle Instance, std::uint8_t MajorFunction,
    GuestAddress CallbackData, GuestAddress RelatedObjects) {
    if (!ValidateGuestRange(Validator_, CallbackData, 1, GuestAccess::Write) ||
        !ValidateGuestRange(Validator_, RelatedObjects, 1, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    const auto InstanceIt = State_.Instances.find(Instance);
    if (InstanceIt == State_.Instances.end()) return {Status::InvalidHandle, {}};
    if (InstanceIt->second.State != FltInstanceState::Active) return {Status::InvalidState, {}};
    const auto FilterIt = State_.Filters.find(InstanceIt->second.Filter);
    if (FilterIt == State_.Filters.end()) return {Status::InvalidState, {}};
    const auto CallbackIt = FilterIt->second.Operations.find(MajorFunction);
    if (CallbackIt == FilterIt->second.Operations.end()) return {Status::NotSupported, {}};
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    const FltOperationState OperationState = CallbackIt->second.Pre.Present()
        ? FltOperationState::PrePending : FltOperationState::PostPending;
    State_.Operations.emplace(Handle, FltOperationSnapshot{
        Handle, Instance, MajorFunction, OperationState,
        CallbackData, RelatedObjects, 0});
    FltBeginOperationResult ResultValue{Handle, std::nullopt};
    if (CallbackIt->second.Pre.Present())
        ResultValue.PreCallback = InvokeLocked(CallbackIt->second.Pre,
            {CallbackData, RelatedObjects, Instance.Value});
    return {Status::Success, std::move(ResultValue)};
}

Status FltmgrProvider::AcknowledgePreOperation(
    GuestHandle Operation, bool RequestPostCallback,
    GuestAddress CompletionContext) {
    if (CompletionContext && !ValidateGuestRange(
            Validator_, CompletionContext, 1, GuestAccess::Read))
        return Status::AddressRejected;
    std::scoped_lock Lock(Mutex_);
    auto OperationIt = State_.Operations.find(Operation);
    if (OperationIt == State_.Operations.end()) return Status::InvalidHandle;
    if (OperationIt->second.State != FltOperationState::PrePending) return Status::InvalidState;
    const auto InstanceIt = State_.Instances.find(OperationIt->second.Instance);
    const auto FilterIt = InstanceIt == State_.Instances.end()
        ? State_.Filters.end() : State_.Filters.find(InstanceIt->second.Filter);
    if (FilterIt == State_.Filters.end()) return Status::InvalidState;
    const auto CallbackIt = FilterIt->second.Operations.find(OperationIt->second.MajorFunction);
    if (CallbackIt == FilterIt->second.Operations.end()) return Status::InvalidState;
    if (!RequestPostCallback) {
        State_.Operations.erase(OperationIt);
        return Status::Success;
    }
    if (!CallbackIt->second.Post.Present()) return Status::NotSupported;
    OperationIt->second.State = FltOperationState::PostPending;
    OperationIt->second.CompletionContext = CompletionContext;
    return Status::Success;
}

Result<std::optional<CallbackInvocation>> FltmgrProvider::CompleteOperation(
    GuestHandle Operation, std::uint64_t OperationStatus) {
    std::scoped_lock Lock(Mutex_);
    const auto OperationIt = State_.Operations.find(Operation);
    if (OperationIt == State_.Operations.end()) return {Status::InvalidHandle, std::nullopt};
    if (OperationIt->second.State != FltOperationState::PostPending)
        return {Status::InvalidState, std::nullopt};
    const auto InstanceIt = State_.Instances.find(OperationIt->second.Instance);
    const auto FilterIt = InstanceIt == State_.Instances.end()
        ? State_.Filters.end() : State_.Filters.find(InstanceIt->second.Filter);
    if (FilterIt == State_.Filters.end()) return {Status::InvalidState, std::nullopt};
    const auto CallbackIt = FilterIt->second.Operations.find(OperationIt->second.MajorFunction);
    if (CallbackIt == FilterIt->second.Operations.end()) return {Status::InvalidState, std::nullopt};
    std::optional<CallbackInvocation> Event;
    if (CallbackIt->second.Post.Present())
        Event = InvokeLocked(CallbackIt->second.Post,
            {OperationIt->second.CallbackData, OperationIt->second.RelatedObjects,
             OperationIt->second.CompletionContext, OperationStatus});
    State_.Operations.erase(OperationIt);
    return {Status::Success, std::move(Event)};
}

void FltmgrProvider::DeleteOwnedContextsLocked(
    GuestHandle Owner, std::vector<CallbackInvocation>& Events) {
    for (auto It = State_.Contexts.begin(); It != State_.Contexts.end();) {
        if (It->second.Owner != Owner) { ++It; continue; }
        if (It->second.Cleanup.Present())
            Events.push_back(InvokeLocked(It->second.Cleanup, {Owner.Value, It->second.Address}));
        It = State_.Contexts.erase(It);
    }
}

Result<std::vector<CallbackInvocation>> FltmgrProvider::DetachInstance(GuestHandle Instance) {
    std::scoped_lock Lock(Mutex_);
    const auto InstanceIt = State_.Instances.find(Instance);
    if (InstanceIt == State_.Instances.end()) return {Status::InvalidHandle, {}};
    for (const auto& [Handle, Operation] : State_.Operations) {
        (void)Handle;
        if (Operation.Instance == Instance) return {Status::Busy, {}};
    }
    const auto FilterIt = State_.Filters.find(InstanceIt->second.Filter);
    if (FilterIt == State_.Filters.end()) return {Status::InvalidState, {}};
    std::vector<CallbackInvocation> Events;
    if (FilterIt->second.Callbacks.InstanceTeardownStart.Present())
        Events.push_back(InvokeLocked(FilterIt->second.Callbacks.InstanceTeardownStart,
            {Instance.Value, InstanceIt->second.Volume}));
    DeleteOwnedContextsLocked(Instance, Events);
    if (FilterIt->second.Callbacks.InstanceTeardownComplete.Present())
        Events.push_back(InvokeLocked(FilterIt->second.Callbacks.InstanceTeardownComplete,
            {Instance.Value, InstanceIt->second.Volume}));
    State_.Instances.erase(InstanceIt);
    return {Status::Success, std::move(Events)};
}

Result<std::optional<CallbackInvocation>> FltmgrProvider::UnregisterFilter(GuestHandle Filter) {
    std::scoped_lock Lock(Mutex_);
    const auto FilterIt = State_.Filters.find(Filter);
    if (FilterIt == State_.Filters.end()) return {Status::InvalidHandle, std::nullopt};
    for (const auto& [Handle, Instance] : State_.Instances) {
        (void)Handle;
        if (Instance.Filter == Filter) return {Status::Busy, std::nullopt};
    }
    std::vector<CallbackInvocation> ContextEvents;
    DeleteOwnedContextsLocked(Filter, ContextEvents);
    std::optional<CallbackInvocation> Event;
    if (FilterIt->second.Callbacks.Unload.Present())
        Event = InvokeLocked(FilterIt->second.Callbacks.Unload, {Filter.Value});
    State_.Filters.erase(FilterIt);
    return {Status::Success, std::move(Event)};
}

Result<std::vector<CallbackInvocation>> FltmgrProvider::Cleanup() {
    std::scoped_lock Lock(Mutex_);
    if (!State_.Operations.empty()) return {Status::Busy, {}};
    std::vector<CallbackInvocation> Events;
    while (!State_.Instances.empty()) {
        const GuestHandle Instance = State_.Instances.begin()->first;
        const auto InstanceValue = State_.Instances.begin()->second;
        const auto FilterIt = State_.Filters.find(InstanceValue.Filter);
        if (FilterIt != State_.Filters.end() && FilterIt->second.Callbacks.InstanceTeardownStart.Present())
            Events.push_back(InvokeLocked(FilterIt->second.Callbacks.InstanceTeardownStart,
                {Instance.Value, InstanceValue.Volume}));
        DeleteOwnedContextsLocked(Instance, Events);
        if (FilterIt != State_.Filters.end() && FilterIt->second.Callbacks.InstanceTeardownComplete.Present())
            Events.push_back(InvokeLocked(FilterIt->second.Callbacks.InstanceTeardownComplete,
                {Instance.Value, InstanceValue.Volume}));
        State_.Instances.erase(Instance);
    }
    while (!State_.Filters.empty()) {
        const GuestHandle Filter = State_.Filters.begin()->first;
        const auto Callbacks = State_.Filters.begin()->second.Callbacks;
        DeleteOwnedContextsLocked(Filter, Events);
        if (Callbacks.Unload.Present()) Events.push_back(InvokeLocked(Callbacks.Unload, {Filter.Value}));
        State_.Filters.erase(Filter);
    }
    return {Status::Success, std::move(Events)};
}

FltSnapshot FltmgrProvider::Snapshot() const {
    std::scoped_lock Lock(Mutex_);
    return State_;
}

Status FltmgrProvider::ValidateSnapshot(const FltSnapshot& SnapshotValue) const {
    if (!SnapshotValue.NextHandleId || SnapshotValue.NextHandleId > IdMask ||
        !SnapshotValue.NextEventSequence) return Status::CorruptSnapshot;
    std::uint64_t MaximumId = 0;
    std::set<GuestAddress> Drivers;
    for (const auto& [Handle, Filter] : SnapshotValue.Filters) {
        if (Handle != Filter.Handle || !HasHandleTag(Handle, HandleTag) ||
            !Drivers.insert(Filter.DriverObject).second || !ValidFilterState(Filter.State) ||
            !ValidateGuestRange(Validator_, Filter.DriverObject, 1, GuestAccess::Read) ||
            !ValidateCallbacks(Filter.Callbacks) || Filter.Operations.empty())
            return Status::CorruptSnapshot;
        for (const auto& [Major, Callbacks] : Filter.Operations) {
            (void)Major;
            if (!ValidateCallbacks(Callbacks)) return Status::CorruptSnapshot;
        }
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    std::set<std::pair<std::uint64_t, GuestAddress>> InstanceKeys;
    for (const auto& [Handle, Instance] : SnapshotValue.Instances) {
        const auto FilterIt = SnapshotValue.Filters.find(Instance.Filter);
        if (Handle != Instance.Handle || !HasHandleTag(Handle, HandleTag) ||
            FilterIt == SnapshotValue.Filters.end() || FilterIt->second.State != FltFilterState::Started ||
            !ValidInstanceState(Instance.State) ||
            !ValidateGuestRange(Validator_, Instance.Volume, 1, GuestAccess::Read) ||
            !InstanceKeys.emplace(Instance.Filter.Value, Instance.Volume).second)
            return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    std::set<std::pair<std::uint64_t, std::uint64_t>> ContextKeys;
    for (const auto& [Handle, Context] : SnapshotValue.Contexts) {
        if (Handle != Context.Handle || !HasHandleTag(Handle, HandleTag) || !Context.TypeKey ||
            (!SnapshotValue.Filters.contains(Context.Owner) && !SnapshotValue.Instances.contains(Context.Owner)) ||
            !ValidateGuestRange(Validator_, Context.Address, Context.Size, GuestAccess::Write) ||
            Context.Cleanup.ArgumentCount > 8 || !ValidateCallback(Validator_, Context.Cleanup) ||
            !ContextKeys.emplace(Context.Owner.Value, Context.TypeKey).second)
            return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    for (const auto& [Handle, Operation] : SnapshotValue.Operations) {
        const auto InstanceIt = SnapshotValue.Instances.find(Operation.Instance);
        if (Handle != Operation.Handle || !HasHandleTag(Handle, HandleTag) ||
            InstanceIt == SnapshotValue.Instances.end() || InstanceIt->second.State != FltInstanceState::Active ||
            !ValidOperationState(Operation.State) ||
            !ValidateGuestRange(Validator_, Operation.CallbackData, 1, GuestAccess::Write) ||
            !ValidateGuestRange(Validator_, Operation.RelatedObjects, 1, GuestAccess::Read))
            return Status::CorruptSnapshot;
        const auto& Filter = SnapshotValue.Filters.at(InstanceIt->second.Filter);
        const auto CallbackIt = Filter.Operations.find(Operation.MajorFunction);
        if (CallbackIt == Filter.Operations.end() ||
            (Operation.State == FltOperationState::PrePending && !CallbackIt->second.Pre.Present()) ||
            (Operation.State == FltOperationState::PostPending && !CallbackIt->second.Post.Present()) ||
            (Operation.CompletionContext && !ValidateGuestRange(
                Validator_, Operation.CompletionContext, 1, GuestAccess::Read)))
            return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    return SnapshotValue.NextHandleId <= MaximumId ? Status::CorruptSnapshot : Status::Success;
}

Status FltmgrProvider::Restore(const FltSnapshot& SnapshotValue) {
    const Status Result = ValidateSnapshot(SnapshotValue);
    if (Result != Status::Success) return Result;
    std::scoped_lock Lock(Mutex_);
    State_ = SnapshotValue;
    return Status::Success;
}

} // namespace Kevlar::Host::Frameworks
