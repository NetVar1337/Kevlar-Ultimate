#include "kmdf_provider.h"

#include <algorithm>
#include <limits>
#include <set>

namespace Kevlar::Host::Frameworks {
namespace {

constexpr std::uint64_t IdMask = (std::uint64_t{1} << 48) - 1;

bool ValidObjectType(KmdfObjectType Type) {
    return Type >= KmdfObjectType::Driver && Type <= KmdfObjectType::Generic;
}

bool ValidQueueMode(KmdfQueueMode Mode) {
    return Mode >= KmdfQueueMode::Sequential && Mode <= KmdfQueueMode::Manual;
}

bool ValidRequestKind(KmdfRequestKind Kind) {
    return Kind >= KmdfRequestKind::Default && Kind <= KmdfRequestKind::DeviceControl;
}

bool ValidRequestState(KmdfRequestState State) {
    return State >= KmdfRequestState::Created && State <= KmdfRequestState::Cancelled;
}

} // namespace

KmdfProvider::KmdfProvider(GuestAddressValidator Validator)
    : Validator_(std::move(Validator)) {}

std::string_view KmdfProvider::Name() const noexcept { return "kmdf"; }

CapabilityReport KmdfProvider::Capabilities() const {
    std::scoped_lock Lock(Mutex_);
    std::size_t Pending = 0;
    for (const auto& [Handle, Request] : State_.Requests) {
        (void)Handle;
        if (Request.State == KmdfRequestState::Queued ||
            Request.State == KmdfRequestState::Dispatched) ++Pending;
    }
    return {std::string(Name()), StateVersion,
        {"objects", "typed-contexts", "queues", "requests", "cleanup-callbacks", "snapshot"},
        State_.Objects.size() + State_.Contexts.size(), Pending};
}

ProviderState KmdfProvider::CaptureState() const {
    return {std::string(Name()), StateVersion, Snapshot()};
}

Status KmdfProvider::ValidateState(const ProviderState& State) const {
    if (State.Provider != Name() || State.Version != StateVersion) return Status::CorruptSnapshot;
    const auto* Value = std::any_cast<KmdfSnapshot>(&State.State);
    return Value ? ValidateSnapshot(*Value) : Status::CorruptSnapshot;
}

Status KmdfProvider::RestoreState(const ProviderState& State) {
    if (State.Provider != Name() || State.Version != StateVersion) return Status::CorruptSnapshot;
    const auto* Value = std::any_cast<KmdfSnapshot>(&State.State);
    return Value ? Restore(*Value) : Status::CorruptSnapshot;
}

void KmdfProvider::Reset() {
    std::scoped_lock Lock(Mutex_);
    State_ = {};
}

GuestHandle KmdfProvider::AllocateHandleLocked() {
    if (!State_.NextHandleId || State_.NextHandleId > IdMask) return {};
    return MakeHandle(HandleTag, State_.NextHandleId++);
}

bool KmdfProvider::ValidateCallbacks(const KmdfObjectCallbacks& Callbacks) const {
    return Callbacks.Cleanup.ArgumentCount <= 8 && Callbacks.Destroy.ArgumentCount <= 8 &&
        ValidateCallback(Validator_, Callbacks.Cleanup) && ValidateCallback(Validator_, Callbacks.Destroy);
}

bool KmdfProvider::ValidateCallbacks(const KmdfQueueCallbacks& Callbacks) const {
    return Callbacks.Default.ArgumentCount <= 8 && Callbacks.Read.ArgumentCount <= 8 &&
        Callbacks.Write.ArgumentCount <= 8 && Callbacks.DeviceControl.ArgumentCount <= 8 &&
        ValidateCallback(Validator_, Callbacks.Default) && ValidateCallback(Validator_, Callbacks.Read) &&
        ValidateCallback(Validator_, Callbacks.Write) && ValidateCallback(Validator_, Callbacks.DeviceControl);
}

bool KmdfProvider::ValidateCallbacks(const KmdfRequestCallbacks& Callbacks) const {
    return Callbacks.Cancel.ArgumentCount <= 8 && ValidateCallback(Validator_, Callbacks.Cancel);
}

Result<GuestHandle> KmdfProvider::CreateObject(
    KmdfObjectType Type, GuestHandle Parent, KmdfObjectCallbacks Callbacks) {
    if (!ValidObjectType(Type) || Type == KmdfObjectType::Queue || Type == KmdfObjectType::Request ||
        !ValidateCallbacks(Callbacks)) return {Status::InvalidArgument, {}};
    std::scoped_lock Lock(Mutex_);
    if (Type == KmdfObjectType::Driver) {
        if (Parent) return {Status::InvalidArgument, {}};
    } else {
        const auto It = State_.Objects.find(Parent);
        if (It == State_.Objects.end()) return {Status::InvalidHandle, {}};
        if (Type == KmdfObjectType::Device && It->second.Type != KmdfObjectType::Driver)
            return {Status::InvalidState, {}};
    }
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Objects.emplace(Handle, KmdfObjectSnapshot{Handle, Type, Parent, std::move(Callbacks)});
    return {Status::Success, Handle};
}

Result<GuestHandle> KmdfProvider::CreateContext(
    GuestHandle Owner, std::uint64_t TypeKey, GuestAddress Address,
    std::size_t Size, CallbackDescriptor Cleanup) {
    if (!TypeKey || !ValidateGuestRange(Validator_, Address, Size, GuestAccess::Write) ||
        Cleanup.ArgumentCount > 8 || !ValidateCallback(Validator_, Cleanup))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    if (!State_.Objects.contains(Owner)) return {Status::InvalidHandle, {}};
    for (const auto& [Handle, Context] : State_.Contexts) {
        (void)Handle;
        if (Context.Owner == Owner && Context.TypeKey == TypeKey) return {Status::Duplicate, {}};
    }
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Contexts.emplace(Handle,
        KmdfContextSnapshot{Handle, Owner, TypeKey, Address, Size, std::move(Cleanup)});
    return {Status::Success, Handle};
}

Result<GuestHandle> KmdfProvider::CreateQueue(
    GuestHandle Device, KmdfQueueMode Mode, KmdfQueueCallbacks Callbacks) {
    if (!ValidQueueMode(Mode) || !ValidateCallbacks(Callbacks)) return {Status::InvalidArgument, {}};
    std::scoped_lock Lock(Mutex_);
    const auto DeviceIt = State_.Objects.find(Device);
    if (DeviceIt == State_.Objects.end()) return {Status::InvalidHandle, {}};
    if (DeviceIt->second.Type != KmdfObjectType::Device) return {Status::InvalidState, {}};
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Objects.emplace(Handle,
        KmdfObjectSnapshot{Handle, KmdfObjectType::Queue, Device, {}});
    State_.Queues.emplace(Handle, KmdfQueueSnapshot{Handle, Device, Mode, std::move(Callbacks), {}, {}});
    return {Status::Success, Handle};
}

Result<GuestHandle> KmdfProvider::CreateRequest(
    GuestHandle Queue, KmdfRequestKind Kind, GuestAddress RequestData,
    std::size_t RequestDataSize, KmdfRequestCallbacks Callbacks) {
    if (!ValidRequestKind(Kind) || !ValidateCallbacks(Callbacks) ||
        ((RequestData == 0) != (RequestDataSize == 0))) return {Status::InvalidArgument, {}};
    if (RequestData && !ValidateGuestRange(
            Validator_, RequestData, RequestDataSize, GuestAccess::Read))
        return {Status::AddressRejected, {}};
    std::scoped_lock Lock(Mutex_);
    if (!State_.Queues.contains(Queue)) return {Status::InvalidHandle, {}};
    const GuestHandle Handle = AllocateHandleLocked();
    if (!Handle) return {Status::Busy, {}};
    State_.Objects.emplace(Handle,
        KmdfObjectSnapshot{Handle, KmdfObjectType::Request, Queue, {}});
    State_.Requests.emplace(Handle, KmdfRequestSnapshot{
        Handle, Queue, Kind, KmdfRequestState::Created, RequestData,
        RequestDataSize, std::move(Callbacks), 0});
    return {Status::Success, Handle};
}

Status KmdfProvider::EnqueueRequest(GuestHandle Request) {
    std::scoped_lock Lock(Mutex_);
    const auto RequestIt = State_.Requests.find(Request);
    if (RequestIt == State_.Requests.end()) return Status::InvalidHandle;
    if (RequestIt->second.State != KmdfRequestState::Created) return Status::InvalidState;
    auto QueueIt = State_.Queues.find(RequestIt->second.Queue);
    if (QueueIt == State_.Queues.end()) return Status::InvalidState;
    QueueIt->second.Pending.push_back(Request);
    RequestIt->second.State = KmdfRequestState::Queued;
    return Status::Success;
}

CallbackInvocation KmdfProvider::InvokeLocked(
    const CallbackDescriptor& Callback,
    std::initializer_list<GuestAddress> Arguments) {
    return MakeInvocation(State_.NextEventSequence++, Callback, Arguments);
}

Result<CallbackInvocation> KmdfProvider::DispatchNext(GuestHandle Queue) {
    std::scoped_lock Lock(Mutex_);
    auto QueueIt = State_.Queues.find(Queue);
    if (QueueIt == State_.Queues.end()) return {Status::InvalidHandle, {}};
    auto& QueueValue = QueueIt->second;
    if (QueueValue.Mode == KmdfQueueMode::Sequential && QueueValue.Active)
        return {Status::Busy, {}};
    if (QueueValue.Pending.empty()) return {Status::InvalidState, {}};
    const GuestHandle RequestHandle = QueueValue.Pending.front();
    auto RequestIt = State_.Requests.find(RequestHandle);
    if (RequestIt == State_.Requests.end() || RequestIt->second.State != KmdfRequestState::Queued)
        return {Status::InvalidState, {}};
    const auto& Request = RequestIt->second;
    const CallbackDescriptor* Callback = &QueueValue.Callbacks.Default;
    switch (Request.Kind) {
    case KmdfRequestKind::Read: Callback = &QueueValue.Callbacks.Read; break;
    case KmdfRequestKind::Write: Callback = &QueueValue.Callbacks.Write; break;
    case KmdfRequestKind::DeviceControl: Callback = &QueueValue.Callbacks.DeviceControl; break;
    default: break;
    }
    if (!Callback->Present()) return {Status::NotSupported, {}};
    QueueValue.Pending.pop_front();
    RequestIt->second.State = KmdfRequestState::Dispatched;
    if (QueueValue.Mode == KmdfQueueMode::Sequential) QueueValue.Active = RequestHandle;
    if (Request.Kind == KmdfRequestKind::DeviceControl)
        return {Status::Success, InvokeLocked(*Callback,
            {Queue.Value, RequestHandle.Value, Request.RequestData, Request.RequestDataSize})};
    if (Request.Kind == KmdfRequestKind::Read || Request.Kind == KmdfRequestKind::Write)
        return {Status::Success, InvokeLocked(*Callback,
            {Queue.Value, RequestHandle.Value, Request.RequestDataSize})};
    return {Status::Success, InvokeLocked(*Callback, {Queue.Value, RequestHandle.Value})};
}

Result<std::optional<CallbackInvocation>> KmdfProvider::CancelRequest(GuestHandle Request) {
    std::scoped_lock Lock(Mutex_);
    auto RequestIt = State_.Requests.find(Request);
    if (RequestIt == State_.Requests.end()) return {Status::InvalidHandle, std::nullopt};
    auto& Value = RequestIt->second;
    if (Value.State == KmdfRequestState::Completed || Value.State == KmdfRequestState::Cancelled)
        return {Status::InvalidState, std::nullopt};
    auto QueueIt = State_.Queues.find(Value.Queue);
    if (QueueIt == State_.Queues.end()) return {Status::InvalidState, std::nullopt};
    auto& Pending = QueueIt->second.Pending;
    Pending.erase(std::remove(Pending.begin(), Pending.end(), Request), Pending.end());
    if (QueueIt->second.Active == Request) QueueIt->second.Active.reset();
    Value.State = KmdfRequestState::Cancelled;
    if (!Value.Callbacks.Cancel.Present()) return {Status::Success, std::nullopt};
    return {Status::Success, InvokeLocked(Value.Callbacks.Cancel, {Request.Value})};
}

Status KmdfProvider::CompleteRequest(GuestHandle Request, std::uint64_t CompletionStatus) {
    std::scoped_lock Lock(Mutex_);
    auto RequestIt = State_.Requests.find(Request);
    if (RequestIt == State_.Requests.end()) return Status::InvalidHandle;
    if (RequestIt->second.State != KmdfRequestState::Dispatched) return Status::InvalidState;
    auto QueueIt = State_.Queues.find(RequestIt->second.Queue);
    if (QueueIt == State_.Queues.end()) return Status::InvalidState;
    if (QueueIt->second.Active == Request) QueueIt->second.Active.reset();
    RequestIt->second.State = KmdfRequestState::Completed;
    RequestIt->second.CompletionStatus = CompletionStatus;
    return Status::Success;
}

std::vector<CallbackInvocation> KmdfProvider::DeleteObjectLocked(GuestHandle Object) {
    std::vector<CallbackInvocation> Result;
    std::vector<GuestHandle> Children;
    for (const auto& [Handle, Value] : State_.Objects)
        if (Value.Parent == Object) Children.push_back(Handle);
    for (GuestHandle Child : Children) {
        auto ChildResult = DeleteObjectLocked(Child);
        Result.insert(Result.end(), ChildResult.begin(), ChildResult.end());
    }

    std::vector<GuestHandle> ContextHandles;
    for (const auto& [Handle, Context] : State_.Contexts)
        if (Context.Owner == Object) ContextHandles.push_back(Handle);
    for (GuestHandle ContextHandle : ContextHandles) {
        const auto Context = State_.Contexts.at(ContextHandle);
        if (Context.Cleanup.Present())
            Result.push_back(InvokeLocked(Context.Cleanup,
                {Object.Value, Context.Address}));
        State_.Contexts.erase(ContextHandle);
    }

    if (auto QueueIt = State_.Queues.find(Object); QueueIt != State_.Queues.end())
        State_.Queues.erase(QueueIt);
    if (auto RequestIt = State_.Requests.find(Object); RequestIt != State_.Requests.end()) {
        if (auto QueueIt = State_.Queues.find(RequestIt->second.Queue); QueueIt != State_.Queues.end()) {
            auto& Pending = QueueIt->second.Pending;
            Pending.erase(std::remove(Pending.begin(), Pending.end(), Object), Pending.end());
            if (QueueIt->second.Active == Object) QueueIt->second.Active.reset();
        }
        State_.Requests.erase(RequestIt);
    }

    const auto ObjectIt = State_.Objects.find(Object);
    if (ObjectIt != State_.Objects.end()) {
        const KmdfObjectCallbacks Callbacks = ObjectIt->second.Callbacks;
        if (Callbacks.Cleanup.Present())
            Result.push_back(InvokeLocked(Callbacks.Cleanup, {Object.Value}));
        if (Callbacks.Destroy.Present())
            Result.push_back(InvokeLocked(Callbacks.Destroy, {Object.Value}));
        State_.Objects.erase(ObjectIt);
    }
    return Result;
}

Result<std::vector<CallbackInvocation>> KmdfProvider::DeleteObject(GuestHandle Object) {
    std::scoped_lock Lock(Mutex_);
    if (!HasHandleTag(Object, HandleTag) || !State_.Objects.contains(Object))
        return {Status::InvalidHandle, {}};
    return {Status::Success, DeleteObjectLocked(Object)};
}

Result<std::vector<CallbackInvocation>> KmdfProvider::Cleanup() {
    std::scoped_lock Lock(Mutex_);
    std::vector<CallbackInvocation> Result;
    std::vector<GuestHandle> Roots;
    for (const auto& [Handle, Object] : State_.Objects)
        if (!Object.Parent) Roots.push_back(Handle);
    for (GuestHandle Root : Roots) {
        auto Events = DeleteObjectLocked(Root);
        Result.insert(Result.end(), Events.begin(), Events.end());
    }
    return {Status::Success, std::move(Result)};
}

std::optional<KmdfObjectSnapshot> KmdfProvider::Object(GuestHandle Handle) const {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Objects.find(Handle);
    return It == State_.Objects.end() ? std::nullopt : std::optional(It->second);
}

std::optional<KmdfContextSnapshot> KmdfProvider::Context(GuestHandle Handle) const {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Contexts.find(Handle);
    return It == State_.Contexts.end() ? std::nullopt : std::optional(It->second);
}

std::optional<KmdfRequestSnapshot> KmdfProvider::Request(GuestHandle Handle) const {
    std::scoped_lock Lock(Mutex_);
    const auto It = State_.Requests.find(Handle);
    return It == State_.Requests.end() ? std::nullopt : std::optional(It->second);
}

KmdfSnapshot KmdfProvider::Snapshot() const {
    std::scoped_lock Lock(Mutex_);
    return State_;
}

Status KmdfProvider::ValidateSnapshot(const KmdfSnapshot& SnapshotValue) const {
    if (!SnapshotValue.NextHandleId || SnapshotValue.NextHandleId > IdMask ||
        !SnapshotValue.NextEventSequence) return Status::CorruptSnapshot;
    std::uint64_t MaximumId = 0;
    for (const auto& [Handle, Object] : SnapshotValue.Objects) {
        if (Handle != Object.Handle || !HasHandleTag(Handle, HandleTag) || !ValidObjectType(Object.Type) ||
            !ValidateCallbacks(Object.Callbacks)) return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
        if (Object.Type == KmdfObjectType::Driver) {
            if (Object.Parent) return Status::CorruptSnapshot;
        } else {
            const auto Parent = SnapshotValue.Objects.find(Object.Parent);
            if (Parent == SnapshotValue.Objects.end() || Parent->first.Value >= Handle.Value)
                return Status::CorruptSnapshot;
            if (Object.Type == KmdfObjectType::Device && Parent->second.Type != KmdfObjectType::Driver)
                return Status::CorruptSnapshot;
            if (Object.Type == KmdfObjectType::Queue && Parent->second.Type != KmdfObjectType::Device)
                return Status::CorruptSnapshot;
            if (Object.Type == KmdfObjectType::Request && Parent->second.Type != KmdfObjectType::Queue)
                return Status::CorruptSnapshot;
        }
    }
    std::set<std::pair<std::uint64_t, std::uint64_t>> ContextKeys;
    for (const auto& [Handle, Context] : SnapshotValue.Contexts) {
        if (Handle != Context.Handle || !HasHandleTag(Handle, HandleTag) || !Context.TypeKey ||
            !SnapshotValue.Objects.contains(Context.Owner) ||
            !ValidateGuestRange(Validator_, Context.Address, Context.Size, GuestAccess::Write) ||
            Context.Cleanup.ArgumentCount > 8 || !ValidateCallback(Validator_, Context.Cleanup) ||
            !ContextKeys.emplace(Context.Owner.Value, Context.TypeKey).second)
            return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    for (const auto& [Handle, Queue] : SnapshotValue.Queues) {
        const auto ObjectIt = SnapshotValue.Objects.find(Handle);
        if (Handle != Queue.Handle || ObjectIt == SnapshotValue.Objects.end() ||
            ObjectIt->second.Type != KmdfObjectType::Queue || ObjectIt->second.Parent != Queue.Device ||
            !ValidQueueMode(Queue.Mode) || !ValidateCallbacks(Queue.Callbacks) ||
            (Queue.Mode != KmdfQueueMode::Sequential && Queue.Active))
            return Status::CorruptSnapshot;
    }
    std::set<GuestHandle> Referenced;
    for (const auto& [Handle, Queue] : SnapshotValue.Queues) {
        for (GuestHandle Request : Queue.Pending) {
            const auto RequestIt = SnapshotValue.Requests.find(Request);
            if (RequestIt == SnapshotValue.Requests.end() || RequestIt->second.Queue != Handle ||
                RequestIt->second.State != KmdfRequestState::Queued || !Referenced.insert(Request).second)
                return Status::CorruptSnapshot;
        }
        if (Queue.Active) {
            const auto RequestIt = SnapshotValue.Requests.find(*Queue.Active);
            if (RequestIt == SnapshotValue.Requests.end() || RequestIt->second.Queue != Handle ||
                RequestIt->second.State != KmdfRequestState::Dispatched ||
                !Referenced.insert(*Queue.Active).second) return Status::CorruptSnapshot;
        }
    }
    for (const auto& [Handle, Request] : SnapshotValue.Requests) {
        const auto ObjectIt = SnapshotValue.Objects.find(Handle);
        if (Handle != Request.Handle || ObjectIt == SnapshotValue.Objects.end() ||
            ObjectIt->second.Type != KmdfObjectType::Request || ObjectIt->second.Parent != Request.Queue ||
            !SnapshotValue.Queues.contains(Request.Queue) || !ValidRequestKind(Request.Kind) ||
            !ValidRequestState(Request.State) || !ValidateCallbacks(Request.Callbacks) ||
            ((Request.RequestData == 0) != (Request.RequestDataSize == 0)) ||
            (Request.RequestData && !ValidateGuestRange(Validator_, Request.RequestData,
                Request.RequestDataSize, GuestAccess::Read))) return Status::CorruptSnapshot;
        const bool MustBeReferenced = Request.State == KmdfRequestState::Queued ||
            (Request.State == KmdfRequestState::Dispatched &&
             SnapshotValue.Queues.at(Request.Queue).Mode == KmdfQueueMode::Sequential);
        if (Referenced.contains(Handle) != MustBeReferenced) return Status::CorruptSnapshot;
        MaximumId = std::max(MaximumId, Handle.Value & IdMask);
    }
    return SnapshotValue.NextHandleId <= MaximumId ? Status::CorruptSnapshot : Status::Success;
}

Status KmdfProvider::Restore(const KmdfSnapshot& SnapshotValue) {
    const Status Validation = ValidateSnapshot(SnapshotValue);
    if (Validation != Status::Success) return Validation;
    std::scoped_lock Lock(Mutex_);
    State_ = SnapshotValue;
    return Status::Success;
}

} // namespace Kevlar::Host::Frameworks
