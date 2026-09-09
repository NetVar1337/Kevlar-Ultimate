#include "driver_lifecycle.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace Kevlar::Lifecycle {
namespace {

constexpr std::size_t kMaximumSnapshotEntries = 1u << 20;

bool IsValidDriverState(DriverState State) noexcept {
    return State <= DriverState::Failed;
}

bool IsValidDevicePower(DevicePowerState State) noexcept {
    return State <= DevicePowerState::D3;
}

bool IsValidSystemPower(SystemPowerState State) noexcept {
    return State <= SystemPowerState::Shutdown;
}

bool IsValidResourceType(ResourceType Type) noexcept {
    return Type <= ResourceType::DevicePrivate;
}

bool IsValidRelationType(DeviceRelationType Type) noexcept {
    return Type <= DeviceRelationType::Target;
}

bool IsValidEvent(LifecycleEvent Event) noexcept {
    return Event <= LifecycleEvent::Unload;
}

bool IsValidError(LifecycleError Error) noexcept {
    return Error <= LifecycleError::CorruptSnapshot;
}

bool IsValidDispatchKind(DispatchKind Kind) noexcept {
    return Kind <= DispatchKind::Wmi;
}

bool IsNonEmptyRange(const GuestRange& Range) noexcept {
    return Range.Address != 0 && Range.Length != 0;
}

bool RangeDoesNotOverflow(const GuestRange& Range) noexcept {
    return Range.Length != 0 &&
           Range.Address <= std::numeric_limits<GuestAddress>::max() - (Range.Length - 1);
}

} // namespace

DriverLifecycle::DriverLifecycle(LifecycleConfig Config)
    : Config_(std::move(Config)), NextSyntheticIdentity_(Config_.FirstSyntheticIdentity) {
    if (NextSyntheticIdentity_ == 0 ||
        NextSyntheticIdentity_ > std::numeric_limits<std::uint64_t>::max() - 1) {
        State_ = DriverState::Failed;
    }
}

bool DriverLifecycle::ValidateGuestRange(const GuestRange& Range, GuestAccess Access) const noexcept {
    if (Range.Address == 0 || Range.Length == 0) return Range.Address == 0 && Range.Length == 0;
    if (!RangeDoesNotOverflow(Range) || !Config_.ValidateGuestAddress) return false;
    try {
        return Config_.ValidateGuestAddress(Range.Address, Range.Length, Access);
    } catch (...) {
        return false;
    }
}

bool DriverLifecycle::ValidateDriverIdentity(const DriverIdentity& Driver) const noexcept {
    return IsNonEmptyRange(Driver.DriverObject) &&
           ValidateGuestRange(Driver.DriverObject, GuestAccess::ReadWrite) &&
           ValidateGuestRange(Driver.RegistryPath, GuestAccess::Read);
}

bool DriverLifecycle::ValidateDeviceDescription(const DeviceDescription& Device) const noexcept {
    return !Device.InstanceId.empty() && IsNonEmptyRange(Device.PhysicalDeviceObject) &&
           IsNonEmptyRange(Device.FunctionalDeviceObject) &&
           Device.PhysicalDeviceObject.Address != Device.FunctionalDeviceObject.Address &&
           ValidateGuestRange(Device.PhysicalDeviceObject, GuestAccess::ReadWrite) &&
           ValidateGuestRange(Device.FunctionalDeviceObject, GuestAccess::ReadWrite);
}

bool DriverLifecycle::ValidateResources(const ResourceLists& Resources) const noexcept {
    if (Resources.Raw.size() > kMaximumSnapshotEntries ||
        Resources.Translated.size() > kMaximumSnapshotEntries) return false;
    const auto Valid = [](const std::vector<ResourceDescriptor>& List) {
        return std::all_of(List.begin(), List.end(), [](const ResourceDescriptor& Resource) {
            return IsValidResourceType(Resource.Type) && Resource.Length != 0 &&
                   Resource.Start <= std::numeric_limits<std::uint64_t>::max() -
                                         (Resource.Length - 1);
        });
    };
    return Valid(Resources.Raw) && Valid(Resources.Translated);
}

bool DriverLifecycle::ValidateRelations(const std::vector<DeviceRelation>& Relations) const noexcept {
    if (Relations.size() > kMaximumSnapshotEntries) return false;
    for (const auto& Relation : Relations) {
        if (!IsValidRelationType(Relation.Type) ||
            Relation.Objects.size() > kMaximumSnapshotEntries) return false;
        for (const auto& Object : Relation.Objects) {
            if (!IsNonEmptyRange(Object) ||
                !ValidateGuestRange(Object, GuestAccess::ReadWrite)) return false;
        }
    }
    return true;
}

bool DriverLifecycle::ValidateWmiRequest(const WmiRequest& Request) const noexcept {
    return ValidateGuestRange(Request.Input, GuestAccess::Read) &&
           ValidateGuestRange(Request.Output, GuestAccess::Write);
}

CallbackResult DriverLifecycle::InvokeDriverEntry(const DriverEntryInvocation& Invocation,
                                                   bool& Threw) const noexcept {
    Threw = false;
    if (!Config_.Callbacks.DriverEntry) return {};
    try {
        return Config_.Callbacks.DriverEntry(Invocation);
    } catch (...) {
        Threw = true;
        return {false, 0};
    }
}

CallbackResult DriverLifecycle::InvokeAddDevice(const AddDeviceInvocation& Invocation,
                                                 bool& Threw) const noexcept {
    Threw = false;
    if (!Config_.Callbacks.AddDevice) return {};
    try {
        return Config_.Callbacks.AddDevice(Invocation);
    } catch (...) {
        Threw = true;
        return {false, 0};
    }
}

CallbackResult DriverLifecycle::InvokeDispatch(const DispatchInvocation& Invocation,
                                                bool& Threw) const noexcept {
    Threw = false;
    if (!IsValidDispatchKind(Invocation.Kind) || !Config_.Callbacks.Dispatch) return {};
    try {
        return Config_.Callbacks.Dispatch(Invocation);
    } catch (...) {
        Threw = true;
        return {false, 0};
    }
}

CallbackResult DriverLifecycle::InvokeUnload(const UnloadInvocation& Invocation,
                                              bool& Threw) const noexcept {
    Threw = false;
    if (!Config_.Callbacks.Unload) return {};
    try {
        return Config_.Callbacks.Unload(Invocation);
    } catch (...) {
        Threw = true;
        return {false, 0};
    }
}

LifecycleResult DriverLifecycle::RecordLocked(LifecycleEvent Event, DriverState From,
                                               DriverState To, LifecycleError Error,
                                               std::int64_t CallbackStatus,
                                               std::uint64_t Subject) {
    Journal_.push_back(JournalEntry{NextJournalSequence_++, Event, From, To, Error,
                                    CallbackStatus, Subject});
    return {Error, CallbackStatus};
}

LifecycleResult DriverLifecycle::RejectLocked(LifecycleEvent Event, LifecycleError Error,
                                               std::uint64_t Subject) {
    return RecordLocked(Event, State_, State_, Error, 0, Subject);
}

void DriverLifecycle::EnterFailedLocked(LifecycleEvent Event, DriverState From,
                                        LifecycleError Error,
                                        std::int64_t CallbackStatus) {
    State_ = DriverState::Failed;
    OperationInProgress_ = false;
    RemoveGate_ = false;
    RecordLocked(Event, From, DriverState::Failed, Error, CallbackStatus);
    RemoveCondition_.notify_all();
}

DispatchInvocation DriverLifecycle::MakeDispatchLocked(DispatchKind Kind) const {
    DispatchInvocation Invocation;
    Invocation.Kind = Kind;
    if (Driver_) Invocation.Driver = *Driver_;
    Invocation.Device = Device_;
    Invocation.Resources = Resources_;
    Invocation.PreviousDevicePower = DevicePower_;
    Invocation.TargetDevicePower = DevicePower_;
    Invocation.PreviousSystemPower = SystemPower_;
    Invocation.TargetSystemPower = SystemPower_;
    return Invocation;
}

std::uint64_t DriverLifecycle::RemoveLockCountLocked() const noexcept {
    std::uint64_t Total = 0;
    for (const auto& [Tag, Count] : RemoveLocks_) {
        (void)Tag;
        if (Total > std::numeric_limits<std::uint64_t>::max() - Count)
            return std::numeric_limits<std::uint64_t>::max();
        Total += Count;
    }
    return Total;
}

LifecycleResult DriverLifecycle::EnterDriver(const DriverIdentity& Driver) {
    if (!ValidateDriverIdentity(Driver)) {
        std::scoped_lock Lock(Mutex_);
        return RejectLocked(LifecycleEvent::DriverEntry, LifecycleError::InvalidGuestAddress);
    }

    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::DriverEntry, LifecycleError::Busy);
        if (State_ != DriverState::Loaded)
            return RejectLocked(LifecycleEvent::DriverEntry, LifecycleError::IllegalTransition);
        OperationInProgress_ = true;
        State_ = DriverState::DriverEntry;
        Driver_ = Driver;
    }

    bool Threw = false;
    const auto Callback = InvokeDriverEntry(DriverEntryInvocation{Driver}, Threw);

    std::scoped_lock Lock(Mutex_);
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        EnterFailedLocked(LifecycleEvent::DriverEntry, DriverState::Loaded, Error,
                          Callback.Status);
        return {Error, Callback.Status};
    }
    State_ = Config_.ExplicitNoDevice ? DriverState::Running : DriverState::DriverEntry;
    OperationInProgress_ = false;
    return RecordLocked(LifecycleEvent::DriverEntry, DriverState::Loaded, State_,
                        LifecycleError::None, Callback.Status);
}

LifecycleResult DriverLifecycle::AttachDevice(const DeviceDescription& Device) {
    if (!ValidateDeviceDescription(Device)) {
        std::scoped_lock Lock(Mutex_);
        return RejectLocked(LifecycleEvent::AddDevice, LifecycleError::InvalidGuestAddress);
    }

    DriverState From;
    DeviceIdentity Identity;
    DriverIdentity Driver;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::AddDevice, LifecycleError::Busy);
        const bool InitialDevice = State_ == DriverState::DriverEntry;
        const bool PersistentReplacement = Config_.PersistentDriver &&
            State_ == DriverState::Running && !Device_;
        if ((!InitialDevice && !PersistentReplacement) || !Driver_ || Device_ ||
            SystemPower_ != SystemPowerState::Working)
            return RejectLocked(LifecycleEvent::AddDevice, LifecycleError::IllegalTransition);
        if (NextSyntheticIdentity_ == 0 ||
            NextSyntheticIdentity_ > std::numeric_limits<std::uint64_t>::max() - 1)
            return RejectLocked(LifecycleEvent::AddDevice, LifecycleError::InvalidConfiguration);

        From = State_;
        Driver = *Driver_;
        Identity = {NextSyntheticIdentity_, NextSyntheticIdentity_ + 1, Device};
        Device_ = Identity;
        State_ = DriverState::AddDevice;
        OperationInProgress_ = true;
    }

    bool Threw = false;
    const auto Callback = InvokeAddDevice(AddDeviceInvocation{Driver, Identity}, Threw);

    std::scoped_lock Lock(Mutex_);
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        EnterFailedLocked(LifecycleEvent::AddDevice, From, Error, Callback.Status);
        return {Error, Callback.Status};
    }
    NextSyntheticIdentity_ += 2;
    State_ = DriverState::AddDevice;
    OperationInProgress_ = false;
    return RecordLocked(LifecycleEvent::AddDevice, From, State_, LifecycleError::None,
                        Callback.Status, Identity.SyntheticFdo);
}

LifecycleResult DriverLifecycle::StartDevice(const ResourceLists& Resources) {
    if (!ValidateResources(Resources)) {
        std::scoped_lock Lock(Mutex_);
        return RejectLocked(LifecycleEvent::PnpStart, LifecycleError::InvalidResources);
    }

    DriverState From;
    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::PnpStart, LifecycleError::Busy);
        if ((State_ != DriverState::AddDevice && State_ != DriverState::PnpStop) ||
            !Device_ || SystemPower_ != SystemPowerState::Working ||
            DevicePower_ != DevicePowerState::D3)
            return RejectLocked(LifecycleEvent::PnpStart, LifecycleError::IllegalTransition);
        From = State_;
        State_ = DriverState::PnpStart;
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::PnpStart);
        Invocation.Resources = Resources;
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        EnterFailedLocked(LifecycleEvent::PnpStart, From, Error, Callback.Status);
        return {Error, Callback.Status};
    }
    Resources_ = Resources;
    DevicePower_ = DevicePowerState::D0;
    State_ = DriverState::Running;
    OperationInProgress_ = false;
    return RecordLocked(LifecycleEvent::PnpStart, From, State_, LifecycleError::None,
                        Callback.Status, Device_->SyntheticFdo);
}

LifecycleResult DriverLifecycle::QueryStopDevice() {
    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::PnpQueryStop, LifecycleError::Busy);
        if (State_ != DriverState::Running || !Device_ ||
            DevicePower_ != DevicePowerState::D0)
            return RejectLocked(LifecycleEvent::PnpQueryStop, LifecycleError::IllegalTransition);
        State_ = DriverState::PnpQueryStop;
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::PnpQueryStop);
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    if (Threw || !Callback.Succeeded) {
        State_ = DriverState::Running;
        OperationInProgress_ = false;
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        return RecordLocked(LifecycleEvent::PnpQueryStop, DriverState::Running,
                            DriverState::Running, Error, Callback.Status);
    }
    OperationInProgress_ = false;
    return RecordLocked(LifecycleEvent::PnpQueryStop, DriverState::Running,
                        DriverState::PnpQueryStop, LifecycleError::None, Callback.Status);
}

LifecycleResult DriverLifecycle::CancelStopDevice() {
    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::PnpCancelStop, LifecycleError::Busy);
        if (State_ != DriverState::PnpQueryStop || !Device_)
            return RejectLocked(LifecycleEvent::PnpCancelStop, LifecycleError::IllegalTransition);
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::PnpCancelStop);
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    OperationInProgress_ = false;
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        return RecordLocked(LifecycleEvent::PnpCancelStop, DriverState::PnpQueryStop,
                            DriverState::PnpQueryStop, Error, Callback.Status);
    }
    State_ = DriverState::Running;
    return RecordLocked(LifecycleEvent::PnpCancelStop, DriverState::PnpQueryStop,
                        DriverState::Running, LifecycleError::None, Callback.Status);
}

LifecycleResult DriverLifecycle::StopDevice() {
    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::PnpStop, LifecycleError::Busy);
        if (State_ != DriverState::PnpQueryStop || !Device_ ||
            DevicePower_ != DevicePowerState::D3)
            return RejectLocked(LifecycleEvent::PnpStop, LifecycleError::IllegalTransition);
        State_ = DriverState::PnpStop;
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::PnpStop);
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        EnterFailedLocked(LifecycleEvent::PnpStop, DriverState::PnpQueryStop, Error,
                          Callback.Status);
        return {Error, Callback.Status};
    }
    OperationInProgress_ = false;
    return RecordLocked(LifecycleEvent::PnpStop, DriverState::PnpQueryStop,
                        DriverState::PnpStop, LifecycleError::None, Callback.Status,
                        Device_->SyntheticFdo);
}

LifecycleResult DriverLifecycle::QueryRemoveDevice() {
    DriverState From;
    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::PnpQueryRemove, LifecycleError::Busy);
        if ((State_ != DriverState::Running && State_ != DriverState::PnpStop) || !Device_)
            return RejectLocked(LifecycleEvent::PnpQueryRemove, LifecycleError::IllegalTransition);
        From = State_;
        QueryRemoveReturnState_ = From;
        State_ = DriverState::PnpQueryRemove;
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::PnpQueryRemove);
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    if (Threw || !Callback.Succeeded) {
        State_ = From;
        QueryRemoveReturnState_ = DriverState::Running;
        OperationInProgress_ = false;
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        return RecordLocked(LifecycleEvent::PnpQueryRemove, From, From, Error,
                            Callback.Status);
    }
    OperationInProgress_ = false;
    return RecordLocked(LifecycleEvent::PnpQueryRemove, From,
                        DriverState::PnpQueryRemove, LifecycleError::None,
                        Callback.Status);
}

LifecycleResult DriverLifecycle::CancelRemoveDevice() {
    DriverState Target;
    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::PnpCancelRemove, LifecycleError::Busy);
        if (State_ != DriverState::PnpQueryRemove || !Device_ ||
            (QueryRemoveReturnState_ != DriverState::Running &&
             QueryRemoveReturnState_ != DriverState::PnpStop))
            return RejectLocked(LifecycleEvent::PnpCancelRemove, LifecycleError::IllegalTransition);
        Target = QueryRemoveReturnState_;
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::PnpCancelRemove);
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    OperationInProgress_ = false;
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        return RecordLocked(LifecycleEvent::PnpCancelRemove,
                            DriverState::PnpQueryRemove,
                            DriverState::PnpQueryRemove, Error, Callback.Status);
    }
    State_ = Target;
    QueryRemoveReturnState_ = DriverState::Running;
    return RecordLocked(LifecycleEvent::PnpCancelRemove,
                        DriverState::PnpQueryRemove, Target,
                        LifecycleError::None, Callback.Status);
}

LifecycleResult DriverLifecycle::RemoveDevice() {
    DispatchInvocation Invocation;
    std::uint64_t Subject = 0;
    {
        std::unique_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::PnpRemove, LifecycleError::Busy);
        if (State_ != DriverState::PnpQueryRemove || !Device_ ||
            DevicePower_ != DevicePowerState::D3)
            return RejectLocked(LifecycleEvent::PnpRemove, LifecycleError::IllegalTransition);
        Subject = Device_->SyntheticFdo;
        RemoveGate_ = true;
        OperationInProgress_ = true;
        State_ = DriverState::PnpRemove;
        RemoveCondition_.wait(Lock, [this] {
            return OutstandingIrps_.empty() && RemoveLocks_.empty();
        });
        Invocation = MakeDispatchLocked(DispatchKind::PnpRemove);
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    RemoveGate_ = false;
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        EnterFailedLocked(LifecycleEvent::PnpRemove,
                          DriverState::PnpQueryRemove, Error, Callback.Status);
        return {Error, Callback.Status};
    }
    Device_.reset();
    Resources_ = {};
    Relations_.clear();
    DevicePower_ = DevicePowerState::D3;
    QueryRemoveReturnState_ = DriverState::Running;
    State_ = Config_.PersistentDriver ? DriverState::Running : DriverState::PnpRemove;
    OperationInProgress_ = false;
    return RecordLocked(LifecycleEvent::PnpRemove, DriverState::PnpQueryRemove,
                        State_, LifecycleError::None, Callback.Status, Subject);
}

LifecycleResult DriverLifecycle::SetDevicePower(DevicePowerState Target) {
    if (!IsValidDevicePower(Target)) {
        std::scoped_lock Lock(Mutex_);
        return RejectLocked(LifecycleEvent::DevicePower, LifecycleError::IllegalTransition,
                            static_cast<std::uint64_t>(Target));
    }

    DevicePowerState Previous;
    DriverState DriverStateValue;
    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::DevicePower, LifecycleError::Busy);
        const bool StateAllowsPower = State_ == DriverState::Running ||
            State_ == DriverState::PnpQueryStop || State_ == DriverState::PnpQueryRemove;
        if (!StateAllowsPower || !Device_ ||
            (SystemPower_ != SystemPowerState::Working && Target == DevicePowerState::D0))
            return RejectLocked(LifecycleEvent::DevicePower, LifecycleError::IllegalTransition,
                                static_cast<std::uint64_t>(Target));
        Previous = DevicePower_;
        DriverStateValue = State_;
        if (Previous == Target)
            return RecordLocked(LifecycleEvent::DevicePower, State_, State_,
                                LifecycleError::None, 0,
                                static_cast<std::uint64_t>(Target));
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::DevicePower);
        Invocation.TargetDevicePower = Target;
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    OperationInProgress_ = false;
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        return RecordLocked(LifecycleEvent::DevicePower, DriverStateValue,
                            DriverStateValue, Error, Callback.Status,
                            static_cast<std::uint64_t>(Target));
    }
    DevicePower_ = Target;
    return RecordLocked(LifecycleEvent::DevicePower, DriverStateValue,
                        DriverStateValue, LifecycleError::None, Callback.Status,
                        static_cast<std::uint64_t>(Target));
}

LifecycleResult DriverLifecycle::SetSystemPower(SystemPowerState Target) {
    if (!IsValidSystemPower(Target)) {
        std::scoped_lock Lock(Mutex_);
        return RejectLocked(LifecycleEvent::SystemPower, LifecycleError::IllegalTransition,
                            static_cast<std::uint64_t>(Target));
    }

    SystemPowerState Previous;
    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::SystemPower, LifecycleError::Busy);
        if (State_ != DriverState::Running || !Driver_ ||
            (Target != SystemPowerState::Working && DevicePower_ != DevicePowerState::D3))
            return RejectLocked(LifecycleEvent::SystemPower, LifecycleError::IllegalTransition,
                                static_cast<std::uint64_t>(Target));
        Previous = SystemPower_;
        if (Previous == Target)
            return RecordLocked(LifecycleEvent::SystemPower, State_, State_,
                                LifecycleError::None, 0,
                                static_cast<std::uint64_t>(Target));
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::SystemPower);
        Invocation.TargetSystemPower = Target;
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    OperationInProgress_ = false;
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        return RecordLocked(LifecycleEvent::SystemPower, DriverState::Running,
                            DriverState::Running, Error, Callback.Status,
                            static_cast<std::uint64_t>(Target));
    }
    SystemPower_ = Target;
    return RecordLocked(LifecycleEvent::SystemPower, DriverState::Running,
                        DriverState::Running, LifecycleError::None, Callback.Status,
                        static_cast<std::uint64_t>(Target));
}

LifecycleResult DriverLifecycle::DispatchWmi(const WmiRequest& Request) {
    if (!ValidateWmiRequest(Request)) {
        std::scoped_lock Lock(Mutex_);
        return RejectLocked(LifecycleEvent::Wmi, LifecycleError::InvalidGuestAddress,
                            Request.ProviderId);
    }

    DispatchInvocation Invocation;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::Wmi, LifecycleError::Busy,
                                                       Request.ProviderId);
        if (State_ != DriverState::Running || !Driver_)
            return RejectLocked(LifecycleEvent::Wmi, LifecycleError::IllegalTransition,
                                Request.ProviderId);
        OperationInProgress_ = true;
        Invocation = MakeDispatchLocked(DispatchKind::Wmi);
        Invocation.Wmi = Request;
    }

    bool Threw = false;
    const auto Callback = InvokeDispatch(Invocation, Threw);

    std::scoped_lock Lock(Mutex_);
    OperationInProgress_ = false;
    const auto Error = Threw ? LifecycleError::CallbackException
                             : Callback.Succeeded ? LifecycleError::None
                                                  : LifecycleError::CallbackRejected;
    return RecordLocked(LifecycleEvent::Wmi, DriverState::Running,
                        DriverState::Running, Error, Callback.Status,
                        Request.ProviderId);
}

LifecycleResult DriverLifecycle::SetDeviceRelations(std::vector<DeviceRelation> Relations) {
    if (!ValidateRelations(Relations)) {
        std::scoped_lock Lock(Mutex_);
        return RejectLocked(LifecycleEvent::RelationsUpdated,
                            LifecycleError::InvalidGuestAddress);
    }
    std::scoped_lock Lock(Mutex_);
    if (OperationInProgress_) return RejectLocked(LifecycleEvent::RelationsUpdated, LifecycleError::Busy);
    if (!Device_ || (State_ != DriverState::AddDevice && State_ != DriverState::Running &&
                     State_ != DriverState::PnpStop))
        return RejectLocked(LifecycleEvent::RelationsUpdated,
                            LifecycleError::IllegalTransition);
    Relations_ = std::move(Relations);
    return RecordLocked(LifecycleEvent::RelationsUpdated, State_, State_);
}

LifecycleResult DriverLifecycle::AcquireRemoveLock(std::uint64_t Tag) {
    std::scoped_lock Lock(Mutex_);
    if (Tag == 0) return RejectLocked(LifecycleEvent::RemoveLockAcquired,
                                      LifecycleError::InvalidRemoveLock, Tag);
    if (OperationInProgress_ || RemoveGate_ || State_ != DriverState::Running)
        return RejectLocked(LifecycleEvent::RemoveLockAcquired,
                            RemoveGate_ ? LifecycleError::RemoveInProgress
                                        : LifecycleError::IllegalTransition,
                            Tag);
    auto& Count = RemoveLocks_[Tag];
    if (Count == std::numeric_limits<std::uint64_t>::max()) {
        RemoveLocks_.erase(Tag);
        return RejectLocked(LifecycleEvent::RemoveLockAcquired,
                            LifecycleError::InvalidRemoveLock, Tag);
    }
    ++Count;
    return RecordLocked(LifecycleEvent::RemoveLockAcquired, State_, State_,
                        LifecycleError::None, 0, Tag);
}

LifecycleResult DriverLifecycle::ReleaseRemoveLock(std::uint64_t Tag) {
    std::scoped_lock Lock(Mutex_);
    const auto It = RemoveLocks_.find(Tag);
    if (Tag == 0 || It == RemoveLocks_.end())
        return RejectLocked(LifecycleEvent::RemoveLockReleased,
                            LifecycleError::InvalidRemoveLock, Tag);
    if (--It->second == 0) RemoveLocks_.erase(It);
    const auto Result = RecordLocked(LifecycleEvent::RemoveLockReleased,
                                     State_, State_, LifecycleError::None, 0, Tag);
    if (RemoveLocks_.empty() && OutstandingIrps_.empty()) RemoveCondition_.notify_all();
    return Result;
}

LifecycleResult DriverLifecycle::BeginIrp(std::uint64_t IrpId) {
    std::scoped_lock Lock(Mutex_);
    if (IrpId == 0)
        return RejectLocked(LifecycleEvent::IrpStarted, LifecycleError::DuplicateIrp, IrpId);
    if (OperationInProgress_ || RemoveGate_ || State_ != DriverState::Running)
        return RejectLocked(LifecycleEvent::IrpStarted,
                            RemoveGate_ ? LifecycleError::RemoveInProgress
                                        : LifecycleError::IllegalTransition,
                            IrpId);
    const auto It = std::lower_bound(OutstandingIrps_.begin(), OutstandingIrps_.end(), IrpId);
    if (It != OutstandingIrps_.end() && *It == IrpId)
        return RejectLocked(LifecycleEvent::IrpStarted, LifecycleError::DuplicateIrp, IrpId);
    OutstandingIrps_.insert(It, IrpId);
    return RecordLocked(LifecycleEvent::IrpStarted, State_, State_,
                        LifecycleError::None, 0, IrpId);
}

LifecycleResult DriverLifecycle::CompleteIrp(std::uint64_t IrpId) {
    std::scoped_lock Lock(Mutex_);
    const auto It = std::lower_bound(OutstandingIrps_.begin(), OutstandingIrps_.end(), IrpId);
    if (It == OutstandingIrps_.end() || *It != IrpId)
        return RejectLocked(LifecycleEvent::IrpCompleted, LifecycleError::UnknownIrp, IrpId);
    OutstandingIrps_.erase(It);
    const auto Result = RecordLocked(LifecycleEvent::IrpCompleted, State_, State_,
                                     LifecycleError::None, 0, IrpId);
    if (OutstandingIrps_.empty() && RemoveLocks_.empty()) RemoveCondition_.notify_all();
    return Result;
}

LifecycleResult DriverLifecycle::Unload() {
    DriverIdentity Driver;
    DriverState From;
    {
        std::scoped_lock Lock(Mutex_);
        if (OperationInProgress_) return RejectLocked(LifecycleEvent::Unload, LifecycleError::Busy);
        const bool RemovedDevice = State_ == DriverState::PnpRemove;
        const bool DeviceLessRunning = State_ == DriverState::Running && !Device_;
        if ((!RemovedDevice && !DeviceLessRunning) || !Driver_ ||
            !OutstandingIrps_.empty() || !RemoveLocks_.empty() ||
            DevicePower_ != DevicePowerState::D3 ||
            SystemPower_ != SystemPowerState::Working)
            return RejectLocked(LifecycleEvent::Unload, LifecycleError::IllegalTransition);
        From = State_;
        Driver = *Driver_;
        State_ = DriverState::Unload;
        OperationInProgress_ = true;
    }

    bool Threw = false;
    const auto Callback = InvokeUnload(UnloadInvocation{Driver}, Threw);

    std::scoped_lock Lock(Mutex_);
    if (Threw || !Callback.Succeeded) {
        const auto Error = Threw ? LifecycleError::CallbackException
                                 : LifecycleError::CallbackRejected;
        EnterFailedLocked(LifecycleEvent::Unload, From, Error, Callback.Status);
        return {Error, Callback.Status};
    }
    Driver_.reset();
    State_ = DriverState::Unload;
    OperationInProgress_ = false;
    return RecordLocked(LifecycleEvent::Unload, From, DriverState::Unload,
                        LifecycleError::None, Callback.Status);
}

DriverState DriverLifecycle::State() const {
    std::scoped_lock Lock(Mutex_);
    return State_;
}

DevicePowerState DriverLifecycle::DevicePower() const {
    std::scoped_lock Lock(Mutex_);
    return DevicePower_;
}

SystemPowerState DriverLifecycle::SystemPower() const {
    std::scoped_lock Lock(Mutex_);
    return SystemPower_;
}

std::optional<DriverIdentity> DriverLifecycle::Driver() const {
    std::scoped_lock Lock(Mutex_);
    return Driver_;
}

std::optional<DeviceIdentity> DriverLifecycle::Device() const {
    std::scoped_lock Lock(Mutex_);
    return Device_;
}

ResourceLists DriverLifecycle::Resources() const {
    std::scoped_lock Lock(Mutex_);
    return Resources_;
}

std::vector<DeviceRelation> DriverLifecycle::DeviceRelations() const {
    std::scoped_lock Lock(Mutex_);
    return Relations_;
}

std::uint64_t DriverLifecycle::OutstandingIrpCount() const {
    std::scoped_lock Lock(Mutex_);
    return static_cast<std::uint64_t>(OutstandingIrps_.size());
}

std::uint64_t DriverLifecycle::RemoveLockCount() const {
    std::scoped_lock Lock(Mutex_);
    return RemoveLockCountLocked();
}

std::vector<JournalEntry> DriverLifecycle::Journal() const {
    std::scoped_lock Lock(Mutex_);
    return Journal_;
}

std::optional<DriverLifecycleSnapshot> DriverLifecycle::Snapshot() const {
    std::scoped_lock Lock(Mutex_);
    if (OperationInProgress_ || RemoveGate_) return std::nullopt;
    DriverLifecycleSnapshot Result;
    Result.PersistentDriver = Config_.PersistentDriver;
    Result.ExplicitNoDevice = Config_.ExplicitNoDevice;
    Result.State = State_;
    Result.DevicePower = DevicePower_;
    Result.SystemPower = SystemPower_;
    Result.QueryRemoveReturnState = QueryRemoveReturnState_;
    Result.Driver = Driver_;
    Result.Device = Device_;
    Result.Resources = Resources_;
    Result.Relations = Relations_;
    Result.OutstandingIrps = OutstandingIrps_;
    Result.Journal = Journal_;
    Result.NextJournalSequence = NextJournalSequence_;
    Result.NextSyntheticIdentity = NextSyntheticIdentity_;
    Result.RemoveLocks.reserve(RemoveLocks_.size());
    for (const auto& [Tag, Count] : RemoveLocks_)
        Result.RemoveLocks.push_back({Tag, Count});
    return Result;
}

bool DriverLifecycle::ValidateSnapshot(const DriverLifecycleSnapshot& Snapshot) const noexcept {
    if (Snapshot.PersistentDriver != Config_.PersistentDriver ||
        Snapshot.ExplicitNoDevice != Config_.ExplicitNoDevice ||
        !IsValidDriverState(Snapshot.State) ||
        !IsValidDriverState(Snapshot.QueryRemoveReturnState) ||
        !IsValidDevicePower(Snapshot.DevicePower) ||
        !IsValidSystemPower(Snapshot.SystemPower) ||
        Snapshot.NextJournalSequence == 0 || Snapshot.NextSyntheticIdentity == 0 ||
        Snapshot.RemoveLocks.size() > kMaximumSnapshotEntries ||
        Snapshot.OutstandingIrps.size() > kMaximumSnapshotEntries ||
        Snapshot.Journal.size() > kMaximumSnapshotEntries ||
        !ValidateResources(Snapshot.Resources) ||
        !ValidateRelations(Snapshot.Relations)) return false;

    if (Snapshot.Driver && !ValidateDriverIdentity(*Snapshot.Driver)) return false;
    if (Snapshot.Device &&
        (!ValidateDeviceDescription(Snapshot.Device->Guest) ||
         Snapshot.Device->SyntheticPdo == 0 || Snapshot.Device->SyntheticFdo == 0 ||
         Snapshot.Device->SyntheticPdo == Snapshot.Device->SyntheticFdo ||
         Snapshot.Device->SyntheticPdo >= Snapshot.NextSyntheticIdentity ||
         Snapshot.Device->SyntheticFdo >= Snapshot.NextSyntheticIdentity)) return false;

    const bool NeedsDriver = Snapshot.State != DriverState::Loaded &&
                             Snapshot.State != DriverState::Unload;
    if (NeedsDriver != Snapshot.Driver.has_value()) return false;
    const bool NeedsDevice = Snapshot.State == DriverState::AddDevice ||
        Snapshot.State == DriverState::PnpStart || Snapshot.State == DriverState::PnpQueryStop ||
        Snapshot.State == DriverState::PnpStop || Snapshot.State == DriverState::PnpQueryRemove;
    if (NeedsDevice && !Snapshot.Device) return false;
    if ((Snapshot.State == DriverState::Loaded || Snapshot.State == DriverState::DriverEntry ||
         Snapshot.State == DriverState::PnpRemove || Snapshot.State == DriverState::Unload) &&
        Snapshot.Device) return false;
    if (Snapshot.State == DriverState::Running && !Snapshot.Device &&
        !Snapshot.ExplicitNoDevice && !Snapshot.PersistentDriver) return false;
    if (Snapshot.State == DriverState::PnpQueryRemove &&
        Snapshot.QueryRemoveReturnState != DriverState::Running &&
        Snapshot.QueryRemoveReturnState != DriverState::PnpStop) return false;
    if (Snapshot.State != DriverState::PnpQueryRemove &&
        Snapshot.QueryRemoveReturnState != DriverState::Running) return false;
    if (!Snapshot.Device && (!Snapshot.Resources.Raw.empty() ||
                             !Snapshot.Resources.Translated.empty() ||
                             !Snapshot.Relations.empty())) return false;
    if (Snapshot.SystemPower != SystemPowerState::Working &&
        Snapshot.DevicePower != DevicePowerState::D3) return false;
    if ((Snapshot.State == DriverState::AddDevice || Snapshot.State == DriverState::PnpStop ||
         Snapshot.State == DriverState::PnpQueryRemove || Snapshot.State == DriverState::PnpRemove ||
         Snapshot.State == DriverState::Unload || Snapshot.State == DriverState::Loaded ||
         Snapshot.State == DriverState::DriverEntry) &&
        Snapshot.DevicePower != DevicePowerState::D3) return false;
    if ((!Snapshot.OutstandingIrps.empty() || !Snapshot.RemoveLocks.empty()) &&
        Snapshot.State != DriverState::Running) return false;

    std::uint64_t PreviousTag = 0;
    for (const auto& Lock : Snapshot.RemoveLocks) {
        if (Lock.Tag == 0 || Lock.Count == 0 || Lock.Tag <= PreviousTag) return false;
        PreviousTag = Lock.Tag;
    }
    if (!std::is_sorted(Snapshot.OutstandingIrps.begin(), Snapshot.OutstandingIrps.end()) ||
        std::adjacent_find(Snapshot.OutstandingIrps.begin(), Snapshot.OutstandingIrps.end()) !=
            Snapshot.OutstandingIrps.end() ||
        std::find(Snapshot.OutstandingIrps.begin(), Snapshot.OutstandingIrps.end(), 0) !=
            Snapshot.OutstandingIrps.end()) return false;

    std::uint64_t PreviousSequence = 0;
    for (const auto& Entry : Snapshot.Journal) {
        if (Entry.Sequence == 0 || Entry.Sequence <= PreviousSequence ||
            !IsValidEvent(Entry.Event) || !IsValidDriverState(Entry.From) ||
            !IsValidDriverState(Entry.To) || !IsValidError(Entry.Error)) return false;
        PreviousSequence = Entry.Sequence;
    }
    return Snapshot.NextJournalSequence > PreviousSequence;
}

LifecycleResult DriverLifecycle::Restore(const DriverLifecycleSnapshot& SnapshotValue) {
    if (!ValidateSnapshot(SnapshotValue)) return {LifecycleError::CorruptSnapshot, 0};

    std::scoped_lock Lock(Mutex_);
    if (OperationInProgress_ || RemoveGate_) return {LifecycleError::Busy, 0};

    std::map<std::uint64_t, std::uint64_t> Locks;
    for (const auto& LockValue : SnapshotValue.RemoveLocks)
        Locks.emplace(LockValue.Tag, LockValue.Count);

    State_ = SnapshotValue.State;
    DevicePower_ = SnapshotValue.DevicePower;
    SystemPower_ = SnapshotValue.SystemPower;
    QueryRemoveReturnState_ = SnapshotValue.QueryRemoveReturnState;
    Driver_ = SnapshotValue.Driver;
    Device_ = SnapshotValue.Device;
    Resources_ = SnapshotValue.Resources;
    Relations_ = SnapshotValue.Relations;
    RemoveLocks_ = std::move(Locks);
    OutstandingIrps_ = SnapshotValue.OutstandingIrps;
    Journal_ = SnapshotValue.Journal;
    NextJournalSequence_ = SnapshotValue.NextJournalSequence;
    NextSyntheticIdentity_ = SnapshotValue.NextSyntheticIdentity;
    OperationInProgress_ = false;
    RemoveGate_ = false;
    return {};
}

} // namespace Kevlar::Lifecycle
