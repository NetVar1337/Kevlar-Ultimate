#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace Kevlar::Lifecycle {

using GuestAddress = std::uint64_t;

struct GuestRange {
    GuestAddress Address = 0;
    std::uint64_t Length = 0;

    bool operator==(const GuestRange&) const = default;
};

enum class GuestAccess : std::uint8_t {
    Read,
    Write,
    ReadWrite,
};

using GuestAddressValidator =
    std::function<bool(GuestAddress Address, std::uint64_t Length, GuestAccess Access)>;

enum class DriverState : std::uint8_t {
    Loaded,
    DriverEntry,
    AddDevice,
    PnpStart,
    Running,
    PnpQueryStop,
    PnpStop,
    PnpQueryRemove,
    PnpRemove,
    Unload,
    Failed,
};

enum class DevicePowerState : std::uint8_t {
    D0,
    D1,
    D2,
    D3,
};

enum class SystemPowerState : std::uint8_t {
    Working,
    Sleeping1,
    Sleeping2,
    Sleeping3,
    Hibernate,
    Shutdown,
};

enum class ResourceType : std::uint8_t {
    Port,
    Memory,
    Interrupt,
    Dma,
    DevicePrivate,
};

struct ResourceDescriptor {
    ResourceType Type = ResourceType::Memory;
    std::uint64_t Start = 0;
    std::uint64_t Length = 0;
    std::uint32_t Flags = 0;

    bool operator==(const ResourceDescriptor&) const = default;
};

struct ResourceLists {
    std::vector<ResourceDescriptor> Raw;
    std::vector<ResourceDescriptor> Translated;

    bool operator==(const ResourceLists&) const = default;
};

enum class DeviceRelationType : std::uint8_t {
    Bus,
    Ejection,
    Removal,
    Target,
};

struct DeviceRelation {
    DeviceRelationType Type = DeviceRelationType::Bus;
    std::vector<GuestRange> Objects;

    bool operator==(const DeviceRelation&) const = default;
};

struct DriverIdentity {
    GuestRange DriverObject;
    GuestRange RegistryPath;

    bool operator==(const DriverIdentity&) const = default;
};

struct DeviceDescription {
    GuestRange PhysicalDeviceObject;
    GuestRange FunctionalDeviceObject;
    std::string InstanceId;

    bool operator==(const DeviceDescription&) const = default;
};

struct DeviceIdentity {
    std::uint64_t SyntheticPdo = 0;
    std::uint64_t SyntheticFdo = 0;
    DeviceDescription Guest;

    bool operator==(const DeviceIdentity&) const = default;
};

enum class DispatchKind : std::uint8_t {
    PnpStart,
    PnpQueryStop,
    PnpCancelStop,
    PnpStop,
    PnpQueryRemove,
    PnpCancelRemove,
    PnpRemove,
    DevicePower,
    SystemPower,
    Wmi,
};

struct WmiRequest {
    std::uint32_t ProviderId = 0;
    std::uint8_t MinorFunction = 0;
    GuestRange Input;
    GuestRange Output;

    bool operator==(const WmiRequest&) const = default;
};

struct DriverEntryInvocation {
    DriverIdentity Driver;
};

struct AddDeviceInvocation {
    DriverIdentity Driver;
    DeviceIdentity Device;
};

struct DispatchInvocation {
    DispatchKind Kind = DispatchKind::PnpStart;
    DriverIdentity Driver;
    std::optional<DeviceIdentity> Device;
    ResourceLists Resources;
    DevicePowerState PreviousDevicePower = DevicePowerState::D3;
    DevicePowerState TargetDevicePower = DevicePowerState::D3;
    SystemPowerState PreviousSystemPower = SystemPowerState::Working;
    SystemPowerState TargetSystemPower = SystemPowerState::Working;
    WmiRequest Wmi;
};

struct UnloadInvocation {
    DriverIdentity Driver;
};

struct CallbackResult {
    bool Succeeded = true;
    std::int64_t Status = 0;
};

struct LifecycleCallbacks {
    std::function<CallbackResult(const DriverEntryInvocation&)> DriverEntry;
    std::function<CallbackResult(const AddDeviceInvocation&)> AddDevice;
    std::function<CallbackResult(const DispatchInvocation&)> Dispatch;
    std::function<CallbackResult(const UnloadInvocation&)> Unload;
};

struct LifecycleConfig {
    bool PersistentDriver = false;
    bool ExplicitNoDevice = false;
    std::uint64_t FirstSyntheticIdentity = 1;
    GuestAddressValidator ValidateGuestAddress;
    LifecycleCallbacks Callbacks;
};

enum class LifecycleError : std::uint8_t {
    None,
    IllegalTransition,
    InvalidConfiguration,
    InvalidGuestAddress,
    InvalidResources,
    DuplicateIrp,
    UnknownIrp,
    InvalidRemoveLock,
    RemoveInProgress,
    CallbackRejected,
    CallbackException,
    Busy,
    CorruptSnapshot,
};

struct LifecycleResult {
    LifecycleError Error = LifecycleError::None;
    std::int64_t CallbackStatus = 0;

    [[nodiscard]] bool Ok() const noexcept { return Error == LifecycleError::None; }
    explicit operator bool() const noexcept { return Ok(); }
};

enum class LifecycleEvent : std::uint8_t {
    DriverEntry,
    AddDevice,
    PnpStart,
    PnpQueryStop,
    PnpCancelStop,
    PnpStop,
    PnpQueryRemove,
    PnpCancelRemove,
    PnpRemove,
    DevicePower,
    SystemPower,
    Wmi,
    RelationsUpdated,
    RemoveLockAcquired,
    RemoveLockReleased,
    IrpStarted,
    IrpCompleted,
    Unload,
};

struct JournalEntry {
    std::uint64_t Sequence = 0;
    LifecycleEvent Event = LifecycleEvent::DriverEntry;
    DriverState From = DriverState::Loaded;
    DriverState To = DriverState::Loaded;
    LifecycleError Error = LifecycleError::None;
    std::int64_t CallbackStatus = 0;
    std::uint64_t Subject = 0;

    bool operator==(const JournalEntry&) const = default;
};

struct RemoveLockSnapshot {
    std::uint64_t Tag = 0;
    std::uint64_t Count = 0;

    bool operator==(const RemoveLockSnapshot&) const = default;
};

struct DriverLifecycleSnapshot {
    bool PersistentDriver = false;
    bool ExplicitNoDevice = false;
    DriverState State = DriverState::Loaded;
    DevicePowerState DevicePower = DevicePowerState::D3;
    SystemPowerState SystemPower = SystemPowerState::Working;
    DriverState QueryRemoveReturnState = DriverState::Running;
    std::optional<DriverIdentity> Driver;
    std::optional<DeviceIdentity> Device;
    ResourceLists Resources;
    std::vector<DeviceRelation> Relations;
    std::vector<RemoveLockSnapshot> RemoveLocks;
    std::vector<std::uint64_t> OutstandingIrps;
    std::vector<JournalEntry> Journal;
    std::uint64_t NextJournalSequence = 1;
    std::uint64_t NextSyntheticIdentity = 1;

    bool operator==(const DriverLifecycleSnapshot&) const = default;
};

class DriverLifecycle final {
public:
    explicit DriverLifecycle(LifecycleConfig Config);
    DriverLifecycle(const DriverLifecycle&) = delete;
    DriverLifecycle& operator=(const DriverLifecycle&) = delete;

    [[nodiscard]] LifecycleResult EnterDriver(const DriverIdentity& Driver);
    [[nodiscard]] LifecycleResult AttachDevice(const DeviceDescription& Device);
    [[nodiscard]] LifecycleResult StartDevice(const ResourceLists& Resources);
    [[nodiscard]] LifecycleResult QueryStopDevice();
    [[nodiscard]] LifecycleResult CancelStopDevice();
    [[nodiscard]] LifecycleResult StopDevice();
    [[nodiscard]] LifecycleResult QueryRemoveDevice();
    [[nodiscard]] LifecycleResult CancelRemoveDevice();
    [[nodiscard]] LifecycleResult RemoveDevice();

    [[nodiscard]] LifecycleResult SetDevicePower(DevicePowerState State);
    [[nodiscard]] LifecycleResult SetSystemPower(SystemPowerState State);
    [[nodiscard]] LifecycleResult DispatchWmi(const WmiRequest& Request);
    [[nodiscard]] LifecycleResult SetDeviceRelations(std::vector<DeviceRelation> Relations);

    [[nodiscard]] LifecycleResult AcquireRemoveLock(std::uint64_t Tag);
    [[nodiscard]] LifecycleResult ReleaseRemoveLock(std::uint64_t Tag);
    [[nodiscard]] LifecycleResult BeginIrp(std::uint64_t IrpId);
    [[nodiscard]] LifecycleResult CompleteIrp(std::uint64_t IrpId);
    [[nodiscard]] LifecycleResult Unload();

    [[nodiscard]] DriverState State() const;
    [[nodiscard]] DevicePowerState DevicePower() const;
    [[nodiscard]] SystemPowerState SystemPower() const;
    [[nodiscard]] std::optional<DriverIdentity> Driver() const;
    [[nodiscard]] std::optional<DeviceIdentity> Device() const;
    [[nodiscard]] ResourceLists Resources() const;
    [[nodiscard]] std::vector<DeviceRelation> DeviceRelations() const;
    [[nodiscard]] std::uint64_t OutstandingIrpCount() const;
    [[nodiscard]] std::uint64_t RemoveLockCount() const;
    [[nodiscard]] std::vector<JournalEntry> Journal() const;

    // A snapshot is unavailable while a guest callback or remove drain is in progress.
    [[nodiscard]] std::optional<DriverLifecycleSnapshot> Snapshot() const;
    [[nodiscard]] LifecycleResult Restore(const DriverLifecycleSnapshot& Snapshot);

private:
    [[nodiscard]] bool ValidateGuestRange(const GuestRange& Range, GuestAccess Access) const noexcept;
    [[nodiscard]] bool ValidateDriverIdentity(const DriverIdentity& Driver) const noexcept;
    [[nodiscard]] bool ValidateDeviceDescription(const DeviceDescription& Device) const noexcept;
    [[nodiscard]] bool ValidateResources(const ResourceLists& Resources) const noexcept;
    [[nodiscard]] bool ValidateRelations(const std::vector<DeviceRelation>& Relations) const noexcept;
    [[nodiscard]] bool ValidateWmiRequest(const WmiRequest& Request) const noexcept;
    [[nodiscard]] bool ValidateSnapshot(const DriverLifecycleSnapshot& Snapshot) const noexcept;

    [[nodiscard]] CallbackResult InvokeDriverEntry(const DriverEntryInvocation& Invocation,
                                                   bool& Threw) const noexcept;
    [[nodiscard]] CallbackResult InvokeAddDevice(const AddDeviceInvocation& Invocation,
                                                 bool& Threw) const noexcept;
    [[nodiscard]] CallbackResult InvokeDispatch(const DispatchInvocation& Invocation,
                                                bool& Threw) const noexcept;
    [[nodiscard]] CallbackResult InvokeUnload(const UnloadInvocation& Invocation,
                                              bool& Threw) const noexcept;

    LifecycleResult RecordLocked(LifecycleEvent Event, DriverState From, DriverState To,
                                 LifecycleError Error = LifecycleError::None,
                                 std::int64_t CallbackStatus = 0,
                                 std::uint64_t Subject = 0);
    LifecycleResult RejectLocked(LifecycleEvent Event, LifecycleError Error,
                                 std::uint64_t Subject = 0);
    [[nodiscard]] DispatchInvocation MakeDispatchLocked(DispatchKind Kind) const;
    [[nodiscard]] std::uint64_t RemoveLockCountLocked() const noexcept;
    void EnterFailedLocked(LifecycleEvent Event, DriverState From,
                           LifecycleError Error, std::int64_t CallbackStatus);

    LifecycleConfig Config_;
    mutable std::mutex Mutex_;
    std::condition_variable RemoveCondition_;
    DriverState State_ = DriverState::Loaded;
    DevicePowerState DevicePower_ = DevicePowerState::D3;
    SystemPowerState SystemPower_ = SystemPowerState::Working;
    DriverState QueryRemoveReturnState_ = DriverState::Running;
    std::optional<DriverIdentity> Driver_;
    std::optional<DeviceIdentity> Device_;
    ResourceLists Resources_;
    std::vector<DeviceRelation> Relations_;
    std::map<std::uint64_t, std::uint64_t> RemoveLocks_;
    std::vector<std::uint64_t> OutstandingIrps_;
    std::vector<JournalEntry> Journal_;
    std::uint64_t NextJournalSequence_ = 1;
    std::uint64_t NextSyntheticIdentity_ = 1;
    bool OperationInProgress_ = false;
    bool RemoveGate_ = false;
};

} // namespace Kevlar::Lifecycle
