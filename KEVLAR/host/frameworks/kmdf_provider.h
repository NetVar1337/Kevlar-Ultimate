#pragma once

#include "framework_provider.h"

#include <deque>
#include <map>
#include <mutex>
#include <optional>

namespace Kevlar::Host::Frameworks {

enum class KmdfObjectType : std::uint8_t { Driver, Device, Queue, Request, Generic };
enum class KmdfQueueMode : std::uint8_t { Sequential, Parallel, Manual };
enum class KmdfRequestKind : std::uint8_t { Default, Read, Write, DeviceControl };
enum class KmdfRequestState : std::uint8_t { Created, Queued, Dispatched, Completed, Cancelled };

struct KmdfObjectCallbacks {
    CallbackDescriptor Cleanup{"EvtCleanupCallback", 0, 1};
    CallbackDescriptor Destroy{"EvtDestroyCallback", 0, 1};

    bool operator==(const KmdfObjectCallbacks&) const = default;
};

struct KmdfQueueCallbacks {
    CallbackDescriptor Default{"EvtIoDefault", 0, 2};
    CallbackDescriptor Read{"EvtIoRead", 0, 3};
    CallbackDescriptor Write{"EvtIoWrite", 0, 3};
    CallbackDescriptor DeviceControl{"EvtIoDeviceControl", 0, 4};

    bool operator==(const KmdfQueueCallbacks&) const = default;
};

struct KmdfRequestCallbacks {
    CallbackDescriptor Cancel{"EvtRequestCancel", 0, 1};

    bool operator==(const KmdfRequestCallbacks&) const = default;
};

struct KmdfObjectSnapshot {
    GuestHandle Handle;
    KmdfObjectType Type = KmdfObjectType::Generic;
    GuestHandle Parent;
    KmdfObjectCallbacks Callbacks;

    bool operator==(const KmdfObjectSnapshot&) const = default;
};

struct KmdfContextSnapshot {
    GuestHandle Handle;
    GuestHandle Owner;
    std::uint64_t TypeKey = 0;
    GuestAddress Address = 0;
    std::size_t Size = 0;
    CallbackDescriptor Cleanup{"EvtContextCleanup", 0, 2};

    bool operator==(const KmdfContextSnapshot&) const = default;
};

struct KmdfQueueSnapshot {
    GuestHandle Handle;
    GuestHandle Device;
    KmdfQueueMode Mode = KmdfQueueMode::Sequential;
    KmdfQueueCallbacks Callbacks;
    std::deque<GuestHandle> Pending;
    std::optional<GuestHandle> Active;

    bool operator==(const KmdfQueueSnapshot&) const = default;
};

struct KmdfRequestSnapshot {
    GuestHandle Handle;
    GuestHandle Queue;
    KmdfRequestKind Kind = KmdfRequestKind::Default;
    KmdfRequestState State = KmdfRequestState::Created;
    GuestAddress RequestData = 0;
    std::size_t RequestDataSize = 0;
    KmdfRequestCallbacks Callbacks;
    std::uint64_t CompletionStatus = 0;

    bool operator==(const KmdfRequestSnapshot&) const = default;
};

struct KmdfSnapshot {
    std::uint64_t NextHandleId = 1;
    std::uint64_t NextEventSequence = 1;
    std::map<GuestHandle, KmdfObjectSnapshot> Objects;
    std::map<GuestHandle, KmdfContextSnapshot> Contexts;
    std::map<GuestHandle, KmdfQueueSnapshot> Queues;
    std::map<GuestHandle, KmdfRequestSnapshot> Requests;

    bool operator==(const KmdfSnapshot&) const = default;
};

class KmdfProvider final : public FrameworkProvider {
public:
    explicit KmdfProvider(GuestAddressValidator Validator);

    [[nodiscard]] std::string_view Name() const noexcept override;
    [[nodiscard]] CapabilityReport Capabilities() const override;
    [[nodiscard]] ProviderState CaptureState() const override;
    [[nodiscard]] Status ValidateState(const ProviderState& State) const override;
    [[nodiscard]] Status RestoreState(const ProviderState& State) override;
    void Reset() override;

    [[nodiscard]] Result<GuestHandle> CreateObject(
        KmdfObjectType Type, GuestHandle Parent = {},
        KmdfObjectCallbacks Callbacks = {});
    [[nodiscard]] Result<GuestHandle> CreateContext(
        GuestHandle Owner, std::uint64_t TypeKey, GuestAddress Address,
        std::size_t Size, CallbackDescriptor Cleanup = {"EvtContextCleanup", 0, 2});
    [[nodiscard]] Result<GuestHandle> CreateQueue(
        GuestHandle Device, KmdfQueueMode Mode, KmdfQueueCallbacks Callbacks);
    [[nodiscard]] Result<GuestHandle> CreateRequest(
        GuestHandle Queue, KmdfRequestKind Kind, GuestAddress RequestData,
        std::size_t RequestDataSize, KmdfRequestCallbacks Callbacks = {});

    [[nodiscard]] Status EnqueueRequest(GuestHandle Request);
    [[nodiscard]] Result<CallbackInvocation> DispatchNext(GuestHandle Queue);
    [[nodiscard]] Result<std::optional<CallbackInvocation>> CancelRequest(GuestHandle Request);
    [[nodiscard]] Status CompleteRequest(GuestHandle Request, std::uint64_t CompletionStatus);
    [[nodiscard]] Result<std::vector<CallbackInvocation>> DeleteObject(GuestHandle Object);
    [[nodiscard]] Result<std::vector<CallbackInvocation>> Cleanup();

    [[nodiscard]] std::optional<KmdfObjectSnapshot> Object(GuestHandle Handle) const;
    [[nodiscard]] std::optional<KmdfContextSnapshot> Context(GuestHandle Handle) const;
    [[nodiscard]] std::optional<KmdfRequestSnapshot> Request(GuestHandle Handle) const;
    [[nodiscard]] KmdfSnapshot Snapshot() const;
    [[nodiscard]] Status Restore(const KmdfSnapshot& Snapshot);

private:
    static constexpr std::uint16_t HandleTag = 0x4B4D;
    static constexpr std::uint32_t StateVersion = 1;

    [[nodiscard]] GuestHandle AllocateHandleLocked();
    [[nodiscard]] bool ValidateCallbacks(const KmdfObjectCallbacks& Callbacks) const;
    [[nodiscard]] bool ValidateCallbacks(const KmdfQueueCallbacks& Callbacks) const;
    [[nodiscard]] bool ValidateCallbacks(const KmdfRequestCallbacks& Callbacks) const;
    [[nodiscard]] Status ValidateSnapshot(const KmdfSnapshot& Snapshot) const;
    [[nodiscard]] std::vector<CallbackInvocation> DeleteObjectLocked(GuestHandle Object);
    [[nodiscard]] CallbackInvocation InvokeLocked(
        const CallbackDescriptor& Callback,
        std::initializer_list<GuestAddress> Arguments);

    GuestAddressValidator Validator_;
    mutable std::mutex Mutex_;
    KmdfSnapshot State_;
};

} // namespace Kevlar::Host::Frameworks
