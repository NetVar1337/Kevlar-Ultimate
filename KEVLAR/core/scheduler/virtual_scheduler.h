#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <span>
#include <vector>

namespace Kevlar::Scheduler {

using ThreadId = std::uint64_t;
using ObjectId = std::uint64_t;
using EventId = std::uint64_t;
using TimerId = std::uint64_t;

constexpr std::uint32_t kPriorityLevels = 32;
constexpr std::uint32_t kNoCpu = 0xffffffffu;
constexpr std::size_t kNoObjectIndex = static_cast<std::size_t>(-1);

enum class ThreadState : std::uint8_t {
    Runnable,
    Running,
    Blocked,
    Terminated,
};

enum class WaitMode : std::uint8_t {
    Any,
    All,
};

enum class WaitObjectType : std::uint8_t {
    Notification,
    Synchronization,
};

enum class WakeReason : std::uint8_t {
    None,
    Object,
    Timeout,
    Alerted,
    Cancelled,
    Terminated,
};

enum class Irql : std::uint8_t {
    Passive = 0,
    Apc = 1,
    Dispatch = 2,
    Device = 3,
    High = 15,
};

enum class DispatchKind : std::uint8_t {
    Idle,
    RunThread,
    Interrupt,
    Dpc,
    Apc,
    WorkItem,
};

enum class EventKind : std::uint8_t {
    ThreadRegistered,
    ThreadScheduled,
    QuantumExpired,
    ThreadYielded,
    ThreadBlocked,
    ThreadWoken,
    ThreadTerminated,
    ObjectCreated,
    ObjectSignaled,
    ObjectReset,
    InterruptQueued,
    DpcQueued,
    ApcQueued,
    WorkItemQueued,
    DispatchStarted,
    DispatchCompleted,
    TimerQueued,
    TimerFired,
    TimeAdvanced,
    WaitCancelled,
    EventCancelled,
    IrqlRaised,
    IrqlLowered,
    SnapshotRestored,
};

struct SchedulerConfig {
    std::uint32_t cpu_count = 1;
    std::uint64_t default_quantum = 10'000;
    std::uint64_t nanoseconds_per_instruction = 1;
    std::size_t journal_capacity = 4096;
};

struct ThreadInfo {
    ThreadId id = 0;
    ThreadState state = ThreadState::Terminated;
    std::uint8_t priority = 0;
    std::uint64_t affinity_mask = 0;
    std::uint64_t quantum = 0;
    std::uint64_t quantum_remaining = 0;
    std::uint32_t current_cpu = kNoCpu;
    WakeReason last_wake_reason = WakeReason::None;
    std::size_t wake_object_index = kNoObjectIndex;
};

struct ScheduleDecision {
    DispatchKind kind = DispatchKind::Idle;
    std::uint32_t cpu = kNoCpu;
    ThreadId thread = 0;
    EventId event = 0;
    std::uint64_t guest_routine = 0;
    std::uint64_t context = 0;
    std::uint32_t vector = 0;
    Irql dispatch_irql = Irql::Passive;
    std::uint64_t quantum_remaining = 0;
};

struct WaitResult {
    bool accepted = false;
    bool completed = false;
    WakeReason reason = WakeReason::None;
    std::size_t object_index = kNoObjectIndex;
};

struct AccountResult {
    bool accepted = false;
    bool quantum_expired = false;
    std::uint64_t quantum_remaining = 0;
    std::uint64_t virtual_time = 0;
};

struct JournalEvent {
    std::uint64_t sequence = 0;
    std::uint64_t virtual_time = 0;
    EventKind kind = EventKind::ThreadRegistered;
    std::uint32_t cpu = kNoCpu;
    ThreadId thread = 0;
    std::uint64_t subject = 0;
    std::uint64_t value = 0;

    bool operator==(const JournalEvent&) const = default;
};

struct SchedulerSnapshot {
    std::vector<std::uint8_t> bytes;
};

class VirtualScheduler final {
public:
    VirtualScheduler(SchedulerConfig config, std::uint64_t seed);

    VirtualScheduler(const VirtualScheduler&) = delete;
    VirtualScheduler& operator=(const VirtualScheduler&) = delete;

    bool RegisterThread(ThreadId thread, std::uint8_t priority,
                        std::uint64_t affinity_mask, std::uint64_t quantum = 0);
    bool SetThreadPriority(ThreadId thread, std::uint8_t priority);
    bool SetThreadAffinity(ThreadId thread, std::uint64_t affinity_mask);
    bool YieldThread(std::uint32_t cpu);
    bool TerminateThread(ThreadId thread);

    ScheduleDecision ScheduleNext(std::uint32_t cpu);
    AccountResult AccountInstructions(std::uint32_t cpu, std::uint64_t instructions);

    EventId QueueInterrupt(std::uint32_t cpu, std::uint32_t vector,
                           std::uint64_t guest_routine, std::uint64_t context,
                           Irql irql = Irql::Device);
    EventId QueueDpc(std::uint32_t cpu, std::uint64_t guest_routine,
                     std::uint64_t context);
    EventId QueueApc(ThreadId thread, std::uint64_t guest_routine,
                     std::uint64_t context);
    EventId QueueWorkItem(std::uint8_t priority, std::uint64_t guest_routine,
                          std::uint64_t context);
    bool CancelQueuedEvent(EventId event);
    bool CompleteDispatch(std::uint32_t cpu, EventId event);

    bool CreateWaitObject(ObjectId object, WaitObjectType type,
                          bool initially_signaled = false);
    bool ResetObject(ObjectId object);
    WaitResult Wait(ThreadId thread, std::span<const ObjectId> objects,
                    WaitMode mode, std::optional<std::uint64_t> timeout,
                    bool alertable = false);
    std::size_t SignalObject(ObjectId object);
    bool CancelWait(ThreadId thread);

    bool AdvanceTime(std::uint64_t nanoseconds);
    std::uint64_t VirtualTime() const;

    bool RaiseIrql(std::uint32_t cpu, Irql new_irql);
    bool LowerIrql(std::uint32_t cpu, Irql new_irql);
    std::optional<Irql> CurrentIrql(std::uint32_t cpu) const;

    std::optional<ThreadInfo> GetThreadInfo(ThreadId thread) const;
    std::vector<JournalEvent> Journal() const;
    void ClearJournal();

    SchedulerSnapshot Snapshot() const;
    bool Restore(const SchedulerSnapshot& snapshot);
    std::uint64_t Seed() const;
    SchedulerConfig Config() const;

private:
    struct WaitState {
        WaitMode mode = WaitMode::Any;
        std::vector<ObjectId> objects;
        bool alertable = false;
        std::uint64_t generation = 0;
        TimerId timer = 0;
        std::uint64_t sequence = 0;
    };

    struct ThreadRecord {
        ThreadInfo info;
        std::optional<WaitState> wait;
        bool queued = false;
    };

    struct WaitObjectRecord {
        WaitObjectType type = WaitObjectType::Notification;
        bool signaled = false;
    };

    struct QueuedEvent {
        EventId id = 0;
        std::uint64_t sequence = 0;
        std::uint8_t priority = 0;
        std::uint32_t cpu = kNoCpu;
        ThreadId thread = 0;
        std::uint32_t vector = 0;
        Irql irql = Irql::Passive;
        std::uint64_t guest_routine = 0;
        std::uint64_t context = 0;
    };

    struct TimerRecord {
        std::uint64_t due_time = 0;
        std::uint64_t sequence = 0;
        TimerId id = 0;
        ThreadId thread = 0;
        std::uint64_t wait_generation = 0;
    };

    struct TimerLater {
        bool operator()(const TimerRecord& lhs, const TimerRecord& rhs) const;
    };

    struct DispatchFrame {
        EventId event = 0;
        Irql previous_irql = Irql::Passive;
    };

    struct CpuRecord {
        Irql irql = Irql::Passive;
        ThreadId current_thread = 0;
        std::optional<DispatchFrame> active_dispatch;
        std::deque<QueuedEvent> interrupts;
        std::deque<QueuedEvent> dpcs;
    };

    mutable std::mutex mutex_;
    SchedulerConfig config_;
    std::uint64_t seed_ = 0;
    std::uint64_t virtual_time_ = 0;
    std::uint64_t next_sequence_ = 1;
    EventId next_event_id_ = 1;
    TimerId next_timer_id_ = 1;
    std::uint64_t next_wait_generation_ = 1;

    std::vector<CpuRecord> cpus_;
    std::map<ThreadId, ThreadRecord> threads_;
    std::map<ObjectId, WaitObjectRecord> objects_;
    std::array<std::deque<ThreadId>, kPriorityLevels> run_queues_;
    std::map<ThreadId, std::deque<QueuedEvent>> apcs_;
    std::deque<QueuedEvent> work_items_;
    std::priority_queue<TimerRecord, std::vector<TimerRecord>, TimerLater> timers_;
    std::set<EventId> cancelled_events_;
    std::deque<JournalEvent> journal_;

    bool IsValidCpu(std::uint32_t cpu) const;
    std::uint64_t ValidAffinityMask() const;
    std::uint64_t AllocateSequence();
    EventId AllocateEventId();
    TimerId AllocateTimerId();
    void Record(EventKind kind, std::uint32_t cpu, ThreadId thread,
                std::uint64_t subject, std::uint64_t value,
                std::optional<std::uint64_t> sequence = std::nullopt);

    void EnqueueRunnable(ThreadRecord& thread);
    void RemoveFromRunQueue(ThreadId thread);
    void ReleaseCpu(ThreadRecord& thread);
    ThreadRecord* PickRunnable(std::uint32_t cpu);
    bool WakeThread(ThreadRecord& thread, WakeReason reason, std::size_t object_index);
    bool IsWaitSatisfied(const WaitState& wait, std::size_t& object_index) const;
    void ConsumeWaitObjects(const WaitState& wait, std::size_t object_index);
    std::size_t SatisfyWaiters(ObjectId signaled_object);
    void ProcessTimers();

    std::optional<QueuedEvent> PopInterrupt(CpuRecord& cpu);
    std::optional<QueuedEvent> PopWorkItem();
    static bool IsIrqlValueValid(Irql irql);
    static bool IsHigherIrql(Irql lhs, Irql rhs);
    static bool CanDispatchAt(Irql current, Irql required);
    ScheduleDecision BeginDispatch(std::uint32_t cpu, DispatchKind kind,
                                   const QueuedEvent& event, Irql dispatch_irql);

    SchedulerSnapshot SnapshotLocked() const;
    bool RestoreLocked(std::span<const std::uint8_t> bytes);
};

} // namespace Kevlar::Scheduler
