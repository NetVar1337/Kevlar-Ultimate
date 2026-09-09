#include "core/scheduler/virtual_scheduler.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace Kevlar::Scheduler {
namespace {

constexpr std::uint8_t kSnapshotMagic[8] = {'K', 'V', 'S', 'C', 'H', 'E', 'D', 1};
constexpr std::uint32_t kSnapshotVersion = 1;
constexpr std::uint64_t kMaximumDecodedEntries = 1'000'000;

template <typename T>
constexpr auto ToValue(T value) noexcept {
    return static_cast<std::underlying_type_t<T>>(value);
}

class BinaryWriter {
public:
    void U8(std::uint8_t value) { bytes_.push_back(value); }

    void U32(std::uint32_t value) {
        for (unsigned shift = 0; shift != 32; shift += 8) {
            U8(static_cast<std::uint8_t>(value >> shift));
        }
    }

    void U64(std::uint64_t value) {
        for (unsigned shift = 0; shift != 64; shift += 8) {
            U8(static_cast<std::uint8_t>(value >> shift));
        }
    }

    void Bool(bool value) { U8(value ? 1 : 0); }

    void Bytes(std::span<const std::uint8_t> bytes) {
        bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
    }

    std::vector<std::uint8_t> Take() { return std::move(bytes_); }

private:
    std::vector<std::uint8_t> bytes_;
};

class BinaryReader {
public:
    explicit BinaryReader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

    std::uint8_t U8() {
        if (offset_ == bytes_.size()) {
            valid_ = false;
            return 0;
        }
        return bytes_[offset_++];
    }

    std::uint32_t U32() {
        std::uint32_t value = 0;
        for (unsigned shift = 0; shift != 32; shift += 8) {
            value |= static_cast<std::uint32_t>(U8()) << shift;
        }
        return value;
    }

    std::uint64_t U64() {
        std::uint64_t value = 0;
        for (unsigned shift = 0; shift != 64; shift += 8) {
            value |= static_cast<std::uint64_t>(U8()) << shift;
        }
        return value;
    }

    bool Bool() {
        const auto value = U8();
        if (value > 1) {
            valid_ = false;
        }
        return value != 0;
    }

    std::uint64_t Count() {
        const auto count = U64();
        if (count > kMaximumDecodedEntries) {
            valid_ = false;
            return 0;
        }
        return count;
    }

    bool Consume(std::span<const std::uint8_t> expected) {
        if (offset_ > bytes_.size() || expected.size() > bytes_.size() - offset_) {
            valid_ = false;
            return false;
        }
        if (!std::equal(expected.begin(), expected.end(), bytes_.begin() + offset_)) {
            valid_ = false;
            return false;
        }
        offset_ += expected.size();
        return true;
    }

    bool Finished() const { return valid_ && offset_ == bytes_.size(); }
    bool Valid() const { return valid_; }

private:
    std::span<const std::uint8_t> bytes_;
    std::size_t offset_ = 0;
    bool valid_ = true;
};

bool AddWouldOverflow(std::uint64_t lhs, std::uint64_t rhs) {
    return rhs > std::numeric_limits<std::uint64_t>::max() - lhs;
}

bool MultiplyWouldOverflow(std::uint64_t lhs, std::uint64_t rhs) {
    return lhs != 0 && rhs > std::numeric_limits<std::uint64_t>::max() / lhs;
}

} // namespace

bool VirtualScheduler::TimerLater::operator()(const TimerRecord& lhs,
                                               const TimerRecord& rhs) const {
    return std::tie(lhs.due_time, lhs.sequence, lhs.id) >
           std::tie(rhs.due_time, rhs.sequence, rhs.id);
}

VirtualScheduler::VirtualScheduler(SchedulerConfig config, std::uint64_t seed)
    : config_(config), seed_(seed) {
    if (config_.cpu_count == 0 || config_.cpu_count > 64) {
        throw std::invalid_argument("scheduler cpu_count must be in [1, 64]");
    }
    if (config_.default_quantum == 0) {
        throw std::invalid_argument("scheduler default_quantum must be nonzero");
    }
    if (config_.nanoseconds_per_instruction == 0) {
        throw std::invalid_argument("scheduler instruction duration must be nonzero");
    }
    cpus_.resize(config_.cpu_count);
}

bool VirtualScheduler::IsValidCpu(std::uint32_t cpu) const {
    return cpu < cpus_.size();
}

std::uint64_t VirtualScheduler::ValidAffinityMask() const {
    return config_.cpu_count == 64
               ? std::numeric_limits<std::uint64_t>::max()
               : ((std::uint64_t{1} << config_.cpu_count) - 1);
}

std::uint64_t VirtualScheduler::AllocateSequence() {
    if (next_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("scheduler event sequence exhausted");
    }
    return next_sequence_++;
}

EventId VirtualScheduler::AllocateEventId() {
    if (next_event_id_ == 0 || next_event_id_ == std::numeric_limits<EventId>::max()) {
        return 0;
    }
    return next_event_id_++;
}

TimerId VirtualScheduler::AllocateTimerId() {
    if (next_timer_id_ == 0 || next_timer_id_ == std::numeric_limits<TimerId>::max()) {
        return 0;
    }
    return next_timer_id_++;
}

void VirtualScheduler::Record(EventKind kind, std::uint32_t cpu, ThreadId thread,
                              std::uint64_t subject, std::uint64_t value,
                              std::optional<std::uint64_t> sequence) {
    const auto event_sequence = sequence.value_or(AllocateSequence());
    if (config_.journal_capacity == 0) {
        return;
    }
    while (journal_.size() >= config_.journal_capacity) {
        journal_.pop_front();
    }
    journal_.push_back({event_sequence, virtual_time_, kind, cpu, thread, subject, value});
}

void VirtualScheduler::EnqueueRunnable(ThreadRecord& thread) {
    if (thread.info.state == ThreadState::Terminated || thread.queued) {
        return;
    }
    thread.info.state = ThreadState::Runnable;
    thread.info.current_cpu = kNoCpu;
    run_queues_[thread.info.priority].push_back(thread.info.id);
    thread.queued = true;
}

void VirtualScheduler::RemoveFromRunQueue(ThreadId thread) {
    auto found = threads_.find(thread);
    if (found == threads_.end() || !found->second.queued) {
        return;
    }
    auto& queue = run_queues_[found->second.info.priority];
    const auto item = std::find(queue.begin(), queue.end(), thread);
    if (item != queue.end()) {
        queue.erase(item);
    }
    found->second.queued = false;
}

void VirtualScheduler::ReleaseCpu(ThreadRecord& thread) {
    if (thread.info.current_cpu != kNoCpu && IsValidCpu(thread.info.current_cpu)) {
        auto& cpu = cpus_[thread.info.current_cpu];
        if (cpu.current_thread == thread.info.id) {
            cpu.current_thread = 0;
        }
    }
    thread.info.current_cpu = kNoCpu;
}

VirtualScheduler::ThreadRecord* VirtualScheduler::PickRunnable(std::uint32_t cpu) {
    const auto mask = std::uint64_t{1} << cpu;
    for (std::size_t priority = kPriorityLevels; priority-- > 0;) {
        auto& queue = run_queues_[priority];
        for (auto position = queue.begin(); position != queue.end();) {
            auto found = threads_.find(*position);
            if (found == threads_.end() || !found->second.queued ||
                found->second.info.state != ThreadState::Runnable) {
                position = queue.erase(position);
                continue;
            }
            if ((found->second.info.affinity_mask & mask) == 0) {
                ++position;
                continue;
            }
            found->second.queued = false;
            queue.erase(position);
            return &found->second;
        }
    }
    return nullptr;
}

bool VirtualScheduler::RegisterThread(ThreadId thread, std::uint8_t priority,
                                      std::uint64_t affinity_mask, std::uint64_t quantum) {
    std::lock_guard lock(mutex_);
    affinity_mask &= ValidAffinityMask();
    if (thread == 0 || priority >= kPriorityLevels || affinity_mask == 0 ||
        threads_.contains(thread)) {
        return false;
    }
    if (quantum == 0) {
        quantum = config_.default_quantum;
    }
    ThreadRecord record;
    record.info.id = thread;
    record.info.state = ThreadState::Runnable;
    record.info.priority = priority;
    record.info.affinity_mask = affinity_mask;
    record.info.quantum = quantum;
    record.info.quantum_remaining = quantum;
    auto [position, inserted] = threads_.emplace(thread, std::move(record));
    if (!inserted) {
        return false;
    }
    EnqueueRunnable(position->second);
    Record(EventKind::ThreadRegistered, kNoCpu, thread, priority, quantum);
    return true;
}

bool VirtualScheduler::SetThreadPriority(ThreadId thread, std::uint8_t priority) {
    std::lock_guard lock(mutex_);
    auto found = threads_.find(thread);
    if (found == threads_.end() || priority >= kPriorityLevels ||
        found->second.info.state == ThreadState::Terminated) {
        return false;
    }
    const bool was_queued = found->second.queued;
    if (was_queued) {
        RemoveFromRunQueue(thread);
    }
    found->second.info.priority = priority;
    if (was_queued) {
        EnqueueRunnable(found->second);
    }
    return true;
}

bool VirtualScheduler::SetThreadAffinity(ThreadId thread, std::uint64_t affinity_mask) {
    std::lock_guard lock(mutex_);
    auto found = threads_.find(thread);
    affinity_mask &= ValidAffinityMask();
    if (found == threads_.end() || affinity_mask == 0 ||
        found->second.info.state == ThreadState::Terminated) {
        return false;
    }
    found->second.info.affinity_mask = affinity_mask;
    if (found->second.info.state == ThreadState::Running &&
        (affinity_mask & (std::uint64_t{1} << found->second.info.current_cpu)) == 0) {
        ReleaseCpu(found->second);
        EnqueueRunnable(found->second);
    }
    return true;
}

bool VirtualScheduler::YieldThread(std::uint32_t cpu) {
    std::lock_guard lock(mutex_);
    if (!IsValidCpu(cpu) || cpus_[cpu].current_thread == 0) {
        return false;
    }
    auto found = threads_.find(cpus_[cpu].current_thread);
    if (found == threads_.end() || found->second.info.state != ThreadState::Running) {
        cpus_[cpu].current_thread = 0;
        return false;
    }
    ReleaseCpu(found->second);
    EnqueueRunnable(found->second);
    Record(EventKind::ThreadYielded, cpu, found->first, 0, 0);
    return true;
}

bool VirtualScheduler::TerminateThread(ThreadId thread) {
    std::lock_guard lock(mutex_);
    auto found = threads_.find(thread);
    if (found == threads_.end() || found->second.info.state == ThreadState::Terminated) {
        return false;
    }
    RemoveFromRunQueue(thread);
    ReleaseCpu(found->second);
    found->second.wait.reset();
    found->second.info.state = ThreadState::Terminated;
    found->second.info.last_wake_reason = WakeReason::Terminated;
    found->second.info.wake_object_index = kNoObjectIndex;
    auto apcs = apcs_.find(thread);
    if (apcs != apcs_.end()) {
        for (const auto& apc : apcs->second) {
            cancelled_events_.insert(apc.id);
        }
        apcs_.erase(apcs);
    }
    Record(EventKind::ThreadTerminated, kNoCpu, thread, 0, 0);
    return true;
}

bool VirtualScheduler::IsIrqlValueValid(Irql irql) {
    return ToValue(irql) <= ToValue(Irql::High);
}

bool VirtualScheduler::IsHigherIrql(Irql lhs, Irql rhs) {
    return ToValue(lhs) > ToValue(rhs);
}

bool VirtualScheduler::CanDispatchAt(Irql current, Irql required) {
    return ToValue(current) <= ToValue(required);
}

std::optional<VirtualScheduler::QueuedEvent>
VirtualScheduler::PopInterrupt(CpuRecord& cpu) {
    for (auto position = cpu.interrupts.begin(); position != cpu.interrupts.end();) {
        if (cancelled_events_.erase(position->id) != 0) {
            position = cpu.interrupts.erase(position);
        } else {
            ++position;
        }
    }
    auto best = cpu.interrupts.end();
    for (auto position = cpu.interrupts.begin(); position != cpu.interrupts.end(); ++position) {
        if (!IsHigherIrql(position->irql, cpu.irql)) {
            continue;
        }
        if (best == cpu.interrupts.end() || IsHigherIrql(position->irql, best->irql) ||
            (position->irql == best->irql && position->sequence < best->sequence)) {
            best = position;
        }
    }
    if (best == cpu.interrupts.end()) {
        return std::nullopt;
    }
    QueuedEvent result = *best;
    cpu.interrupts.erase(best);
    return result;
}

std::optional<VirtualScheduler::QueuedEvent> VirtualScheduler::PopWorkItem() {
    for (auto position = work_items_.begin(); position != work_items_.end();) {
        if (cancelled_events_.erase(position->id) != 0) {
            position = work_items_.erase(position);
        } else {
            ++position;
        }
    }
    auto best = work_items_.end();
    for (auto position = work_items_.begin(); position != work_items_.end(); ++position) {
        if (best == work_items_.end() || position->priority > best->priority ||
            (position->priority == best->priority && position->sequence < best->sequence)) {
            best = position;
        }
    }
    if (best == work_items_.end()) {
        return std::nullopt;
    }
    QueuedEvent result = *best;
    work_items_.erase(best);
    return result;
}

ScheduleDecision VirtualScheduler::BeginDispatch(std::uint32_t cpu_index,
                                                 DispatchKind kind,
                                                 const QueuedEvent& event,
                                                 Irql dispatch_irql) {
    auto& cpu = cpus_[cpu_index];
    cpu.active_dispatch = DispatchFrame{event.id, cpu.irql};
    cpu.irql = dispatch_irql;
    Record(EventKind::DispatchStarted, cpu_index, event.thread, event.id,
           static_cast<std::uint64_t>(ToValue(kind)));
    return {kind, cpu_index, event.thread, event.id, event.guest_routine,
            event.context, event.vector, dispatch_irql, 0};
}

ScheduleDecision VirtualScheduler::ScheduleNext(std::uint32_t cpu_index) {
    std::lock_guard lock(mutex_);
    ProcessTimers();
    if (!IsValidCpu(cpu_index)) {
        return {};
    }
    auto& cpu = cpus_[cpu_index];
    if (cpu.active_dispatch.has_value()) {
        return {DispatchKind::Idle, cpu_index};
    }

    if (auto interrupt = PopInterrupt(cpu)) {
        return BeginDispatch(cpu_index, DispatchKind::Interrupt, *interrupt, interrupt->irql);
    }

    while (!cpu.dpcs.empty() && cancelled_events_.erase(cpu.dpcs.front().id) != 0) {
        cpu.dpcs.pop_front();
    }
    if (CanDispatchAt(cpu.irql, Irql::Dispatch) && !cpu.dpcs.empty()) {
        const auto dpc = cpu.dpcs.front();
        cpu.dpcs.pop_front();
        return BeginDispatch(cpu_index, DispatchKind::Dpc, dpc, Irql::Dispatch);
    }

    auto dispatch_apc = [&](ThreadId thread) -> std::optional<ScheduleDecision> {
        if (!CanDispatchAt(cpu.irql, Irql::Apc)) {
            return std::nullopt;
        }
        auto pending = apcs_.find(thread);
        if (pending == apcs_.end()) {
            return std::nullopt;
        }
        while (!pending->second.empty() &&
               cancelled_events_.erase(pending->second.front().id) != 0) {
            pending->second.pop_front();
        }
        if (pending->second.empty()) {
            apcs_.erase(pending);
            return std::nullopt;
        }
        const auto apc = pending->second.front();
        pending->second.pop_front();
        if (pending->second.empty()) {
            apcs_.erase(pending);
        }
        return BeginDispatch(cpu_index, DispatchKind::Apc, apc, Irql::Apc);
    };

    if (cpu.current_thread != 0) {
        auto found = threads_.find(cpu.current_thread);
        if (found == threads_.end() || found->second.info.state != ThreadState::Running) {
            cpu.current_thread = 0;
        } else {
            if (auto apc = dispatch_apc(found->first)) {
                return *apc;
            }
            Record(EventKind::ThreadScheduled, cpu_index, found->first, 0,
                   found->second.info.quantum_remaining);
            return {DispatchKind::RunThread, cpu_index, found->first, 0, 0, 0, 0,
                    cpu.irql, found->second.info.quantum_remaining};
        }
    }

    if (cpu.irql == Irql::Passive) {
        if (auto work = PopWorkItem()) {
            return BeginDispatch(cpu_index, DispatchKind::WorkItem, *work, Irql::Passive);
        }
    }

    auto* next = PickRunnable(cpu_index);
    if (next == nullptr) {
        return {DispatchKind::Idle, cpu_index};
    }
    next->info.state = ThreadState::Running;
    next->info.current_cpu = cpu_index;
    cpu.current_thread = next->info.id;
    if (auto apc = dispatch_apc(next->info.id)) {
        return *apc;
    }
    Record(EventKind::ThreadScheduled, cpu_index, next->info.id, 0,
           next->info.quantum_remaining);
    return {DispatchKind::RunThread, cpu_index, next->info.id, 0, 0, 0, 0,
            cpu.irql, next->info.quantum_remaining};
}

AccountResult VirtualScheduler::AccountInstructions(std::uint32_t cpu,
                                                     std::uint64_t instructions) {
    std::lock_guard lock(mutex_);
    AccountResult result;
    result.virtual_time = virtual_time_;
    if (!IsValidCpu(cpu) || cpus_[cpu].current_thread == 0 ||
        MultiplyWouldOverflow(instructions, config_.nanoseconds_per_instruction)) {
        return result;
    }
    const auto elapsed = instructions * config_.nanoseconds_per_instruction;
    if (AddWouldOverflow(virtual_time_, elapsed)) {
        return result;
    }
    auto found = threads_.find(cpus_[cpu].current_thread);
    if (found == threads_.end() || found->second.info.state != ThreadState::Running) {
        cpus_[cpu].current_thread = 0;
        return result;
    }

    result.accepted = true;
    virtual_time_ += elapsed;
    if (instructions >= found->second.info.quantum_remaining) {
        found->second.info.quantum_remaining = found->second.info.quantum;
        ReleaseCpu(found->second);
        EnqueueRunnable(found->second);
        result.quantum_expired = true;
        Record(EventKind::QuantumExpired, cpu, found->first, instructions, 0);
    } else {
        found->second.info.quantum_remaining -= instructions;
    }
    result.quantum_remaining = found->second.info.quantum_remaining;
    result.virtual_time = virtual_time_;
    ProcessTimers();
    return result;
}

EventId VirtualScheduler::QueueInterrupt(std::uint32_t cpu, std::uint32_t vector,
                                         std::uint64_t guest_routine,
                                         std::uint64_t context, Irql irql) {
    std::lock_guard lock(mutex_);
    if (!IsValidCpu(cpu) || vector > 255 || !IsIrqlValueValid(irql) ||
        !IsHigherIrql(irql, Irql::Passive)) {
        return 0;
    }
    const auto id = AllocateEventId();
    if (id == 0) {
        return 0;
    }
    const auto sequence = AllocateSequence();
    cpus_[cpu].interrupts.push_back(
        {id, sequence, 0, cpu, 0, vector, irql, guest_routine, context});
    Record(EventKind::InterruptQueued, cpu, 0, id, vector, sequence);
    return id;
}

EventId VirtualScheduler::QueueDpc(std::uint32_t cpu, std::uint64_t guest_routine,
                                   std::uint64_t context) {
    std::lock_guard lock(mutex_);
    if (!IsValidCpu(cpu)) {
        return 0;
    }
    const auto id = AllocateEventId();
    if (id == 0) {
        return 0;
    }
    const auto sequence = AllocateSequence();
    cpus_[cpu].dpcs.push_back(
        {id, sequence, 0, cpu, 0, 0, Irql::Dispatch, guest_routine, context});
    Record(EventKind::DpcQueued, cpu, 0, id, 0, sequence);
    return id;
}

EventId VirtualScheduler::QueueApc(ThreadId thread, std::uint64_t guest_routine,
                                   std::uint64_t context) {
    std::lock_guard lock(mutex_);
    auto target = threads_.find(thread);
    if (target == threads_.end() || target->second.info.state == ThreadState::Terminated) {
        return 0;
    }
    const auto id = AllocateEventId();
    if (id == 0) {
        return 0;
    }
    const auto sequence = AllocateSequence();
    apcs_[thread].push_back(
        {id, sequence, 0, kNoCpu, thread, 0, Irql::Apc, guest_routine, context});
    Record(EventKind::ApcQueued, kNoCpu, thread, id, 0, sequence);
    if (target->second.info.state == ThreadState::Blocked && target->second.wait.has_value() &&
        target->second.wait->alertable) {
        WakeThread(target->second, WakeReason::Alerted, kNoObjectIndex);
    }
    return id;
}

EventId VirtualScheduler::QueueWorkItem(std::uint8_t priority,
                                        std::uint64_t guest_routine,
                                        std::uint64_t context) {
    std::lock_guard lock(mutex_);
    if (priority >= kPriorityLevels) {
        return 0;
    }
    const auto id = AllocateEventId();
    if (id == 0) {
        return 0;
    }
    const auto sequence = AllocateSequence();
    work_items_.push_back(
        {id, sequence, priority, kNoCpu, 0, 0, Irql::Passive, guest_routine, context});
    Record(EventKind::WorkItemQueued, kNoCpu, 0, id, priority, sequence);
    return id;
}

bool VirtualScheduler::CancelQueuedEvent(EventId event) {
    std::lock_guard lock(mutex_);
    if (event == 0) {
        return false;
    }
    bool found = false;
    for (const auto& cpu : cpus_) {
        found = found || std::any_of(cpu.interrupts.begin(), cpu.interrupts.end(),
                                    [event](const auto& item) { return item.id == event; });
        found = found || std::any_of(cpu.dpcs.begin(), cpu.dpcs.end(),
                                    [event](const auto& item) { return item.id == event; });
    }
    for (const auto& [thread, queue] : apcs_) {
        (void)thread;
        found = found || std::any_of(queue.begin(), queue.end(),
                                    [event](const auto& item) { return item.id == event; });
    }
    found = found || std::any_of(work_items_.begin(), work_items_.end(),
                                [event](const auto& item) { return item.id == event; });
    if (!found) {
        return false;
    }
    cancelled_events_.insert(event);
    Record(EventKind::EventCancelled, kNoCpu, 0, event, 0);
    return true;
}

bool VirtualScheduler::CompleteDispatch(std::uint32_t cpu, EventId event) {
    std::lock_guard lock(mutex_);
    if (!IsValidCpu(cpu) || !cpus_[cpu].active_dispatch.has_value() ||
        cpus_[cpu].active_dispatch->event != event) {
        return false;
    }
    cpus_[cpu].irql = cpus_[cpu].active_dispatch->previous_irql;
    cpus_[cpu].active_dispatch.reset();
    Record(EventKind::DispatchCompleted, cpu, 0, event, 0);
    return true;
}

bool VirtualScheduler::CreateWaitObject(ObjectId object, WaitObjectType type,
                                        bool initially_signaled) {
    std::lock_guard lock(mutex_);
    if (object == 0 || objects_.contains(object)) {
        return false;
    }
    objects_.emplace(object, WaitObjectRecord{type, initially_signaled});
    Record(EventKind::ObjectCreated, kNoCpu, 0, object,
           initially_signaled ? 1 : 0);
    return true;
}

bool VirtualScheduler::ResetObject(ObjectId object) {
    std::lock_guard lock(mutex_);
    auto found = objects_.find(object);
    if (found == objects_.end()) {
        return false;
    }
    found->second.signaled = false;
    Record(EventKind::ObjectReset, kNoCpu, 0, object, 0);
    return true;
}

bool VirtualScheduler::IsWaitSatisfied(const WaitState& wait,
                                       std::size_t& object_index) const {
    object_index = kNoObjectIndex;
    if (wait.mode == WaitMode::Any) {
        for (std::size_t index = 0; index < wait.objects.size(); ++index) {
            auto found = objects_.find(wait.objects[index]);
            if (found != objects_.end() && found->second.signaled) {
                object_index = index;
                return true;
            }
        }
        return false;
    }
    for (const auto object : wait.objects) {
        auto found = objects_.find(object);
        if (found == objects_.end() || !found->second.signaled) {
            return false;
        }
    }
    return true;
}

void VirtualScheduler::ConsumeWaitObjects(const WaitState& wait,
                                          std::size_t object_index) {
    if (wait.mode == WaitMode::Any) {
        if (object_index < wait.objects.size()) {
            auto found = objects_.find(wait.objects[object_index]);
            if (found != objects_.end() &&
                found->second.type == WaitObjectType::Synchronization) {
                found->second.signaled = false;
            }
        }
        return;
    }
    for (const auto object : wait.objects) {
        auto found = objects_.find(object);
        if (found != objects_.end() &&
            found->second.type == WaitObjectType::Synchronization) {
            found->second.signaled = false;
        }
    }
}

bool VirtualScheduler::WakeThread(ThreadRecord& thread, WakeReason reason,
                                  std::size_t object_index) {
    if (thread.info.state != ThreadState::Blocked || !thread.wait.has_value()) {
        return false;
    }
    thread.wait.reset();
    thread.info.last_wake_reason = reason;
    thread.info.wake_object_index = object_index;
    EnqueueRunnable(thread);
    Record(EventKind::ThreadWoken, kNoCpu, thread.info.id,
           object_index == kNoObjectIndex ? 0 : static_cast<std::uint64_t>(object_index),
           static_cast<std::uint64_t>(ToValue(reason)));
    return true;
}

WaitResult VirtualScheduler::Wait(ThreadId thread, std::span<const ObjectId> objects,
                                  WaitMode mode,
                                  std::optional<std::uint64_t> timeout,
                                  bool alertable) {
    std::lock_guard lock(mutex_);
    auto found = threads_.find(thread);
    if (found == threads_.end() || found->second.info.state == ThreadState::Blocked ||
        found->second.info.state == ThreadState::Terminated || objects.empty()) {
        return {};
    }
    std::set<ObjectId> unique;
    for (const auto object : objects) {
        if (!objects_.contains(object) ||
            (mode == WaitMode::All && !unique.insert(object).second)) {
            return {};
        }
    }

    WaitState wait;
    wait.mode = mode;
    wait.objects.assign(objects.begin(), objects.end());
    wait.alertable = alertable;
    wait.generation = next_wait_generation_++;
    wait.sequence = AllocateSequence();

    std::size_t object_index = kNoObjectIndex;
    if (IsWaitSatisfied(wait, object_index)) {
        ConsumeWaitObjects(wait, object_index);
        found->second.info.last_wake_reason = WakeReason::Object;
        found->second.info.wake_object_index = object_index;
        Record(EventKind::ThreadWoken, found->second.info.current_cpu, thread,
               object_index == kNoObjectIndex ? 0 : static_cast<std::uint64_t>(object_index),
               static_cast<std::uint64_t>(ToValue(WakeReason::Object)), wait.sequence);
        return {true, true, WakeReason::Object, object_index};
    }
    if (timeout.has_value() && *timeout == 0) {
        found->second.info.last_wake_reason = WakeReason::Timeout;
        found->second.info.wake_object_index = kNoObjectIndex;
        Record(EventKind::ThreadWoken, found->second.info.current_cpu, thread, 0,
               static_cast<std::uint64_t>(ToValue(WakeReason::Timeout)), wait.sequence);
        return {true, true, WakeReason::Timeout, kNoObjectIndex};
    }
    if (timeout.has_value() && AddWouldOverflow(virtual_time_, *timeout)) {
        return {};
    }

    RemoveFromRunQueue(thread);
    ReleaseCpu(found->second);
    found->second.info.state = ThreadState::Blocked;
    found->second.info.last_wake_reason = WakeReason::None;
    found->second.info.wake_object_index = kNoObjectIndex;
    if (timeout.has_value()) {
        const auto timer_id = AllocateTimerId();
        if (timer_id == 0) {
            EnqueueRunnable(found->second);
            return {};
        }
        const auto timer_sequence = AllocateSequence();
        wait.timer = timer_id;
        timers_.push({virtual_time_ + *timeout, timer_sequence, timer_id, thread,
                      wait.generation});
        Record(EventKind::TimerQueued, kNoCpu, thread, timer_id,
               virtual_time_ + *timeout, timer_sequence);
    }
    found->second.wait = std::move(wait);
    Record(EventKind::ThreadBlocked, kNoCpu, thread, 0,
           static_cast<std::uint64_t>(ToValue(mode)));
    return {true, false, WakeReason::None, kNoObjectIndex};
}

std::size_t VirtualScheduler::SatisfyWaiters(ObjectId signaled_object) {
    std::vector<std::pair<std::uint64_t, ThreadId>> candidates;
    for (const auto& [id, thread] : threads_) {
        if (thread.info.state != ThreadState::Blocked || !thread.wait.has_value() ||
            std::find(thread.wait->objects.begin(), thread.wait->objects.end(),
                      signaled_object) == thread.wait->objects.end()) {
            continue;
        }
        candidates.emplace_back(thread.wait->sequence, id);
    }
    std::sort(candidates.begin(), candidates.end());

    std::size_t woken = 0;
    for (const auto& [sequence, id] : candidates) {
        (void)sequence;
        auto found = threads_.find(id);
        if (found == threads_.end() || !found->second.wait.has_value()) {
            continue;
        }
        std::size_t object_index = kNoObjectIndex;
        if (!IsWaitSatisfied(*found->second.wait, object_index)) {
            continue;
        }
        ConsumeWaitObjects(*found->second.wait, object_index);
        if (WakeThread(found->second, WakeReason::Object, object_index)) {
            ++woken;
        }
    }
    return woken;
}

std::size_t VirtualScheduler::SignalObject(ObjectId object) {
    std::lock_guard lock(mutex_);
    auto found = objects_.find(object);
    if (found == objects_.end()) {
        return 0;
    }
    found->second.signaled = true;
    Record(EventKind::ObjectSignaled, kNoCpu, 0, object, 0);
    return SatisfyWaiters(object);
}

bool VirtualScheduler::CancelWait(ThreadId thread) {
    std::lock_guard lock(mutex_);
    auto found = threads_.find(thread);
    if (found == threads_.end() || found->second.info.state != ThreadState::Blocked ||
        !found->second.wait.has_value()) {
        return false;
    }
    if (!WakeThread(found->second, WakeReason::Cancelled, kNoObjectIndex)) {
        return false;
    }
    Record(EventKind::WaitCancelled, kNoCpu, thread, 0, 0);
    return true;
}

void VirtualScheduler::ProcessTimers() {
    while (!timers_.empty() && timers_.top().due_time <= virtual_time_) {
        const auto timer = timers_.top();
        timers_.pop();
        auto found = threads_.find(timer.thread);
        if (found == threads_.end() || found->second.info.state != ThreadState::Blocked ||
            !found->second.wait.has_value() ||
            found->second.wait->generation != timer.wait_generation ||
            found->second.wait->timer != timer.id) {
            continue;
        }
        Record(EventKind::TimerFired, kNoCpu, timer.thread, timer.id, timer.due_time);
        WakeThread(found->second, WakeReason::Timeout, kNoObjectIndex);
    }
}

bool VirtualScheduler::AdvanceTime(std::uint64_t nanoseconds) {
    std::lock_guard lock(mutex_);
    if (AddWouldOverflow(virtual_time_, nanoseconds)) {
        return false;
    }
    virtual_time_ += nanoseconds;
    Record(EventKind::TimeAdvanced, kNoCpu, 0, nanoseconds, virtual_time_);
    ProcessTimers();
    return true;
}

std::uint64_t VirtualScheduler::VirtualTime() const {
    std::lock_guard lock(mutex_);
    return virtual_time_;
}

bool VirtualScheduler::RaiseIrql(std::uint32_t cpu, Irql new_irql) {
    std::lock_guard lock(mutex_);
    if (!IsValidCpu(cpu) || !IsIrqlValueValid(new_irql) ||
        IsHigherIrql(cpus_[cpu].irql, new_irql) || cpus_[cpu].active_dispatch.has_value()) {
        return false;
    }
    const auto previous = cpus_[cpu].irql;
    cpus_[cpu].irql = new_irql;
    Record(EventKind::IrqlRaised, cpu, 0, ToValue(previous), ToValue(new_irql));
    return true;
}

bool VirtualScheduler::LowerIrql(std::uint32_t cpu, Irql new_irql) {
    std::lock_guard lock(mutex_);
    if (!IsValidCpu(cpu) || !IsIrqlValueValid(new_irql) ||
        IsHigherIrql(new_irql, cpus_[cpu].irql) || cpus_[cpu].active_dispatch.has_value()) {
        return false;
    }
    const auto previous = cpus_[cpu].irql;
    cpus_[cpu].irql = new_irql;
    Record(EventKind::IrqlLowered, cpu, 0, ToValue(previous), ToValue(new_irql));
    return true;
}

std::optional<Irql> VirtualScheduler::CurrentIrql(std::uint32_t cpu) const {
    std::lock_guard lock(mutex_);
    if (!IsValidCpu(cpu)) {
        return std::nullopt;
    }
    return cpus_[cpu].irql;
}

std::optional<ThreadInfo> VirtualScheduler::GetThreadInfo(ThreadId thread) const {
    std::lock_guard lock(mutex_);
    auto found = threads_.find(thread);
    if (found == threads_.end()) {
        return std::nullopt;
    }
    return found->second.info;
}

std::vector<JournalEvent> VirtualScheduler::Journal() const {
    std::lock_guard lock(mutex_);
    return {journal_.begin(), journal_.end()};
}

void VirtualScheduler::ClearJournal() {
    std::lock_guard lock(mutex_);
    journal_.clear();
}

std::uint64_t VirtualScheduler::Seed() const {
    std::lock_guard lock(mutex_);
    return seed_;
}

SchedulerConfig VirtualScheduler::Config() const {
    std::lock_guard lock(mutex_);
    return config_;
}

SchedulerSnapshot VirtualScheduler::Snapshot() const {
    std::lock_guard lock(mutex_);
    return SnapshotLocked();
}

SchedulerSnapshot VirtualScheduler::SnapshotLocked() const {
    BinaryWriter writer;
    writer.Bytes(kSnapshotMagic);
    writer.U32(kSnapshotVersion);
    writer.U32(config_.cpu_count);
    writer.U64(config_.default_quantum);
    writer.U64(config_.nanoseconds_per_instruction);
    writer.U64(static_cast<std::uint64_t>(config_.journal_capacity));
    writer.U64(seed_);
    writer.U64(virtual_time_);
    writer.U64(next_sequence_);
    writer.U64(next_event_id_);
    writer.U64(next_timer_id_);
    writer.U64(next_wait_generation_);

    const auto write_event = [&writer](const QueuedEvent& event) {
        writer.U64(event.id);
        writer.U64(event.sequence);
        writer.U8(event.priority);
        writer.U32(event.cpu);
        writer.U64(event.thread);
        writer.U32(event.vector);
        writer.U8(ToValue(event.irql));
        writer.U64(event.guest_routine);
        writer.U64(event.context);
    };
    const auto write_event_queue = [&writer, &write_event](const auto& queue) {
        writer.U64(static_cast<std::uint64_t>(queue.size()));
        for (const auto& event : queue) {
            write_event(event);
        }
    };

    writer.U64(static_cast<std::uint64_t>(cpus_.size()));
    for (const auto& cpu : cpus_) {
        writer.U8(ToValue(cpu.irql));
        writer.U64(cpu.current_thread);
        writer.Bool(cpu.active_dispatch.has_value());
        if (cpu.active_dispatch.has_value()) {
            writer.U64(cpu.active_dispatch->event);
            writer.U8(ToValue(cpu.active_dispatch->previous_irql));
        }
        write_event_queue(cpu.interrupts);
        write_event_queue(cpu.dpcs);
    }

    writer.U64(static_cast<std::uint64_t>(threads_.size()));
    for (const auto& [id, thread] : threads_) {
        writer.U64(id);
        writer.U8(ToValue(thread.info.state));
        writer.U8(thread.info.priority);
        writer.U64(thread.info.affinity_mask);
        writer.U64(thread.info.quantum);
        writer.U64(thread.info.quantum_remaining);
        writer.U32(thread.info.current_cpu);
        writer.U8(ToValue(thread.info.last_wake_reason));
        writer.U64(static_cast<std::uint64_t>(thread.info.wake_object_index));
        writer.Bool(thread.queued);
        writer.Bool(thread.wait.has_value());
        if (thread.wait.has_value()) {
            writer.U8(ToValue(thread.wait->mode));
            writer.U64(static_cast<std::uint64_t>(thread.wait->objects.size()));
            for (const auto object : thread.wait->objects) {
                writer.U64(object);
            }
            writer.Bool(thread.wait->alertable);
            writer.U64(thread.wait->generation);
            writer.U64(thread.wait->timer);
            writer.U64(thread.wait->sequence);
        }
    }

    writer.U64(static_cast<std::uint64_t>(objects_.size()));
    for (const auto& [id, object] : objects_) {
        writer.U64(id);
        writer.U8(ToValue(object.type));
        writer.Bool(object.signaled);
    }

    for (const auto& queue : run_queues_) {
        writer.U64(static_cast<std::uint64_t>(queue.size()));
        for (const auto thread : queue) {
            writer.U64(thread);
        }
    }

    writer.U64(static_cast<std::uint64_t>(apcs_.size()));
    for (const auto& [thread, queue] : apcs_) {
        writer.U64(thread);
        write_event_queue(queue);
    }
    write_event_queue(work_items_);

    auto timers = timers_;
    writer.U64(static_cast<std::uint64_t>(timers.size()));
    while (!timers.empty()) {
        const auto timer = timers.top();
        timers.pop();
        writer.U64(timer.due_time);
        writer.U64(timer.sequence);
        writer.U64(timer.id);
        writer.U64(timer.thread);
        writer.U64(timer.wait_generation);
    }

    writer.U64(static_cast<std::uint64_t>(cancelled_events_.size()));
    for (const auto event : cancelled_events_) {
        writer.U64(event);
    }

    writer.U64(static_cast<std::uint64_t>(journal_.size()));
    for (const auto& event : journal_) {
        writer.U64(event.sequence);
        writer.U64(event.virtual_time);
        writer.U8(ToValue(event.kind));
        writer.U32(event.cpu);
        writer.U64(event.thread);
        writer.U64(event.subject);
        writer.U64(event.value);
    }
    return {writer.Take()};
}

bool VirtualScheduler::Restore(const SchedulerSnapshot& snapshot) {
    std::lock_guard lock(mutex_);
    return RestoreLocked(snapshot.bytes);
}

bool VirtualScheduler::RestoreLocked(std::span<const std::uint8_t> bytes) {
    BinaryReader reader(bytes);
    if (!reader.Consume(kSnapshotMagic) || reader.U32() != kSnapshotVersion) {
        return false;
    }

    SchedulerConfig new_config;
    new_config.cpu_count = reader.U32();
    new_config.default_quantum = reader.U64();
    new_config.nanoseconds_per_instruction = reader.U64();
    const auto journal_capacity = reader.U64();
    if (journal_capacity > std::numeric_limits<std::size_t>::max()) {
        return false;
    }
    new_config.journal_capacity = static_cast<std::size_t>(journal_capacity);
    const auto new_seed = reader.U64();
    const auto new_virtual_time = reader.U64();
    const auto new_next_sequence = reader.U64();
    const auto new_next_event_id = reader.U64();
    const auto new_next_timer_id = reader.U64();
    const auto new_next_wait_generation = reader.U64();
    if (new_config.cpu_count == 0 || new_config.cpu_count > 64 ||
        new_config.default_quantum == 0 || new_config.nanoseconds_per_instruction == 0 ||
        new_next_sequence == 0 || new_next_event_id == 0 || new_next_timer_id == 0 ||
        new_next_wait_generation == 0) {
        return false;
    }

    const auto read_event = [&reader]() {
        QueuedEvent event;
        event.id = reader.U64();
        event.sequence = reader.U64();
        event.priority = reader.U8();
        event.cpu = reader.U32();
        event.thread = reader.U64();
        event.vector = reader.U32();
        event.irql = static_cast<Irql>(reader.U8());
        event.guest_routine = reader.U64();
        event.context = reader.U64();
        return event;
    };
    const auto read_event_queue = [&reader, &read_event](auto& queue) {
        const auto count = reader.Count();
        for (std::uint64_t index = 0; index < count; ++index) {
            queue.push_back(read_event());
        }
    };

    std::vector<CpuRecord> new_cpus;
    const auto cpu_count = reader.Count();
    if (cpu_count != new_config.cpu_count) {
        return false;
    }
    new_cpus.resize(static_cast<std::size_t>(cpu_count));
    for (auto& cpu : new_cpus) {
        cpu.irql = static_cast<Irql>(reader.U8());
        cpu.current_thread = reader.U64();
        if (reader.Bool()) {
            cpu.active_dispatch = DispatchFrame{reader.U64(),
                                                static_cast<Irql>(reader.U8())};
        }
        read_event_queue(cpu.interrupts);
        read_event_queue(cpu.dpcs);
    }

    std::map<ThreadId, ThreadRecord> new_threads;
    const auto thread_count = reader.Count();
    for (std::uint64_t index = 0; index < thread_count; ++index) {
        const auto id = reader.U64();
        ThreadRecord thread;
        thread.info.id = id;
        thread.info.state = static_cast<ThreadState>(reader.U8());
        thread.info.priority = reader.U8();
        thread.info.affinity_mask = reader.U64();
        thread.info.quantum = reader.U64();
        thread.info.quantum_remaining = reader.U64();
        thread.info.current_cpu = reader.U32();
        thread.info.last_wake_reason = static_cast<WakeReason>(reader.U8());
        const auto wake_index = reader.U64();
        if (wake_index != std::numeric_limits<std::uint64_t>::max() &&
            wake_index > std::numeric_limits<std::size_t>::max()) {
            return false;
        }
        thread.info.wake_object_index = static_cast<std::size_t>(wake_index);
        thread.queued = reader.Bool();
        if (reader.Bool()) {
            WaitState wait;
            wait.mode = static_cast<WaitMode>(reader.U8());
            const auto count = reader.Count();
            wait.objects.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t object_index = 0; object_index < count; ++object_index) {
                wait.objects.push_back(reader.U64());
            }
            wait.alertable = reader.Bool();
            wait.generation = reader.U64();
            wait.timer = reader.U64();
            wait.sequence = reader.U64();
            thread.wait = std::move(wait);
        }
        if (id == 0 || !new_threads.emplace(id, std::move(thread)).second) {
            return false;
        }
    }

    std::map<ObjectId, WaitObjectRecord> new_objects;
    const auto object_count = reader.Count();
    for (std::uint64_t index = 0; index < object_count; ++index) {
        const auto id = reader.U64();
        WaitObjectRecord object{static_cast<WaitObjectType>(reader.U8()), reader.Bool()};
        if (id == 0 || !new_objects.emplace(id, object).second) {
            return false;
        }
    }

    std::array<std::deque<ThreadId>, kPriorityLevels> new_run_queues;
    for (auto& queue : new_run_queues) {
        const auto count = reader.Count();
        for (std::uint64_t index = 0; index < count; ++index) {
            queue.push_back(reader.U64());
        }
    }

    std::map<ThreadId, std::deque<QueuedEvent>> new_apcs;
    const auto apc_thread_count = reader.Count();
    for (std::uint64_t index = 0; index < apc_thread_count; ++index) {
        const auto thread = reader.U64();
        std::deque<QueuedEvent> queue;
        read_event_queue(queue);
        if (!new_apcs.emplace(thread, std::move(queue)).second) {
            return false;
        }
    }
    std::deque<QueuedEvent> new_work_items;
    read_event_queue(new_work_items);

    std::priority_queue<TimerRecord, std::vector<TimerRecord>, TimerLater> new_timers;
    const auto timer_count = reader.Count();
    for (std::uint64_t index = 0; index < timer_count; ++index) {
        TimerRecord timer;
        timer.due_time = reader.U64();
        timer.sequence = reader.U64();
        timer.id = reader.U64();
        timer.thread = reader.U64();
        timer.wait_generation = reader.U64();
        new_timers.push(timer);
    }

    std::set<EventId> new_cancelled_events;
    const auto cancelled_count = reader.Count();
    for (std::uint64_t index = 0; index < cancelled_count; ++index) {
        if (!new_cancelled_events.insert(reader.U64()).second) {
            return false;
        }
    }

    std::deque<JournalEvent> new_journal;
    const auto journal_count = reader.Count();
    if (journal_count > new_config.journal_capacity) {
        return false;
    }
    for (std::uint64_t index = 0; index < journal_count; ++index) {
        JournalEvent event;
        event.sequence = reader.U64();
        event.virtual_time = reader.U64();
        event.kind = static_cast<EventKind>(reader.U8());
        event.cpu = reader.U32();
        event.thread = reader.U64();
        event.subject = reader.U64();
        event.value = reader.U64();
        new_journal.push_back(event);
    }
    if (!reader.Finished()) {
        return false;
    }

    const auto valid_affinity = new_config.cpu_count == 64
                                    ? std::numeric_limits<std::uint64_t>::max()
                                    : ((std::uint64_t{1} << new_config.cpu_count) - 1);
    std::map<ThreadId, std::size_t> queued_counts;
    for (std::size_t priority = 0; priority < new_run_queues.size(); ++priority) {
        for (const auto thread_id : new_run_queues[priority]) {
            auto found = new_threads.find(thread_id);
            if (found == new_threads.end() || found->second.info.priority != priority) {
                return false;
            }
            ++queued_counts[thread_id];
        }
    }

    std::set<ThreadId> running_threads;
    for (std::size_t cpu_index = 0; cpu_index < new_cpus.size(); ++cpu_index) {
        const auto& cpu = new_cpus[cpu_index];
        if (!IsIrqlValueValid(cpu.irql) ||
            (cpu.active_dispatch.has_value() &&
             !IsIrqlValueValid(cpu.active_dispatch->previous_irql))) {
            return false;
        }
        if (cpu.current_thread != 0) {
            auto found = new_threads.find(cpu.current_thread);
            if (found == new_threads.end() || found->second.info.state != ThreadState::Running ||
                found->second.info.current_cpu != cpu_index ||
                !running_threads.insert(cpu.current_thread).second) {
                return false;
            }
        }
    }

    for (const auto& [id, thread] : new_threads) {
        const auto state_value = ToValue(thread.info.state);
        if (state_value > ToValue(ThreadState::Terminated) ||
            thread.info.priority >= kPriorityLevels || thread.info.quantum == 0 ||
            thread.info.quantum_remaining == 0 ||
            thread.info.quantum_remaining > thread.info.quantum ||
            thread.info.affinity_mask == 0 ||
            (thread.info.affinity_mask & ~valid_affinity) != 0 ||
            ToValue(thread.info.last_wake_reason) > ToValue(WakeReason::Terminated)) {
            return false;
        }
        const bool is_blocked = thread.info.state == ThreadState::Blocked;
        if (is_blocked != thread.wait.has_value() ||
            thread.queued != (thread.info.state == ThreadState::Runnable) ||
            queued_counts[id] != (thread.queued ? 1u : 0u)) {
            return false;
        }
        if (thread.info.state == ThreadState::Running) {
            if (thread.info.current_cpu >= new_cpus.size() ||
                new_cpus[thread.info.current_cpu].current_thread != id) {
                return false;
            }
        } else if (thread.info.current_cpu != kNoCpu) {
            return false;
        }
        if (thread.wait.has_value()) {
            if (thread.wait->objects.empty() ||
                ToValue(thread.wait->mode) > ToValue(WaitMode::All) ||
                thread.wait->generation == 0 || thread.wait->sequence == 0) {
                return false;
            }
            std::set<ObjectId> wait_unique;
            for (const auto object : thread.wait->objects) {
                if (!new_objects.contains(object) ||
                    (thread.wait->mode == WaitMode::All &&
                     !wait_unique.insert(object).second)) {
                    return false;
                }
            }
        }
    }

    for (const auto& [id, object] : new_objects) {
        (void)id;
        if (ToValue(object.type) > ToValue(WaitObjectType::Synchronization)) {
            return false;
        }
    }

    std::set<EventId> queued_event_ids;
    const auto validate_event = [&](const QueuedEvent& event) {
        return event.id != 0 && event.sequence != 0 && event.priority < kPriorityLevels &&
               event.vector <= 255 && IsIrqlValueValid(event.irql) &&
               queued_event_ids.insert(event.id).second;
    };
    for (std::size_t cpu_index = 0; cpu_index < new_cpus.size(); ++cpu_index) {
        for (const auto& event : new_cpus[cpu_index].interrupts) {
            if (!validate_event(event) || event.cpu != cpu_index ||
                !IsHigherIrql(event.irql, Irql::Passive)) {
                return false;
            }
        }
        for (const auto& event : new_cpus[cpu_index].dpcs) {
            if (!validate_event(event) || event.cpu != cpu_index ||
                event.irql != Irql::Dispatch) {
                return false;
            }
        }
    }
    for (const auto& [thread_id, queue] : new_apcs) {
        if (!new_threads.contains(thread_id)) {
            return false;
        }
        for (const auto& event : queue) {
            if (!validate_event(event) || event.thread != thread_id || event.irql != Irql::Apc) {
                return false;
            }
        }
    }
    for (const auto& event : new_work_items) {
        if (!validate_event(event) || event.irql != Irql::Passive) {
            return false;
        }
    }
    for (const auto event : new_cancelled_events) {
        if (!queued_event_ids.contains(event)) {
            return false;
        }
    }

    std::uint64_t previous_journal_sequence = 0;
    for (const auto& event : new_journal) {
        if (event.sequence <= previous_journal_sequence || event.sequence >= new_next_sequence ||
            event.virtual_time > new_virtual_time ||
            ToValue(event.kind) > ToValue(EventKind::SnapshotRestored)) {
            return false;
        }
        previous_journal_sequence = event.sequence;
    }

    config_ = new_config;
    seed_ = new_seed;
    virtual_time_ = new_virtual_time;
    next_sequence_ = new_next_sequence;
    next_event_id_ = new_next_event_id;
    next_timer_id_ = new_next_timer_id;
    next_wait_generation_ = new_next_wait_generation;
    cpus_ = std::move(new_cpus);
    threads_ = std::move(new_threads);
    objects_ = std::move(new_objects);
    run_queues_ = std::move(new_run_queues);
    apcs_ = std::move(new_apcs);
    work_items_ = std::move(new_work_items);
    timers_ = std::move(new_timers);
    cancelled_events_ = std::move(new_cancelled_events);
    journal_ = std::move(new_journal);
    return true;
}

} // namespace Kevlar::Scheduler
