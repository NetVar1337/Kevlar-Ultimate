#include "core/scheduler/virtual_scheduler.h"

#include <array>
#include <cassert>
#include <cstdint>

using namespace Kevlar::Scheduler;

namespace {

bool SameDecision(const ScheduleDecision& lhs, const ScheduleDecision& rhs) {
    return lhs.kind == rhs.kind && lhs.cpu == rhs.cpu && lhs.thread == rhs.thread &&
           lhs.event == rhs.event && lhs.guest_routine == rhs.guest_routine &&
           lhs.context == rhs.context && lhs.vector == rhs.vector &&
           lhs.dispatch_irql == rhs.dispatch_irql &&
           lhs.quantum_remaining == rhs.quantum_remaining;
}

} // namespace

int main() {
    const SchedulerConfig config{
        .cpu_count = 2,
        .default_quantum = 5,
        .nanoseconds_per_instruction = 10,
        .journal_capacity = 256,
    };
    VirtualScheduler scheduler(config, 0x4b45564c4152ULL);

    assert(scheduler.RegisterThread(10, 4, 0b01));
    assert(scheduler.RegisterThread(20, 12, 0b01));
    assert(scheduler.RegisterThread(30, 8, 0b10));

    // Highest priority wins, while affinity keeps thread 30 on virtual CPU 1.
    auto decision = scheduler.ScheduleNext(0);
    assert(decision.kind == DispatchKind::RunThread && decision.thread == 20);
    decision = scheduler.ScheduleNext(1);
    assert(decision.kind == DispatchKind::RunThread && decision.thread == 30);

    // Interrupts precede DPCs and both preserve FIFO order within their class.
    const auto dpc = scheduler.QueueDpc(0, 0x2000, 2);
    const auto interrupt1 = scheduler.QueueInterrupt(0, 0x41, 0x1000, 1);
    const auto interrupt2 = scheduler.QueueInterrupt(0, 0x42, 0x1001, 2);
    assert(dpc != 0 && interrupt1 != 0 && interrupt2 != 0);
    decision = scheduler.ScheduleNext(0);
    assert(decision.kind == DispatchKind::Interrupt && decision.event == interrupt1);
    assert(scheduler.CompleteDispatch(0, decision.event));
    decision = scheduler.ScheduleNext(0);
    assert(decision.kind == DispatchKind::Interrupt && decision.event == interrupt2);
    assert(scheduler.CompleteDispatch(0, decision.event));
    decision = scheduler.ScheduleNext(0);
    assert(decision.kind == DispatchKind::Dpc && decision.event == dpc);
    assert(scheduler.CompleteDispatch(0, decision.event));

    // A quantum boundary is deterministic and advances only virtual time.
    const auto accounted = scheduler.AccountInstructions(0, 5);
    assert(accounted.accepted && accounted.quantum_expired);
    assert(accounted.virtual_time == 50);

    // Wait-all remains blocked until both objects are signaled.
    assert(scheduler.CreateWaitObject(100, WaitObjectType::Notification));
    assert(scheduler.CreateWaitObject(200, WaitObjectType::Synchronization));
    const std::array<ObjectId, 2> all_objects{100, 200};
    auto wait = scheduler.Wait(10, all_objects, WaitMode::All, 100, false);
    assert(wait.accepted && !wait.completed);
    assert(scheduler.SignalObject(100) == 0);
    assert(scheduler.SignalObject(200) == 1);
    const auto awakened = scheduler.GetThreadInfo(10);
    assert(awakened && awakened->state == ThreadState::Runnable);
    assert(awakened->last_wake_reason == WakeReason::Object);

    // Alertable waits wake for APC delivery without consuming the queued APC.
    const std::array<ObjectId, 1> one_object{100};
    assert(scheduler.ResetObject(100));
    wait = scheduler.Wait(10, one_object, WaitMode::Any, std::nullopt, true);
    assert(wait.accepted && !wait.completed);
    const auto apc = scheduler.QueueApc(10, 0x3000, 3);
    assert(apc != 0);
    assert(scheduler.SetThreadPriority(10, 31));

    // A byte snapshot includes queues, virtual time, IRQL, wait state and journal.
    const auto snapshot = scheduler.Snapshot();
    VirtualScheduler restored({1, 1, 1, 1}, 0);
    assert(restored.Restore(snapshot));

    const auto original_apc = scheduler.ScheduleNext(0);
    const auto restored_apc = restored.ScheduleNext(0);
    assert(SameDecision(original_apc, restored_apc));
    assert(original_apc.kind == DispatchKind::Apc && original_apc.thread == 10);
    assert(scheduler.CompleteDispatch(0, original_apc.event));
    assert(restored.CompleteDispatch(0, restored_apc.event));

    const auto original_run = scheduler.ScheduleNext(0);
    const auto restored_run = restored.ScheduleNext(0);
    assert(SameDecision(original_run, restored_run));

    // Separate equal inputs produce the same stable work-item ordering.
    VirtualScheduler first(config, 7);
    VirtualScheduler second(config, 7);
    const auto first_low = first.QueueWorkItem(2, 0x4000, 1);
    const auto first_high = first.QueueWorkItem(9, 0x4001, 2);
    const auto second_low = second.QueueWorkItem(2, 0x4000, 1);
    const auto second_high = second.QueueWorkItem(9, 0x4001, 2);
    assert(first_low == second_low && first_high == second_high);
    assert(SameDecision(first.ScheduleNext(0), second.ScheduleNext(0)));

    // Timer expiration is driven solely by explicit virtual-time advancement.
    VirtualScheduler timers(config, 9);
    assert(timers.RegisterThread(1, 1, 1));
    assert(timers.CreateWaitObject(1, WaitObjectType::Notification));
    const std::array<ObjectId, 1> timer_object{1};
    wait = timers.Wait(1, timer_object, WaitMode::Any, 25, false);
    assert(wait.accepted && !wait.completed);
    assert(timers.AdvanceTime(24));
    assert(timers.GetThreadInfo(1)->state == ThreadState::Blocked);
    assert(timers.AdvanceTime(1));
    assert(timers.GetThreadInfo(1)->last_wake_reason == WakeReason::Timeout);

    const auto journal = scheduler.Journal();
    for (std::size_t index = 1; index < journal.size(); ++index) {
        assert(journal[index - 1].sequence < journal[index].sequence);
    }
    return 0;
}
