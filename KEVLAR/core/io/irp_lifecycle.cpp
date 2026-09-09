#include "core/io/io_manager.h"
#include "core/io/irp_dispatch.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include "core/object/handle_manager.h"
#include "core/process/unicorn_threading.h"
#include "include/nt_define.h"
#include "include/ntoskrnl_struct.h"
#include <Logger/Logger.h>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace {

constexpr UCHAR SL_PENDING_RETURNED = 0x01;
constexpr UCHAR SL_INVOKE_ON_CANCEL = 0x20;
constexpr UCHAR SL_INVOKE_ON_SUCCESS = 0x40;
constexpr UCHAR SL_INVOKE_ON_ERROR = 0x80;
constexpr ULONG IRP_BUFFERED_IO = 0x00000010;
constexpr ULONG IRP_INPUT_OPERATION = 0x00000040;

struct IrpState {
    uc_engine* Engine = nullptr;
    uint64_t Address = 0;
    UCHAR StackCount = 0;
    std::recursive_mutex Lock;
    bool Pending = false;
    bool Completing = false;
    bool Completed = false;
    bool Freed = false;
    bool MemoryFreed = false;
    unsigned CallbackDepth = 0;
};

std::unordered_map<uint64_t, std::shared_ptr<IrpState>> Irps;
std::mutex IrpsLock;

template <typename T>
T* ResolveGuest(uint64_t Address) {
    if (!Address)
        return nullptr;

    uint64_t Base = 0;
    uint64_t Size = 0;
    void* Host = nullptr;
    if (!UnicornMem::FindAllocation(Address, Base, Host, Size) || Address < Base)
        return nullptr;
    const uint64_t Offset = Address - Base;
    if (Offset > Size || sizeof(T) > Size - Offset)
        return nullptr;
    return reinterpret_cast<T*>(static_cast<unsigned char*>(Host) + Offset);
}

void* ResolveGuestSpan(uint64_t Address, uint64_t& Remaining) {
    Remaining = 0;
    if (!Address)
        return nullptr;

    uint64_t Base = 0;
    uint64_t Size = 0;
    void* Host = nullptr;
    if (!UnicornMem::FindAllocation(Address, Base, Host, Size) || Address < Base)
        return nullptr;
    const uint64_t Offset = Address - Base;
    if (Offset >= Size)
        return nullptr;
    Remaining = Size - Offset;
    return static_cast<unsigned char*>(Host) + Offset;
}

std::shared_ptr<IrpState> FindState(uint64_t IrpUcAddr) {
    std::lock_guard<std::mutex> Guard(IrpsLock);
    auto It = Irps.find(IrpUcAddr);
    return It == Irps.end() ? nullptr : It->second;
}

void RemoveState(uint64_t IrpUcAddr, const std::shared_ptr<IrpState>& State) {
    std::lock_guard<std::mutex> Guard(IrpsLock);
    auto It = Irps.find(IrpUcAddr);
    if (It != Irps.end() && It->second == State)
        Irps.erase(It);
}

void FreeBackingIfReady(const std::shared_ptr<IrpState>& State) {
    uc_engine* Engine = nullptr;
    uint64_t Address = 0;
    {
        std::lock_guard<std::recursive_mutex> Guard(State->Lock);
        if (!State->Freed || State->MemoryFreed || State->Completing || State->CallbackDepth != 0)
            return;
        State->MemoryFreed = true;
        Engine = State->Engine;
        Address = State->Address;
    }
    if (Engine && Address)
        UnicornMem::FreePool(Engine, Address);
}

bool ValidateCursor(const IrpState& State, const _IRP* Irp, uint64_t& Current) {
    if (!Irp || Irp->CurrentLocation < 1 || Irp->CurrentLocation > State.StackCount + 1)
        return false;

    const uint64_t Expected = State.Address + sizeof(_IRP) +
        (uint64_t)(Irp->CurrentLocation - 1) * sizeof(_IO_STACK_LOCATION);
    Current = (uint64_t)Irp->Tail.Overlay.CurrentStackLocation;
    return Current == Expected;
}

bool InvokeGuest(
    uc_engine* FallbackEngine, uint64_t Routine,
    uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4,
    uint64_t& Result)
{
    ThreadContext* Thread = UnicornThread::GetCurrent();
    uc_engine* Uc = Thread ? Thread->Engine : FallbackEngine;
    if (!Uc)
        Uc = UnicornEmu::PrimaryEngine;
    if (!Uc || !Routine)
        return false;

    static const int Registers[] = {
        UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9,
        UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
        UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_RSP, UC_X86_REG_RAX,
        UC_X86_REG_RBX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RBP,
        UC_X86_REG_EFLAGS
    };
    uint64_t Saved[_countof(Registers)] = {};
    for (size_t I = 0; I < _countof(Registers); ++I)
        uc_reg_read(Uc, Registers[I], &Saved[I]);

    uint64_t Rsp = Saved[10] - 0x28;
    uint64_t Zero = 0;
    uint64_t ReturnAddress = SENTINEL_RET_ADDR;
    bool StackReady =
        uc_mem_write(Uc, Rsp, &ReturnAddress, sizeof(ReturnAddress)) == UC_ERR_OK &&
        uc_mem_write(Uc, Rsp + 0x08, &Zero, sizeof(Zero)) == UC_ERR_OK &&
        uc_mem_write(Uc, Rsp + 0x10, &Zero, sizeof(Zero)) == UC_ERR_OK &&
        uc_mem_write(Uc, Rsp + 0x18, &Zero, sizeof(Zero)) == UC_ERR_OK &&
        uc_mem_write(Uc, Rsp + 0x20, &Zero, sizeof(Zero)) == UC_ERR_OK;

    uc_err Error = UC_ERR_WRITE_UNMAPPED;
    if (StackReady) {
        uc_reg_write(Uc, UC_X86_REG_RCX, &Arg1);
        uc_reg_write(Uc, UC_X86_REG_RDX, &Arg2);
        uc_reg_write(Uc, UC_X86_REG_R8, &Arg3);
        uc_reg_write(Uc, UC_X86_REG_R9, &Arg4);
        uc_reg_write(Uc, UC_X86_REG_RSP, &Rsp);
        Error = uc_emu_start(Uc, Routine, SENTINEL_RET_ADDR, 0, 0);
        uc_reg_read(Uc, UC_X86_REG_RAX, &Result);
    }

    for (size_t I = 0; I < _countof(Registers); ++I)
        uc_reg_write(Uc, Registers[I], &Saved[I]);

    if (Error != UC_ERR_OK) {
        Logger::Log("{RED}IRP callback 0x%llx failed: %s{RESET}\n", Routine, uc_strerror(Error));
        return false;
    }
    return true;
}

void FinalizeUserNotification(uint64_t IrpUcAddr, _IRP* Irp) {
    if ((Irp->Flags & IRP_BUFFERED_IO) && (Irp->Flags & IRP_INPUT_OPERATION) &&
        Irp->IoStatus.Information != 0) {
        uint64_t SourceRemaining = 0;
        uint64_t DestinationRemaining = 0;
        void* Source = ResolveGuestSpan((uint64_t)Irp->AssociatedIrp.SystemBuffer, SourceRemaining);
        void* Destination = ResolveGuestSpan((uint64_t)Irp->UserBuffer, DestinationRemaining);
        if (Source && Destination && Source != Destination) {
            const uint64_t CopyLength = (std::min)(
                static_cast<uint64_t>(Irp->IoStatus.Information),
                (std::min)(SourceRemaining, DestinationRemaining));
            if (CopyLength != Irp->IoStatus.Information) {
                Logger::Log("{RED}IofCompleteRequest IRP=0x%llx truncated invalid buffered copy %llu -> %llu{RESET}\n",
                    IrpUcAddr, Irp->IoStatus.Information, CopyLength);
            }
            if (CopyLength)
                memcpy(Destination, Source, (size_t)CopyLength);
        } else if (!Source || !Destination) {
            Logger::Log("{RED}IofCompleteRequest IRP=0x%llx has invalid buffered I/O pointer{RESET}\n", IrpUcAddr);
        }
    }

    if (Irp->UserIosb) {
        auto UserIosb = ResolveGuest<_IO_STATUS_BLOCK>((uint64_t)Irp->UserIosb);
        if (UserIosb) {
            UserIosb->Status = Irp->IoStatus.Status;
            UserIosb->Information = Irp->IoStatus.Information;
        } else {
            Logger::Log("{RED}IofCompleteRequest IRP=0x%llx has invalid UserIosb{RESET}\n", IrpUcAddr);
        }
    }

    if (Irp->UserEvent) {
        uintptr_t Event = HandleManager::GetHandle((uintptr_t)Irp->UserEvent);
        if (Event)
            SetEvent((HANDLE)Event);
    }
}

} // namespace

bool IoManager::RegisterIrp(uc_engine* Uc, uint64_t IrpUcAddr, CCHAR StackSize) {
    if (!Uc || !IrpUcAddr || StackSize <= 0)
        return false;

    const uint64_t Required = sizeof(_IRP) + (uint64_t)(UCHAR)StackSize * sizeof(_IO_STACK_LOCATION);
    uint64_t Base = 0;
    uint64_t Size = 0;
    void* Host = nullptr;
    if (!UnicornMem::FindAllocation(IrpUcAddr, Base, Host, Size) ||
        Base != IrpUcAddr || Size < Required) {
        Logger::Log("{RED}IoManager::RegisterIrp invalid guest allocation 0x%llx{RESET}\n", IrpUcAddr);
        return false;
    }

    auto State = std::make_shared<IrpState>();
    State->Engine = Uc;
    State->Address = IrpUcAddr;
    State->StackCount = (UCHAR)StackSize;

    std::lock_guard<std::mutex> Guard(IrpsLock);
    if (Irps.find(IrpUcAddr) != Irps.end()) {
        Logger::Log("{RED}IoManager::RegisterIrp duplicate IRP 0x%llx{RESET}\n", IrpUcAddr);
        return false;
    }
    Irps.emplace(IrpUcAddr, std::move(State));
    return true;
}

void IoManager::ReleaseIrp(uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State) {
        Logger::Log("{RED}IoManager::FreeIrp invalid/double free IRP=0x%llx ignored{RESET}\n", IrpUcAddr);
        return;
    }

    {
        std::lock_guard<std::recursive_mutex> Guard(State->Lock);
        if (State->Freed) {
            Logger::Log("{RED}IoManager::FreeIrp double free IRP=0x%llx ignored{RESET}\n", IrpUcAddr);
            return;
        }
        State->Freed = true;
    }
    RemoveState(IrpUcAddr, State);
    FreeBackingIfReady(State);
    bool MemoryFreed = false;
    {
        std::lock_guard<std::recursive_mutex> Guard(State->Lock);
        MemoryFreed = State->MemoryFreed;
    }
    Logger::Log("{GRY}IoManager::FreeIrp 0x%llx%s{RESET}\n", IrpUcAddr,
        MemoryFreed ? "" : " (deferred until callback returns)");
}

void IoManager::ResetLifecycle() {
    std::unordered_map<uint64_t, std::shared_ptr<IrpState>> Old;
    {
        std::lock_guard<std::mutex> Guard(IrpsLock);
        Old.swap(Irps);
    }
    for (auto& Pair : Old) {
        std::lock_guard<std::recursive_mutex> Guard(Pair.second->Lock);
        Pair.second->Freed = true;
    }
}

uint64_t IoManager::GetCurrentStackLocation(uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State)
        return 0;
    std::lock_guard<std::recursive_mutex> Guard(State->Lock);
    auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
    uint64_t Current = 0;
    if (State->Freed || !ValidateCursor(*State, Irp, Current) ||
        Irp->CurrentLocation > State->StackCount)
        return 0;
    return Current;
}

uint64_t IoManager::GetNextStackLocation(uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State)
        return 0;
    std::lock_guard<std::recursive_mutex> Guard(State->Lock);
    auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
    uint64_t Current = 0;
    if (State->Freed || !ValidateCursor(*State, Irp, Current) || Irp->CurrentLocation <= 1)
        return 0;
    return Current - sizeof(_IO_STACK_LOCATION);
}

bool IoManager::SkipCurrentStackLocation(uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State)
        return false;
    std::lock_guard<std::recursive_mutex> Guard(State->Lock);
    auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
    uint64_t Current = 0;
    if (State->Freed || !ValidateCursor(*State, Irp, Current) ||
        Irp->CurrentLocation > State->StackCount)
        return false;
    ++Irp->CurrentLocation;
    Irp->Tail.Overlay.CurrentStackLocation =
        (_IO_STACK_LOCATION*)(Current + sizeof(_IO_STACK_LOCATION));
    return true;
}

bool IoManager::CopyCurrentStackLocationToNext(uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State)
        return false;
    std::lock_guard<std::recursive_mutex> Guard(State->Lock);
    auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
    uint64_t Current = 0;
    if (State->Freed || !ValidateCursor(*State, Irp, Current) ||
        Irp->CurrentLocation <= 1 || Irp->CurrentLocation > State->StackCount)
        return false;

    auto CurrentStack = ResolveGuest<_IO_STACK_LOCATION>(Current);
    auto NextStack = ResolveGuest<_IO_STACK_LOCATION>(Current - sizeof(_IO_STACK_LOCATION));
    if (!CurrentStack || !NextStack)
        return false;
    memcpy(NextStack, CurrentStack, offsetof(_IO_STACK_LOCATION, CompletionRoutine));
    NextStack->Control = 0;
    NextStack->CompletionRoutine = nullptr;
    NextStack->Context = nullptr;
    return true;
}

bool IoManager::SetCompletionRoutine(
    uint64_t IrpUcAddr, uint64_t RoutineUcAddr, uint64_t ContextUcAddr,
    bool InvokeOnSuccess, bool InvokeOnError, bool InvokeOnCancel)
{
    auto State = FindState(IrpUcAddr);
    if (!State || !RoutineUcAddr)
        return false;
    std::lock_guard<std::recursive_mutex> Guard(State->Lock);
    auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
    uint64_t Current = 0;
    if (State->Freed || State->Completed || !ValidateCursor(*State, Irp, Current) ||
        Irp->CurrentLocation <= 1)
        return false;

    auto NextStack = ResolveGuest<_IO_STACK_LOCATION>(Current - sizeof(_IO_STACK_LOCATION));
    if (!NextStack)
        return false;
    NextStack->CompletionRoutine = (void*)RoutineUcAddr;
    NextStack->Context = (void*)ContextUcAddr;
    NextStack->Control &= ~(SL_INVOKE_ON_CANCEL | SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR);
    if (InvokeOnCancel)
        NextStack->Control |= SL_INVOKE_ON_CANCEL;
    if (InvokeOnSuccess)
        NextStack->Control |= SL_INVOKE_ON_SUCCESS;
    if (InvokeOnError)
        NextStack->Control |= SL_INVOKE_ON_ERROR;
    return true;
}

bool IoManager::MarkIrpPending(uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State)
        return false;
    std::lock_guard<std::recursive_mutex> Guard(State->Lock);
    auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
    uint64_t Current = 0;
    if (State->Freed || State->Completed || !ValidateCursor(*State, Irp, Current) ||
        Irp->CurrentLocation > State->StackCount)
        return false;
    auto Stack = ResolveGuest<_IO_STACK_LOCATION>(Current);
    if (!Stack)
        return false;
    Stack->Control |= SL_PENDING_RETURNED;
    Irp->PendingReturned = TRUE;
    State->Pending = true;
    return true;
}

uint64_t IoManager::ExchangeCancelRoutine(uint64_t IrpUcAddr, uint64_t CancelRoutineUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State)
        return 0;
    std::lock_guard<std::recursive_mutex> Guard(State->Lock);
    auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
    if (State->Freed || State->Completed || !Irp)
        return 0;
    uint64_t Previous = (uint64_t)Irp->CancelRoutine;
    Irp->CancelRoutine = (decltype(Irp->CancelRoutine))CancelRoutineUcAddr;
    return Previous;
}

BOOLEAN IoManager::CancelIrp(uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State) {
        Logger::Log("{RED}IoCancelIrp invalid IRP=0x%llx{RESET}\n", IrpUcAddr);
        return FALSE;
    }

    bool FreeAfter = false;
    BOOLEAN Invoked = FALSE;
    {
        std::lock_guard<std::recursive_mutex> Guard(State->Lock);
        auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
        if (State->Freed || State->Completed || !Irp)
            return FALSE;

        Irp->Cancel = TRUE;
        Irp->CancelIrql = 2;
        uint64_t Routine = (uint64_t)Irp->CancelRoutine;
        Irp->CancelRoutine = nullptr;
        if (!Routine)
            return FALSE;

        uint64_t Current = 0;
        uint64_t Device = 0;
        if (ValidateCursor(*State, Irp, Current) && Irp->CurrentLocation <= State->StackCount) {
            auto Stack = ResolveGuest<_IO_STACK_LOCATION>(Current);
            if (Stack)
                Device = (uint64_t)Stack->DeviceObject;
        }

        ++State->CallbackDepth;
        uint64_t Ignored = 0;
        Invoked = TRUE;
        if (!InvokeGuest(State->Engine, Routine, Device, IrpUcAddr, 0, 0, Ignored))
            Logger::Log("{RED}IoCancelIrp cancel callback failed IRP=0x%llx{RESET}\n", IrpUcAddr);
        --State->CallbackDepth;
        FreeAfter = State->Freed && !State->Completing && State->CallbackDepth == 0;
    }
    if (FreeAfter)
        FreeBackingIfReady(State);
    return Invoked;
}

NTSTATUS IoManager::CallDriver(uint64_t DeviceObjUcAddr, uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State) {
        Logger::Log("{RED}IofCallDriver invalid IRP=0x%llx{RESET}\n", IrpUcAddr);
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = KEVLAR_STATUS_INTERNAL_ERROR;
    bool FreeAfter = false;
    {
        std::lock_guard<std::recursive_mutex> Guard(State->Lock);
        auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
        auto Device = ResolveGuest<_DEVICE_OBJECT>(DeviceObjUcAddr);
        uint64_t Current = 0;
        if (State->Freed || State->Completed || !Device ||
            !ValidateCursor(*State, Irp, Current) || Irp->CurrentLocation <= 1) {
            Logger::Log("{RED}IofCallDriver rejected IRP=0x%llx Device=0x%llx stack cursor{RESET}\n",
                IrpUcAddr, DeviceObjUcAddr);
            return STATUS_INVALID_PARAMETER;
        }

        auto Driver = ResolveGuest<_DRIVER_OBJECT>((uint64_t)Device->DriverObject);
        const uint64_t NextAddress = Current - sizeof(_IO_STACK_LOCATION);
        auto NextStack = ResolveGuest<_IO_STACK_LOCATION>(NextAddress);
        if (!Driver || !NextStack) {
            Logger::Log("{RED}IofCallDriver invalid device/driver stack IRP=0x%llx Device=0x%llx{RESET}\n",
                IrpUcAddr, DeviceObjUcAddr);
            return STATUS_NO_SUCH_DEVICE;
        }

        --Irp->CurrentLocation;
        Irp->Tail.Overlay.CurrentStackLocation = (_IO_STACK_LOCATION*)NextAddress;
        NextStack->DeviceObject = (_DEVICE_OBJECT*)DeviceObjUcAddr;
        const uint64_t Dispatch = ReadDispatchRoutine(Driver, NextStack->MajorFunction);
        if (!Dispatch) {
            ++Irp->CurrentLocation;
            Irp->Tail.Overlay.CurrentStackLocation = (_IO_STACK_LOCATION*)Current;
            Logger::Log("{YEL}IofCallDriver Device=0x%llx MJ=0x%02x has no dispatch{RESET}\n",
                DeviceObjUcAddr, NextStack->MajorFunction);
            return (NTSTATUS)0xC0000010L;
        }

        ++State->CallbackDepth;
        uint64_t Result = 0;
        const bool Called = InvokeGuest(State->Engine, Dispatch, DeviceObjUcAddr, IrpUcAddr, 0, 0, Result);
        --State->CallbackDepth;
        if (Called) {
            Status = (NTSTATUS)Result;
            if (Status == STATUS_PENDING) {
                State->Pending = true;
                Irp = ResolveGuest<_IRP>(IrpUcAddr);
                if (Irp)
                    Irp->PendingReturned = TRUE;
            }
        }
        FreeAfter = State->Freed && !State->Completing && State->CallbackDepth == 0;
    }
    if (FreeAfter)
        FreeBackingIfReady(State);
    return Status;
}

IoManager::CompletionDisposition IoManager::CompleteRequest(uint64_t IrpUcAddr) {
    auto State = FindState(IrpUcAddr);
    if (!State) {
        Logger::Log("{RED}IofCompleteRequest invalid IRP=0x%llx ignored{RESET}\n", IrpUcAddr);
        return CompletionDisposition::InvalidIrp;
    }

    CompletionDisposition Disposition = CompletionDisposition::InvalidIrp;
    bool FreeAfter = false;
    NTSTATUS FinalStatus = STATUS_INVALID_PARAMETER;
    ULONG_PTR FinalInformation = 0;
    bool Signal = false;
    {
        std::lock_guard<std::recursive_mutex> Guard(State->Lock);
        if (State->Freed)
            return CompletionDisposition::Freed;
        if (State->Completed || State->Completing) {
            Logger::Log("{RED}IofCompleteRequest duplicate IRP=0x%llx ignored{RESET}\n", IrpUcAddr);
            return CompletionDisposition::AlreadyCompleted;
        }

        auto Irp = ResolveGuest<_IRP>(IrpUcAddr);
        uint64_t Current = 0;
        if (!ValidateCursor(*State, Irp, Current)) {
            Logger::Log("{RED}IofCompleteRequest corrupt stack cursor IRP=0x%llx ignored{RESET}\n", IrpUcAddr);
            return CompletionDisposition::InvalidIrp;
        }

        State->Completing = true;
        Irp->CancelRoutine = nullptr;

        while (Irp->CurrentLocation <= State->StackCount) {
            auto Stack = ResolveGuest<_IO_STACK_LOCATION>(Current);
            if (!Stack) {
                State->Completing = false;
                return CompletionDisposition::InvalidIrp;
            }

            const UCHAR Control = Stack->Control;
            const uint64_t Routine = (uint64_t)Stack->CompletionRoutine;
            const uint64_t Context = (uint64_t)Stack->Context;
            const uint64_t Device = (uint64_t)Stack->DeviceObject;
            if (Control & SL_PENDING_RETURNED) {
                Irp->PendingReturned = TRUE;
                State->Pending = true;
            }

            Stack->CompletionRoutine = nullptr;
            Stack->Context = nullptr;
            Stack->Control &= ~(SL_INVOKE_ON_CANCEL | SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR);
            ++Irp->CurrentLocation;
            Current += sizeof(_IO_STACK_LOCATION);
            Irp->Tail.Overlay.CurrentStackLocation = (_IO_STACK_LOCATION*)Current;

            const bool Success = Irp->IoStatus.Status >= 0;
            const bool Invoke = Routine &&
                ((Irp->Cancel && (Control & SL_INVOKE_ON_CANCEL)) ||
                 (Success && (Control & SL_INVOKE_ON_SUCCESS)) ||
                 (!Success && (Control & SL_INVOKE_ON_ERROR)));
            if (Invoke) {
                ++State->CallbackDepth;
                uint64_t Result = 0;
                const bool Called = InvokeGuest(
                    State->Engine, Routine, Device, IrpUcAddr, Context, 0, Result);
                --State->CallbackDepth;
                if (!Called) {
                    Logger::Log("{RED}IofCompleteRequest completion callback failed IRP=0x%llx{RESET}\n", IrpUcAddr);
                } else if ((NTSTATUS)Result == STATUS_MORE_PROCESSING_REQUIRED) {
                    State->Completing = false;
                    Disposition = State->Freed ? CompletionDisposition::Freed : CompletionDisposition::Deferred;
                    FreeAfter = State->Freed && State->CallbackDepth == 0;
                    break;
                }
                if (State->Freed) {
                    State->Completing = false;
                    Disposition = CompletionDisposition::Freed;
                    FreeAfter = State->CallbackDepth == 0;
                    break;
                }
                Irp = ResolveGuest<_IRP>(IrpUcAddr);
                if (!Irp) {
                    State->Completing = false;
                    Disposition = CompletionDisposition::Freed;
                    break;
                }
            }
        }

        if (State->Completing) {
            FinalizeUserNotification(IrpUcAddr, Irp);
            FinalStatus = Irp->IoStatus.Status;
            FinalInformation = (ULONG_PTR)Irp->IoStatus.Information;
            State->Completed = true;
            State->Completing = false;
            State->Pending = false;
            Signal = true;
            Disposition = CompletionDisposition::Completed;
        }
    }

    if (FreeAfter)
        FreeBackingIfReady(State);
    if (Signal) {
        SignalCompletion(IrpUcAddr, FinalStatus, FinalInformation);
        Logger::Log("{GRY}IofCompleteRequest IRP=0x%llx Status=0x%08x Info=%llu{RESET}\n",
            IrpUcAddr, FinalStatus, (uint64_t)FinalInformation);
    }
    return Disposition;
}
