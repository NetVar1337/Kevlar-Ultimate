#pragma once

#include <windows.h>
#include <cstdint>
#include <unicorn/unicorn.h>
#include <unordered_map>
#include <mutex>

namespace IoManager {

struct IrpCompletionInfo {
    HANDLE Event;
    NTSTATUS Status;
    ULONG_PTR Information;
    bool Completed;
};

enum class CompletionDisposition {
    Completed,
    Deferred,
    InvalidIrp,
    AlreadyCompleted,
    Freed
};

void Initialize();
void Shutdown();

bool RegisterIrp(uc_engine* Uc, uint64_t IrpUcAddr, CCHAR StackSize);
void ReleaseIrp(uint64_t IrpUcAddr);
void ResetLifecycle();
CompletionDisposition CompleteRequest(uint64_t IrpUcAddr);
NTSTATUS CallDriver(uint64_t DeviceObjUcAddr, uint64_t IrpUcAddr);
uint64_t ExchangeCancelRoutine(uint64_t IrpUcAddr, uint64_t CancelRoutineUcAddr);
BOOLEAN CancelIrp(uint64_t IrpUcAddr);
bool MarkIrpPending(uint64_t IrpUcAddr);
uint64_t GetCurrentStackLocation(uint64_t IrpUcAddr);
uint64_t GetNextStackLocation(uint64_t IrpUcAddr);
bool SkipCurrentStackLocation(uint64_t IrpUcAddr);
bool CopyCurrentStackLocationToNext(uint64_t IrpUcAddr);
bool SetCompletionRoutine(
    uint64_t IrpUcAddr, uint64_t RoutineUcAddr, uint64_t ContextUcAddr,
    bool InvokeOnSuccess, bool InvokeOnError, bool InvokeOnCancel);

void SignalCompletion(uint64_t IrpUcAddr, NTSTATUS Status, ULONG_PTR Information);

uint64_t AllocateIrp(uc_engine* Uc, CCHAR StackSize);
void FreeIrp(uint64_t IrpUcAddr);

uint64_t AllocateFileObject(uc_engine* Uc, uint64_t DeviceObjUcAddr);
void FreeFileObject(uint64_t FileObjUcAddr);

struct DispatchResult {
    NTSTATUS Status;
    ULONG_PTR Information;
    bool TimedOut;
};

DispatchResult DispatchCreate(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr);
DispatchResult DispatchClose(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr);
DispatchResult DispatchCleanup(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr);
DispatchResult DispatchDeviceIoControl(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    ULONG IoControlCode,
    void* InputBuffer, ULONG InputLength,
    void* OutputBuffer, ULONG OutputLength,
    ULONG* BytesReturned);
DispatchResult DispatchWrite(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* WriteBuffer, ULONG WriteLength,
    ULONG WriteOffset, ULONG* BytesWritten);
DispatchResult DispatchRead(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* ReadBuffer, ULONG ReadLength,
    ULONG ReadOffset, ULONG* BytesRead);

void SetIoctlWaitMs(DWORD Ms);
// 0=off; 1/2 encrypt whole buffer with classic/x64 pointer key;
// 3/4 encrypt from packet +0x28 with classic/x64 pointer key;
// 5 uses the current Apex VM's whitened x64 key at packet +0x28.
// Applied after guest METHOD_NEITHER input allocation so the key uses the
// exact Type3InputBuffer address seen by the driver.
void SetEacXteaMode(int Mode);

}
