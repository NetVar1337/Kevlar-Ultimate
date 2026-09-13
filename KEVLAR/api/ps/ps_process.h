#pragma once
#include "include/common.h"
#include <string>

namespace PsCallbacks {

struct ProcessEvent {
    uint64_t Process = 0;
    uint64_t ProcessId = 0;
    uint64_t ParentProcessId = 0;
    uint64_t CreatingProcessId = 0;
    uint64_t CreatingThreadId = 0;
    uint64_t FileObject = 0;
    uint32_t Flags = 0;
    uint32_t NotifyType = 0;
    NTSTATUS CreationStatus = STATUS_SUCCESS;
    bool Create = true;
    std::wstring ImageFileName;
    std::wstring CommandLine;
};

struct ImageEvent {
    std::wstring FullImageName;
    uint64_t ProcessId = 0;
    uint64_t ImageBase = 0;
    uint64_t ImageSize = 0;
    uint32_t ImageSelector = 0;
    uint32_t ImageSectionNumber = 0;
    uint32_t Properties = 0;
};

NTSTATUS TriggerProcess(uc_engine* Engine, ProcessEvent& Event);
NTSTATUS TriggerThread(uc_engine* Engine, uint64_t ProcessId, uint64_t ThreadId, bool Create);
NTSTATUS TriggerImage(uc_engine* Engine, const ImageEvent& Event);
size_t ProcessCallbackCount();
size_t ThreadCallbackCount();
size_t ImageCallbackCount();

void RegisterPidName(uint64_t Pid, const std::string& Name);
}

PVOID h_PsGetProcessWow64Process(_EPROCESS* Process);
_PEB* h_PsGetProcessPeb(_EPROCESS* process);
HANDLE h_PsGetProcessInheritedFromUniqueProcessId(_EPROCESS* Process);
LONGLONG h_PsGetProcessCreateTimeQuadPart(_EPROCESS* process);
NTSTATUS h_PsLookupProcessByProcessId(HANDLE ProcessId, _EPROCESS** Process);
HANDLE h_PsGetProcessId(_EPROCESS* Process);
_EPROCESS* h_PsGetCurrentProcess();
_EPROCESS* h_PsGetCurrentThreadProcess();
HANDLE h_PsGetCurrentThreadId();
HANDLE h_PsGetCurrentThreadProcessId();
bool h_PsIsProtectedProcess(_EPROCESS* process);
PACCESS_TOKEN h_PsReferencePrimaryToken(_EPROCESS* Process);
NTSTATUS h_PsRemoveLoadImageNotifyRoutine(void* NotifyRoutine);
NTSTATUS h_PsSetCreateProcessNotifyRoutineEx(void* NotifyRoutine, BOOLEAN Remove);
NTSTATUS h_PsCreateSystemThread(PHANDLE ThreadHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, HANDLE ProcessHandle, void* ClientId, void* StartRoutine, PVOID StartContext);
NTSTATUS h_PsTerminateSystemThread(NTSTATUS exitstatus);
NTSTATUS h_PsSetCreateThreadNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS h_PsRemoveCreateThreadNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS h_PsSetLoadImageNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS h_PsLookupThreadByThreadId(HANDLE ThreadId, PVOID* Thread);
HANDLE h_PsGetThreadId(_ETHREAD* Thread);
HANDLE h_PsGetThreadProcessId(_ETHREAD* Thread);
HANDLE h_PsGetThreadProcess(_ETHREAD* Thread);
char* h_PsGetProcessImageFileName(_EPROCESS* Process);
BOOLEAN h_PsIsSystemThread(_ETHREAD* Thread);
NTSTATUS h_PsAcquireProcessExitSynchronization(_EPROCESS* Process);
void h_PsReleaseProcessExitSynchronization(_EPROCESS* Process);
NTSTATUS h_PsSetCreateProcessNotifyRoutineEx2(uint32_t NotifyType, PVOID NotifyInformation, BOOLEAN Remove);
NTSTATUS h_PsSuspendProcess(void* Process);
NTSTATUS h_PsResumeProcess(void* Process);
void* h_PsGetProcessSectionBaseAddress(void* Process);
NTSTATUS h_PsGetProcessExitStatus(void* Process);
void* h_PsGetProcessWin32Process(void* Process);

// Forward declarations also in ob_object.h; repeated here for ps-adjacent callers.
LONG_PTR h_ObfReferenceObject(PVOID Object);
uint64_t h_ObfDereferenceObject(PVOID Object);
