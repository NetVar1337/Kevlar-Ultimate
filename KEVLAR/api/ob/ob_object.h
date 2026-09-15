#pragma once
#include "include/common.h"
#include <vector>

namespace ObCallbacks {

constexpr uint32_t OperationHandleCreate = 0x1;
constexpr uint32_t OperationHandleDuplicate = 0x2;

struct OperationEvent {
    uint64_t Object = 0;
    uint64_t ObjectType = 0;
    uint64_t SourceProcess = 0;
    uint64_t TargetProcess = 0;
    uint32_t Operation = OperationHandleCreate;
    uint32_t Flags = 0;
    ACCESS_MASK DesiredAccess = 0;
    ACCESS_MASK OriginalDesiredAccess = 0;
    ACCESS_MASK GrantedAccess = 0;
    NTSTATUS ReturnStatus = STATUS_SUCCESS;
};

struct CallbackFrame {
    uint64_t RegistrationHandle = 0;
    uint64_t PostOperation = 0;
    uint64_t RegistrationContext = 0;
    uint64_t CallContext = 0;
};

NTSTATUS TriggerPre(uc_engine* Engine, OperationEvent& Event,
    std::vector<CallbackFrame>& Frames);
NTSTATUS TriggerPost(uc_engine* Engine, const OperationEvent& Event,
    std::vector<CallbackFrame>& Frames);
size_t RegisteredCount();

}

uint64_t h_ObfDereferenceObject(PVOID obj);
LONG_PTR h_ObfReferenceObject(PVOID Object);
NTSTATUS h_ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState, ACCESS_MASK DesiredAccess, uint64_t ObjectType, uint64_t AccessMode, PHANDLE Handle);
NTSTATUS h_ObQueryNameString(PVOID Object, PVOID ObjectNameInfo, ULONG Length, PULONG ReturnLength);
NTSTATUS h_ObReferenceObjectByPointer(PVOID Object, ACCESS_MASK DesiredAccess, _OBJECT_TYPE* ObjectType, uint8_t AccessMode);
NTSTATUS h_ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK DesiredAccess, _OBJECT_TYPE* ObjectType, uint64_t AccessMode, PVOID* Object, void* HandleInformation);
NTSTATUS h_ObRegisterCallbacks(PVOID CallbackRegistration, PVOID* RegistrationHandle);
void h_ObUnRegisterCallbacks(PVOID RegistrationHandle);
void* h_ObGetFilterVersion(void* arg);
NTSTATUS h_ObDereferenceObjectDeferDelete(PVOID Object);
void h_ObDereferenceObjectWithTag(PVOID Object, ULONG Tag);
NTSTATUS h_ObOpenObjectByName(OBJECT_ATTRIBUTES* ObjectAttributes, void* ObjectType, uint8_t AccessMode, void* AccessState, ACCESS_MASK DesiredAccess, void* ParseContext, PHANDLE Handle);
NTSTATUS h_ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, void* AccessState, ACCESS_MASK DesiredAccess, void* ObjectType, uint8_t AccessMode, void* ParseContext, PVOID* Object);
NTSTATUS h_ObOpenObjectByPointerWithTag(PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState, ACCESS_MASK DesiredAccess, uint64_t ObjectType, uint8_t AccessMode, ULONG Tag, PHANDLE Handle);
