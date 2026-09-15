#include "include/common.h"
#include "ob_object.h"
#include "api/nt/nt_memory.h"
#include "core/memory/unicorn_memory.h"
#include "core/exec/unicorn_engine.h"
#include "api/ob/cm_callback.h"
#include <algorithm>
#include <mutex>
#include <vector>

namespace {

struct GuestObCallbackRegistration {
    uint16_t Version;
    uint16_t OperationRegistrationCount;
    uint32_t Reserved;
    UNICODE_STRING Altitude;
    uint64_t RegistrationContext;
    uint64_t OperationRegistration;
};

struct GuestObOperationRegistration {
    uint64_t ObjectType;
    uint32_t Operations;
    uint32_t Reserved;
    uint64_t PreOperation;
    uint64_t PostOperation;
};

struct GuestObPreParameters {
    uint32_t DesiredAccess;
    uint32_t OriginalDesiredAccess;
    uint64_t SourceProcess;
    uint64_t TargetProcess;
};

struct GuestObPreInformation {
    uint32_t Operation;
    uint32_t Flags;
    uint64_t Object;
    uint64_t ObjectType;
    uint64_t CallContext;
    uint64_t Parameters;
};

struct GuestObPostParameters {
    uint32_t GrantedAccess;
    uint32_t Reserved;
};

struct GuestObPostInformation {
    uint32_t Operation;
    uint32_t Flags;
    uint64_t Object;
    uint64_t ObjectType;
    uint64_t CallContext;
    int32_t ReturnStatus;
    uint32_t Reserved;
    uint64_t Parameters;
};

struct ObOperationRegistration {
    uint64_t ObjectType;
    uint32_t Operations;
    uint64_t PreOperation;
    uint64_t PostOperation;
};

struct ObRegistration {
    uint64_t Handle;
    uint64_t Context;
    uint64_t Sequence;
    uc_engine* Engine;
    std::wstring Altitude;
    std::vector<ObOperationRegistration> Operations;
};

std::mutex g_ObCallbackLock;
std::vector<ObRegistration> g_ObCallbacks;
uint64_t g_ObSequence = 1;
constexpr size_t kObRegistrationLimit = 64;
constexpr size_t kObOperationLimit = 64;
constexpr uint16_t kObRegistrationVersion = 0x100;
constexpr uint64_t kObHandleMagic = 0x454C444E4148424FULL; // "OBHANDLE"

bool IsObAltitudeValid(const std::wstring& Altitude) {
    if (Altitude.empty() || Altitude.size() > 255)
        return false;
    bool Dot = false;
    for (wchar_t Ch : Altitude) {
        if (Ch >= L'0' && Ch <= L'9')
            continue;
        if (Ch == L'.' && !Dot) {
            Dot = true;
            continue;
        }
        return false;
    }
    return Altitude.front() != L'.' && Altitude.back() != L'.';
}

bool ObRegistrationPrecedes(const ObRegistration& Left, const ObRegistration& Right) {
    if (Left.Altitude == Right.Altitude)
        return Left.Sequence < Right.Sequence;
    return CallbackRuntime::AltitudePrecedes(Left.Altitude, Right.Altitude);
}

}
static std::unordered_map<uint64_t, int32_t> g_ObRefCount;
static std::mutex g_ObRefCountLock;


uint64_t h_ObfDereferenceObject(PVOID obj) {
    if (!obj)
        return 0;
    uint64_t Addr = (uint64_t)(uintptr_t)obj;
    {
        std::lock_guard<std::mutex> Guard(g_ObRefCountLock);
        auto It = g_ObRefCount.find(Addr);
        if (It != g_ObRefCount.end()) {
            It->second--;
            if (It->second <= 0) {
                Logger::Log("{YEL}[ObRef] ObfDereferenceObject: object 0x%llx refcount reached 0 -- would be freed{RESET}\n", Addr);
                g_ObRefCount.erase(It);
            }
        }
    }
    return 0;
}


LONG_PTR h_ObfReferenceObject(PVOID Object) {
    if (!Object)
        return -1;
    uint64_t Addr = (uint64_t)(uintptr_t)Object;
    {
        std::lock_guard<std::mutex> Guard(g_ObRefCountLock);
        g_ObRefCount[Addr]++;
    }
    if (Object == (PVOID)EPROCESS_BASE_UC) {
        Logger::Log("{GRY}\tObfReferenceObject: EPROCESS 0x%llx refcount bumped{RESET}\n", Addr);
        return (LONG_PTR)EPROCESS_BASE_UC;
    }
    Logger::Log("{GRY}\tObfReferenceObject: object 0x%llx refcount bumped{RESET}\n", Addr);
    return (LONG_PTR)Object;
}

NTSTATUS h_ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState, ACCESS_MASK DesiredAccess, uint64_t ObjectType,
    uint64_t AccessMode, PHANDLE Handle) {
    return STATUS_SUCCESS;
}

NTSTATUS h_ObQueryNameString(PVOID Object, PVOID ObjectNameInfo, ULONG Length, PULONG ReturnLength) {
    Logger::Log("{YEL}\tUnimplemented function call detected{RESET}\n");
    return STATUS_SUCCESS;
}

// ObReferenceObjectByPointer bumps the object's reference count without touching a
// handle table: ObfReferenceObject already models exactly that bookkeeping.
NTSTATUS h_ObReferenceObjectByPointer(PVOID Object, ACCESS_MASK DesiredAccess,
    _OBJECT_TYPE* ObjectType, uint8_t AccessMode) {
    if (!Object)
        return STATUS_INVALID_PARAMETER;
    (void)DesiredAccess;
    (void)ObjectType;
    (void)AccessMode;
    h_ObfReferenceObject(Object);
    return STATUS_SUCCESS;
}

NTSTATUS h_ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK DesiredAccess, _OBJECT_TYPE* ObjectType, uint64_t AccessMode, PVOID* Object,
    void* HandleInformation) {

    auto HostObject = UcPtr(Object);

    if (ObjectType == PsThreadType) {
        *HostObject = (PVOID)&FakeKernelThread;

        std::lock_guard<std::mutex> TmGuard(Environment::ThreadManager::ThreadManagerLock);
        if (Environment::ThreadManager::environment_threads.contains((uintptr_t)handle)) {
            *(_ETHREAD**)HostObject = Environment::ThreadManager::environment_threads[(uintptr_t)handle];
        }
    }
    else if (ObjectType == PsProcessType) {
        *HostObject = (PVOID)handle;
    }
    else if (!ObjectType)
    {
        *HostObject = (PVOID)handle;
    }
    else {
        *HostObject = (PVOID)handle;
    }


    return 0;
}

NTSTATUS h_ObRegisterCallbacks(PVOID CallbackRegistration, PVOID* RegistrationHandle) {
    uc_engine* Engine = CallbackRuntime::SelectEngine(nullptr);
    if (!Engine || !CallbackRegistration || !RegistrationHandle)
        return STATUS_INVALID_PARAMETER;

    GuestObCallbackRegistration Registration = {};
    if (!CallbackRuntime::ReadGuest(
            Engine, (uint64_t)CallbackRegistration, &Registration, sizeof(Registration)) ||
        Registration.Version != kObRegistrationVersion ||
        !Registration.OperationRegistration ||
        Registration.OperationRegistrationCount == 0 ||
        Registration.OperationRegistrationCount > kObOperationLimit)
        return STATUS_INVALID_PARAMETER;

    std::wstring Altitude;
    const uint64_t AltitudeAddress =
        (uint64_t)CallbackRegistration + offsetof(GuestObCallbackRegistration, Altitude);
    if (!CallbackRuntime::ReadUnicodeString(Engine, AltitudeAddress, Altitude) ||
        !IsObAltitudeValid(Altitude))
        return STATUS_INVALID_PARAMETER;

    std::vector<ObOperationRegistration> Operations;
    Operations.reserve(Registration.OperationRegistrationCount);
    for (uint16_t Index = 0; Index < Registration.OperationRegistrationCount; ++Index) {
        GuestObOperationRegistration GuestOperation = {};
        const uint64_t OperationAddress =
            Registration.OperationRegistration + (uint64_t)Index * sizeof(GuestOperation);
        if (!CallbackRuntime::ReadGuest(
                Engine, OperationAddress, &GuestOperation, sizeof(GuestOperation)) ||
            !GuestOperation.ObjectType ||
            !(GuestOperation.Operations & (ObCallbacks::OperationHandleCreate |
                                           ObCallbacks::OperationHandleDuplicate)) ||
            (GuestOperation.Operations & ~(ObCallbacks::OperationHandleCreate |
                                           ObCallbacks::OperationHandleDuplicate)) ||
            (!GuestOperation.PreOperation && !GuestOperation.PostOperation))
            return STATUS_INVALID_PARAMETER;

        for (const auto& Existing : Operations) {
            if (Existing.ObjectType == GuestOperation.ObjectType &&
                (Existing.Operations & GuestOperation.Operations))
                return STATUS_INVALID_PARAMETER;
        }
        Operations.push_back({
            GuestOperation.ObjectType,
            GuestOperation.Operations,
            GuestOperation.PreOperation,
            GuestOperation.PostOperation
        });
    }

    std::lock_guard<std::mutex> Guard(g_ObCallbackLock);
    if (g_ObCallbacks.size() >= kObRegistrationLimit)
        return STATUS_INSUFFICIENT_RESOURCES;
    for (const auto& Existing : g_ObCallbacks) {
        if (!CallbackRuntime::AltitudePrecedes(Existing.Altitude, Altitude) &&
            !CallbackRuntime::AltitudePrecedes(Altitude, Existing.Altitude))
            return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
    }

    const uint64_t Sequence = g_ObSequence++;
    const uint64_t Handle = CallbackRuntime::AllocateOpaqueHandle(
        Engine, kObHandleMagic, Sequence, "ObCallbackHandle");
    if (!Handle)
        return STATUS_INSUFFICIENT_RESOURCES;
    if (!CallbackRuntime::WriteGuest(
            Engine, (uint64_t)RegistrationHandle, &Handle, sizeof(Handle))) {
        CallbackRuntime::FreeGuest(Engine, Handle);
        return STATUS_INVALID_PARAMETER;
    }

    g_ObCallbacks.push_back({
        Handle,
        Registration.RegistrationContext,
        Sequence,
        Engine,
        std::move(Altitude),
        std::move(Operations)
    });
    return STATUS_SUCCESS;
}

void h_ObUnRegisterCallbacks(PVOID RegistrationHandle) {
    const uint64_t Handle = (uint64_t)RegistrationHandle;
    uc_engine* Engine = nullptr;
    {
        std::lock_guard<std::mutex> Guard(g_ObCallbackLock);
        auto It = std::find_if(g_ObCallbacks.begin(), g_ObCallbacks.end(),
            [Handle](const ObRegistration& Entry) { return Entry.Handle == Handle; });
        if (It == g_ObCallbacks.end())
            return;
        Engine = It->Engine;
        g_ObCallbacks.erase(It);
    }
    CallbackRuntime::FreeGuest(Engine, Handle);
}

void* h_ObGetFilterVersion(void* arg) {
    return (void*)(uintptr_t)kObRegistrationVersion;
}

NTSTATUS h_ObDereferenceObjectDeferDelete(PVOID Object) {
    return 0;
}

void h_ObDereferenceObjectWithTag(PVOID Object, ULONG Tag) {}

NTSTATUS h_ObOpenObjectByName(
    OBJECT_ATTRIBUTES* ObjectAttributes,
    void* ObjectType,
    uint8_t AccessMode,
    void* AccessState,
    ACCESS_MASK DesiredAccess,
    void* ParseContext,
    PHANDLE Handle)
{
    auto HostHandle = UcPtr(Handle);
    OBJECT_ATTRIBUTES LocalOa;
    UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* NameStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;

    Logger::Log("{CYN}\tObOpenObjectByName: %ls access=%08x mode=%u{RESET}\n",
        NameStr ? NameStr : L"(null)",
        DesiredAccess, (unsigned)AccessMode);

    if (NameStr && _wcsicmp(NameStr, L"\\Device\\PhysicalMemory") == 0) {
        *HostHandle = SectionHandleManager::AllocateHandle();
        Logger::Log("{GRN}\t-> PhysicalMemory fake handle %p{RESET}\n", *HostHandle);
        return STATUS_SUCCESS;
    }

    _IO_STATUS_BLOCK Isb = {};
    NTSTATUS Ret = __NtRoutine("NtOpenFile", HostHandle,
        DesiredAccess | SYNCHRONIZE, &LocalOa, &Isb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0x00000020);

    if (Ret < 0) {
        NTSTATUS SecRet = __NtRoutine("ZwOpenSection", HostHandle, DesiredAccess, &LocalOa);
        if (SecRet >= 0)
            Ret = SecRet;
    }

    Logger::Log("{GRY}\t-> %08x{RESET}\n", Ret);
    return Ret;
}

NTSTATUS h_ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    void* AccessState,
    ACCESS_MASK DesiredAccess,
    void* ObjectType,
    uint8_t AccessMode,
    void* ParseContext,
    PVOID* Object)
{
    auto HostName = UcPtr(ObjectName);
    PWSTR Buf = nullptr;
    if (HostName && HostName->Buffer) {
        Buf = UcPtr(HostName->Buffer);
    }
    Logger::Log("{CYN}\tObReferenceObjectByName: %ls access=%08x{RESET}\n",
        Buf ? Buf : L"(null)", DesiredAccess);
    if (Object) {
        auto HostObj = UcPtr(Object);
        *HostObj = nullptr;

        HANDLE RegHandle = nullptr;
        if (Buf && NamedObjectRegistry::Find(Buf, &RegHandle)) {
            // Return a synthetic KEVLOBJ block (magic + host handle) that our
            // ZwMapViewOfSection / section paths understand.
            uint64_t Blk = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, 32, "NamedObjRef");
            if (Blk) {
                auto* Host = (uint64_t*)UnicornMem::UcToHost(Blk);
                if (Host) {
                    Host[0] = 0x4A56454B424A4FULL; // 'KEVLOBJ\0' little-endian tag
                    Host[1] = (uint64_t)RegHandle;
                    Host[2] = 0;
                    Host[3] = 0;
                    *HostObj = (PVOID)Blk;
                    Logger::Log("{GRN}\t-> named-object ref %ls = guest 0x%llx (host handle %p){RESET}\n",
                        Buf, (unsigned long long)Blk, RegHandle);
                    return STATUS_SUCCESS;
                }
            }
        }
        if (Buf && NamedObjectRegistry::IsBlockedEacName(Buf)) {
            Logger::Log("{YEL}\tObReferenceObjectByName: %ls blocked (live host EAC objects are off-limits){RESET}\n", Buf);
            return 0xC0000034;
        }
    }
    return 0xC0000034;
}

NTSTATUS h_ObOpenObjectByPointerWithTag(
    PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState,
    ACCESS_MASK DesiredAccess, uint64_t ObjectType, uint8_t AccessMode,
    ULONG Tag, PHANDLE Handle)
{
    Logger::Log("{CYN}\tObOpenObjectByPointerWithTag: object=%p tag=%08x{RESET}\n", Object, Tag);
    if (Handle) {
        auto HostHandle = UcPtr(Handle);
        *HostHandle = nullptr;
    }
    return 0xC0000034;
}

NTSTATUS ObCallbacks::TriggerPre(uc_engine* Engine, OperationEvent& Event,
    std::vector<CallbackFrame>& Frames) {
    Engine = CallbackRuntime::SelectEngine(Engine);
    Frames.clear();
    if (!Engine || !Event.Object || !Event.ObjectType ||
        (Event.Operation != OperationHandleCreate &&
         Event.Operation != OperationHandleDuplicate))
        return STATUS_INVALID_PARAMETER;

    std::vector<ObRegistration> Registrations;
    {
        std::lock_guard<std::mutex> Guard(g_ObCallbackLock);
        Registrations = g_ObCallbacks;
    }
    std::stable_sort(Registrations.begin(), Registrations.end(), ObRegistrationPrecedes);

    for (const auto& Registration : Registrations) {
        for (const auto& Operation : Registration.Operations) {
            if (Operation.ObjectType != Event.ObjectType ||
                !(Operation.Operations & Event.Operation))
                continue;

            GuestObPreParameters Parameters = {};
            Parameters.DesiredAccess = Event.DesiredAccess;
            Parameters.OriginalDesiredAccess = Event.OriginalDesiredAccess;
            Parameters.SourceProcess = Event.SourceProcess;
            Parameters.TargetProcess = Event.TargetProcess;
            const uint64_t ParametersAddress = CallbackRuntime::AllocateGuestCopy(
                Engine, &Parameters, sizeof(Parameters), "ObPreParameters");
            if (!ParametersAddress)
                return STATUS_INSUFFICIENT_RESOURCES;

            GuestObPreInformation Information = {};
            Information.Operation = Event.Operation;
            Information.Flags = Event.Flags;
            Information.Object = Event.Object;
            Information.ObjectType = Event.ObjectType;
            Information.Parameters = ParametersAddress;
            const uint64_t InformationAddress = CallbackRuntime::AllocateGuestCopy(
                Engine, &Information, sizeof(Information), "ObPreInformation");
            if (!InformationAddress) {
                CallbackRuntime::FreeGuest(Engine, ParametersAddress);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS Status = STATUS_SUCCESS;
            if (Operation.PreOperation) {
                const uint64_t Arguments[] = {
                    Registration.Context,
                    InformationAddress
                };
                uint64_t PreResult = 0;
                if (!CallbackRuntime::InvokeGuest(
                        Engine, Operation.PreOperation, Arguments, 2, &PreResult))
                    Status = (NTSTATUS)0xC0000001L;
            }

            if (Status >= 0 &&
                (!CallbackRuntime::ReadGuest(
                    Engine, ParametersAddress, &Parameters, sizeof(Parameters)) ||
                 !CallbackRuntime::ReadGuest(
                    Engine, InformationAddress, &Information, sizeof(Information))))
                Status = STATUS_INVALID_PARAMETER;

            CallbackRuntime::FreeGuest(Engine, InformationAddress);
            CallbackRuntime::FreeGuest(Engine, ParametersAddress);
            if (Status < 0)
                return Status;

            Event.DesiredAccess = Parameters.DesiredAccess;
            if (Operation.PostOperation) {
                Frames.push_back({
                    Registration.Handle,
                    Operation.PostOperation,
                    Registration.Context,
                    Information.CallContext
                });
            }
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS ObCallbacks::TriggerPost(uc_engine* Engine, const OperationEvent& Event,
    std::vector<CallbackFrame>& Frames) {
    Engine = CallbackRuntime::SelectEngine(Engine);
    if (!Engine || !Event.Object || !Event.ObjectType ||
        (Event.Operation != OperationHandleCreate &&
         Event.Operation != OperationHandleDuplicate))
        return STATUS_INVALID_PARAMETER;

    NTSTATUS Result = STATUS_SUCCESS;
    for (auto It = Frames.rbegin(); It != Frames.rend(); ++It) {
        GuestObPostParameters Parameters = {};
        Parameters.GrantedAccess = Event.GrantedAccess;
        const uint64_t ParametersAddress = CallbackRuntime::AllocateGuestCopy(
            Engine, &Parameters, sizeof(Parameters), "ObPostParameters");
        if (!ParametersAddress) {
            Result = STATUS_INSUFFICIENT_RESOURCES;
            continue;
        }

        GuestObPostInformation Information = {};
        Information.Operation = Event.Operation;
        Information.Flags = Event.Flags;
        Information.Object = Event.Object;
        Information.ObjectType = Event.ObjectType;
        Information.CallContext = It->CallContext;
        Information.ReturnStatus = Event.ReturnStatus;
        Information.Parameters = ParametersAddress;
        const uint64_t InformationAddress = CallbackRuntime::AllocateGuestCopy(
            Engine, &Information, sizeof(Information), "ObPostInformation");
        if (!InformationAddress) {
            CallbackRuntime::FreeGuest(Engine, ParametersAddress);
            Result = STATUS_INSUFFICIENT_RESOURCES;
            continue;
        }

        const uint64_t Arguments[] = {
            It->RegistrationContext,
            InformationAddress
        };
        if (!CallbackRuntime::InvokeGuest(
                Engine, It->PostOperation, Arguments, 2, nullptr))
            Result = (NTSTATUS)0xC0000001L;

        CallbackRuntime::FreeGuest(Engine, InformationAddress);
        CallbackRuntime::FreeGuest(Engine, ParametersAddress);
    }
    Frames.clear();
    return Result;
}

size_t ObCallbacks::RegisteredCount() {
    std::lock_guard<std::mutex> Guard(g_ObCallbackLock);
    return g_ObCallbacks.size();
}
