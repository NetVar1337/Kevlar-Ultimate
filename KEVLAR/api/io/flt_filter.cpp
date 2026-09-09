#include "flt_filter.h"
#include "core/registry/virtual_fs.h"
#include "api/ob/cm_callback.h"
#include <algorithm>
#include <atomic>
#include <mutex>
#include <vector>

namespace {

struct GuestFltRegistration {
    uint16_t Size;
    uint16_t Version;
    uint32_t Flags;
    uint64_t ContextRegistration;
    uint64_t OperationRegistration;
};

struct GuestFltOperationRegistration {
    uint8_t MajorFunction;
    uint8_t Reserved[3];
    uint32_t Flags;
    uint64_t PreOperation;
    uint64_t PostOperation;
    uint64_t Reserved1;
};

struct FltOperationRegistration {
    uint8_t MajorFunction;
    uint32_t Flags;
    uint64_t PreOperation;
    uint64_t PostOperation;
};

struct FltRegistration {
    uint64_t Driver;
    uint64_t Registration;
    uint64_t Handle;
    uint64_t Sequence;
    uc_engine* Engine;
    bool Started;
    std::vector<FltOperationRegistration> Operations;
};

std::mutex g_FltCallbackLock;
std::vector<FltRegistration> g_FltCallbacks;
uint64_t g_FltSequence = 1;
constexpr size_t kFltFilterLimit = 64;
constexpr size_t kFltOperationLimit = 128;
constexpr uint8_t kFltOperationEnd = 0x80;
constexpr uint64_t kFltHandleMagic = 0x454C444E41485446ULL; // "FTHANDLE"

}

NTSTATUS h_FltRegisterFilter(PVOID Driver, PVOID Registration, PVOID* RetFilter) {
    uc_engine* Engine = CallbackRuntime::SelectEngine(nullptr);
    if (!Engine || !Driver || !Registration || !RetFilter)
        return STATUS_INVALID_PARAMETER;

    GuestFltRegistration GuestRegistration = {};
    if (!CallbackRuntime::ReadGuest(
            Engine, (uint64_t)Registration, &GuestRegistration, sizeof(GuestRegistration)) ||
        GuestRegistration.Size < sizeof(GuestFltRegistration) ||
        GuestRegistration.Size > 0x100 ||
        GuestRegistration.Version < 0x0200 ||
        GuestRegistration.Version > 0x0203 ||
        !GuestRegistration.OperationRegistration)
        return STATUS_INVALID_PARAMETER;

    std::vector<FltOperationRegistration> Operations;
    bool FoundTerminator = false;
    for (size_t Index = 0; Index < kFltOperationLimit; ++Index) {
        GuestFltOperationRegistration GuestOperation = {};
        const uint64_t Address = GuestRegistration.OperationRegistration +
            Index * sizeof(GuestOperation);
        if (!CallbackRuntime::ReadGuest(
                Engine, Address, &GuestOperation, sizeof(GuestOperation)))
            return STATUS_INVALID_PARAMETER;
        if (GuestOperation.MajorFunction == kFltOperationEnd) {
            FoundTerminator = true;
            break;
        }
        if ((GuestOperation.Flags & ~0x7UL) || !GuestOperation.PreOperation)
            return STATUS_INVALID_PARAMETER;
        if (std::find_if(Operations.begin(), Operations.end(),
                [&GuestOperation](const FltOperationRegistration& Existing) {
                    return Existing.MajorFunction == GuestOperation.MajorFunction;
                }) != Operations.end())
            return STATUS_FLT_DUPLICATE_ENTRY;
        Operations.push_back({
            GuestOperation.MajorFunction,
            GuestOperation.Flags,
            GuestOperation.PreOperation,
            GuestOperation.PostOperation
        });
    }
    if (!FoundTerminator)
        return STATUS_INVALID_PARAMETER;

    std::lock_guard<std::mutex> Guard(g_FltCallbackLock);
    if (g_FltCallbacks.size() >= kFltFilterLimit)
        return STATUS_INSUFFICIENT_RESOURCES;
    for (const auto& Existing : g_FltCallbacks) {
        if (Existing.Driver == (uint64_t)Driver ||
            Existing.Registration == (uint64_t)Registration)
            return STATUS_FLT_REGISTRATION_BUSY;
    }

    const uint64_t Sequence = g_FltSequence++;
    const uint64_t Handle = CallbackRuntime::AllocateOpaqueHandle(
        Engine, kFltHandleMagic, Sequence, "FltFilterHandle");
    if (!Handle)
        return STATUS_INSUFFICIENT_RESOURCES;
    if (!CallbackRuntime::WriteGuest(Engine, (uint64_t)RetFilter, &Handle, sizeof(Handle))) {
        CallbackRuntime::FreeGuest(Engine, Handle);
        return STATUS_INVALID_PARAMETER;
    }
    g_FltCallbacks.push_back({
        (uint64_t)Driver,
        (uint64_t)Registration,
        Handle,
        Sequence,
        Engine,
        false,
        std::move(Operations)
    });
    return STATUS_SUCCESS;
}

NTSTATUS h_FltStartFiltering(PVOID Filter) {
    std::lock_guard<std::mutex> Guard(g_FltCallbackLock);
    auto It = std::find_if(g_FltCallbacks.begin(), g_FltCallbacks.end(),
        [Filter](const FltRegistration& Entry) {
            return Entry.Handle == (uint64_t)Filter;
        });
    if (It == g_FltCallbacks.end())
        return STATUS_FLT_FILTER_NOT_FOUND;
    if (It->Started)
        return STATUS_FLT_REGISTRATION_BUSY;
    It->Started = true;
    return STATUS_SUCCESS;
}

NTSTATUS h_FltUnregisterFilter(PVOID Filter) {
    uc_engine* Engine = nullptr;
    const uint64_t Handle = (uint64_t)Filter;
    {
        std::lock_guard<std::mutex> Guard(g_FltCallbackLock);
        auto It = std::find_if(g_FltCallbacks.begin(), g_FltCallbacks.end(),
            [Handle](const FltRegistration& Entry) {
                return Entry.Handle == Handle;
            });
        if (It == g_FltCallbacks.end())
            return STATUS_FLT_FILTER_NOT_FOUND;
        Engine = It->Engine;
        g_FltCallbacks.erase(It);
    }
    CallbackRuntime::FreeGuest(Engine, Handle);
    return STATUS_SUCCESS;
}

void h_FltObjectDereference(PVOID Object) {
}

NTSTATUS h_FltGetFilterInformation(PVOID Filter, uint32_t InfoClass, PVOID Buffer, ULONG BufSize, PULONG BytesReturned) {
    if (BytesReturned) {
        auto HostRet = UcPtr(BytesReturned);
        *HostRet = 0;
    }
    return 0xC000000D;
}

PVOID h_FltGetRoutineAddress(const char* FltRoutineName) {
    auto HostName = UcPtr(FltRoutineName);
    bool IsAscii = true;
    int Len = 0;
    for (int I = 0; I < 256 && HostName[I]; I++) {
        if ((unsigned char)HostName[I] < 0x20 || (unsigned char)HostName[I] > 0x7E) {
            IsAscii = false;
            break;
        }
        Len++;
    }

    if (IsAscii && Len > 0) {
        Logger::Log("{CYN}FltGetRoutineAddress: %s{RESET}\n", HostName);
        std::string Name(HostName, Len);
        {
            std::shared_lock<std::shared_mutex> Guard(Provider::ProviderLock);
            if (Provider::function_providers.contains(Name)) {
                PVOID Func = Provider::function_providers[Name];
                Guard.unlock();
                return (PVOID)UnicornEmu::AllocateSentinel(Name.c_str(), Func);
            }
        }
    } else {
        Logger::Log("{YEL}FltGetRoutineAddress: (encrypted/unreadable, returning generic stub){RESET}\n");
    }

    static PVOID GenericFltStub = (PVOID)[](uint64_t A1, uint64_t A2, uint64_t A3, uint64_t A4) -> uint64_t {
        Logger::Log("{YEL}\t[FLT-STUB] unimplemented filter routine called a1=%llx a2=%llx{RESET}\n", A1, A2);
        return 0;
    };
    static std::atomic<int> FltStubCounter{0};
    char StubName[64];
    sprintf(StubName, "FltAutoStub_%d", FltStubCounter.fetch_add(1));
    {
        std::unique_lock<std::shared_mutex> Guard(Provider::ProviderLock);
        Provider::function_providers[StubName] = GenericFltStub;
    }
    uint64_t Sentinel = UnicornEmu::AllocateSentinel(StubName, GenericFltStub);
    Logger::Log("{YEL}\t-> flt auto-stub sentinel 0x%llx{RESET}\n", Sentinel);
    return (PVOID)Sentinel;
}

void h_FltSetCallbackDataDirty(PVOID Data) {
}

NTSTATUS h_FltGetDiskDeviceObject(PVOID Volume, PVOID* DiskDevice) {
    if (DiskDevice) {
        auto HostPtr = UcPtr(DiskDevice);
        *HostPtr = nullptr;
    }
    return 0xC000000D;
}

NTSTATUS h_FltGetVolumeFromInstance(PVOID Instance, PVOID* Volume) {
    if (Volume) {
        auto HostPtr = UcPtr(Volume);
        *HostPtr = nullptr;
    }
    return 0xC000000D;
}

NTSTATUS h_FltAllocateCallbackData(PVOID Instance, PVOID FileObject, PVOID* RetNewCbdData) {
    if (RetNewCbdData) {
        auto HostPtr = UcPtr(RetNewCbdData);
        uint64_t FakeCbd = UnicornMem::AllocatePool(UnicornThread::GetCurrentEngine(), 0x200);
        *HostPtr = (PVOID)FakeCbd;
    }
    return 0;
}

void h_FltFreeCallbackData(PVOID CbdData) {
}

NTSTATUS h_FltPerformSynchronousIo(PVOID CbdData) {
    return 0;
}

NTSTATUS h_FltCancellableWaitForSingleObject(PVOID Object, PLARGE_INTEGER Timeout, PVOID CbdData) {
    return 0;
}

NTSTATUS h_FltCancellableWaitForMultipleObjects(ULONG Count, PVOID* ObjectArray, uint32_t WaitType, PLARGE_INTEGER Timeout, PVOID WaitBlockArray, PVOID CbdData) {
    return 0;
}

NTSTATUS h_FltClose(PVOID* FileObject) {
    return 0;
}

NTSTATUS h_FltCreateFile(PVOID Filter, PVOID Instance, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PVOID ObjAttr, PVOID IoStatusBlock, PLARGE_INTEGER AllocSize, ULONG FileAttrs, ULONG ShareAccess, ULONG CreateDisp, ULONG CreateOpts, PVOID EaBuffer, ULONG EaLength, ULONG Flags) {
    Logger::Log("{CYN}FltCreateFile called{RESET}\n");

    auto HostHandle = UcPtr(FileHandle);
    auto HostIsb = UcPtr(IoStatusBlock);

    if (ObjAttr) {
        OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
        TranslateObjAttr((OBJECT_ATTRIBUTES*)ObjAttr, LocalOa, LocalName);

        const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;
        Logger::Log("  {YEL}FltCreateFile: {WHT}%ls{RESET}\n", PathStr ? PathStr : L"(null)");

        std::wstring LocalPath = PathStr ? VirtualFs::NtPathToLocalW(PathStr) : L"";
        if (!LocalPath.empty()) {
            HANDLE H = VirtualFs::CreateLocalFile(LocalPath, DesiredAccess, FileAttrs, ShareAccess, CreateDisp, CreateOpts);
            if (H != INVALID_HANDLE_VALUE) {
                *HostHandle = H;
                if (HostIsb) {
                    auto Isb = (_IO_STATUS_BLOCK*)HostIsb;
                    Isb->Status = 0;
                    Isb->Information = 2;
                }
                Logger::Log("  {GRN}VFS: FltCreateFile -> {WHT}%ls{RESET}\n", LocalPath.c_str());
                return 0;
            }
        }

        std::wstring RewrittenStorage;
        UNICODE_STRING RewrittenName = {};
        RewriteSystemRootPath(LocalOa, RewrittenName, RewrittenStorage);
        ULONG SafeOpts = CreateOpts & ~(0x00010000);
        ACCESS_MASK SafeAccess = DesiredAccess;
        if (SafeOpts & (0x10 | 0x20))
            SafeAccess |= SYNCHRONIZE;
        auto Ret = __NtRoutine("NtCreateFile", HostHandle, SafeAccess, &LocalOa, HostIsb, AllocSize, FileAttrs, ShareAccess,
            CreateDisp, SafeOpts, EaBuffer, EaLength);
        Logger::Log("  {GRY}FltCreateFile OS return: {WHT}%08x{RESET}\n", Ret);
        return Ret;
    }

    if (HostHandle)
        *HostHandle = (HANDLE)0x1234;
    return 0;
}

NTSTATUS h_FltGetVolumeProperties(PVOID Volume, PVOID VolumeProperties, ULONG Length, PULONG LengthReturned) {
    if (LengthReturned) {
        auto HostPtr = UcPtr(LengthReturned);
        *HostPtr = 0;
    }
    return 0xC000000D;
}

void FltCallbacks::ReleaseFrame(OperationFrame& Frame) {
    if (Frame.Engine) {
        CallbackRuntime::FreeGuest(Frame.Engine, Frame.CallbackData);
        CallbackRuntime::FreeGuest(Frame.Engine, Frame.RelatedObjects);
    }
    Frame = {};
}

NTSTATUS FltCallbacks::TriggerPre(uc_engine* Engine, OperationEvent& Event,
    OperationFrame& Frame, uint32_t* PreOperationStatus) {
    ReleaseFrame(Frame);
    Engine = CallbackRuntime::SelectEngine(Engine);
    if (!Engine || !Event.CallbackData || !Event.CallbackDataSize ||
        !Event.RelatedObjects || !Event.RelatedObjectsSize)
        return STATUS_INVALID_PARAMETER;

    std::vector<FltRegistration> Filters;
    {
        std::lock_guard<std::mutex> Guard(g_FltCallbackLock);
        for (const auto& Filter : g_FltCallbacks) {
            if (Filter.Started)
                Filters.push_back(Filter);
        }
    }
    std::stable_sort(Filters.begin(), Filters.end(),
        [](const FltRegistration& Left, const FltRegistration& Right) {
            return Left.Sequence < Right.Sequence;
        });

    Frame.Engine = Engine;
    Frame.CallbackData = CallbackRuntime::AllocateGuestCopy(
        Engine, Event.CallbackData, Event.CallbackDataSize, "FltCallbackData");
    Frame.RelatedObjects = CallbackRuntime::AllocateGuestCopy(
        Engine, Event.RelatedObjects, Event.RelatedObjectsSize, "FltRelatedObjects");
    if (!Frame.CallbackData || !Frame.RelatedObjects) {
        ReleaseFrame(Frame);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    uint32_t LastPreStatus = 1; // FLT_PREOP_SUCCESS_NO_CALLBACK
    NTSTATUS Result = STATUS_SUCCESS;
    bool StopDispatch = false;
    for (const auto& Filter : Filters) {
        for (const auto& Operation : Filter.Operations) {
            if (Operation.MajorFunction != Event.MajorFunction)
                continue;

            uint64_t CompletionContext = 0;
            const uint64_t CompletionContextAddress = CallbackRuntime::AllocateGuestCopy(
                Engine, &CompletionContext, sizeof(CompletionContext), "FltCompletionContext");
            if (!CompletionContextAddress) {
                Result = STATUS_INSUFFICIENT_RESOURCES;
                StopDispatch = true;
                break;
            }

            const uint64_t Arguments[] = {
                Frame.CallbackData,
                Frame.RelatedObjects,
                CompletionContextAddress
            };
            uint64_t CallbackResult = 0;
            if (!CallbackRuntime::InvokeGuest(
                    Engine, Operation.PreOperation, Arguments, 3, &CallbackResult) ||
                !CallbackRuntime::ReadGuest(
                    Engine, CompletionContextAddress,
                    &CompletionContext, sizeof(CompletionContext))) {
                Result = (NTSTATUS)0xC0000001L;
                CallbackRuntime::FreeGuest(Engine, CompletionContextAddress);
                StopDispatch = true;
                break;
            }
            CallbackRuntime::FreeGuest(Engine, CompletionContextAddress);

            LastPreStatus = (uint32_t)CallbackResult;
            if ((LastPreStatus == 0 || LastPreStatus == 5) && Operation.PostOperation) {
                Frame.PostCallbacks.push_back({
                    Operation.PostOperation,
                    CompletionContext
                });
            }
            if (LastPreStatus > 6) {
                Result = STATUS_INVALID_PARAMETER;
                StopDispatch = true;
                break;
            }
            if (LastPreStatus == 2 || LastPreStatus == 3 ||
                LastPreStatus == 4 || LastPreStatus == 6) {
                StopDispatch = true;
                break;
            }
        }
        if (StopDispatch)
            break;
    }

    if (!CallbackRuntime::ReadGuest(
            Engine, Frame.CallbackData, Event.CallbackData, Event.CallbackDataSize) ||
        !CallbackRuntime::ReadGuest(
            Engine, Frame.RelatedObjects, Event.RelatedObjects, Event.RelatedObjectsSize))
        Result = STATUS_INVALID_PARAMETER;
    if (PreOperationStatus)
        *PreOperationStatus = LastPreStatus;
    if (Frame.PostCallbacks.empty())
        ReleaseFrame(Frame);
    return Result;
}

NTSTATUS FltCallbacks::TriggerPost(OperationEvent& Event, OperationFrame& Frame) {
    if (!Frame.Engine || !Frame.CallbackData || !Frame.RelatedObjects ||
        !Event.CallbackData || !Event.CallbackDataSize ||
        !Event.RelatedObjects || !Event.RelatedObjectsSize)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS Result = STATUS_SUCCESS;
    if (!CallbackRuntime::WriteGuest(
            Frame.Engine, Frame.CallbackData, Event.CallbackData, Event.CallbackDataSize) ||
        !CallbackRuntime::WriteGuest(
            Frame.Engine, Frame.RelatedObjects, Event.RelatedObjects, Event.RelatedObjectsSize))
        Result = STATUS_INVALID_PARAMETER;

    if (Result >= 0) {
        for (auto It = Frame.PostCallbacks.rbegin(); It != Frame.PostCallbacks.rend(); ++It) {
            const uint64_t Arguments[] = {
                Frame.CallbackData,
                Frame.RelatedObjects,
                It->CompletionContext,
                Event.PostOperationFlags
            };
            if (!CallbackRuntime::InvokeGuest(
                    Frame.Engine, It->Function, Arguments, 4, nullptr))
                Result = (NTSTATUS)0xC0000001L;
        }
    }

    if (!CallbackRuntime::ReadGuest(
            Frame.Engine, Frame.CallbackData, Event.CallbackData, Event.CallbackDataSize) ||
        !CallbackRuntime::ReadGuest(
            Frame.Engine, Frame.RelatedObjects, Event.RelatedObjects, Event.RelatedObjectsSize))
        Result = STATUS_INVALID_PARAMETER;
    ReleaseFrame(Frame);
    return Result;
}

size_t FltCallbacks::RegisteredCount() {
    std::lock_guard<std::mutex> Guard(g_FltCallbackLock);
    return g_FltCallbacks.size();
}
