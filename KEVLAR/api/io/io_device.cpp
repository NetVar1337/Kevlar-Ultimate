#include "include/common.h"
#include "io_device.h"
#include "core/registry/virtual_fs.h"
#include "core/process/unicorn_threading.h"
#include "core/io/io_manager.h"
#include <algorithm>
#include <unordered_map>
#include <mutex>
#include "api/nt/nt_memory.h"

NTSTATUS h_ZwClose(HANDLE Handle);

namespace DeviceTracker {
    std::vector<DeviceInfo> Devices;
    std::mutex DeviceLock;

    uint64_t FindByName(const std::wstring& Name) {
        std::lock_guard<std::mutex> Guard(DeviceLock);
        for (auto& Dev : Devices) {
            if (Dev.DeviceName == Name || Dev.SymLinkName == Name)
                return Dev.UcAddr;
        }
        return 0;
    }

    uint64_t GetFirst() {
        std::lock_guard<std::mutex> Guard(DeviceLock);
        if (!Devices.empty())
            return Devices[0].UcAddr;
        return 0;
    }

    const DeviceInfo* GetByIndex(size_t Index) {
        std::lock_guard<std::mutex> Guard(DeviceLock);
        if (Index < Devices.size())
            return &Devices[Index];
        return nullptr;
    }

    size_t GetCount() {
        std::lock_guard<std::mutex> Guard(DeviceLock);
        return Devices.size();
    }
}

static std::unordered_map<std::wstring, std::wstring> g_SymlinkMap;
static std::mutex g_SymlinkLock;

namespace {

_DEVICE_OBJECT* ResolveDevice(uint64_t Address) {
    if (!Address)
        return nullptr;
    uint64_t Base = 0;
    uint64_t Size = 0;
    void* Host = nullptr;
    if (!UnicornMem::FindAllocation(Address, Base, Host, Size) || Address < Base)
        return nullptr;
    uint64_t Offset = Address - Base;
    if (Offset > Size || sizeof(_DEVICE_OBJECT) > Size - Offset)
        return nullptr;
    return (_DEVICE_OBJECT*)((unsigned char*)Host + Offset);
}

uint64_t TopDeviceLocked(uint64_t Address) {
    uint64_t Current = Address;
    for (unsigned Depth = 0; Depth < 128; ++Depth) {
        auto Device = ResolveDevice(Current);
        if (!Device)
            return 0;
        uint64_t Attached = (uint64_t)Device->AttachedDevice;
        if (!Attached)
            return Current;
        if (Attached == Current)
            return 0;
        Current = Attached;
    }
    return 0;
}

DeviceTracker::DeviceInfo* TrackedDeviceLocked(uint64_t Address) {
    for (auto& Device : DeviceTracker::Devices) {
        if (Device.UcAddr == Address)
            return &Device;
    }
    return nullptr;
}

bool WriteAttachedDevice(uint64_t OutputAddress, uint64_t Value) {
    uint64_t Base = 0;
    uint64_t Size = 0;
    void* Host = nullptr;
    if (!UnicornMem::FindAllocation(OutputAddress, Base, Host, Size) || OutputAddress < Base)
        return false;
    const uint64_t Offset = OutputAddress - Base;
    if (Offset > Size || sizeof(_DEVICE_OBJECT*) > Size - Offset)
        return false;
    *(_DEVICE_OBJECT**)((unsigned char*)Host + Offset) = (_DEVICE_OBJECT*)Value;
    return true;
}

} // namespace

NTSTATUS h_IoCreateDevice(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DWORD DeviceType,
    ULONG DeviceCharacteristics, BOOLEAN Exclusive, _DEVICE_OBJECT** DeviceObject) {
    uint64_t DevUcAddr = UnicornMem::AllocateVariable(UnicornThread::GetCurrentEngine(), sizeof(_DEVICE_OBJECT) + DeviceExtensionSize, "CreatedDeviceObject");
    if (!DevUcAddr)
        return STATUS_INSUFFICIENT_RESOURCES;
    auto RealDevice = (_DEVICE_OBJECT*)UnicornMem::UcToHost(DevUcAddr);

    memset(RealDevice, 0, sizeof(_DEVICE_OBJECT));

    RealDevice->DeviceType = DeviceType;
    RealDevice->Type = 3;
    RealDevice->Size = sizeof(_DEVICE_OBJECT);
    RealDevice->ReferenceCount = 1;
    RealDevice->DriverObject = DriverObject;
    RealDevice->NextDevice = 0;
    RealDevice->StackSize = 1;

    if (DeviceExtensionSize) {
        RealDevice->DeviceExtension = (PVOID)(DevUcAddr + sizeof(_DEVICE_OBJECT));
    }

    auto HostDevObj = (_DEVICE_OBJECT**)UnicornMem::UcToHost((uint64_t)DeviceObject);
    if (HostDevObj) {
        *HostDevObj = (_DEVICE_OBJECT*)DevUcAddr;
    } else {
        uc_mem_write(UnicornThread::GetCurrentEngine(), (uint64_t)DeviceObject, &DevUcAddr, sizeof(DevUcAddr));
    }

    auto HostDevName = DeviceName ? UcPtr(DeviceName) : nullptr;
    std::wstring DevNameStr;
    if (HostDevName && HostDevName->Buffer) {
        auto HostBuf = UcPtr(HostDevName->Buffer);
        if (HostBuf)
            DevNameStr = std::wstring(HostBuf, HostDevName->Length / sizeof(wchar_t));
    }

    Logger::Log("  {GRN}Created device: {WHT}%ls {GRN}-> {WHT}0x%llx {GRN}ext=0x%llx/0x%x{RESET}\n",
        DevNameStr.empty() ? L"(null)" : DevNameStr.c_str(), DevUcAddr,
        (unsigned long long)(DeviceExtensionSize ? DevUcAddr + sizeof(_DEVICE_OBJECT) : 0),
        DeviceExtensionSize);

    {
        std::lock_guard<std::mutex> Guard(DeviceTracker::DeviceLock);
        DeviceTracker::Devices.push_back({ DevUcAddr, DevNameStr, L"", DeviceType,
            DeviceExtensionSize ? DevUcAddr + sizeof(_DEVICE_OBJECT) : 0, DeviceExtensionSize });
    }

    return 0;
}

NTSTATUS h_IoCreateFileEx(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, void* IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength,
    void* CreateFileType, PVOID InternalParameters, ULONG Options, void* DriverContext) {

    auto HostHandle = UcPtr(FileHandle);
    auto HostIsb = UcPtr(IoStatusBlock);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;
    Logger::Log("  {YEL}IoCreateFileEx: {WHT}%ls{RESET}\n", PathStr ? PathStr : L"(null)");

    if (DesiredAccess == 0xC0000000)
        DesiredAccess = 0xC0100080;

    std::wstring LocalPath = PathStr ? VirtualFs::NtPathToLocalW(PathStr) : L"";

    if (!LocalPath.empty()) {
        bool IsCreate = (Disposition == 0 || Disposition == 2 || Disposition == 3 || Disposition == 5);
        bool Exists = VirtualFs::LocalExists(LocalPath);

        if (IsCreate || Exists) {
            HANDLE H = VirtualFs::CreateLocalFile(LocalPath, DesiredAccess, FileAttributes, ShareAccess, Disposition, CreateOptions);
            if (H != INVALID_HANDLE_VALUE) {
                *HostHandle = H;
                if (HostIsb) {
                    auto Isb = (_IO_STATUS_BLOCK*)HostIsb;
                    Isb->Status = 0;
                    Isb->Information = Exists ? 1 : 2;
                }
                Logger::Log("  {GRN}VFS: IoCreateFileEx -> {WHT}%ls {GRN}handle={WHT}%p{RESET}\n", LocalPath.c_str(), H);
                return 0;
            }
        }
    }

    std::wstring RewrittenStorage;
    UNICODE_STRING RewrittenName = {};
    RewriteSystemRootPath(LocalOa, RewrittenName, RewrittenStorage);
    ULONG SafeOptions = CreateOptions & ~(0x00010000);
    ACCESS_MASK SafeAccess = DesiredAccess;
    if (SafeOptions & (0x10 | 0x20))
        SafeAccess |= SYNCHRONIZE;
    auto Ret = __NtRoutine("NtCreateFile", HostHandle, SafeAccess, &LocalOa, HostIsb, AllocationSize, FileAttributes, ShareAccess,
        Disposition, SafeOptions, EaBuffer, EaLength);
    Logger::Log("  {GRY}IoCreateFileEx OS return: {WHT}%08x{RESET}\n", Ret);
    return Ret;
}

void h_IoDeleteController(PVOID ControllerObject) {
    _EX_FAST_REF* ref = (_EX_FAST_REF*)ControllerObject;
    //TODO This needs to dereference the object, Check ntoskrnl.exe code.
    Logger::Log("{CYN}\tDeleting controller : %llx{RESET}\n", static_cast<const void*>(ControllerObject));
    return;
}

NTSTATUS h_IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName) {

    int TemporaryObject;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE LinkHandle;

    auto HostSymName = UcPtr(SymbolicLinkName);
    UNICODE_STRING LocalSymName = *HostSymName;
    LocalSymName.Buffer = UcPtr(LocalSymName.Buffer);

    Logger::Log("{CYN}\tIoDeleteSymbolicLink: %ls{RESET}\n", LocalSymName.Buffer);

    std::wstring SymStr(LocalSymName.Buffer, LocalSymName.Length / sizeof(wchar_t));
    {
        std::lock_guard<std::mutex> Guard(g_SymlinkLock);
        g_SymlinkMap.erase(SymStr);
    }

    memset(&ObjectAttributes.Attributes + 1, 0, 20);
    LinkHandle = 0;
    ObjectAttributes.RootDirectory = 0;
    ObjectAttributes.ObjectName = &LocalSymName;
    *(uintptr_t*)&ObjectAttributes.Length = 48;
    ObjectAttributes.Attributes = 576;
    TemporaryObject = __NtRoutine("ZwOpenSymbolicLinkObject", &LinkHandle, 0x10000u, &ObjectAttributes);
    if (TemporaryObject >= 0) {
        TemporaryObject = __NtRoutine("ZwMakeTemporaryObject", LinkHandle);
        if (TemporaryObject >= 0)
            h_ZwClose(&LinkHandle);
    }

    if (TemporaryObject == (int)0xC0000034)
        TemporaryObject = 0;

    return TemporaryObject;
}


NTSTATUS h_IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName) {
    auto HostSym = UcPtr(SymbolicLinkName);
    auto HostDev = UcPtr(DeviceName);
    auto HostSymBuf = UcPtr(HostSym->Buffer);
    auto HostDevBuf = UcPtr(HostDev->Buffer);
    Logger::Log("{CYN}\tIoCreateSymbolicLink: %ls -> %ls{RESET}\n", HostSymBuf, HostDevBuf);

    std::wstring SymStr(HostSymBuf, HostSym->Length / sizeof(wchar_t));
    std::wstring DevStr(HostDevBuf, HostDev->Length / sizeof(wchar_t));

    // Register in the VFS named-object registry so subsequent ObReferenceObjectByName
    // and ZwOpenSection/ZwOpenEvent lookups can find it.
    NamedObjectRegistry::Register(SymStr.c_str(), nullptr);
    Logger::Log("{GRN}\tIoCreateSymbolicLink: registered %ls in NamedObjectRegistry{RESET}\n", SymStr.c_str());

    // Store the symlink→target mapping for IoGetDeviceObjectPointer lookups.
    {
        std::lock_guard<std::mutex> Guard(g_SymlinkLock);
        g_SymlinkMap[SymStr] = DevStr;
    }

    // Update DeviceTracker with the symbolic link name for the matching device.
    {
        std::lock_guard<std::mutex> Guard(DeviceTracker::DeviceLock);
        for (auto& Dev : DeviceTracker::Devices) {
            if (Dev.DeviceName == DevStr) {
                Dev.SymLinkName = SymStr;
                Logger::Log("{CYN}\tLinked symlink {WHT}%ls{CYN} -> device {WHT}%ls{RESET}\n",
                    SymStr.c_str(), DevStr.c_str());
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}

BOOL h_IoIsSystemThread(_ETHREAD* thread) {
    auto HostThread = UcPtr(thread);
    auto ret = (HostThread->Tcb.MiscFlags & 0x400) != 0;
    return ret;
}

void h_IoDeleteDevice(_DEVICE_OBJECT* obj) {

}

//todo definitely will blowup
void* h_IoGetTopLevelIrp() {
    Logger::Log("{YEL}\tIoGetTopLevelIrp blows up sorry{RESET}\n");
    static int irp = 0;
    return &irp;
}

NTSTATUS h_IoQueryFileDosDeviceName(PVOID fileObject, PVOID* name_info) {
    typedef struct _OBJECT_NAME_INFORMATION {
        UNICODE_STRING Name;
    } aids;
    static aids n;
    auto HostNameInfo = UcPtr(name_info);
    *HostNameInfo = (PVOID)&n;

    return STATUS_SUCCESS;
}

NTSTATUS h_IoWMIOpenBlock(LPCGUID Guid, ULONG DesiredAccess, PVOID* DataBlockObject) {
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe((GUID*)Guid, LocalGuid);
    auto HostDbo = UcPtr(DataBlockObject);
    if (HostGuid)
        Logger::Log("{CYN}\tWMI GUID : %08x-%04x-%04x with access : %llx{RESET}\n", HostGuid->Data1, HostGuid->Data2, HostGuid->Data3, DesiredAccess);
    else
        Logger::Log("{YEL}\tWMI GUID : <untranslated %llx> with access : %llx{RESET}\n", (uint64_t)Guid, DesiredAccess);
    if (HostDbo)
        *HostDbo = nullptr;
    return STATUS_SUCCESS;
}

NTSTATUS h_IoWMIQueryAllData(PVOID DataBlockObject, PULONG InOutBufferSize, PVOID OutBuffer) { return STATUS_SUCCESS; }

void h_IofCompleteRequest(void* pirp, CHAR boost) {
    (void)boost;
    IoManager::CompleteRequest((uint64_t)pirp);
}

_IRP* h_IoAllocateIrp(CCHAR StackSize, BOOLEAN ChargeQuota) {
    (void)ChargeQuota;
    uc_engine* Uc = UnicornThread::GetCurrentEngine();
    if (!Uc)
        Uc = UnicornEmu::PrimaryEngine;
    return (_IRP*)IoManager::AllocateIrp(Uc, StackSize);
}

void h_IoFreeIrp(_IRP* Irp) {
    IoManager::FreeIrp((uint64_t)Irp);
}

BOOLEAN h_IoCancelIrp(_IRP* Irp) {
    return IoManager::CancelIrp((uint64_t)Irp);
}

PVOID h_IoSetCancelRoutine(_IRP* Irp, PVOID CancelRoutine) {
    return (PVOID)IoManager::ExchangeCancelRoutine((uint64_t)Irp, (uint64_t)CancelRoutine);
}

void h_IoMarkIrpPending(_IRP* Irp) {
    if (!IoManager::MarkIrpPending((uint64_t)Irp))
        Logger::Log("{RED}IoMarkIrpPending rejected IRP=0x%llx{RESET}\n", (uint64_t)Irp);
}

NTSTATUS h_IofCallDriver(_DEVICE_OBJECT* DeviceObject, _IRP* Irp) {
    return IoManager::CallDriver((uint64_t)DeviceObject, (uint64_t)Irp);
}

NTSTATUS h_IoCallDriver(_DEVICE_OBJECT* DeviceObject, _IRP* Irp) {
    return h_IofCallDriver(DeviceObject, Irp);
}

_IO_STACK_LOCATION* h_IoGetCurrentIrpStackLocation(_IRP* Irp) {
    return (_IO_STACK_LOCATION*)IoManager::GetCurrentStackLocation((uint64_t)Irp);
}

_IO_STACK_LOCATION* h_IoGetNextIrpStackLocation(_IRP* Irp) {
    return (_IO_STACK_LOCATION*)IoManager::GetNextStackLocation((uint64_t)Irp);
}

void h_IoSkipCurrentIrpStackLocation(_IRP* Irp) {
    if (!IoManager::SkipCurrentStackLocation((uint64_t)Irp))
        Logger::Log("{RED}IoSkipCurrentIrpStackLocation rejected IRP=0x%llx{RESET}\n", (uint64_t)Irp);
}

void h_IoCopyCurrentIrpStackLocationToNext(_IRP* Irp) {
    if (!IoManager::CopyCurrentStackLocationToNext((uint64_t)Irp))
        Logger::Log("{RED}IoCopyCurrentIrpStackLocationToNext rejected IRP=0x%llx{RESET}\n", (uint64_t)Irp);
}

void h_IoSetCompletionRoutine(
    _IRP* Irp, PVOID CompletionRoutine, PVOID Context,
    BOOLEAN InvokeOnSuccess, BOOLEAN InvokeOnError, BOOLEAN InvokeOnCancel)
{
    if (!IoManager::SetCompletionRoutine(
            (uint64_t)Irp, (uint64_t)CompletionRoutine, (uint64_t)Context,
            InvokeOnSuccess != FALSE, InvokeOnError != FALSE, InvokeOnCancel != FALSE)) {
        Logger::Log("{RED}IoSetCompletionRoutine rejected IRP=0x%llx Routine=0x%llx{RESET}\n",
            (uint64_t)Irp, (uint64_t)CompletionRoutine);
    }
}

NTSTATUS h_IoSetCompletionRoutineEx(
    _DEVICE_OBJECT* DeviceObject, _IRP* Irp, PVOID CompletionRoutine, PVOID Context,
    BOOLEAN InvokeOnSuccess, BOOLEAN InvokeOnError, BOOLEAN InvokeOnCancel)
{
    (void)DeviceObject;
    return IoManager::SetCompletionRoutine(
        (uint64_t)Irp, (uint64_t)CompletionRoutine, (uint64_t)Context,
        InvokeOnSuccess != FALSE, InvokeOnError != FALSE, InvokeOnCancel != FALSE)
        ? STATUS_SUCCESS
        : STATUS_INVALID_PARAMETER;
}

NTSTATUS h_IoGetDeviceInterfaces(
    const GUID* InterfaceClassGuid,
    _DEVICE_OBJECT* PhysicalDeviceObject,
    ULONG          Flags,
    wchar_t** SymbolicLinkList
) {
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe((GUID*)InterfaceClassGuid, LocalGuid);
    auto HostLinkList = UcPtr(SymbolicLinkList);
    wchar_t GUID[256] = { 0 };
    if (HostGuid)
        StringFromGUID2(*HostGuid, GUID, 64);
    Logger::Log("{CYN}\tInterface Class Guid : %ls{RESET}\n", GUID);
    if (PhysicalDeviceObject) {
        auto HostDev = UcPtr(PhysicalDeviceObject);
        if (HostDev->DriverObject) {
            auto HostDrv = UcPtr(HostDev->DriverObject);
            auto HostDrvNameBuf = UcPtr(HostDrv->DriverName.Buffer);
            Logger::Log("{CYN}Device driver name : %ls{RESET}\t", HostDrvNameBuf);
        }
    }
    *HostLinkList = (wchar_t*)0;

    return STATUS_NOT_FOUND;
}

NTSTATUS h_IoCreateNotificationEvent(PUNICODE_STRING EventName, PHANDLE EventHandle) {
    auto HostName = UcPtr(EventName);
    auto HostHandle = UcPtr(EventHandle);
    *HostHandle = (HANDLE)0xFACE;
    return STATUS_SUCCESS;
}

_DEVICE_OBJECT* h_IoAttachDeviceToDeviceStack(
    _DEVICE_OBJECT* SourceDevice, _DEVICE_OBJECT* TargetDevice)
{
    const uint64_t SourceAddress = (uint64_t)SourceDevice;
    const uint64_t TargetAddress = (uint64_t)TargetDevice;
    std::lock_guard<std::mutex> Guard(DeviceTracker::DeviceLock);
    auto Source = ResolveDevice(SourceAddress);
    uint64_t TopAddress = TopDeviceLocked(TargetAddress);
    auto Top = ResolveDevice(TopAddress);
    if (!Source || !Top || SourceAddress == TopAddress)
        return nullptr;

    auto TrackedSource = TrackedDeviceLocked(SourceAddress);
    if (TrackedSource && TrackedSource->AttachedToUcAddr)
        return nullptr;
    for (uint64_t Current = TargetAddress; Current;) {
        if (Current == SourceAddress)
            return nullptr;
        auto Device = ResolveDevice(Current);
        if (!Device)
            return nullptr;
        Current = (uint64_t)Device->AttachedDevice;
    }

    Top->AttachedDevice = (_DEVICE_OBJECT*)SourceAddress;
    Source->StackSize = (CHAR)std::min<int>(127, std::max<int>(1, Top->StackSize) + 1);
    if (TrackedSource)
        TrackedSource->AttachedToUcAddr = TopAddress;
    Logger::Log("{CYN}IoAttachDeviceToDeviceStack source=0x%llx lower=0x%llx{RESET}\n",
        SourceAddress, TopAddress);
    return (_DEVICE_OBJECT*)TopAddress;
}

NTSTATUS h_IoAttachDeviceToDeviceStackSafe(
    _DEVICE_OBJECT* SourceDevice, _DEVICE_OBJECT* TargetDevice,
    _DEVICE_OBJECT** AttachedToDeviceObject)
{
    if (!AttachedToDeviceObject ||
        !WriteAttachedDevice((uint64_t)AttachedToDeviceObject, 0))
        return STATUS_INVALID_PARAMETER;
    auto Lower = h_IoAttachDeviceToDeviceStack(SourceDevice, TargetDevice);
    if (!Lower)
        return STATUS_NO_SUCH_DEVICE;
    return WriteAttachedDevice((uint64_t)AttachedToDeviceObject, (uint64_t)Lower)
        ? STATUS_SUCCESS
        : STATUS_INVALID_PARAMETER;
}

NTSTATUS h_IoAttachDevice(
    _DEVICE_OBJECT* SourceDevice, PUNICODE_STRING TargetDevice,
    _DEVICE_OBJECT** AttachedDevice)
{
    auto Name = (UNICODE_STRING*)UnicornMem::UcToHost((uint64_t)TargetDevice);
    if (!Name || !Name->Buffer || !AttachedDevice)
        return STATUS_INVALID_PARAMETER;
    uint64_t BufferBase = 0;
    uint64_t BufferSize = 0;
    void* BufferHost = nullptr;
    const uint64_t BufferAddress = (uint64_t)Name->Buffer;
    if (!UnicornMem::FindAllocation(BufferAddress, BufferBase, BufferHost, BufferSize) ||
        BufferAddress < BufferBase ||
        BufferAddress - BufferBase > BufferSize ||
        Name->Length > BufferSize - (BufferAddress - BufferBase))
        return STATUS_INVALID_PARAMETER;
    auto Buffer = (wchar_t*)((unsigned char*)BufferHost + (BufferAddress - BufferBase));
    std::wstring TargetName(Buffer, Name->Length / sizeof(wchar_t));
    uint64_t TargetAddress = DeviceTracker::FindByName(TargetName);
    if (!TargetAddress)
        return STATUS_NO_SUCH_DEVICE;
    return h_IoAttachDeviceToDeviceStackSafe(
        SourceDevice, (_DEVICE_OBJECT*)TargetAddress, AttachedDevice);
}

void h_IoDetachDevice(_DEVICE_OBJECT* TargetDevice) {
    const uint64_t TargetAddress = (uint64_t)TargetDevice;
    std::lock_guard<std::mutex> Guard(DeviceTracker::DeviceLock);
    auto Target = ResolveDevice(TargetAddress);
    if (!Target)
        return;
    const uint64_t UpperAddress = (uint64_t)Target->AttachedDevice;
    auto Upper = ResolveDevice(UpperAddress);
    if (!Upper)
        return;

    const uint64_t SuccessorAddress = (uint64_t)Upper->AttachedDevice;
    Target->AttachedDevice = (_DEVICE_OBJECT*)SuccessorAddress;
    Upper->AttachedDevice = nullptr;
    Upper->StackSize = 1;
    if (auto Entry = TrackedDeviceLocked(UpperAddress))
        Entry->AttachedToUcAddr = 0;
    if (auto Entry = TrackedDeviceLocked(SuccessorAddress))
        Entry->AttachedToUcAddr = TargetAddress;
    if (auto Successor = ResolveDevice(SuccessorAddress))
        Successor->StackSize = (CHAR)std::min<int>(127, std::max<int>(1, Target->StackSize) + 1);
    Logger::Log("{CYN}IoDetachDevice lower=0x%llx detached=0x%llx{RESET}\n",
        TargetAddress, UpperAddress);
}

PVOID h_IoGetAttachedDevice(_DEVICE_OBJECT* DeviceObject) {
    std::lock_guard<std::mutex> Guard(DeviceTracker::DeviceLock);
    return (PVOID)TopDeviceLocked((uint64_t)DeviceObject);
}

PVOID h_IoGetAttachedDeviceReference(_DEVICE_OBJECT* DeviceObject) {
    std::lock_guard<std::mutex> Guard(DeviceTracker::DeviceLock);
    uint64_t TopAddress = TopDeviceLocked((uint64_t)DeviceObject);
    auto Top = ResolveDevice(TopAddress);
    if (!Top)
        return nullptr;
    ++Top->ReferenceCount;
    return (PVOID)TopAddress;
}

NTSTATUS h_IoRegisterPlugPlayNotification(uint32_t EventCategory, ULONG EventCategoryFlags, PVOID EventCategoryData, PVOID DriverObject, PVOID CallbackRoutine, PVOID Context, PVOID* NotificationEntry) {
    Logger::Log("Callback registered. EventCategory: {}, EventCategoryFlags: {}, EventCategoryData: {0x:X}, DriverObject: {0x:X}, CallbackRoutine: {0x:X}, Context: {0x:X}, NotificationEntry: {0x:X}",
        EventCategory, EventCategoryFlags, EventCategoryData, DriverObject, CallbackRoutine, Context, NotificationEntry);
    if (NotificationEntry) {
        auto HostPtr = UcPtr(NotificationEntry);
        *HostPtr = (PVOID)0xDEAD;
    }
    return STATUS_SUCCESS;
}

NTSTATUS h_IoUnregisterPlugPlayNotificationEx(PVOID NotificationEntry) {
    return STATUS_SUCCESS;
}

void* h_IoThreadToProcess(void* Thread) {
    Logger::Log("{CYN}\tIoThreadToProcess: thread=%p{RESET}\n", Thread);
    auto HostThread = (_ETHREAD*)UcPtr((_ETHREAD*)Thread);
    if (HostThread) {
        return (void*)HostThread->Tcb.ApcState.Process;
    }
    return nullptr;
}

struct KEVLAR_IO_WORK_ITEM {
    uint64_t DeviceObject;
    uint64_t WorkerRoutine;
    uint32_t QueueType;
    uint64_t Context;
    uint64_t IoObject;
};

PVOID h_IoAllocateWorkItem(_DEVICE_OBJECT* DeviceObject) {
    uint64_t UcAddr = UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), sizeof(KEVLAR_IO_WORK_ITEM), 'IoWI');
    if (!UcAddr) {
        Logger::Log("{RED}IoAllocateWorkItem: allocation failed{RESET}\n");
        return NULL;
    }

    auto HostItem = (KEVLAR_IO_WORK_ITEM*)UnicornMem::UcToHost(UcAddr);
    if (HostItem) {
        memset(HostItem, 0, sizeof(KEVLAR_IO_WORK_ITEM));
        HostItem->DeviceObject = (uint64_t)DeviceObject;
    }

    Logger::Log("{GRN}IoAllocateWorkItem: DevObj=%p -> WorkItem=0x%llx{RESET}\n", DeviceObject, UcAddr);
    return (PVOID)UcAddr;
}

void h_IoFreeWorkItem(PVOID IoWorkItem) {
    Logger::Log("{GRN}IoFreeWorkItem: 0x%llx{RESET}\n", (uint64_t)IoWorkItem);
    UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), (uint64_t)IoWorkItem);
}

void h_IoQueueWorkItem(PVOID IoWorkItem, PVOID WorkerRoutine, uint32_t QueueType, PVOID Context) {
    Logger::Log("{CYN}IoQueueWorkItem: WorkItem=%p Routine=%p Queue=%u Ctx=%p{RESET}\n",
        IoWorkItem, WorkerRoutine, QueueType, Context);

    auto HostItem = (KEVLAR_IO_WORK_ITEM*)UcPtr((KEVLAR_IO_WORK_ITEM*)IoWorkItem);
    if (HostItem) {
        HostItem->WorkerRoutine = (uint64_t)WorkerRoutine;
        HostItem->QueueType = QueueType;
        HostItem->Context = (uint64_t)Context;
    }

    uint64_t DeviceObject = HostItem ? HostItem->DeviceObject : 0;
    ThreadContext* Ctx = nullptr;
    __try {
        Ctx = UnicornThread::CreateEx(
            (uint64_t)WorkerRoutine,
            DeviceObject,
            (uint64_t)Context,
            0, 0,
            nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}IoQueueWorkItem: exception 0x%08x creating worker thread{RESET}\n", GetExceptionCode());
    }

    if (!Ctx)
        Logger::Log("{RED}IoQueueWorkItem: failed to create worker thread{RESET}\n");
}

void h_IoInitializeWorkItem(PVOID IoObject, PVOID IoWorkItem) {
    Logger::Log("{CYN}IoInitializeWorkItem: IoObj=%p WorkItem=%p{RESET}\n", IoObject, IoWorkItem);

    auto HostItem = (KEVLAR_IO_WORK_ITEM*)UcPtr((KEVLAR_IO_WORK_ITEM*)IoWorkItem);
    if (HostItem) {
        HostItem->IoObject = (uint64_t)IoObject;
    }
}

NTSTATUS h_IoRegisterShutdownNotification(_DEVICE_OBJECT* DeviceObject) {
    return STATUS_SUCCESS;
}

NTSTATUS h_IoCreateDeviceSecure(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DWORD DeviceType,
    ULONG DeviceCharacteristics, BOOLEAN Exclusive, PUNICODE_STRING DefaultSDDLString, void* DeviceClassGuid, _DEVICE_OBJECT** DeviceObject) {
    Logger::Log("{CYN}IoCreateDeviceSecure: forwarding to IoCreateDevice (SDDL/GUID ignored){RESET}\n");
    return h_IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject);
}

NTSTATUS h_IoValidateDeviceIoControlAccess(void* Irp, ULONG RequiredAccess) {
    Logger::Log("{GRY}IoValidateDeviceIoControlAccess: access=0x%x -> granted{RESET}\n", RequiredAccess);
    return STATUS_SUCCESS;
}
