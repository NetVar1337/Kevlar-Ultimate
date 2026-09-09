#include "cm_callback.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <vector>

namespace {

std::recursive_mutex g_InvokeLock;

struct CmRegistration {
    uint64_t Function;
    uint64_t Context;
    uint64_t Driver;
    uint64_t Cookie;
    uint64_t Sequence;
    uc_engine* Engine;
    std::wstring Altitude;
};

std::mutex g_CmLock;
std::vector<CmRegistration> g_CmCallbacks;
uint64_t g_CmSequence = 1;
constexpr size_t kCmCallbackLimit = 100;
constexpr uint64_t kCmCookieMagic = 0x45494B4F4F434D43ULL; // "CMCOOKIE"

bool IsValidAltitude(const std::wstring& Altitude) {
    if (Altitude.empty() || Altitude.size() > 255)
        return false;
    bool SawDigit = false;
    bool SawDot = false;
    for (wchar_t Ch : Altitude) {
        if (Ch >= L'0' && Ch <= L'9') {
            SawDigit = true;
            continue;
        }
        if (Ch == L'.' && !SawDot) {
            SawDot = true;
            continue;
        }
        return false;
    }
    return SawDigit && Altitude.front() != L'.' && Altitude.back() != L'.';
}

NTSTATUS RegisterCmCallback(PVOID Function, PUNICODE_STRING Altitude, PVOID Driver,
    PVOID Context, PLARGE_INTEGER Cookie, bool HasAltitude) {
    uc_engine* Engine = CallbackRuntime::SelectEngine(nullptr);
    if (!Function || !Cookie || !Engine)
        return STATUS_INVALID_PARAMETER;

    std::wstring AltitudeValue;
    if (HasAltitude) {
        if (!Altitude ||
            !CallbackRuntime::ReadUnicodeString(Engine, (uint64_t)Altitude, AltitudeValue) ||
            !IsValidAltitude(AltitudeValue))
            return STATUS_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> Guard(g_CmLock);
    if (g_CmCallbacks.size() >= kCmCallbackLimit)
        return STATUS_INSUFFICIENT_RESOURCES;

    for (const auto& Entry : g_CmCallbacks) {
        if (Entry.Function == (uint64_t)Function && Entry.Context == (uint64_t)Context)
            return STATUS_INVALID_PARAMETER;
        if (HasAltitude && !Entry.Altitude.empty() &&
            !CallbackRuntime::AltitudePrecedes(Entry.Altitude, AltitudeValue) &&
            !CallbackRuntime::AltitudePrecedes(AltitudeValue, Entry.Altitude))
            return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
    }

    const uint64_t Sequence = g_CmSequence++;
    const uint64_t CookieValue = CallbackRuntime::AllocateOpaqueHandle(
        Engine, kCmCookieMagic, Sequence, "CmCallbackCookie");
    if (!CookieValue)
        return STATUS_INSUFFICIENT_RESOURCES;

    LARGE_INTEGER CookieResult = {};
    CookieResult.QuadPart = (LONGLONG)CookieValue;
    if (!CallbackRuntime::WriteGuest(Engine, (uint64_t)Cookie, &CookieResult, sizeof(CookieResult))) {
        CallbackRuntime::FreeGuest(Engine, CookieValue);
        return STATUS_INVALID_PARAMETER;
    }

    g_CmCallbacks.push_back({
        (uint64_t)Function,
        (uint64_t)Context,
        (uint64_t)Driver,
        CookieValue,
        Sequence,
        Engine,
        std::move(AltitudeValue)
    });
    return STATUS_SUCCESS;
}

}

uc_engine* CallbackRuntime::SelectEngine(uc_engine* Engine) {
    return Engine ? Engine : UnicornThread::GetCurrentEngine();
}

bool CallbackRuntime::ReadGuest(uc_engine* Engine, uint64_t Address, void* Buffer, size_t Size) {
    Engine = SelectEngine(Engine);
    if (!Engine || !Address || (!Buffer && Size))
        return false;
    if (!Size)
        return true;

    uint64_t Base = 0;
    uint64_t AllocationSize = 0;
    void* Host = nullptr;
    if (UnicornMem::FindAllocation(Address, Base, Host, AllocationSize)) {
        const uint64_t Offset = Address - Base;
        if (Offset <= AllocationSize && Size <= AllocationSize - Offset) {
            memcpy(Buffer, (uint8_t*)Host + Offset, Size);
            return true;
        }
        return false;
    }
    return uc_mem_read(Engine, Address, Buffer, Size) == UC_ERR_OK;
}

bool CallbackRuntime::WriteGuest(uc_engine* Engine, uint64_t Address, const void* Buffer, size_t Size) {
    Engine = SelectEngine(Engine);
    if (!Engine || !Address || (!Buffer && Size))
        return false;
    if (!Size)
        return true;

    uint64_t Base = 0;
    uint64_t AllocationSize = 0;
    void* Host = nullptr;
    if (UnicornMem::FindAllocation(Address, Base, Host, AllocationSize)) {
        const uint64_t Offset = Address - Base;
        if (Offset <= AllocationSize && Size <= AllocationSize - Offset) {
            memcpy((uint8_t*)Host + Offset, Buffer, Size);
            return true;
        }
        return false;
    }
    return uc_mem_write(Engine, Address, Buffer, Size) == UC_ERR_OK;
}

uint64_t CallbackRuntime::AllocateGuestCopy(uc_engine* Engine, const void* Buffer,
    size_t Size, const char* Name) {
    Engine = SelectEngine(Engine);
    if (!Engine || !Size)
        return 0;
    uint64_t Address = UnicornMem::AllocateVariable(Engine, Size, Name);
    if (!Address)
        return 0;
    if (Buffer && !WriteGuest(Engine, Address, Buffer, Size)) {
        UnicornMem::FreePool(Engine, Address);
        return 0;
    }
    return Address;
}

uint64_t CallbackRuntime::AllocateOpaqueHandle(uc_engine* Engine, uint64_t Magic,
    uint64_t Serial, const char* Name) {
    std::array<uint64_t, 2> Contents = { Magic, Serial };
    return AllocateGuestCopy(Engine, Contents.data(), sizeof(Contents), Name);
}

void CallbackRuntime::FreeGuest(uc_engine* Engine, uint64_t Address) {
    Engine = SelectEngine(Engine);
    if (Engine && Address)
        UnicornMem::FreePool(Engine, Address);
}

bool CallbackRuntime::InvokeGuest(uc_engine* Engine, uint64_t Function,
    const uint64_t* Arguments, size_t ArgumentCount, uint64_t* ReturnValue) {
    Engine = SelectEngine(Engine);
    if (!Engine || !Function || ArgumentCount > 5 || (ArgumentCount && !Arguments))
        return false;

    std::lock_guard<std::recursive_mutex> Guard(g_InvokeLock);
    constexpr std::array<int, 19> Registers = {
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP, UC_X86_REG_EFLAGS, UC_X86_REG_MXCSR
    };
    std::array<uint64_t, Registers.size()> Saved = {};
    for (size_t Index = 0; Index < Registers.size(); ++Index) {
        if (uc_reg_read(Engine, Registers[Index], &Saved[Index]) != UC_ERR_OK)
            return false;
    }

    const uint64_t Stack = AllocateGuestCopy(Engine, nullptr, 0x4000, "CallbackStack");
    if (!Stack)
        return false;
    uint64_t Rsp = (Stack + 0x4000 - 0x100) & ~0xFULL;
    Rsp -= 8;
    uint64_t ReturnAddress = SENTINEL_RET_ADDR;
    std::array<uint64_t, 5> CallArguments = {};
    for (size_t Index = 0; Index < ArgumentCount; ++Index)
        CallArguments[Index] = Arguments[Index];

    bool Prepared =
        WriteGuest(Engine, Rsp, &ReturnAddress, sizeof(ReturnAddress)) &&
        WriteGuest(Engine, Rsp + 8, CallArguments.data(), 4 * sizeof(uint64_t));
    if (ArgumentCount == 5)
        Prepared = Prepared && WriteGuest(Engine, Rsp + 0x28, &CallArguments[4], sizeof(uint64_t));

    uc_err EmulationResult = UC_ERR_ARG;
    if (Prepared) {
        uc_reg_write(Engine, UC_X86_REG_RCX, &CallArguments[0]);
        uc_reg_write(Engine, UC_X86_REG_RDX, &CallArguments[1]);
        uc_reg_write(Engine, UC_X86_REG_R8, &CallArguments[2]);
        uc_reg_write(Engine, UC_X86_REG_R9, &CallArguments[3]);
        uc_reg_write(Engine, UC_X86_REG_RSP, &Rsp);
        EmulationResult = uc_emu_start(Engine, Function, SENTINEL_RET_ADDR, 0, 0);
        if (ReturnValue)
            uc_reg_read(Engine, UC_X86_REG_RAX, ReturnValue);
    }

    for (size_t Index = 0; Index < Registers.size(); ++Index)
        uc_reg_write(Engine, Registers[Index], &Saved[Index]);
    FreeGuest(Engine, Stack);
    return Prepared && EmulationResult == UC_ERR_OK;
}

bool CallbackRuntime::ReadUnicodeString(uc_engine* Engine, uint64_t Address, std::wstring& Value) {
    Value.clear();
    UNICODE_STRING String = {};
    if (!ReadGuest(Engine, Address, &String, sizeof(String)) ||
        (String.Length & 1) || String.Length > String.MaximumLength ||
        String.Length > 510 || (String.Length && !String.Buffer))
        return false;
    if (!String.Length)
        return true;

    Value.resize(String.Length / sizeof(wchar_t));
    if (!ReadGuest(Engine, (uint64_t)String.Buffer, Value.data(), String.Length)) {
        Value.clear();
        return false;
    }
    return true;
}

bool CallbackRuntime::AltitudePrecedes(const std::wstring& Left, const std::wstring& Right) {
    auto Split = [](const std::wstring& Value, std::wstring& Whole, std::wstring& Fraction) {
        const size_t Dot = Value.find(L'.');
        Whole = Value.substr(0, Dot);
        Fraction = Dot == std::wstring::npos ? L"" : Value.substr(Dot + 1);
        const size_t NonZero = Whole.find_first_not_of(L'0');
        Whole = NonZero == std::wstring::npos ? L"0" : Whole.substr(NonZero);
        while (!Fraction.empty() && Fraction.back() == L'0')
            Fraction.pop_back();
    };

    std::wstring LeftWhole, LeftFraction, RightWhole, RightFraction;
    Split(Left, LeftWhole, LeftFraction);
    Split(Right, RightWhole, RightFraction);
    if (LeftWhole.size() != RightWhole.size())
        return LeftWhole.size() > RightWhole.size();
    if (LeftWhole != RightWhole)
        return LeftWhole > RightWhole;
    const size_t Digits = (std::max)(LeftFraction.size(), RightFraction.size());
    LeftFraction.resize(Digits, L'0');
    RightFraction.resize(Digits, L'0');
    return LeftFraction > RightFraction;
}

NTSTATUS h_CmRegisterCallbackEx(PVOID Function, PUNICODE_STRING Altitude, PVOID Driver,
    PVOID Context, PLARGE_INTEGER Cookie, PVOID Reserved) {
    if (!Driver || Reserved)
        return STATUS_INVALID_PARAMETER;
    return RegisterCmCallback(Function, Altitude, Driver, Context, Cookie, true);
}

NTSTATUS h_CmUnRegisterCallback(LARGE_INTEGER Cookie) {
    const uint64_t CookieValue = (uint64_t)Cookie.QuadPart;
    uc_engine* Engine = nullptr;
    {
        std::lock_guard<std::mutex> Guard(g_CmLock);
        auto It = std::find_if(g_CmCallbacks.begin(), g_CmCallbacks.end(),
            [CookieValue](const CmRegistration& Entry) { return Entry.Cookie == CookieValue; });
        if (It == g_CmCallbacks.end())
            return STATUS_INVALID_PARAMETER;
        Engine = It->Engine;
        g_CmCallbacks.erase(It);
    }
    CallbackRuntime::FreeGuest(Engine, CookieValue);
    return STATUS_SUCCESS;
}

NTSTATUS h_CmRegisterCallback(PVOID Function, PVOID Context, PLARGE_INTEGER Cookie) {
    return RegisterCmCallback(Function, nullptr, nullptr, Context, Cookie, false);
}

NTSTATUS CmCallbacks::Trigger(uc_engine* Engine, uint32_t NotifyClass,
    void* Argument2, size_t Argument2Size) {
    Engine = CallbackRuntime::SelectEngine(Engine);
    if (!Engine || (Argument2Size && !Argument2))
        return STATUS_INVALID_PARAMETER;

    std::vector<CmRegistration> Callbacks;
    {
        std::lock_guard<std::mutex> Guard(g_CmLock);
        Callbacks = g_CmCallbacks;
    }
    std::stable_sort(Callbacks.begin(), Callbacks.end(),
        [](const CmRegistration& Left, const CmRegistration& Right) {
            if (Left.Altitude == Right.Altitude)
                return Left.Sequence < Right.Sequence;
            if (Left.Altitude.empty())
                return false;
            if (Right.Altitude.empty())
                return true;
            return CallbackRuntime::AltitudePrecedes(Left.Altitude, Right.Altitude);
        });

    const uint64_t GuestArgument = Argument2Size
        ? CallbackRuntime::AllocateGuestCopy(Engine, Argument2, Argument2Size, "CmCallbackArgument")
        : 0;
    if (Argument2Size && !GuestArgument)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS Status = STATUS_SUCCESS;
    for (const auto& Entry : Callbacks) {
        const uint64_t Arguments[] = { Entry.Context, NotifyClass, GuestArgument };
        uint64_t Result = 0;
        if (!CallbackRuntime::InvokeGuest(Engine, Entry.Function, Arguments, 3, &Result)) {
            Status = (NTSTATUS)0xC0000001L;
            break;
        }
        Status = (NTSTATUS)Result;
        if (Status < 0)
            break;
    }

    if (GuestArgument) {
        if (!CallbackRuntime::ReadGuest(Engine, GuestArgument, Argument2, Argument2Size) &&
            Status >= 0)
            Status = STATUS_INVALID_PARAMETER;
        CallbackRuntime::FreeGuest(Engine, GuestArgument);
    }
    return Status;
}

size_t CmCallbacks::RegisteredCount() {
    std::lock_guard<std::mutex> Guard(g_CmLock);
    return g_CmCallbacks.size();
}
