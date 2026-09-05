#include "core/io/usermode_client.h"
#include "core/memory/unicorn_memory.h"
#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "api/io/io_device.h"
#include "core/io/io_manager.h"
#include <unicorn/unicorn.h>
#include <Logger/Logger.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>

static std::vector<uint8_t> ParseHex(const std::string& S) {
    std::vector<uint8_t> Out;
    for (size_t I = 0; I + 1 < S.size(); I += 2) {
        auto V = [](char C) -> int {
            if (C >= '0' && C <= '9') return C - '0';
            if (C >= 'a' && C <= 'f') return C - 'a' + 10;
            if (C >= 'A' && C <= 'F') return C - 'A' + 10;
            return -1;
        };
        int H = V(S[I]), L = V(S[I + 1]);
        if (H < 0 || L < 0) break;
        Out.push_back((uint8_t)((H << 4) | L));
    }
    return Out;
}

static std::string HexDump(const uint8_t* P, size_t N) {
    std::string S;
    char Buf[8];
    for (size_t I = 0; I < N; I++) {
        snprintf(Buf, sizeof(Buf), "%02x", P[I]);
        S += Buf;
    }
    return S;
}

namespace UsermodeClient {

bool RunScript(const std::string& ScriptPath, int DelaySeconds) {
    std::ifstream F(ScriptPath);
    if (!F) {
        Logger::Log("{RED}client: cannot open script %s{RESET}\n", ScriptPath.c_str());
        return false;
    }
    if (DelaySeconds > 0) {
        Logger::Log("{CYN}client: waiting %ds for driver init before user-mode ops{RESET}\n", DelaySeconds);
        std::this_thread::sleep_for(std::chrono::seconds(DelaySeconds));
    }

    uint64_t DevUc = 0;
    uint64_t FileUc = 0;
    std::string Line;
    while (std::getline(F, Line)) {
        auto Hash = Line.find('#');
        if (Hash != std::string::npos) Line = Line.substr(0, Hash);
        std::istringstream Is(Line);
        std::string Op;
        Is >> Op;
        if (Op.empty()) continue;

        if (Op == "list") {
            size_t N = DeviceTracker::GetCount();
            Logger::Log("{GRN}client: %zu device(s){RESET}\n", N);
            for (size_t I = 0; I < N; I++) {
                auto* Info = DeviceTracker::GetByIndex(I);
                if (!Info) continue;
                Logger::Log("  [%zu] uc=0x%llx name=%ls type=0x%x{RESET}\n",
                    I, (unsigned long long)Info->UcAddr, Info->DeviceName.c_str(), Info->DeviceType);
            }
        } else if (Op == "wait") {
            int Sec = 0; Is >> Sec;
            std::this_thread::sleep_for(std::chrono::seconds(Sec));
        } else if (Op == "select") {
            std::string Arg; Is >> Arg;
            bool IsIdx = !Arg.empty() && Arg[0] >= '0' && Arg[0] <= '9';
            if (IsIdx && Arg.size() > 2 && Arg[1] == 'x') IsIdx = false;
            uint64_t Found = 0;
            if (IsIdx) {
                auto* Info = DeviceTracker::GetByIndex((size_t)strtoull(Arg.c_str(), nullptr, 10));
                if (Info) Found = Info->UcAddr;
            } else {
                std::wstring W;
                for (size_t I = 0; I < Arg.size(); I++) W += (wchar_t)(unsigned char)Arg[I];
                size_t N = DeviceTracker::GetCount();
                for (size_t I = 0; I < N; I++) {
                    auto* Info = DeviceTracker::GetByIndex(I);
                    if (Info && Info->DeviceName.find(W) != std::wstring::npos) { Found = Info->UcAddr; break; }
                }
                if (!Found) {
                    std::wstring Full = L"\\Device\\" + W;
                    Found = DeviceTracker::FindByName(Full);
                }
            }
            DevUc = Found;
            Logger::Log("{CYN}client: select %s -> uc=0x%llx{RESET}\n", Arg.c_str(), (unsigned long long)DevUc);
        } else if (Op == "open") {
            if (!DevUc) { Logger::Log("{RED}client: open without device{RESET}\n"); continue; }
            FileUc = IoManager::AllocateFileObject(UnicornEmu::PrimaryEngine, DevUc);
            auto R = IoManager::DispatchCreate(DevUc, FileUc);
            Logger::Log("{GRN}client: CreateFile -> 0x%08x info=0x%llx{RESET}\n", (unsigned)R.Status, (unsigned long long)R.Information);
            if (R.Status != 0) { IoManager::FreeFileObject(FileUc); FileUc = 0; }
        } else if (Op == "close") {
            if (!DevUc || !FileUc) { Logger::Log("{RED}client: close without open{RESET}\n"); continue; }
            auto R = IoManager::DispatchClose(DevUc, FileUc);
            IoManager::FreeFileObject(FileUc);
            FileUc = 0;
            Logger::Log("{GRN}client: CloseFile -> 0x%08x{RESET}\n", (unsigned)R.Status);
        } else if (Op == "ioctl") {
            if (!DevUc || !FileUc) { Logger::Log("{RED}client: ioctl without open{RESET}\n"); continue; }
            std::string Code, InHex; ULONG OutLen = 0;
            Is >> Code >> InHex >> OutLen;
            ULONG In0 = 0; ULONG In1 = 0;
            sscanf(Code.c_str(), "%lx", &In0);
            sscanf(Code.c_str(), "%x", &In1);
            auto CodeVal = In0 ? In0 : In1;
            std::vector<uint8_t> In;
            if (InHex != "-" && !InHex.empty()) In = ParseHex(InHex);
            std::vector<uint8_t> Out(OutLen ? OutLen : 4096, 0);
            ULONG Returned = 0;
            auto R = IoManager::DispatchDeviceIoControl(DevUc, FileUc, CodeVal,
                In.empty() ? nullptr : In.data(), (ULONG)In.size(),
                Out.empty() ? nullptr : Out.data(), (ULONG)Out.size(), &Returned);
            Logger::Log("{GRN}client: IOCTL 0x%08x -> 0x%08x ret=%u out=%s{RESET}\n",
                CodeVal, (unsigned)R.Status, Returned, HexDump(Out.data(), Returned > 96 ? 96 : Returned).c_str());
        } else if (Op == "read") {
            if (!DevUc || !FileUc) { Logger::Log("{RED}client: read without open{RESET}\n"); continue; }
            ULONG Len = 0, Off = 0; Is >> Len >> Off;
            std::vector<uint8_t> Out(Len ? Len : 256, 0);
            ULONG Got = 0;
            auto R = IoManager::DispatchRead(DevUc, FileUc, Out.data(), (ULONG)Out.size(), Off, &Got);
            Logger::Log("{GRN}client: READ -> 0x%08x got=%u data=%s{RESET}\n",
                (unsigned)R.Status, Got, HexDump(Out.data(), Got > 96 ? 96 : Got).c_str());
        } else if (Op == "write") {
            if (!DevUc || !FileUc) { Logger::Log("{RED}client: write without open{RESET}\n"); continue; }
            std::string InHex; ULONG Off = 0; Is >> InHex >> Off;
            auto In = ParseHex(InHex);
            ULONG Put = 0;
            auto R = IoManager::DispatchWrite(DevUc, FileUc, In.data(), (ULONG)In.size(), Off, &Put);
            Logger::Log("{GRN}client: WRITE -> 0x%08x put=%u{RESET}\n", (unsigned)R.Status, Put);
        } else if (Op == "dump") {
            uint64_t Addr = 0; ULONG Len = 0;
            std::string A; Is >> A >> Len;
            Addr = strtoull(A.c_str(), nullptr, 16);
            std::vector<uint8_t> Buf(Len ? Len : 64, 0);
            auto Host = UnicornMem::UcToHost(Addr);
            if (Host) {
                memcpy(Buf.data(), Host, Buf.size());
                Logger::Log("{GRN}client: dump 0x%llx len=%u -> %s{RESET}\n",
                    (unsigned long long)Addr, Len, HexDump(Buf.data(), Buf.size() > 96 ? 96 : Buf.size()).c_str());
            } else {
                uc_err E = uc_mem_read(UnicornEmu::PrimaryEngine, Addr, Buf.data(), Buf.size());
                Logger::Log("{GRN}client: dump 0x%llx (uc) err=%d -> %s{RESET}\n",
                    (unsigned long long)Addr, (int)E, HexDump(Buf.data(), Buf.size() > 96 ? 96 : Buf.size()).c_str());
            }
        } else {
            Logger::Log("{YEL}client: unknown op '%s'{RESET}\n", Op.c_str());
        }
        if (Line.size() > 512) break;
    }
    if (FileUc && DevUc) { IoManager::DispatchClose(DevUc, FileUc); IoManager::FreeFileObject(FileUc); }
    Logger::Log("{GRN}client: script finished{RESET}\n");

    return true;
}

}
