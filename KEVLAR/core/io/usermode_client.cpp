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
#include <ctime>
#include <algorithm>

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
    bool FollowMode = false;
    int FollowIdleSec = 600;
    time_t LastLineTime = time(nullptr);
    for (;;) {
        if (!std::getline(F, Line)) {
            if (!FollowMode) break;
            if ((time(nullptr) - LastLineTime) > FollowIdleSec) {
                Logger::Log("{CYN}client: follow idle timeout (%ds), script done{RESET}\n", FollowIdleSec);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            F.clear();
            continue;
        }
        LastLineTime = time(nullptr);
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
        } else if (Op == "follow") {
            int Idle = 0; Is >> Idle;
            FollowMode = true;
            FollowIdleSec = (Idle > 0) ? Idle : 600;
            Logger::Log("{CYN}client: follow mode on (idle limit %ds){RESET}\n", FollowIdleSec);
        } else if (Op == "stop") {
            Logger::Log("{CYN}client: stop — exiting script loop{RESET}\n");
            FollowMode = false;
            break;
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
            auto* Fo = (_FILE_OBJECT*)UnicornMem::UcToHost(FileUc);
            if (Fo) {
                Logger::Log("{CYN}client: FILE_OBJECT fsctx=%p fsctx2=%p flags=0x%x access=R%d/W%d shared=R%d/W%d{RESET}\n",
                    Fo->FsContext, Fo->FsContext2, Fo->Flags,
                    Fo->ReadAccess ? 1 : 0, Fo->WriteAccess ? 1 : 0,
                    Fo->SharedRead ? 1 : 0, Fo->SharedWrite ? 1 : 0);
            }
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
        } else if (Op == "eacio") {
            // eacio <keymode:1|2> <plain_hex|-> <outlen>
            // Encrypt after guest METHOD_NEITHER allocation so the XTEA key
            // uses the exact Type3InputBuffer address observed by EAC.
            if (!DevUc || !FileUc) { Logger::Log("{RED}client: eacio without open{RESET}\n"); continue; }
            int Mode = 1; std::string InHex; ULONG OutLen = 0;
            Is >> Mode >> InHex >> OutLen;
            std::vector<uint8_t> In;
            if (InHex != "-" && !InHex.empty()) In = ParseHex(InHex);
            if (In.empty()) In.resize(8, 0);
            In.resize((In.size() + 7) & ~7ULL, 0);
            std::vector<uint8_t> Out(OutLen ? OutLen : 512, 0);
            ULONG Returned = 0;
            if (Mode < 1 || Mode > 5) Mode = 1;
            IoManager::SetEacXteaMode(Mode);
            auto R = IoManager::DispatchDeviceIoControl(DevUc, FileUc, 0x22DD03,
                In.data(), (ULONG)In.size(), Out.data(), (ULONG)Out.size(), &Returned);
            IoManager::SetEacXteaMode(0);
            Logger::Log("{GRN}client: EACIO mode=%d -> 0x%08x ret=%u out=%s{RESET}\n",
                Mode, (unsigned)R.Status, Returned,
                HexDump(Out.data(), Returned > 96 ? 96 : Returned).c_str());
        } else if (Op == "eaczeros") {
            // eaczeros <keymode:1..5> <input_len> <outlen>
            if (!DevUc || !FileUc) { Logger::Log("{RED}client: eaczeros without open{RESET}\n"); continue; }
            int Mode = 5; ULONG InLen = 64, OutLen = 512;
            Is >> Mode >> InLen >> OutLen;
            if (InLen < 8) InLen = 8;
            if (InLen > 0x100000) InLen = 0x100000;
            InLen = (InLen + 7) & ~7u;
            if (Mode < 1 || Mode > 5) Mode = 5;
            std::vector<uint8_t> In(InLen, 0), Out(OutLen ? OutLen : InLen, 0);
            ULONG Returned = 0;
            IoManager::SetEacXteaMode(Mode);
            auto R = IoManager::DispatchDeviceIoControl(DevUc, FileUc, 0x22DD03,
                In.data(), (ULONG)In.size(), Out.data(), (ULONG)Out.size(), &Returned);
            IoManager::SetEacXteaMode(0);
            Logger::Log("{GRN}client: EACZEROS mode=%d len=%u -> 0x%08x ret=%u out=%s{RESET}\n",
                Mode, InLen, (unsigned)R.Status, Returned,
                HexDump(Out.data(), Returned > 96 ? 96 : Returned).c_str());
        } else if (Op == "eacsweep") {
            // eacsweep <keymode:1..4> <field_off> <value_lo> <value_hi>
            //          <packet_len> <outlen> <wait_ms>
            // Varies one plaintext dword, XTEA-encrypts after guest allocation,
            // then dispatches 0x22DD03. Icount outliers identify accepted fields.
            if (!DevUc || !FileUc) { Logger::Log("{RED}client: eacsweep without open{RESET}\n"); continue; }
            int Mode = 3, WaitMs = 2000;
            ULONG FieldOff = 0, Lo = 0, Hi = 0, PacketLen = 0x40, OutLen = 512;
            Is >> Mode >> FieldOff >> Lo >> Hi >> PacketLen >> OutLen >> WaitMs;
            if (PacketLen < FieldOff + 4) PacketLen = FieldOff + 4;
            PacketLen = (PacketLen + 7) & ~7u;
            if (Hi < Lo || Hi - Lo > 0x1000) {
                Logger::Log("{RED}client: eacsweep invalid range{RESET}\n");
                continue;
            }
            std::vector<uint8_t> In(PacketLen, 0), Out(OutLen ? OutLen : 512, 0);
            IoManager::SetIoctlWaitMs((DWORD)WaitMs);
            Logger::Log("{CYN}client: eacsweep mode=%d off=0x%x val=0x%x-0x%x len=0x%x out=%u{RESET}\n",
                Mode, FieldOff, Lo, Hi, PacketLen, OutLen);
            uint32_t Timeouts = 0;
            for (ULONG V = Lo; V <= Hi; V++) {
                std::fill(In.begin(), In.end(), (uint8_t)0);
                memcpy(In.data() + FieldOff, &V, sizeof(V));
                std::fill(Out.begin(), Out.end(), (uint8_t)0);
                ULONG Returned = 0;
                IoManager::SetEacXteaMode(Mode);
                auto R = IoManager::DispatchDeviceIoControl(DevUc, FileUc, 0x22DD03,
                    In.data(), (ULONG)In.size(), Out.data(), (ULONG)Out.size(), &Returned);
                IoManager::SetEacXteaMode(0);
                if (R.TimedOut) {
                    Timeouts++;
                    Logger::Log("{YEL}eacsweep off=0x%x val=0x%x -> TIMEOUT status=0x%08x{RESET}\n",
                        FieldOff, V, (unsigned)R.Status);
                    if (Timeouts >= 16) break;
                } else {
                    Logger::Log("eacsweep off=0x%x val=0x%x -> 0x%08x ret=%u %s{RESET}\n",
                        FieldOff, V, (unsigned)R.Status, Returned,
                        Returned ? HexDump(Out.data(), Returned > 48 ? 48 : Returned).c_str() : "");
                }
            }
            IoManager::SetEacXteaMode(0);
            IoManager::SetIoctlWaitMs(0);
            Logger::Log("{CYN}client: eacsweep done timeouts=%u{RESET}\n", Timeouts);
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
        } else if (Op == "dumpdev") {
            // dumpdev <len>: dump selected device extension for active-state diffing.
            ULONG Len = 0x200; Is >> Len;
            const DeviceTracker::DeviceInfo* Info = nullptr;
            size_t N = DeviceTracker::GetCount();
            for (size_t I = 0; I < N; I++) {
                auto* D = DeviceTracker::GetByIndex(I);
                if (D && D->UcAddr == DevUc) { Info = D; break; }
            }
            if (!Info || !Info->ExtensionUcAddr) {
                Logger::Log("{YEL}client: dumpdev selected device has no extension{RESET}\n");
                continue;
            }
            if (!Len || Len > Info->ExtensionSize) Len = Info->ExtensionSize;
            std::vector<uint8_t> Buf(Len, 0);
            auto* Host = UnicornMem::UcToHost(Info->ExtensionUcAddr);
            if (Host) memcpy(Buf.data(), Host, Len);
            else uc_mem_read(UnicornEmu::PrimaryEngine, Info->ExtensionUcAddr, Buf.data(), Len);
            Logger::Log("{GRN}client: dumpdev ext=0x%llx len=0x%x -> %s{RESET}\n",
                (unsigned long long)Info->ExtensionUcAddr, Len,
                HexDump(Buf.data(), Buf.size() > 256 ? 256 : Buf.size()).c_str());
        } else if (Op == "sweep") {
            // sweep <devtype_hex> <access> <fn_lo> <fn_hi> <method> <outlen> <in_hex|-> <wait_ms>
            std::string DevS, InHex;
            ULONG Acc = 0, FnLo = 0, FnHi = 0, Mth = 0, OutLen = 0;
            int WaitMs = 2000;
            Is >> DevS >> Acc >> FnLo >> FnHi >> Mth >> OutLen >> InHex >> WaitMs;
            ULONG Dev = (ULONG)strtoul(DevS.c_str(), nullptr, 16);
            if (!DevUc || !FileUc) { Logger::Log("{RED}client: sweep without open{RESET}\n"); continue; }
            std::vector<uint8_t> In;
            if (InHex != "-" && !InHex.empty()) In = ParseHex(InHex);
            std::vector<uint8_t> Out(OutLen ? OutLen : 64, 0);
            IoManager::SetIoctlWaitMs((DWORD)WaitMs);
            uint32_t Timeouts = 0, Done = 0;
            Logger::Log("{CYN}client: sweep dev=0x%x acc=%u fn=0x%x-0x%x mth=%u out=%u wait=%dms{RESET}\n",
                Dev, Acc, FnLo, FnHi, Mth, OutLen, WaitMs);
            for (ULONG Fn = FnLo; Fn <= FnHi && FnHi - FnLo < 0x2000; Fn++) {
                ULONG Code = (Dev << 16) | (Acc << 14) | (Fn << 2) | (Mth & 3);
                ULONG Returned = 0;
                std::fill(Out.begin(), Out.end(), (uint8_t)0);
                auto R = IoManager::DispatchDeviceIoControl(DevUc, FileUc, Code,
                    In.empty() ? nullptr : In.data(), (ULONG)In.size(),
                    Out.data(), (ULONG)Out.size(), &Returned);
                Done++;
                if (R.TimedOut) {
                    Timeouts++;
                    Logger::Log("{YEL}sweep 0x%08x -> TIMEOUT status=0x%08x{RESET}\n", Code, (unsigned)R.Status);
                    if (Timeouts >= 16) { Logger::Log("{RED}client: sweep aborting after 16 timeouts{RESET}\n"); break; }
                } else {
                    std::string Hx = Returned ? HexDump(Out.data(), Returned > 32 ? 32 : Returned) : "";
                    Logger::Log("sweep 0x%08x -> 0x%08x ret=%u %s{RESET}\n", Code, (unsigned)R.Status, Returned, Hx.c_str());
                }
            }
            IoManager::SetIoctlWaitMs(0);
            Logger::Log("{CYN}client: sweep done n=%u timeouts=%u{RESET}\n", Done, Timeouts);
        } else if (Op == "sweepall") {
            // sweepall <access> <fn_lo> <fn_hi> <method> <outlen> <wait_ms>
            // Runs the grid against EVERY tracked device using each device's own
            // type (comm device names are randomized; can't preselect by name).
            // Restores the previously selected device/file on exit.
            ULONG Acc = 0, FnLo = 0, FnHi = 0, Mth = 0, OutLen = 64;
            int WaitMs = 2000;
            Is >> Acc >> FnLo >> FnHi >> Mth >> OutLen >> WaitMs;
            uint64_t SaveDev = DevUc, SaveFile = FileUc;
            if (SaveFile) {
                IoManager::DispatchClose(SaveDev, SaveFile);
                IoManager::FreeFileObject(SaveFile);
                FileUc = 0;
            }
            IoManager::SetIoctlWaitMs((DWORD)WaitMs);
            size_t N = DeviceTracker::GetCount();
            uint32_t Grand = 0, GrandTo = 0;
            for (size_t K = 0; K < N; K++) {
                auto* Info = DeviceTracker::GetByIndex(K);
                if (!Info) continue;
                ULONG Dev = Info->DeviceType ? Info->DeviceType : 0x22;
                uint64_t F = IoManager::AllocateFileObject(UnicornEmu::PrimaryEngine, Info->UcAddr);
                auto CR = IoManager::DispatchCreate(Info->UcAddr, F);
                if (CR.Status != 0) {
                    Logger::Log("{YEL}sweepall: create on %ls -> 0x%08x, skipping{RESET}\n",
                        Info->DeviceName.c_str(), (unsigned)CR.Status);
                    IoManager::FreeFileObject(F);
                    continue;
                }
                Logger::Log("{CYN}sweepall dev=%ls type=0x%x acc=%u fn=0x%x-0x%x mth=%u out=%u{RESET}\n",
                    Info->DeviceName.c_str(), Dev, Acc, FnLo, FnHi, Mth, OutLen);
                std::vector<uint8_t> Out(OutLen ? OutLen : 64, 0);
                uint32_t To = 0, Dn = 0;
                for (ULONG Fn = FnLo; Fn <= FnHi && FnHi - FnLo < 0x2000; Fn++) {
                    ULONG Code = (Dev << 16) | (Acc << 14) | (Fn << 2) | (Mth & 3);
                    ULONG Returned = 0;
                    std::fill(Out.begin(), Out.end(), (uint8_t)0);
                    auto R = IoManager::DispatchDeviceIoControl(Info->UcAddr, F, Code,
                        nullptr, 0, Out.data(), (ULONG)Out.size(), &Returned);
                    Dn++;
                    if (R.TimedOut) {
                        To++;
                        Logger::Log("{YEL}sweepall 0x%08x -> TIMEOUT status=0x%08x{RESET}\n", Code, (unsigned)R.Status);
                        if (To >= 16) { Logger::Log("{RED}sweepall: aborting device after 16 timeouts{RESET}\n"); break; }
                    } else {
                        std::string Hx = Returned ? HexDump(Out.data(), Returned > 32 ? 32 : Returned) : "";
                        Logger::Log("sweepall 0x%08x -> 0x%08x ret=%u %s{RESET}\n", Code, (unsigned)R.Status, Returned, Hx.c_str());
                    }
                }
                Grand += Dn; GrandTo += To;
                IoManager::DispatchClose(Info->UcAddr, F);
                IoManager::FreeFileObject(F);
            }
            IoManager::SetIoctlWaitMs(0);
            DevUc = SaveDev;
            FileUc = 0;  // saved file object was closed above; script must re-open
            Logger::Log("{CYN}client: sweepall done n=%u timeouts=%u{RESET}\n", Grand, GrandTo);
        } else if (Op == "probe") {
            std::string A, B; Is >> A >> B;
            UnicornEmu::DispatchProbeA = (A == "-" || A.empty()) ? 0 : strtoull(A.c_str(), nullptr, 16);
            UnicornEmu::DispatchProbeB = (B == "-" || B.empty()) ? 0 : strtoull(B.c_str(), nullptr, 16);
            UnicornEmu::ProbeEnginesOnly = true;
            Logger::Log("{CYN}client: probe A=0x%llx B=0x%llx (engines created after this see it){RESET}\n",
                (unsigned long long)UnicornEmu::DispatchProbeA, (unsigned long long)UnicornEmu::DispatchProbeB);
        } else if (Op == "ptrace") {
            std::string A, B; Is >> A >> B;
            UnicornEmu::PerThreadTraceStart = (A == "-") ? 0 : strtoull(A.c_str(), nullptr, 16);
            UnicornEmu::PerThreadTraceEnd = (B == "-") ? 0 : strtoull(B.c_str(), nullptr, 16);
            UnicornEmu::ProbeEnginesOnly = true;
            Logger::Log("{CYN}client: per-thread trace window 0x%llx-0x%llx{RESET}\n",
                (unsigned long long)UnicornEmu::PerThreadTraceStart, (unsigned long long)UnicornEmu::PerThreadTraceEnd);
        } else if (Op == "dumpfile") {
            // dumpfile <hexucaddr> <len[dec or 0x-hex]> <path> — bulk raw extract of guest memory
            std::string A, L, Path;
            Is >> A >> L >> Path;
            if (Path.empty()) { Logger::Log("{RED}client: dumpfile needs addr len path{RESET}\n"); continue; }
            uint64_t Addr = strtoull(A.c_str(), nullptr, 16);
            uint64_t Len = strtoull(L.c_str(), nullptr, 0);
            if (!Len) Len = 0x1000;
            std::ofstream Of(Path, std::ios::binary);
            if (!Of) { Logger::Log("{RED}client: dumpfile cannot open %s{RESET}\n", Path.c_str()); continue; }
            uint64_t Done = 0, Miss = 0;
            std::vector<uint8_t> Page(0x1000);
            while (Done < Len) {
                uint64_t Chunk = std::min<uint64_t>(0x1000, Len - Done);
                uint64_t Cur = Addr + Done;
                void* Host = UnicornMem::UcToHost(Cur);
                bool Ok = false;
                if (Host) {
                    memcpy(Page.data(), Host, (size_t)Chunk);
                    Ok = true;
                } else {
                    uc_err E = uc_mem_read(UnicornEmu::PrimaryEngine, Cur, Page.data(), (size_t)Chunk);
                    if (E == UC_ERR_OK) Ok = true;
                }
                if (!Ok) {
                    // salvage per 8-byte slot across partial unmapping
                    uint64_t Got = 0;
                    while (Got < Chunk) {
                        uint64_t Slot = std::min<uint64_t>(8, Chunk - Got);
                        if (uc_mem_read(UnicornEmu::PrimaryEngine, Cur + Got, Page.data() + Got, (size_t)Slot) != UC_ERR_OK)
                            std::fill(Page.begin() + Got, Page.begin() + Got + Slot, (uint8_t)0xFF);
                        Got += Slot;
                    }
                    Miss += Chunk;
                }
                Of.write((const char*)Page.data(), (std::streamsize)Chunk);
                Done += Chunk;
            }
            Of.close();
            Logger::Log("{GRN}client: dumpfile 0x%llx len=0x%llx -> %s (%llu unmapped){RESET}\n",
                (unsigned long long)Addr, (unsigned long long)Len, Path.c_str(), (unsigned long long)Miss);
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
