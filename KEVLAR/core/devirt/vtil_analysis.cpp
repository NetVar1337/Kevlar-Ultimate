#include "core/devirt/vtil_analysis.h"
#include <windows.h>
#include <Logger/Logger.h>
#include <algorithm>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>

namespace {

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

} // namespace

bool VtilAnalysis::LiftImageRegion(const uint8_t* image, size_t imageSize, const Options& options) {
    if (!image || !options.Size || options.Rva >= imageSize ||
        options.InputPath.empty() || options.OutputPath.empty()) {
        Logger::Log("{RED}VTIL: invalid lift options{RESET}\n");
        return false;
    }

    wchar_t executable[MAX_PATH] {};
    DWORD length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
    if (!length || length == MAX_PATH) {
        Logger::Log("{RED}VTIL: cannot determine exe directory{RESET}\n");
        return false;
    }
    std::wstring host(executable, length);
    auto slash = host.find_last_of(L"\\/");
    host = host.substr(0, slash + 1) + L"kevlar-vtil-host.ps1";

    // The caller passes a buffer that is already section-mapped by PEMapper
    // (sections live at their virtual addresses), which is exactly the layout the
    // lifter indexes by RVA. Write it through verbatim. Re-mapping it here from the
    // PE section table corrupted the input: the table's raw offsets describe the
    // on-disk file, not this buffer, so most of the image came out zeroed.
    std::wstring staged = host.substr(0, slash + 1) + L"kevlar-vtil-image.bin";
    {
        std::ofstream out(staged, std::ios::binary | std::ios::trunc);
        if (!out) {
            Logger::Log("{RED}VTIL: cannot stage mapped image{RESET}\n");
            return false;
        }
        out.write((const char*)image, (std::streamsize)imageSize);
        if (!out) {
            Logger::Log("{RED}VTIL: cannot write staged image{RESET}\n");
            return false;
        }
    }

    // Build argv-style command line: powershell.exe -NoProfile -ExecutionPolicy Bypass
    //   -File <host.ps1> -InputPath <path> -Rva <rva> -Size <size> -OutputPath <out>
    auto QuoteW = [](const std::wstring& s) { return L"\"" + s + L"\""; };
    std::wstringstream Cmd;
    Cmd << L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
        << QuoteW(host)
        << L" -InputPath " << QuoteW(staged)
        << L" -Rva " << options.Rva
        << L" -Size " << options.Size
        << L" -OutputPath " << QuoteW(Utf8ToWide(options.OutputPath));
    std::wstring CmdLine = Cmd.str();

    // Pipe stderr for capture
    HANDLE StderrRead = nullptr, StderrWrite = nullptr;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), nullptr, TRUE };
    CreatePipe(&StderrRead, &StderrWrite, &Sa, 0);
    SetHandleInformation(StderrRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW Si = {};
    Si.cb = sizeof(Si);
    Si.dwFlags = STARTF_USESTDHANDLES;
    Si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    Si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    Si.hStdError  = StderrWrite;

    PROCESS_INFORMATION Pi = {};
    BOOL Ok = CreateProcessW(
        nullptr, CmdLine.data(),
        nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &Si, &Pi);
    CloseHandle(StderrWrite);
    if (!Ok) {
        CloseHandle(StderrRead);
        Logger::Log("{RED}VTIL: CreateProcessW failed (error %u){RESET}\n", GetLastError());
        return false;
    }

    constexpr DWORD kTimeoutMs = 5 * 60 * 1000;
    DWORD Wait = WaitForSingleObject(Pi.hProcess, kTimeoutMs);
    if (Wait == WAIT_TIMEOUT) {
        TerminateProcess(Pi.hProcess, 1);
        CloseHandle(Pi.hProcess);
        CloseHandle(Pi.hThread);
        CloseHandle(StderrRead);
        Logger::Log("{RED}VTIL: host timed out after 5 minutes{RESET}\n");
        return false;
    }

    DWORD ExitCode = 1;
    GetExitCodeProcess(Pi.hProcess, &ExitCode);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);

    // Drain stderr
    std::string ErrOut;
    char Buf[4096];
    DWORD Read = 0;
    while (ReadFile(StderrRead, Buf, sizeof(Buf) - 1, &Read, nullptr) && Read > 0) {
        Buf[Read] = '\0';
        ErrOut += Buf;
    }
    CloseHandle(StderrRead);

    if (ExitCode != 0) {
        Logger::Log("{RED}VTIL: host exited %u{RESET}\n", ExitCode);
        if (!ErrOut.empty())
            Logger::Log("{RED}VTIL stderr:\n%s{RESET}\n", ErrOut.c_str());
        return false;
    }

    Logger::Log("{GRN}VTIL: serialized bounded lift RVA 0x%llx size 0x%llx to {WHT}%s{RESET}\n",
        options.Rva, options.Size, options.OutputPath.c_str());
    return true;
}
