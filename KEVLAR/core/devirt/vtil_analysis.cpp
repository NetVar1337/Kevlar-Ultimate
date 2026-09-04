#include "core/devirt/vtil_analysis.h"

#include <cstdlib>
#include <windows.h>

#include <Logger/Logger.h>

namespace {

std::string Quote(const std::string& value) {
    return "\"" + value + "\"";
}

} // namespace

bool VtilAnalysis::LiftImageRegion(const uint8_t* image, size_t imageSize, const Options& options) {
    if (!image || !options.Size || options.Rva >= imageSize || options.InputPath.empty() || options.OutputPath.empty()) {
        Logger::Log("{RED}VTIL: invalid lift options{RESET}\n");
        return false;
    }

    char executable[MAX_PATH] {};
    const DWORD length = GetModuleFileNameA(nullptr, executable, sizeof(executable));
    if (!length || length == sizeof(executable)) {
        Logger::Log("{RED}VTIL: unable to determine executable directory{RESET}\n");
        return false;
    }

    std::string host(executable, length);
    host.erase(host.find_last_of("\\/") + 1);
    host += "kevlar-vtil-host.ps1";
    const std::string command =
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File " + Quote(host) +
        " -InputPath " + Quote(options.InputPath) +
        " -Rva " + std::to_string(options.Rva) +
        " -Size " + std::to_string(options.Size) +
        " -OutputPath " + Quote(options.OutputPath);
    if (std::system(command.c_str()) != 0) {
        Logger::Log("{RED}VTIL: host failed{RESET}\n");
        return false;
    }

    Logger::Log("{GRN}VTIL: serialized bounded lift RVA 0x%llx size 0x%llx to {WHT}%s{RESET}\n",
        options.Rva, options.Size, options.OutputPath.c_str());
    return true;
}
