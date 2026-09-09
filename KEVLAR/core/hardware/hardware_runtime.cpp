#include "core/hardware/hardware_runtime.h"

#include <memory>
#include <mutex>

namespace Kevlar::Hardware {
namespace {
std::mutex RuntimeLock;
std::unique_ptr<HardwareProfile> Runtime = HardwareProfile::CreateRaptorLake(0x4B45564C4152ULL, 0);
}

HardwareProfile& ActiveHardware() {
    return *Runtime;
}

void ResetActiveHardware(std::uint64_t Seed, std::uint64_t VirtualTime) {
    auto Replacement = HardwareProfile::CreateRaptorLake(Seed, VirtualTime);
    std::lock_guard<std::mutex> Guard(RuntimeLock);
    Runtime = std::move(Replacement);
}

} // namespace Kevlar::Hardware
