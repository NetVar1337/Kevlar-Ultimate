#pragma once

#include "core/hardware/hardware_profile.h"

namespace Kevlar::Hardware {

HardwareProfile& ActiveHardware();
void ResetActiveHardware(std::uint64_t Seed = 0x4B45564C4152ULL, std::uint64_t VirtualTime = 0);

} // namespace Kevlar::Hardware
