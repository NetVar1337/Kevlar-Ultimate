#pragma once

#include <cstdint>
#include <unicorn/unicorn.h>

namespace TargetCompat {

bool InstallFaceitAc20260908(uc_engine* Engine, std::uint64_t DriverBase, std::uint64_t DriverSize);

} // namespace TargetCompat
