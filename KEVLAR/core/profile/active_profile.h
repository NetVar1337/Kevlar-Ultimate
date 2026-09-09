#pragma once

#include "core/profile/windows_build_profile.h"

namespace Kevlar::Profile {

[[nodiscard]] const WindowsBuildProfile& Active() noexcept;
[[nodiscard]] bool ActivateBuild(std::uint32_t BuildNumber, ValidationResult* Validation = nullptr);
[[nodiscard]] bool ActivateName(std::string_view Name, ValidationResult* Validation = nullptr);
[[nodiscard]] bool ActivateOverride(std::string_view JsonText, ValidationResult* Validation = nullptr);

} // namespace Kevlar::Profile
