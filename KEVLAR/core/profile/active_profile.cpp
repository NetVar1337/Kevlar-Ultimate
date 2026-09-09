#include "core/profile/active_profile.h"

#include <mutex>

namespace Kevlar::Profile {
namespace {
std::mutex ProfileLock;
WindowsBuildProfile ActiveProfile = *SelectByBuild(26200);

bool Activate(const WindowsBuildProfile* Profile, ValidationResult* OutValidation) {
    ValidationResult Result;
    if (!Profile) {
        Result.Diagnostics.push_back({
            DiagnosticCode::MissingKey, "$profile", "requested build profile was not found"});
    } else {
        Result = Validate(*Profile);
    }
    if (OutValidation)
        *OutValidation = Result;
    if (!Profile || !Result.Ok())
        return false;

    std::lock_guard<std::mutex> Guard(ProfileLock);
    ActiveProfile = *Profile;
    return true;
}
}

const WindowsBuildProfile& Active() noexcept {
    return ActiveProfile;
}

bool ActivateBuild(std::uint32_t BuildNumber, ValidationResult* Validation) {
    return Activate(SelectByBuild(BuildNumber), Validation);
}

bool ActivateName(std::string_view Name, ValidationResult* Validation) {
    return Activate(SelectByName(Name), Validation);
}

bool ActivateOverride(std::string_view JsonText, ValidationResult* Validation) {
    auto Override = LoadOverride(JsonText);
    if (Validation)
        *Validation = Override.Validation;
    if (!Override.Ok())
        return false;
    return Activate(&*Override.Profile, Validation);
}

} // namespace Kevlar::Profile
