#include "framework_provider.h"

#include <algorithm>
#include <limits>
#include <mutex>

namespace Kevlar::Host::Frameworks {

Status FrameworkRegistry::Register(std::shared_ptr<FrameworkProvider> Provider) {
    if (!Provider || Provider->Name().empty()) return Status::InvalidArgument;
    const std::string Name(Provider->Name());
    std::unique_lock Lock(Mutex_);
    const auto It = std::lower_bound(Providers_.begin(), Providers_.end(), Name,
        [](const Entry& EntryValue, const std::string& Value) {
            return EntryValue.Name < Value;
        });
    if (It != Providers_.end() && It->Name == Name) return Status::Duplicate;
    Providers_.insert(It, Entry{Name, std::move(Provider)});
    return Status::Success;
}

Status FrameworkRegistry::Unregister(std::string_view Name) {
    if (Name.empty()) return Status::InvalidArgument;
    std::unique_lock Lock(Mutex_);
    const auto It = std::lower_bound(Providers_.begin(), Providers_.end(), Name,
        [](const Entry& EntryValue, std::string_view Value) {
            return EntryValue.Name < Value;
        });
    if (It == Providers_.end() || It->Name != Name) return Status::InvalidHandle;
    Providers_.erase(It);
    return Status::Success;
}

std::shared_ptr<FrameworkProvider> FrameworkRegistry::Find(std::string_view Name) const {
    std::shared_lock Lock(Mutex_);
    const auto It = std::lower_bound(Providers_.begin(), Providers_.end(), Name,
        [](const Entry& EntryValue, std::string_view Value) {
            return EntryValue.Name < Value;
        });
    return It != Providers_.end() && It->Name == Name ? It->Provider : nullptr;
}

std::vector<CapabilityReport> FrameworkRegistry::Capabilities() const {
    std::shared_lock Lock(Mutex_);
    std::vector<CapabilityReport> Result;
    Result.reserve(Providers_.size());
    for (const auto& EntryValue : Providers_) Result.push_back(EntryValue.Provider->Capabilities());
    return Result;
}

FrameworkRegistrySnapshot FrameworkRegistry::Snapshot() const {
    std::shared_lock Lock(Mutex_);
    FrameworkRegistrySnapshot Result;
    Result.Providers.reserve(Providers_.size());
    for (const auto& EntryValue : Providers_) Result.Providers.push_back(EntryValue.Provider->CaptureState());
    return Result;
}

Status FrameworkRegistry::Restore(const FrameworkRegistrySnapshot& SnapshotValue) {
    std::unique_lock Lock(Mutex_);
    if (SnapshotValue.Providers.size() != Providers_.size()) return Status::CorruptSnapshot;
    for (std::size_t Index = 0; Index < Providers_.size(); ++Index) {
        const auto& Saved = SnapshotValue.Providers[Index];
        if (Saved.Provider != Providers_[Index].Name ||
            Providers_[Index].Provider->ValidateState(Saved) != Status::Success)
            return Status::CorruptSnapshot;
    }

    std::vector<ProviderState> Rollback;
    Rollback.reserve(Providers_.size());
    for (const auto& EntryValue : Providers_) Rollback.push_back(EntryValue.Provider->CaptureState());
    for (std::size_t Index = 0; Index < Providers_.size(); ++Index) {
        const Status Result = Providers_[Index].Provider->RestoreState(SnapshotValue.Providers[Index]);
        if (Result == Status::Success) continue;
        for (std::size_t Restored = 0; Restored < Index; ++Restored)
            (void)Providers_[Restored].Provider->RestoreState(Rollback[Restored]);
        return Result;
    }
    return Status::Success;
}

void FrameworkRegistry::Reset() {
    std::shared_lock Lock(Mutex_);
    for (const auto& EntryValue : Providers_) EntryValue.Provider->Reset();
}

bool ValidateGuestRange(const GuestAddressValidator& Validator, GuestAddress Address,
                        std::size_t Size, GuestAccess Access) noexcept {
    if (!Validator || !Address || !Size) return false;
    if (Address > std::numeric_limits<GuestAddress>::max() - (Size - 1)) return false;
    try {
        return Validator(Address, Size, Access);
    } catch (...) {
        return false;
    }
}

bool ValidateCallback(const GuestAddressValidator& Validator,
                      const CallbackDescriptor& Callback) noexcept {
    return !Callback.Present() ||
        ValidateGuestRange(Validator, Callback.Address, 1, GuestAccess::Execute);
}

GuestHandle MakeHandle(std::uint16_t Tag, std::uint64_t Id) noexcept {
    constexpr std::uint64_t IdMask = (std::uint64_t{1} << 48) - 1;
    if (!Tag || !Id || Id > IdMask) return {};
    return {(static_cast<std::uint64_t>(Tag) << 48) | Id};
}

bool HasHandleTag(GuestHandle Handle, std::uint16_t Tag) noexcept {
    return Handle.IsValid() && static_cast<std::uint16_t>(Handle.Value >> 48) == Tag &&
        (Handle.Value & ((std::uint64_t{1} << 48) - 1)) != 0;
}

CallbackInvocation MakeInvocation(std::uint64_t Sequence,
                                  const CallbackDescriptor& Callback,
                                  std::initializer_list<GuestAddress> Arguments) noexcept {
    CallbackInvocation Result;
    Result.Sequence = Sequence;
    Result.Callback = Callback;
    const std::size_t Count = std::min(Arguments.size(), Result.Arguments.size());
    Result.ArgumentCount = static_cast<std::uint8_t>(Count);
    std::copy_n(Arguments.begin(), Count, Result.Arguments.begin());
    return Result;
}

} // namespace Kevlar::Host::Frameworks
