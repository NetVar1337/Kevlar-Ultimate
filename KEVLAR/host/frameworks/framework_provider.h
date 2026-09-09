#pragma once

#include <any>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace Kevlar::Host::Frameworks {

using GuestAddress = std::uint64_t;

struct GuestHandle {
    std::uint64_t Value = 0;

    [[nodiscard]] constexpr bool IsValid() const noexcept { return Value != 0; }
    constexpr explicit operator bool() const noexcept { return IsValid(); }
    auto operator<=>(const GuestHandle&) const = default;
};

enum class GuestAccess : std::uint8_t {
    Read,
    Write,
    Execute,
};

using GuestAddressValidator =
    std::function<bool(GuestAddress Address, std::size_t Size, GuestAccess Access)>;

enum class Status : std::uint8_t {
    Success,
    InvalidArgument,
    InvalidHandle,
    Duplicate,
    InvalidState,
    AddressRejected,
    NotSupported,
    Busy,
    CorruptSnapshot,
};

template <typename T>
struct Result {
    Status Code = Status::Success;
    T Value{};

    [[nodiscard]] constexpr bool Ok() const noexcept { return Code == Status::Success; }
    constexpr explicit operator bool() const noexcept { return Ok(); }
};

struct CallbackDescriptor {
    std::string Name;
    GuestAddress Address = 0;
    std::uint8_t ArgumentCount = 0;

    [[nodiscard]] bool Present() const noexcept { return Address != 0; }
    bool operator==(const CallbackDescriptor&) const = default;
};

struct CallbackInvocation {
    std::uint64_t Sequence = 0;
    CallbackDescriptor Callback;
    std::array<GuestAddress, 8> Arguments{};
    std::uint8_t ArgumentCount = 0;

    bool operator==(const CallbackInvocation&) const = default;
};

struct CapabilityReport {
    std::string Provider;
    std::uint32_t StateVersion = 1;
    std::vector<std::string> Features;
    std::size_t ActiveObjects = 0;
    std::size_t PendingOperations = 0;
};

struct ProviderState {
    std::string Provider;
    std::uint32_t Version = 1;
    std::any State;
};

class FrameworkProvider {
public:
    virtual ~FrameworkProvider() = default;

    [[nodiscard]] virtual std::string_view Name() const noexcept = 0;
    [[nodiscard]] virtual CapabilityReport Capabilities() const = 0;
    [[nodiscard]] virtual ProviderState CaptureState() const = 0;
    [[nodiscard]] virtual Status ValidateState(const ProviderState& State) const = 0;
    [[nodiscard]] virtual Status RestoreState(const ProviderState& State) = 0;
    virtual void Reset() = 0;
};

struct FrameworkRegistrySnapshot {
    std::vector<ProviderState> Providers;
};

class FrameworkRegistry final {
public:
    [[nodiscard]] Status Register(std::shared_ptr<FrameworkProvider> Provider);
    [[nodiscard]] Status Unregister(std::string_view Name);
    [[nodiscard]] std::shared_ptr<FrameworkProvider> Find(std::string_view Name) const;
    [[nodiscard]] std::vector<CapabilityReport> Capabilities() const;
    [[nodiscard]] FrameworkRegistrySnapshot Snapshot() const;
    [[nodiscard]] Status Restore(const FrameworkRegistrySnapshot& Snapshot);
    void Reset();

private:
    struct Entry {
        std::string Name;
        std::shared_ptr<FrameworkProvider> Provider;
    };

    mutable std::shared_mutex Mutex_;
    std::vector<Entry> Providers_;
};

[[nodiscard]] bool ValidateGuestRange(
    const GuestAddressValidator& Validator, GuestAddress Address,
    std::size_t Size, GuestAccess Access) noexcept;
[[nodiscard]] bool ValidateCallback(
    const GuestAddressValidator& Validator, const CallbackDescriptor& Callback) noexcept;
[[nodiscard]] GuestHandle MakeHandle(std::uint16_t Tag, std::uint64_t Id) noexcept;
[[nodiscard]] bool HasHandleTag(GuestHandle Handle, std::uint16_t Tag) noexcept;
[[nodiscard]] CallbackInvocation MakeInvocation(
    std::uint64_t Sequence, const CallbackDescriptor& Callback,
    std::initializer_list<GuestAddress> Arguments) noexcept;

} // namespace Kevlar::Host::Frameworks
