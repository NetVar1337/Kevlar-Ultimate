#include "host/providers/usermode_provider.h"

#include "core/memory/unicorn_memory.h"
#include "host/providers/provider.h"
#include <Logger/Logger.h>
#include <cstdint>

namespace {

const char* GuestString(uint64_t Address) {
    if (!Address)
        return "";
    auto Host = static_cast<const char*>(UnicornMem::UcToHost(Address));
    return Host ? Host : "<invalid guest string>";
}

uint64_t h_MessageBoxA(uint64_t Window, uint64_t Text, uint64_t Caption, uint64_t Type) {
    Logger::Log("{CYN}\tMessageBoxA: hwnd=0x%llx caption=\"%.256s\" text=\"%.1024s\" type=0x%llx -> IDOK{RESET}\n",
        Window, GuestString(Caption), GuestString(Text), Type);
    return 1; // IDOK
}

} // namespace

void usermode_provider::Initialize() {
    Provider::AddFuncImpl("MessageBoxA", reinterpret_cast<PVOID>(h_MessageBoxA));
}
