#include "core/exec/target_compat.h"

#include <Logger/Logger.h>

namespace {

struct HookSpec {
    std::uint64_t Rva;
    std::uint32_t ExpectedStatus;
    const std::uint8_t* Instruction;
    std::size_t InstructionSize;
};

constexpr std::uint8_t kManifestStore[] = {
    0x48, 0x89, 0x84, 0x24, 0x60, 0x01, 0x00, 0x00,
};
constexpr std::uint8_t kBinaryIdMultiply[] = {
    0x48, 0x0F, 0xAF, 0x84, 0x24, 0xF8, 0x08, 0x00, 0x00,
};
constexpr HookSpec kHooks[] = {
    { 0x009F23E8, 0xC0EB0001u, kManifestStore, sizeof(kManifestStore) },
    { 0x006D9AC1, 0xC0EB0005u, kBinaryIdMultiply, sizeof(kBinaryIdMultiply) },
};

void OnFaceitManifestStatus(uc_engine* Engine, std::uint64_t Address,
                            std::uint32_t Size, void* UserData) {
    const auto Spec = static_cast<const HookSpec*>(UserData);
    std::uint64_t Rax = 0;
    uc_reg_read(Engine, UC_X86_REG_RAX, &Rax);
    if (Spec && static_cast<std::uint32_t>(Rax) == Spec->ExpectedStatus) {
        const auto Previous = static_cast<std::uint32_t>(Rax);
        Rax = 0;
        uc_reg_write(Engine, UC_X86_REG_RAX, &Rax);
        Logger::Log("{YEL}[FACEIT COMPAT] analysis-only status 0x%08x normalized at 0x%llx{RESET}\n",
            Previous, Address);
    }
}

} // namespace

bool TargetCompat::InstallFaceitAc20260908(
    uc_engine* Engine, std::uint64_t DriverBase, std::uint64_t DriverSize) {
    if (!Engine)
        return false;
    for (const auto& Spec : kHooks) {
        if (Spec.Rva >= DriverSize)
            return false;
        const auto Address = DriverBase + Spec.Rva;
        std::uint8_t Bytes[16] = {};
        if (Spec.InstructionSize > sizeof(Bytes)
            || uc_mem_read(Engine, Address, Bytes, Spec.InstructionSize) != UC_ERR_OK
            || memcmp(Bytes, Spec.Instruction, Spec.InstructionSize) != 0) {
            Logger::Log("{RED}FACEIT compatibility signature mismatch at drv+0x%llx{RESET}\n",
                Spec.Rva);
            return false;
        }

        uc_hook Hook = 0;
        const auto Error = uc_hook_add(
            Engine, &Hook, UC_HOOK_CODE, reinterpret_cast<void*>(OnFaceitManifestStatus),
            const_cast<HookSpec*>(&Spec), Address, Address);
        if (Error != UC_ERR_OK) {
            Logger::Log("{RED}FACEIT compatibility hook failed: %s{RESET}\n", uc_strerror(Error));
            return false;
        }
        Logger::Log("{CYN}FACEIT analysis hook installed at drv+0x%llx for status 0x%08x{RESET}\n",
            Spec.Rva, Spec.ExpectedStatus);
    }
    return true;
}
