#include "host/providers/export_contract_runtime.h"

namespace Kevlar::Host::Contracts {

ContractRegistry& ActiveRegistry() {
    static ContractRegistry Registry({
        .Seed = 0x4B45564C4152ULL,
        .InitialVirtualTimeTicks = 0,
        .UnknownPolicy = UnknownExportPolicy::ReturnStatusNotImplemented,
    });
    return Registry;
}

OperationResult LoadActiveCatalog(const std::filesystem::path& Path) {
    return ActiveRegistry().LoadCatalog(Path);
}

} // namespace Kevlar::Host::Contracts
