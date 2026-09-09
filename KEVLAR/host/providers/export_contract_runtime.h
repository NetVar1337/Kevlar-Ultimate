#pragma once

#include "host/providers/export_contracts.h"

#include <filesystem>

namespace Kevlar::Host::Contracts {

ContractRegistry& ActiveRegistry();
OperationResult LoadActiveCatalog(const std::filesystem::path& Path);

} // namespace Kevlar::Host::Contracts
