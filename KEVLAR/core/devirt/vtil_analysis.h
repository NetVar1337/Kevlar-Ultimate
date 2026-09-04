#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace VtilAnalysis {

struct Options {
    uint64_t Rva = 0;
    uint64_t Size = 0;
    std::string InputPath;
    std::string OutputPath;
};

bool LiftImageRegion(const uint8_t* Image, size_t ImageSize, const Options& Options);

} // namespace VtilAnalysis
