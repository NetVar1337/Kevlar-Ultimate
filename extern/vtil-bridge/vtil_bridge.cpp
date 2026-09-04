#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <string>

#include <lifters/core>
#include <lifters/amd64>
#include <vtil/arch>

namespace {
void set_error(char* buffer, size_t capacity, const std::string& message) {
    if (!buffer || !capacity)
        return;
    std::strncpy(buffer, message.c_str(), capacity - 1);
    buffer[capacity - 1] = '\0';
}
}

extern "C" __declspec(dllexport) int kevlar_vtil_lift(
    const uint8_t* image,
    size_t image_size,
    uint64_t rva,
    size_t size,
    const char* output_path,
    char* error,
    size_t error_capacity) {
    try {
        if (!image || !output_path || rva >= image_size || size > image_size - rva) {
            set_error(error, error_capacity, "invalid VTIL input range");
            return 0;
        }

        auto* block = vtil::basic_block::begin(rva, vtil::architecture_amd64);
        auto* routine = block->owner;
        routine->routine_convention = vtil::lifter::host_preserve_all_convention();
        routine->routine_convention.purge_stack = false;

        uint64_t vip = rva;
        uint8_t* code = const_cast<uint8_t*>(image + rva);
        const uint64_t end = rva + size;
        while (vip < end) {
            block->label_begin(vip);
            const size_t length = vtil::lifter::amd64::lifter_t::process(block, vip, code);
            block->label_end();
            if (!length) {
                block->vexit(vip);
                break;
            }
            code += length;
            vip += length;
            if (block->is_complete())
                break;
        }
        if (!block->is_complete())
            block->vexit(vip);

        std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
        if (!output) {
            set_error(error, error_capacity, "failed to open VTIL output");
            return 0;
        }
        vtil::serialize(output, routine);
        output.close();
        if (!output) {
            set_error(error, error_capacity, "failed to write VTIL output");
            return 0;
        }
        return 1;
    } catch (const std::exception& exception) {
        set_error(error, error_capacity, exception.what());
        return 0;
    } catch (...) {
        set_error(error, error_capacity, "unknown VTIL lifting failure");
        return 0;
    }
}
