#include "mem.hpp"

namespace vdk
{
namespace mem
{
const uint8_t* scan(const uint8_t* region, size_t region_size, const char* sign, size_t sign_size)
{
    if (region_size < sign_size)
        return nullptr;

    auto is_match = [](const uint8_t* addr, const char* sign, size_t sign_size)
    {
        for (size_t i = 0; i < sign_size; i++)
            if (static_cast<uint8_t>(sign[i]) != 0x00 && addr[i] != static_cast<uint8_t>(sign[i]))
                return false;
        return true;
    };

    for (size_t i = 0; i <= region_size - sign_size; i++)
        if (is_match(region + i, sign, sign_size))
            return region + i;
    return nullptr;
}
};
};
