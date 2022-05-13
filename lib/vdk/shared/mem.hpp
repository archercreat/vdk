#pragma once
#include <vector>
#include <cstdint>

namespace vdk
{
namespace mem
{
/// \brief Scans region of memory for signature. Returns first found address.
///
const uint8_t* scan(const uint8_t* region, size_t region_size, const char* sign, size_t sign_size);
/// \brief Returns first found entry.
///
template<typename T = uint8_t>
T* find_first(const uint8_t* addr, size_t size, const char* sign, size_t sign_size)
{
    return (T*)scan(addr, size, sign, sign_size);
}
/// \brief Returns all found entries in the given region.
///
template<typename T = uint8_t>
std::vector<T*> find_all(const uint8_t* addr, size_t size, const char* sign, size_t sign_size)
{
    std::vector<T*> out;
    size_t pos = 0;
    while (auto* hit = find_first<T>(addr + pos, size - pos, sign, sign_size))
    {
        out.push_back(hit);
        pos = hit - addr;
    }
    return out;
}
};
};
