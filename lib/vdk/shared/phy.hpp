#pragma once
#include <vector>

namespace vdk
{
namespace phy
{
struct region_t
{
    uint64_t start;
    uint64_t size;
};

/// \brief Return available physical memory regions.
///
std::vector<region_t> regions();
};
};
