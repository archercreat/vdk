#pragma once
#include <functional>

namespace vdk
{
/// \brief User provided function to read physical memory.
///
using rdmem_t = std::function<bool(uint64_t, uint64_t, uint8_t*)>;
/// \brief User provided function to write physical memory.
///
using wrmem_t = std::function<bool(uint64_t, uint64_t, uint8_t*)>;
/// \brief User provided function to write msr value.
///
using wrmsr_t    = std::function<bool(uint32_t, uint64_t)>;
/// \brief RtlFindExportedRoutineByName prototype.
///
using resolver_t = void*(*)(void*, const char*);
/// \brief User provided kernel callback.
///
using cb_t       = std::function<void(void*, resolver_t)>;
};
