#pragma once
#include "types.hpp"
#include <functional>

namespace vdk::msr
{
/// \brief IA32_MSR_LSTAR address.
///
static constexpr auto msr_lstar = 0xC0000082;
/// \brief Prepares environment and executes user provided callback in CPL 0 by hooking msr lstar.
///
void exec(cb_t cb, wrmsr_t wrmsr);
};
