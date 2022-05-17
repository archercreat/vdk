#include "llaccess.hpp"

#include <vdk/vdk.hpp>
#include <vdk/shared/drv.hpp>
#include <vdk/shared/asserts.hpp>

using namespace vdk;

#include <fstream>

namespace llaccess
{
context::context(const std::filesystem::path& path) : path(path)
{
    // Drop driver into provided directory.
    //
    if (std::ofstream of(path, std::ios::binary | std::ios::out); of.is_open())
        of.write(reinterpret_cast<const char*>(raw), sizeof(raw));
    // Load driver.
    //
    fassert(drv::load(path));
    // Get handle.
    //
    std::string str = "\\\\.\\" + path.filename().string();
    drv = CreateFileA(str.c_str(), FILE_ALL_ACCESS, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    //
    //
    fassert(drv != INVALID_HANDLE_VALUE);
}

context::~context()
{
    CloseHandle(drv);
    if (drv::unload(path))
    {
        std::filesystem::remove(path);
    }
}

void context::exec_msr(vdk::cb_t cb)
{
    vdk::msr::exec([&](void* base, vdk::resolver_t resolver)
    {
        cb(base, resolver);
    },
    std::bind(&context::wrmsr, this, std::placeholders::_1, std::placeholders::_2));
}

bool context::mmap(uint64_t addr, uint32_t size, void** value)
{
    phymap_cmd cmd
    {
        .addr = addr,
        .size = size
    };
    unsigned long temp;
    return DeviceIoControl(drv, ioctl_phymap, &cmd, sizeof(cmd), value, sizeof(value), &temp, nullptr);
}

bool context::munmap(void* addr)
{
    uint64_t result;
    unsigned long temp;
    return DeviceIoControl(drv, ioctl_phyumap, &addr, sizeof(addr), &result, sizeof(result), &temp, nullptr);
}

bool context::rdmsr(uint32_t msr, uint64_t* value)
{
    unsigned long temp;
    return DeviceIoControl(drv, ioctl_rdmsr, &msr, sizeof(msr), value, sizeof(value), &temp, nullptr);
}

bool context::wrmsr(uint32_t msr, uint64_t value)
{
    wrmsr_cmd cmd
    {
        .msr   = msr,
        .value = value
    };
    unsigned long temp, result;
    return DeviceIoControl(drv, ioctl_wrmsr, &cmd, sizeof(cmd), &result, sizeof(result), &temp, nullptr);
}

bool context::wrmem(uint64_t addr, uint64_t size, uint8_t* data)
{
    if (size > 4 || addr > 0xffffffff)
        return false;
    rwmem_cmd cmd
    {
        .addr  = addr & 0xffffffff,
        .value = *reinterpret_cast<uint32_t*>(data),
        .size  = size & 0xffff
    };
    unsigned long temp, result;
    return DeviceIoControl(drv, ioctl_wrmem, &cmd, sizeof(cmd), &result, sizeof(result), &temp, nullptr);
}

bool context::rdmem(uint64_t addr, uint64_t size, uint8_t* data)
{
    if (size > 4 || addr > 0xffffffff)
        return false;
    rwmem_cmd cmd
    {
        .addr = addr & 0xffffffff,
        .size = size & 0xffff
    };
    unsigned long temp;
    return DeviceIoControl(drv, ioctl_rdmem, &cmd, sizeof(cmd), data, size, &temp, nullptr);
}
};
