#include "speedfan.hpp"

#include <vdk/vdk.hpp>
#include <vdk/shared/drv.hpp>
#include <vdk/shared/asserts.hpp>

using namespace vdk;

#include <fstream>

namespace speedfan
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

void context::exec_phy(vdk::cb_t cb)
{
    vdk::map::exec([&](void* base, vdk::resolver_t resolver)
    {
        cb(base, resolver);
    },
    std::bind(&context::rdmem, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
    std::bind(&context::wrmem, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
}

void context::exec_msr(vdk::cb_t cb)
{
    vdk::msr::exec([&](void* base, vdk::resolver_t resolver)
    {
        cb(base, resolver);
    },
    std::bind(&context::wrmsr, this, std::placeholders::_1, std::placeholders::_2));
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
        .msr = msr,
        .hi  = (value >> 32) & 0xffffffff,
        .lo  = (value >>  0) & 0xffffffff,
    };
    unsigned long temp, result;
    return DeviceIoControl(drv, ioctl_wrmsr, &cmd, sizeof(cmd), &result, sizeof(result), &temp, nullptr);
}

bool context::wrmem(uint64_t addr, uint64_t size, uint8_t* data)
{
    unsigned long temp{}, out{};
    auto  raw = std::make_unique<uint8_t[]>(sizeof(addr) + size);
    auto* cmd = reinterpret_cast<wrmem_cmd*>(raw.get());
    cmd->addr = addr;
    std::memcpy(&cmd->buf[0], data, size);
    return DeviceIoControl(drv, ioctl_wrmem, cmd, sizeof(addr) + size, &out, sizeof(out), &temp, nullptr);
}

bool context::rdmem(uint64_t addr, uint64_t size, uint8_t* data)
{
    unsigned long temp{};
    return DeviceIoControl(drv, ioctl_rdmem, &addr, sizeof(addr), data, size, &temp, nullptr);
}
};
