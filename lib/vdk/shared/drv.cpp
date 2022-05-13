#include "drv.hpp"
#include "asserts.hpp"

#include <ntdll.h>
#include <memory>
#include <fstream>
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace vdk
{
namespace drv
{
namespace detail
{
enum e_error : uint32_t
{
    ignore   = 0,
    normal   = 1,
    severe   = 2,
    critical = 3
};

enum e_start : uint32_t
{
    boot     = 0,
    system   = 1,
    autoload = 2,
    manual   = 3,
    disabled = 4
};

enum e_type : uint32_t
{
    device     = 1,
    device_fs  = 2,
    network    = 3,
    standalone = 4,
    shared     = 5
};

constexpr auto load_driver_privilege = 10;

inline bool set_privilege()
{
    BOOLEAN enabled;
    return NT_SUCCESS(RtlAdjustPrivilege(load_driver_privilege, TRUE, FALSE, &enabled));
}

inline bool prepare_registry(const std::filesystem::path& path)
{
    HKEY key, subkey;
    LSTATUS status;
    const std::string image_path = "\\??\\" + path.string();

    if(SUCCEEDED(RegOpenKeyA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\", &key)))
    {
        if (SUCCEEDED(RegCreateKeyA(key, path.filename().string().c_str(), &subkey)))
        {
            uint32_t type  = e_type::device;
            uint32_t err   = e_error::normal;
            uint32_t start = e_start::manual;

            status  = RegSetValueExA(subkey, "Type",         0, REG_DWORD, (BYTE*)&type,  4);
            status |= RegSetValueExA(subkey, "ErrorControl", 0, REG_DWORD, (BYTE*)&err,   4);
            status |= RegSetValueExA(subkey, "Start",        0, REG_DWORD, (BYTE*)&start, 4);
            status |= RegSetValueExA(subkey, "ImagePath",    0, REG_SZ,    (BYTE*)image_path.c_str(), image_path.length());

            if (FAILED(status))
            {
                RegDeleteKeyA(key, path.filename().string().c_str());
                RegCloseKey(subkey);
                RegCloseKey(key);
                return false;
            }
            RegCloseKey(subkey);
        }
        RegCloseKey(key);
        return true;
    }
    return false;
}

inline std::wstring make_path(const std::wstring& name)
{
    std::wstring path(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    return path + name;
}
};

std::vector<module_t> loaded()
{
    std::vector<module_t> out;
    unsigned long size{};
    fassert(NtQuerySystemInformation(SystemModuleInformation, nullptr, size, &size) == STATUS_INFO_LENGTH_MISMATCH);

    auto data = std::make_unique<char[]>(size);
    fassert(NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, data.get(), size, &size)));

    const auto mods = reinterpret_cast<PRTL_PROCESS_MODULES>(data.get());
    for (size_t i = 0; i < mods->NumberOfModules; i++)
    {
        const auto& mod = mods->Modules[i];
        module_t module
        {
            .base = reinterpret_cast<uint64_t>(mod.ImageBase),
            .size = static_cast<uint64_t>(mod.ImageSize),
            .name = std::string(reinterpret_cast<const char*>(mod.FullPathName))
        };
        // Replace %systemroot% with absolute path.
        //
        if (auto pos = module.name.find("\\SystemRoot\\"); pos != std::string::npos)
        {
            module.name.replace(pos, pos + sizeof("\\SystemRoot\\") - 1, std::string(getenv("SYSTEMROOT")).append("\\"));
        }
        out.push_back(module);
    }
    return out;
}

module_t ntoskrnl()
{
    for (const auto& module : loaded())
    {
        if (module.name.find("ntoskrnl.exe") != std::string::npos)
            return module;
    }
    fassert(false);
    return {};
}

bool load(const std::filesystem::path& path)
{
    if (detail::prepare_registry(path))
    {
        if (detail::set_privilege())
        {
            UNICODE_STRING str;
            auto wpath = detail::make_path(path.filename().wstring());
            RtlInitUnicodeString(&str, PWSTR(wpath.c_str()));
            auto status = NtLoadDriver(&str);
            return NT_SUCCESS(status) || status == STATUS_IMAGE_ALREADY_LOADED;
        }
    }
    return false;
}

bool unload(const std::filesystem::path& path)
{
    UNICODE_STRING str;
    auto wpath = detail::make_path(path.filename().wstring());
    RtlInitUnicodeString(&str, PWSTR(wpath.c_str()));
    if (detail::set_privilege())
    {
        if (NT_SUCCESS(NtUnloadDriver(&str)))
        {
            if (HKEY key; SUCCEEDED(RegOpenKeyA(HKEY_LOCAL_MACHINE, "system\\CurrentControlSet\\Services", &key)))
            {
                RegDeleteKeyA(key, path.filename().string().c_str());
                RegCloseKey(key);
                return true;
            }
        }
    }
    return false;
}

bool read_file(const std::filesystem::path& path, std::vector<uint8_t>& buf)
{
    if (std::ifstream of(path, std::ios::in | std::ios::ate | std::ios::binary); of.is_open())
    {
        const auto size = of.tellg();
        buf.resize(size);
        of.seekg(0, std::ios::beg);
        of.read(reinterpret_cast<char*>(buf.data()), size);
        return true;
    }
    return false;
}

bool write_file(const std::filesystem::path& path, const std::vector<uint8_t>& buf)
{
    if (std::ofstream inf(path, std::ios::out | std::ios::binary); inf.is_open())
    {
        inf.write(reinterpret_cast<const char*>(buf.data()), buf.size());
        return true;
    }
    return false;
}

};
};
