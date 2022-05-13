#include "phy.hpp"
#include "asserts.hpp"

#include <ntdll.h>
#include <Windows.h>

namespace vdk
{
namespace phy
{
std::vector<region_t> regions()
{
    HKEY key;
    std::vector<region_t> regions;

    if (SUCCEEDED(RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory", 0, KEY_READ, &key)))
    {
        unsigned long type, size;
        fassert(SUCCEEDED(RegQueryValueEx(key, ".Translated", nullptr, &type, nullptr, &size)));
        auto data = std::make_unique<uint8_t[]>(size);
        fassert(SUCCEEDED(RegQueryValueEx(key, ".Translated", nullptr, &type, data.get(), &size)));

        const auto resources = reinterpret_cast<PCM_RESOURCE_LIST>(data.get());

        for (size_t i = 0; i < resources->Count; i++)
        {
            const auto* list = &resources->List[i].PartialResourceList;
            for (size_t j = 0; j < list->Count; j++)
            {
                regions.push_back(region_t{
                    .start = static_cast<uint64_t>(list->PartialDescriptors[j].u.Memory.Start.QuadPart),
                    .size  = static_cast<uint64_t>(list->PartialDescriptors[j].u.Memory.Length)
                });
            }
        }
        RegCloseKey(key);
    }
    return regions;
}
};
};
