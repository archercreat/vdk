#pragma once
#include <ntdll.h>
#include <cstdint>

namespace vdk
{
namespace pe
{
template <typename T>
inline T* rva_to_ptr(uint8_t* base, const uint32_t rva)
{
    const auto nt_headers = PIMAGE_NT_HEADERS(base + PIMAGE_DOS_HEADER(base)->e_lfanew);
    const auto sections   = IMAGE_FIRST_SECTION(nt_headers);

    for(size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        const auto& section = sections[i];
        if(rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData)
            return (T*)(base + (rva - section.VirtualAddress + section.PointerToRawData));
    }

    return (T*)(base + rva);
}
/// \brief Iterates export directory of provided module. No safe checks are performed!
///
uint32_t get_export_rva(uint8_t* base, const char* name);
/// \brief Resolves gadget in PE image. Scans only executable non discardable sections.
///
bool find_pattern(const uint8_t* image, uint64_t base, const char* sign, size_t sign_size, uint64_t& result);
};
};
