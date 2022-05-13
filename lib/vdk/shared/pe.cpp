#include "pe.hpp"
#include "mem.hpp"

#include <string>

namespace vdk
{
namespace pe
{
uint32_t get_export_rva(uint8_t* base, const char* name)
{
    const auto* nt_headers = PIMAGE_NT_HEADERS(base + PIMAGE_DOS_HEADER(base)->e_lfanew);
    const auto  data_dir   = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!data_dir.VirtualAddress || !data_dir.Size)
        return 0;

    const auto* export_dir = rva_to_ptr<IMAGE_EXPORT_DIRECTORY>(base, data_dir.VirtualAddress);
    const auto* names      = rva_to_ptr<uint32_t>(base, export_dir->AddressOfNames);
    const auto* ordinals   = rva_to_ptr<uint16_t>(base, export_dir->AddressOfNameOrdinals);
    const auto* functions  = rva_to_ptr<uint32_t>(base, export_dir->AddressOfFunctions);

    for (size_t i = 0; i < export_dir->NumberOfNames; i++)
    {
        const char* export_name = rva_to_ptr<const char>(base, names[i]);
        if (!std::strcmp(name, export_name))
        {
            // Check for redirected exports.
            //
            const auto func_rva = functions[ordinals[i]];
            if (func_rva >= data_dir.VirtualAddress && func_rva < data_dir.VirtualAddress + data_dir.Size)
                return 0;
            return func_rva;
        }
    }
    return 0;
}

bool find_pattern(const uint8_t* image, uint64_t base, const char* sign, size_t sign_size, uint64_t& result)
{
    const auto nt_headers = PIMAGE_NT_HEADERS(image + PIMAGE_DOS_HEADER(image)->e_lfanew);
    const auto sections   = IMAGE_FIRST_SECTION(nt_headers);

    for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        const auto& section = sections[i];
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE && !(section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            const auto contents = image + section.PointerToRawData;
            if (auto addr = mem::scan(contents, section.SizeOfRawData, sign, sign_size); addr != nullptr)
            {
                result = addr - contents + section.VirtualAddress + base;
                return true;
            }
        }
    }
    return false;
}
};
};
