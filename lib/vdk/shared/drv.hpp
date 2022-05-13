#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <filesystem>

namespace vdk
{
namespace drv
{
struct module_t
{
    uint64_t    base;
    uint64_t    size;
    std::string name;
};
/// \brief Collects info about loaded kernel modules.
///
std::vector<module_t> loaded();
/// \brief Returns info about ntoskrnl module.
///
module_t ntoskrnl();
/// \brief Load driver.
///
bool load(const std::filesystem::path& path);
/// \brief Unload driver.
///
bool unload(const std::filesystem::path& path);
/// \brief Read file.
///
bool read_file(const std::filesystem::path& path, std::vector<uint8_t>& buf);
/// \brief Write file.
///
bool write_file(const std::filesystem::path& path, const std::vector<uint8_t>& buf);
};
};
