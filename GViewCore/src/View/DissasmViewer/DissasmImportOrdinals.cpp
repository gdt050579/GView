#include "DissasmImportOrdinals.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <vector>

using namespace GView::View::DissasmViewer;

namespace
{
constexpr uint32 MAX_SECTIONS          = 96;
constexpr uint32 MAX_EXPORT_NAMES      = 0x10000;
constexpr uint32 MAX_EXPORT_NAME_SIZE  = 512;
constexpr uint64 MAX_EXPORT_IMAGE_SIZE = 64ull * 1024 * 1024; // the DLLs of Windows are a few MB
constexpr uint32 MAX_EXPORT_IMAGES     = 64;                  // the DLLs read for one file (a hostile import table names thousands)
constexpr size_t MAX_DLL_NAME_SIZE     = 128;

template <typename T>
bool ReadValue(const uint8* image, size_t size, uint64 offset, T& value)
{
    if (offset > size || size - offset < sizeof(T))
        return false;
    memcpy(&value, image + offset, sizeof(T));
    return true;
}

bool ReadExportNamesOfFile(const std::filesystem::path& path, std::unordered_map<uint32, std::string>& names)
{
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error))
        return false;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > MAX_EXPORT_IMAGE_SIZE)
        return false;
    std::ifstream file(path, std::ios::binary);
    std::vector<uint8> image(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size())))
        return false;
    return ReadPeExportNamesByOrdinal(image.data(), image.size(), names);
}
} // namespace

bool GView::View::DissasmViewer::ReadPeExportNamesByOrdinal(const uint8* image, size_t size, std::unordered_map<uint32, std::string>& names)
{
    uint16 dosMagic = 0, optionalMagic = 0, sectionCount = 0, optionalSize = 0;
    uint32 peOffset = 0, signature = 0;
    if (!image || !ReadValue(image, size, 0, dosMagic) || dosMagic != 0x5A4D || !ReadValue(image, size, 0x3C, peOffset) ||
        !ReadValue(image, size, peOffset, signature) || signature != 0x4550)
        return false;
    const uint64 fileHeader = static_cast<uint64>(peOffset) + 4;
    const uint64 optional   = fileHeader + 20;
    if (!ReadValue(image, size, fileHeader + 2, sectionCount) || !ReadValue(image, size, fileHeader + 16, optionalSize) ||
        !ReadValue(image, size, optional, optionalMagic) || (optionalMagic != 0x10B && optionalMagic != 0x20B))
        return false;
    // the export directory: the first data directory (after NumberOfRvaAndSizes)
    const uint64 directoryCountOffset = optional + (optionalMagic == 0x10B ? 92 : 108);
    uint32 directoryCount = 0, exportRva = 0;
    if (!ReadValue(image, size, directoryCountOffset, directoryCount) || directoryCount == 0 ||
        !ReadValue(image, size, directoryCountOffset + 4, exportRva) || exportRva == 0)
        return false;
    // the RVAs in the file: through the section headers
    struct Section {
        uint32 virtualAddress, virtualSize, rawSize, rawOffset;
    };
    std::vector<Section> sections;
    for (uint32 index = 0; index < std::min<uint32>(sectionCount, MAX_SECTIONS); index++) {
        const uint64 header = optional + optionalSize + static_cast<uint64>(index) * 40;
        Section section{};
        if (!ReadValue(image, size, header + 8, section.virtualSize) || !ReadValue(image, size, header + 12, section.virtualAddress) ||
            !ReadValue(image, size, header + 16, section.rawSize) || !ReadValue(image, size, header + 20, section.rawOffset))
            return false;
        sections.push_back(section);
    }
    const auto toOffset = [&sections](uint32 rva) -> std::optional<uint64> {
        for (const auto& section : sections) {
            const uint32 extent = std::max(section.virtualSize, section.rawSize);
            if (rva >= section.virtualAddress && rva - section.virtualAddress < extent && rva - section.virtualAddress < section.rawSize)
                return static_cast<uint64>(section.rawOffset) + (rva - section.virtualAddress);
        }
        return std::nullopt;
    };
    // IMAGE_EXPORT_DIRECTORY: Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
    const auto directory = toOffset(exportRva);
    uint32 base = 0, functionCount = 0, nameCount = 0, namesRva = 0, nameOrdinalsRva = 0;
    if (!directory.has_value() || !ReadValue(image, size, directory.value() + 16, base) || !ReadValue(image, size, directory.value() + 20, functionCount) ||
        !ReadValue(image, size, directory.value() + 24, nameCount) || !ReadValue(image, size, directory.value() + 32, namesRva) ||
        !ReadValue(image, size, directory.value() + 36, nameOrdinalsRva))
        return false;
    const auto namesOffset        = toOffset(namesRva);
    const auto nameOrdinalsOffset = toOffset(nameOrdinalsRva);
    if (nameCount == 0)
        return true;
    if (!namesOffset.has_value() || !nameOrdinalsOffset.has_value())
        return false;
    for (uint32 index = 0; index < std::min(nameCount, MAX_EXPORT_NAMES); index++) {
        uint32 nameRva       = 0;
        uint16 functionIndex = 0;
        if (!ReadValue(image, size, namesOffset.value() + static_cast<uint64>(index) * 4, nameRva) ||
            !ReadValue(image, size, nameOrdinalsOffset.value() + static_cast<uint64>(index) * 2, functionIndex))
            return false;
        const auto nameOffset = toOffset(nameRva);
        if (functionIndex >= functionCount || !nameOffset.has_value() || nameOffset.value() >= size)
            continue;
        // a name of printable characters (the mangled C++ names too: ?Get@CFoo@@QEAAXXZ), NUL terminated
        std::string name;
        for (uint64 offset = nameOffset.value(); offset < size && name.size() <= MAX_EXPORT_NAME_SIZE && image[offset] != 0; offset++)
            name.push_back(static_cast<char>(image[offset]));
        const bool printable = std::all_of(name.begin(), name.end(), [](char c) { return c > ' ' && c < 0x7F; });
        if (!name.empty() && name.size() <= MAX_EXPORT_NAME_SIZE && printable)
            names.emplace(base + functionIndex, std::move(name));
    }
    return true;
}

bool GView::View::DissasmViewer::IsPlainDllName(std::string_view dllName)
{
    if (dllName.empty() || dllName.size() > MAX_DLL_NAME_SIZE || dllName.front() == '.')
        return false;
    return std::all_of(dllName.begin(), dllName.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
    });
}

std::vector<std::filesystem::path> GView::View::DissasmViewer::GetImportSearchFolders(std::u16string_view filePath, bool is32BitImage)
{
    std::vector<std::filesystem::path> folders;
    if (!filePath.empty())
        if (auto folder = std::filesystem::path(filePath).parent_path(); !folder.empty())
            folders.push_back(std::move(folder));
#ifdef _WIN32
    wchar_t* systemRoot = nullptr;
    size_t length       = 0;
    if (_wdupenv_s(&systemRoot, &length, L"SystemRoot") == 0 && systemRoot) {
        const std::filesystem::path root(systemRoot);
        free(systemRoot);
        std::error_code error;
        if (is32BitImage && std::filesystem::is_directory(root / "SysWOW64", error))
            folders.push_back(root / "SysWOW64");
        else
            folders.push_back(root / "System32");
    }
#else
    (void) is32BitImage;
#endif
    return folders;
}

std::string Settings::GetImportOrdinalName(std::string_view dllName, uint32 ordinal, std::u16string_view filePath, bool is32BitImage)
{
    auto* settings = static_cast<SettingsData*>(this->data);
    if (!IsPlainDllName(dllName))
        return {};
    std::string key(dllName);
    std::transform(key.begin(), key.end(), key.begin(), [](char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c); });
    key += is32BitImage ? "|32" : "|64";
    auto known = settings->exportNamesByOrdinal.find(key);
    if (known == settings->exportNamesByOrdinal.end()) {
        std::unordered_map<uint32, std::string> names;
        if (settings->exportNamesByOrdinal.size() < MAX_EXPORT_IMAGES)
            for (const auto& folder : GetImportSearchFolders(filePath, is32BitImage)) {
                names.clear();
                if (ReadExportNamesOfFile(folder / std::string(dllName), names))
                    break; // the first DLL found, as the loader
            }
        known = settings->exportNamesByOrdinal.emplace(std::move(key), std::move(names)).first;
    }
    const auto name = known->second.find(ordinal);
    return name != known->second.end() ? name->second : std::string();
}
