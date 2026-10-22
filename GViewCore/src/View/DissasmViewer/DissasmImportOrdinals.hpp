#pragma once
#include "DissasmViewer.hpp"

#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace GView::View::DissasmViewer
{
// the names of the exports of a PE image (a DLL) by their ordinal (the base of the export directory + the index of the function), the
// first name of an ordinal exported under several; false when the image or its export directory is malformed (the names read until
// then are kept)
bool ReadPeExportNamesByOrdinal(const uint8* image, size_t size, std::unordered_map<uint32, std::string>& names);
// the folders where the DLL of an import is looked for: the one of the file (`filePath`), then the system directory of Windows
// (SysWOW64 for a 32 bit image on a 64 bit Windows, System32)
std::vector<std::filesystem::path> GetImportSearchFolders(std::u16string_view filePath, bool is32BitImage);
// a DLL name of an import table that names a file of a folder (no path: certcli.dll, api-ms-win-core-path-l1-1-0.dll)
bool IsPlainDllName(std::string_view dllName);
} // namespace GView::View::DissasmViewer
