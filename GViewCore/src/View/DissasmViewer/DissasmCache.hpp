#pragma once
#include <unordered_map>

#include <AppCUI/include/AppCUI.hpp>

namespace GView::View::DissasmViewer
{
struct DissasmCacheEntry
{
    std::unique_ptr<std::byte[]> data;
    AppCUI::uint32 size;
};

struct DissasmCache {
    bool hasCache;
    AppCUI::OS::File cacheFile;
    std::unordered_map<std::string, DissasmCacheEntry> zonesData;

    void ClearCache(bool forceClear = false);

    static std::filesystem::path GetCacheFilePath(std::u16string_view fileLocation, bool cacheSameLocationAsAnalyzedFile);
    bool AddRegion(std::string regionName, const std::byte* data, AppCUI::uint32 size);

    bool SaveCacheFile(std::u16string_view location);
    bool LoadCacheFile(std::u16string_view location);
};


} // namespace GView::View::DissasmViewer