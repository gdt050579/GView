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

// Version of the cache file format, stored in the DISSASM_CACHE_VERSION_RECORD record (an extra record: the readers written before the
// versions ignore it, they still load the files written now).
//  1: the files written before the version record existed (no version record)
//  2: the version record; the zone validation records keep the version 1 format (the hash of the first data cache window of the zone, so
//     the older readers still accept the file) and a "DisassemblyZoneHash.<start>" record has the hash of the whole zone
// A reader loads the files from DISSASM_CACHE_OLDEST_LOADABLE_VERSION to DISSASM_CACHE_VERSION. A file written by a newer version is not
// loaded (the format may have changed) and it is copied to <cache>.bak before it is overwritten.
constexpr AppCUI::uint32 DISSASM_CACHE_VERSION                 = 2;
constexpr AppCUI::uint32 DISSASM_CACHE_OLDEST_LOADABLE_VERSION = 1;
constexpr std::string_view DISSASM_CACHE_VERSION_RECORD        = "DissasmCacheVersion";

struct DissasmCache {
    bool hasCache = false;
    // the format version of the loaded file (1 for the files without a version record), DISSASM_CACHE_VERSION for a new cache
    AppCUI::uint32 fileVersion = DISSASM_CACHE_VERSION;
    // the cache file exists but it could not be used (corrupted, another version of the file): it is copied to <cache>.bak before it is
    // overwritten, the annotations it holds are not lost
    bool keepBackupOnSave = false;
    AppCUI::OS::File cacheFile;
    std::unordered_map<std::string, DissasmCacheEntry> zonesData;

    void ClearCache(bool forceClear = false);

    // next to the analysed file (<file>.dissasm.cache) or, when cacheSameLocationAsAnalyzedFile is not set, in the cache folder of the user
    // (one file per analysed file); `userCacheFolder` empty selects the default folder of the user
    static std::filesystem::path GetCacheFilePath(
          std::u16string_view fileLocation, bool cacheSameLocationAsAnalyzedFile, const std::filesystem::path& userCacheFolder = {});
    bool AddRegion(std::string regionName, const std::byte* data, AppCUI::uint32 size);

    // written to a temporary file that replaces the cache file once it is complete (a failed write never leaves a truncated cache); the
    // version record (DISSASM_CACHE_VERSION) is written first
    bool SaveCacheFile(std::u16string_view location);
    // false for a file that can not be loaded: corrupted, or a version outside [DISSASM_CACHE_OLDEST_LOADABLE_VERSION, DISSASM_CACHE_VERSION];
    // the version record is not kept in zonesData (it sets fileVersion)
    bool LoadCacheFile(std::u16string_view location);
};


} // namespace GView::View::DissasmViewer