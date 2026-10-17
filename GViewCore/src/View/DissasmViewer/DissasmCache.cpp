#include <filesystem>

#include "DissasmCache.hpp"
#include "DissasmViewer.hpp"
#include "DissasmCodeZone.hpp"
#include "DissasmIOHelpers.hpp"

#include <algorithm>
#include <map>
#include <optional>
#include <unordered_set>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

void DissasmCache::ClearCache(bool forceClear)
{
    if (!hasCache && !forceClear)
        return;
    zonesData.clear();
    cacheFile.Close();
}

bool DissasmCache::AddRegion(std::string regionName, const std::byte* data, AppCUI::uint32 size)
{
    if (zonesData.contains(regionName))
        return false;
    DissasmCacheEntry entry = { std::make_unique<std::byte[]>(size), size };
    memcpy(entry.data.get(), data, size);
    zonesData[std::move(regionName)] = std::move(entry);
    return true;
}

// the cache folder of the user: %LOCALAPPDATA%\GView\DissasmCache, $XDG_CACHE_HOME/gview/dissasm or ~/.cache/gview/dissasm
static std::filesystem::path GetDefaultUserCacheFolder()
{
#ifdef _WIN32
    wchar_t* localAppData = nullptr;
    size_t length         = 0;
    std::filesystem::path folder;
    if (_wdupenv_s(&localAppData, &length, L"LOCALAPPDATA") == 0 && localAppData && *localAppData)
        folder = std::filesystem::path(localAppData) / "GView" / "DissasmCache";
    free(localAppData);
    return folder;
#else
    const char* xdgCache = getenv("XDG_CACHE_HOME");
    if (xdgCache && *xdgCache)
        return std::filesystem::path(xdgCache) / "gview" / "dissasm";
    const char* home = getenv("HOME");
    if (home && *home)
        return std::filesystem::path(home) / ".cache" / "gview" / "dissasm";
    return {};
#endif
}

std::filesystem::path DissasmCache::GetCacheFilePath(
      std::u16string_view fileLocation, bool cacheSameLocationAsAnalyzedFile, const std::filesystem::path& userCacheFolder)
{
    std::filesystem::path analysedFile = fileLocation;
    const auto folder                  = cacheSameLocationAsAnalyzedFile ? std::filesystem::path{}
                                                                         : (userCacheFolder.empty() ? GetDefaultUserCacheFolder() : userCacheFolder);
    if (folder.empty()) {
        // next to the analysed file (also when the user has no cache folder: a single file shared by every analysed file mixed them)
        analysedFile += ".dissasm.cache";
        return analysedFile;
    }

    // one file per analysed file: the file name and a hash (FNV-1a) of the full path, so files with the same name do not share it
    uint64 hash = 14695981039346656037ull;
    for (const char16 c : fileLocation) {
        hash ^= static_cast<uint64>(c);
        hash *= 1099511628211ull;
    }
    LocalString<32> suffix;
    suffix.SetFormat(".%016llx.dissasm.cache", static_cast<unsigned long long>(hash));
    auto path = folder / analysedFile.filename();
    path += suffix.GetText();
    return path;
}

bool DissasmCache::SaveCacheFile(std::u16string_view location)
{
    if (zonesData.empty())
        return false;
    const std::filesystem::path filePath(location.begin(), location.end());
    std::error_code ec;
    if (filePath.has_parent_path())
        std::filesystem::create_directories(filePath.parent_path(), ec); // the cache folder of the user may not exist yet

    // a cache file that could not be loaded is kept (it may hold the annotations of another version of the analysed file)
    if (keepBackupOnSave && std::filesystem::exists(filePath, ec)) {
        auto backupPath = filePath;
        backupPath += ".bak";
        std::filesystem::copy_file(filePath, backupPath, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec)
            return false; // never overwrite it without its copy
        keepBackupOnSave = false;
    }

    auto temporaryPath = filePath;
    temporaryPath += ".tmp";
    if (!cacheFile.Create(temporaryPath, true))
        return false;
    bool written            = true;
    auto write              = [this, &written](const void* data, uint32 size) { written = written && (size == 0 || cacheFile.Write(data, size)); };
    zonesData.erase(std::string(DISSASM_CACHE_VERSION_RECORD)); // written below, once
    const uint32 zonesCount = (uint32) zonesData.size() + 1u;
    uint32 entrySize;
    write(&zonesCount, sizeof(zonesCount));

    // the version record: a record as the others, the readers that do not know it ignore it
    entrySize = static_cast<uint32>(DISSASM_CACHE_VERSION_RECORD.size());
    write(&entrySize, sizeof(entrySize));
    write(DISSASM_CACHE_VERSION_RECORD.data(), entrySize);
    const uint32 version = DISSASM_CACHE_VERSION;
    entrySize            = sizeof(version);
    write(&entrySize, sizeof(entrySize));
    write(&version, sizeof(version));

    for (auto& [name, entry] : zonesData) {
        entrySize = (uint32) name.size();
        write(&entrySize, sizeof(entrySize));
        write(name.data(), entrySize);

        entrySize = entry.size;
        write(&entrySize, sizeof(entrySize));
        write(entry.data.get(), entry.size);
    }
    cacheFile.Close();
    std::error_code renameError;
    if (written)
        std::filesystem::rename(temporaryPath, filePath, renameError); // replaces the previous cache file
    if (!written || renameError) {
        std::filesystem::remove(temporaryPath, ec);
        return false;
    }
    fileVersion = DISSASM_CACHE_VERSION;
    return true;
}

bool DissasmCache::LoadCacheFile(std::u16string_view location)
{
    const std::filesystem::path filePath(location.begin(), location.end());
    fileVersion       = 1; // the files written before the version record
    const bool opened = cacheFile.OpenRead(filePath);
    if (!opened)
        return false;
    const auto fileSize = cacheFile.GetSize();
    if (fileSize == (uint64)-1)
        return false;
    if (fileSize == 0)
        return true;
    if (fileSize < sizeof(uint32) || fileSize > 0xFFFFFFFFull)
        return false;
    std::vector<uint8> buffer;
    buffer.resize((uint32) fileSize);
    const bool readOk = cacheFile.Read(reinterpret_cast<char*>(buffer.data()), (uint32) fileSize);
    cacheFile.Close();
    if (!readOk)
        return false;

    // the cache file is untrusted: every size is checked against the remaining bytes (in size_t, no wrap around)
    const size_t bufferSize = buffer.size();
    size_t offset           = 0;
    uint32 zonesCount       = 0;
    memcpy(&zonesCount, buffer.data() + offset, sizeof(zonesCount));
    offset += sizeof(zonesCount);

    while (offset < bufferSize) {
        if (zonesCount-- == 0)
            return false;
        uint32 entrySize;
        if (bufferSize - offset < sizeof(entrySize))
            return false;
        memcpy(&entrySize, buffer.data() + offset, sizeof(entrySize));
        offset += sizeof(entrySize);
        if (entrySize > bufferSize - offset)
            return false;
        const auto entryDataName = buffer.data() + offset;
        offset += entrySize;
        std::string_view entryName = { (const char*) entryDataName, entrySize };

        if (bufferSize - offset < sizeof(entrySize))
            return false;
        memcpy(&entrySize, buffer.data() + offset, sizeof(entrySize));
        offset += sizeof(entrySize);
        if (entrySize > bufferSize - offset)
            return false;
        const auto entryData = buffer.data() + offset;
        offset += entrySize;

        if (entryName == DISSASM_CACHE_VERSION_RECORD) {
            if (entrySize != sizeof(fileVersion))
                return false;
            memcpy(&fileVersion, entryData, sizeof(fileVersion));
            continue; // not a zone record
        }
        auto newCacheEntry = DissasmCacheEntry{ std::make_unique<std::byte[]>(entrySize), entrySize };
        memcpy(newCacheEntry.data.get(), entryData, entrySize);
        zonesData.emplace(entryName, std::move(newCacheEntry));
    }
    // a file written by a newer version may use a format this version does not know: it is not loaded (nor overwritten without a copy)
    return fileVersion >= DISSASM_CACHE_OLDEST_LOADABLE_VERSION && fileVersion <= DISSASM_CACHE_VERSION;
}

bool DisassemblyZone::ToBuffer(std::vector<std::byte>& buffer, Reference<GView::Object> obj, bool hashWholeZone) const
{
    Hashes::OpenSSLHash hash(Hashes::OpenSSLHashKind::Md5);
    // the data cache returns at most one window: the whole zone is hashed window after window (the caches saved before hashed only the
    // first window, ValidateCacheData still accepts them)
    const uint64 fileSize = obj->GetData().GetSize();
    const uint64 end      = startingZonePoint < fileSize ? std::min(fileSize, startingZonePoint + std::min(size, fileSize)) : startingZonePoint;
    uint64 position       = startingZonePoint;
    do {
        const uint64 remaining = end > position ? end - position : 0;
        const auto zoneData    = obj->GetData().Get(position, static_cast<uint32>(std::min<uint64>(remaining, UINT32_MAX)), false);
        if (zoneData.Empty())
            return false;
        if (!hash.Update(zoneData.GetData(), (uint32) zoneData.GetLength()))
            return false;
        position += zoneData.GetLength();
    } while (hashWholeZone && position < end);
    const auto hashValue = hash.GetHexValue();
    buffer.reserve(hashValue.size() + sizeof(DisassemblyZone));
    buffer.clear();
    buffer.insert(buffer.end(), (const std::byte*) hashValue.data(), (const std::byte*) hashValue.data() + hashValue.size());
    // field by field: the raw structure has padding bytes that are not initialized, they made the validation fail at random
    append_bytes(buffer, startingZonePoint);
    append_bytes(buffer, size);
    append_bytes(buffer, entryPoint);
    append_bytes(buffer, static_cast<uint32>(language));
    return true;
}

// caches saved before the field by field format contain the hash followed by the raw DisassemblyZone structure
static bool IsSameLegacyDisassemblyZone(const DissasmCacheEntry& entry, const std::vector<std::byte>& buffer, const DisassemblyZone& zone)
{
    constexpr size_t fieldsSize = 3 * sizeof(uint64) + sizeof(uint32);
    if (buffer.size() < fieldsSize || entry.size != buffer.size() - fieldsSize + sizeof(DisassemblyZone))
        return false;
    const size_t hashSize = buffer.size() - fieldsSize;
    if (memcmp(entry.data.get(), buffer.data(), hashSize) != 0)
        return false;
    DisassemblyZone cached{};
    memcpy(&cached, entry.data.get() + hashSize, sizeof(DisassemblyZone));
    return cached.startingZonePoint == zone.startingZonePoint && cached.size == zone.size && cached.entryPoint == zone.entryPoint &&
           cached.language == zone.language;
}

// Code zone records are keyed by the file offset of the zone. The records saved before were keyed by the first line of the zone, which
// depends on the view width and on the zones above it (collapsed, initialized or not): they are still read with the current first line.
static void FormatCodeZoneRecordName(LocalString<64>& zoneName, const DissasmCodeZone& zone)
{
    zoneName.SetFormat("DissasmCodeZone.%llu", static_cast<unsigned long long>(zone.zoneDetails.startingZonePoint));
}

static auto FindCodeZoneRecord(DissasmCache& cache, const DissasmCodeZone& zone)
{
    LocalString<64> zoneName;
    FormatCodeZoneRecordName(zoneName, zone);
    auto it = cache.zonesData.find(zoneName.GetText());
    if (it != cache.zonesData.end())
        return it;
    zoneName.SetFormat("DissasmParseZoneType.%u", zone.startLineIndex); // legacy key, with the current layout
    return cache.zonesData.find(zoneName.GetText());
}

constexpr std::string_view LEGACY_CODE_ZONE_RECORD_PREFIX     = "DissasmParseZoneType.";
constexpr std::string_view UNAPPLIED_CODE_ZONE_RECORD_PREFIX = "DissasmCodeZoneUnapplied.";

// the line of a legacy record name ("DissasmParseZoneType.<line>")
static std::optional<uint32> GetLegacyCodeZoneRecordLine(std::string_view name)
{
    if (!name.starts_with(LEGACY_CODE_ZONE_RECORD_PREFIX) || name.size() == LEGACY_CODE_ZONE_RECORD_PREFIX.size())
        return {};
    uint64 line = 0;
    for (const char c : name.substr(LEGACY_CODE_ZONE_RECORD_PREFIX.size())) {
        if (c < '0' || c > '9')
            return {};
        line = line * 10u + static_cast<uint64>(c - '0');
        if (line > UINT32_MAX)
            return {};
    }
    return static_cast<uint32>(line);
}

void GView::View::DissasmViewer::MigrateLegacyCodeZoneRecords(DissasmCache& cache, const std::vector<std::unique_ptr<ParseZone>>& zones)
{
    // the legacy records ordered by their line: the old layout placed the zones in the order of their file offsets as well
    std::map<uint32, std::string> legacyRecords;
    for (const auto& [name, entry] : cache.zonesData) {
        const auto line = GetLegacyCodeZoneRecordLine(name);
        if (line.has_value())
            legacyRecords.emplace(line.value(), name);
    }
    if (legacyRecords.empty())
        return;

    // the code zones (in the order of their file offsets) that have no record under their file offset key
    LocalString<64> zoneName;
    size_t codeZonesCount = 0;
    std::vector<const DissasmCodeZone*> zonesWithoutRecord;
    for (const auto& zone : zones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        codeZonesCount++;
        const auto codeZone = static_cast<const DissasmCodeZone*>(zone.get());
        FormatCodeZoneRecordName(zoneName, *codeZone);
        if (!cache.zonesData.contains(zoneName.GetText()))
            zonesWithoutRecord.push_back(codeZone);
    }
    if (zonesWithoutRecord.empty())
        return;

    auto moveRecord = [&cache, &zoneName](const std::string& legacyName, const DissasmCodeZone& zone) {
        auto node = cache.zonesData.extract(legacyName);
        if (node.empty())
            return;
        FormatCodeZoneRecordName(zoneName, zone);
        node.key() = zoneName.GetText();
        cache.zonesData.insert(std::move(node));
    };

    // The old saves wrote a record for every code zone: when no zone has a new record and there is one legacy record per zone, the
    // records belong to the zones in the same order (the textSize used for the old lines is unknown, but it does not change the order).
    if (zonesWithoutRecord.size() == codeZonesCount && legacyRecords.size() == codeZonesCount) {
        size_t index = 0;
        for (const auto& [line, name] : legacyRecords)
            moveRecord(name, *zonesWithoutRecord[index++]);
        return;
    }
    // otherwise only a record that can not belong to another zone: the only legacy record for the only zone without a record
    if (zonesWithoutRecord.size() == 1 && legacyRecords.size() == 1)
        moveRecord(legacyRecords.begin()->second, *zonesWithoutRecord[0]);
    // the other legacy records are still found with the line of the current layout (FindCodeZoneRecord) and they are kept on save
}

void Instance::LoadCacheData()
{
    if (!config.EnableDeepScanDissasmOnStart)
        return;
    // memory-only task content: no disk interaction at all (a stale cache could also belong to another file)
    if (GView::Security::Learning::Hooks::IsMemoryOnlyObject(obj))
        return;
    const std::filesystem::path path = DissasmCache::GetCacheFilePath(obj->GetPath(), config.CacheSameLocationAsAnalyzedFile);
    std::error_code ec;
    const bool cacheFileExists = std::filesystem::exists(path, ec);
    if (!cacheData.LoadCacheFile(path.u16string()) || !settings->ValidateCacheData(cacheData, obj)) {
        cacheData.ClearCache(true);
        // the next save replaces it: its annotations are kept in a copy instead of being lost
        cacheData.keepBackupOnSave = cacheFileExists;
        return;
    }
    cacheData.hasCache = true;
    // the records keyed by the first line of the zone (old layout) are moved to the file offset key of their zone
    MigrateLegacyCodeZoneRecords(cacheData, settings->parseZones);
}

void Instance::SaveCacheData()
{
    if (!config.EnableDeepScanDissasmOnStart)
        return;
    // The cache persists annotations (comments, labels) next to the analysed file. Memory-only task content must never
    // leave a trace on disk, and a disabled Export feature covers annotation exports as well.
    if (GView::Security::Learning::Hooks::IsMemoryOnlyObject(obj) ||
        GView::App::IsFeatureRestricted(GView::Security::RestrictedMode::Feature::Export))
        return;
    // the code zones that were not initialized in this session (never drawn) have no data of their own: their loaded records are
    // kept as they are (under the file offset key) instead of being overwritten with empty records
    LocalString<64> zoneName;
    std::unordered_map<std::string, DissasmCacheEntry> keptRecords;
    std::unordered_set<std::string> claimedRecords;
    std::unordered_set<std::string> mergedRecords; // the records kept aside that a zone merged: its data has them now
    for (auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto* dissasmZone = (DissasmCodeZone*) zone.get();
        if (dissasmZone->mergedUnappliedRecord) {
            zoneName.SetFormat("DissasmCodeZoneUnapplied.%llu", static_cast<unsigned long long>(dissasmZone->zoneDetails.startingZonePoint));
            mergedRecords.insert(zoneName.GetText());
        }
        auto record = FindCodeZoneRecord(cacheData, *dissasmZone);
        if (record == cacheData.zonesData.end())
            continue;
        claimedRecords.insert(record->first);
        if (dissasmZone->CanReachAsmLines()) {
            if (!dissasmZone->cacheRecordRejected)
                continue; // applied: the zone writes its data below
            // the record could not be applied to this analysis: kept aside instead of being lost under the record written below
            zoneName.SetFormat("DissasmCodeZoneUnapplied.%llu", static_cast<unsigned long long>(dissasmZone->zoneDetails.startingZonePoint));
            // an older record kept aside stays as it is, unless the zone merged it
            if (!cacheData.zonesData.contains(zoneName.GetText()) || mergedRecords.contains(zoneName.GetText()))
                keptRecords.insert_or_assign(zoneName.GetText(), std::move(record->second));
            continue;
        }
        FormatCodeZoneRecordName(zoneName, *dissasmZone);
        keptRecords.insert_or_assign(zoneName.GetText(), std::move(record->second));
    }
    // the records of no zone: the legacy records that were not matched to a zone and the records kept aside before
    for (auto& [name, entry] : cacheData.zonesData) {
        if (claimedRecords.contains(name) || mergedRecords.contains(name) || !entry.data)
            continue;
        if (name.starts_with(LEGACY_CODE_ZONE_RECORD_PREFIX) || name.starts_with(UNAPPLIED_CODE_ZONE_RECORD_PREFIX))
            keptRecords.try_emplace(name, std::move(entry));
    }

    // everything is rebuilt below (a previous save of this session left its records, adding them again would fail)
    cacheData.ClearCache(true);
    if (!settings->SaveToCache(cacheData, obj))
        return;

    std::vector<std::byte> buffer;
    for (auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto* dissasmZone = (DissasmCodeZone*) zone.get();
        FormatCodeZoneRecordName(zoneName, *dissasmZone);
        if (!dissasmZone->CanReachAsmLines()) {
            auto kept = keptRecords.find(zoneName.GetText());
            if (kept != keptRecords.end()) {
                cacheData.zonesData.insert_or_assign(kept->first, std::move(kept->second));
                keptRecords.erase(kept);
            }
            continue;
        }
        if (!dissasmZone->ToBuffer(buffer))
            return;
        if (!cacheData.AddRegion(zoneName.GetText(), buffer.data(), (uint32) buffer.size()))
            return;
    }
    // the records kept aside and the legacy records of no zone
    for (auto& [name, entry] : keptRecords)
        if (entry.data)
            cacheData.zonesData.try_emplace(name, std::move(entry));

    const std::filesystem::path path = DissasmCache::GetCacheFilePath(obj->GetPath(), config.CacheSameLocationAsAnalyzedFile);
    cacheData.SaveCacheFile(path.u16string());
}

bool SettingsData::SaveToCache(DissasmCache& cache, Reference<GView::Object> obj)
{
    std::vector<std::byte> buffer;
    LocalString<64> zoneName;
    for (auto& [start, zone] : disassemblyZones) {
        // the version 1 record (the hash of the first data cache window): the readers of version 1 still validate the file
        if (!zone.ToBuffer(buffer, obj, false))
            return false;
        zoneName.SetFormat("DisassemblyZone.%llu", start);
        if (!cache.AddRegion(zoneName.GetText(), buffer.data(), (uint32) buffer.size()))
            return false;
        // version 2: the hash of the whole zone (a change after the first window is found as well)
        if (!zone.ToBuffer(buffer, obj, true))
            return false;
        zoneName.SetFormat("DisassemblyZoneHash.%llu", start);
        if (!cache.AddRegion(zoneName.GetText(), buffer.data(), (uint32) buffer.size()))
            return false;
    }
    return true;
}

bool SettingsData::ValidateCacheData(DissasmCache& cache, Reference<GView::Object> obj)
{
    std::vector<std::byte> buffer;
    LocalString<64> zoneName;
    for (auto& [start, zone] : disassemblyZones) {
        // every version: the version 1 record (or the raw structure written before the field by field format)
        zoneName.SetFormat("DisassemblyZone.%llu", start);
        const auto entry = cache.zonesData.find(zoneName.GetText());
        if (entry == cache.zonesData.end() || !zone.ToBuffer(buffer, obj, false))
            return false;
        const bool isSameZone = IsSameLegacyDisassemblyZone(entry->second, buffer, zone) ||
                                (entry->second.size == buffer.size() && memcmp(entry->second.data.get(), buffer.data(), buffer.size()) == 0);
        if (!isSameZone)
            return false;

        // from version 2: the whole zone
        if (cache.fileVersion < 2)
            continue;
        zoneName.SetFormat("DisassemblyZoneHash.%llu", start);
        const auto hashEntry = cache.zonesData.find(zoneName.GetText());
        if (hashEntry == cache.zonesData.end() || !zone.ToBuffer(buffer, obj, true))
            return false;
        if (hashEntry->second.size != buffer.size() || memcmp(hashEntry->second.data.get(), buffer.data(), buffer.size()) != 0)
            return false;
    }
    return true;
}

// Code zone records: [magic][version] then
//  - version 3: [comments by anchor][label names by address][local variables][decimal operands]. Nothing depends on the lines: a record
//    applies to any analysis of the zone, what this analysis does not find (a label, a variable) is kept for later.
//  - versions 1 and 2 (read only): [comments by line][annotations by line][local variables] and, from version 2, [decimal operands].
// The records saved before the local variables existed start directly with the comments count (a count equal to the magic is not a
// realistic value) and their lines do not contain the variable lines.
constexpr uint32 DISSASM_CODE_ZONE_CACHE_MAGIC   = 0x5A434447; // "GDCZ"
constexpr uint32 DISSASM_CODE_ZONE_CACHE_VERSION = 3;
constexpr uint32 DISSASM_MAX_LABEL_NAME_SIZE     = 1024;

// decimal operands: [count] then count x [instruction address (uint64)][numbers mask (uint32)]
static void DecimalOperandsToBuffer(const std::map<uint64, uint32>& decimalOperands, std::vector<std::byte>& buffer)
{
    append_bytes(buffer, static_cast<uint32>(decimalOperands.size()));
    for (const auto& [address, mask] : decimalOperands) {
        append_bytes(buffer, address);
        append_bytes(buffer, mask);
    }
}

static bool DecimalOperandsFromBuffer(const std::byte*& start, const std::byte* end, std::map<uint64, uint32>& decimalOperands)
{
    constexpr size_t RECORD_SIZE = sizeof(uint64) + sizeof(uint32);
    uint32 count                 = 0;
    if (!read_primitive(start, end, count) || count > static_cast<size_t>(end - start) / RECORD_SIZE)
        return false;
    for (uint32 i = 0; i < count; i++) {
        uint64 address = 0;
        uint32 mask    = 0;
        if (!read_primitive(start, end, address) || !read_primitive(start, end, mask))
            return false;
        if (mask != 0)
            decimalOperands[address] = mask;
    }
    return true;
}

// label names of the user: [count] then count x [relative address of the label (uint64)][name size (uint32)][name]
static void LabelNamesToBuffer(const std::vector<std::pair<uint64, std::string>>& names, std::vector<std::byte>& buffer)
{
    append_bytes(buffer, static_cast<uint32>(names.size()));
    for (const auto& [address, name] : names) {
        append_bytes(buffer, address);
        append_string(buffer, name);
    }
}

static bool LabelNamesFromBuffer(const std::byte*& start, const std::byte* end, std::vector<std::pair<uint64, std::string>>& names)
{
    constexpr size_t MINIMUM_RECORD_SIZE = sizeof(uint64) + sizeof(uint32);
    uint32 count                         = 0;
    if (!read_primitive(start, end, count) || count > static_cast<size_t>(end - start) / MINIMUM_RECORD_SIZE)
        return false;
    names.reserve(count);
    for (uint32 i = 0; i < count; i++) {
        uint64 address        = 0;
        uint32 nameSize       = 0;
        const std::byte* name = nullptr;
        if (!read_primitive(start, end, address) || !read_primitive(start, end, nameSize) || nameSize == 0 || nameSize > DISSASM_MAX_LABEL_NAME_SIZE ||
            !read_bytes(start, end, nameSize, name))
            return false;
        names.emplace_back(address, std::string(reinterpret_cast<const char*>(name), nameSize));
    }
    return true;
}

bool DissasmCodeZone::ToBuffer(std::vector<std::byte>& buffer) const
{
    buffer.clear(); // the same buffer is used for every zone
    append_bytes(buffer, DISSASM_CODE_ZONE_CACHE_MAGIC);
    append_bytes(buffer, DISSASM_CODE_ZONE_CACHE_VERSION);
    userComments.ToBuffer(buffer);
    LabelNamesToBuffer(GetUserLabelNames(), buffer);
    localVariables.ToBuffer(buffer);
    DecimalOperandsToBuffer(decimalOperands, buffer);
    return true;
}

// Version 3: the variables of the record are matched by function start and frame offset. The names are given to the variables of the
// analysis, the variables of a function of the record that the record does not have were removed by the user. The functions the
// analysis does not find are ignored.
static void ApplyAddressKeyedVariables(DissasmCodeZone& zone, const DissasmLocalVariables& variables, bool& zoneLinesChanged)
{
    std::vector<uint32> removedLines;
    for (const auto& [line, details] : zone.dissasmType.annotations.mappings) {
        if (!IsLocalVariableAnnotation(details))
            continue;
        const auto cachedFunction = variables.FindFunctionByStart(GetLocalVariableAnnotationFunction(details.second));
        if (cachedFunction && !cachedFunction->FindVariable(GetLocalVariableAnnotationOffset(details.second)))
            removedLines.push_back(line); // sorted: the annotations are ordered by line
    }
    for (const auto& cachedFunction : variables.functions) {
        auto freshFunction = zone.localVariables.FindFunctionByStart(cachedFunction.startAddress);
        if (!freshFunction)
            continue;
        for (const auto& cachedVariable : cachedFunction.variables) {
            auto freshVariable = freshFunction->FindVariable(cachedVariable.frameOffset);
            if (freshVariable && freshVariable->name != cachedVariable.name && !freshFunction->HasVariableNamed(cachedVariable.name))
                freshVariable->name = cachedVariable.name;
        }
    }
    if (removedLines.empty())
        return;
    for (const uint32 line : removedLines) {
        const auto value    = zone.dissasmType.annotations.mappings.at(line).second;
        const auto function = zone.localVariables.FindFunctionByStart(GetLocalVariableAnnotationFunction(value));
        if (!function)
            continue;
        if (const auto variable = function->FindVariable(GetLocalVariableAnnotationOffset(value)))
            function->variables.erase(function->variables.begin() + (variable - function->variables.data()));
        if (function->variables.empty())
            zone.localVariables.functions.erase(zone.localVariables.functions.begin() + (function - zone.localVariables.functions.data()));
    }
    zone.RemoveRootAnnotationLines(removedLines);
    zoneLinesChanged = true;
}

// a version 3 record: [comments][label names][local variables][decimal operands]
struct AddressKeyedZoneRecord {
    DissasmUserComments comments;
    std::vector<std::pair<uint64, std::string>> labelNames;
    DissasmLocalVariables variables;
    std::map<uint64, uint32> decimalOperands;

    bool LoadFromBuffer(const std::byte*& start, const std::byte* end)
    {
        return comments.LoadFromBuffer(start, end) && LabelNamesFromBuffer(start, end, labelNames) && variables.LoadFromBuffer(start, end) &&
               DecimalOperandsFromBuffer(start, end, decimalOperands);
    }
};

// the version 3 record in `data`; none for another version or a corrupted record
static std::optional<AddressKeyedZoneRecord> ReadAddressKeyedZoneRecord(const DissasmCacheEntry& entry)
{
    const std::byte* start = entry.data.get();
    const std::byte* end   = start + entry.size;
    uint32 magic = 0, version = 0;
    if (!read_primitive(start, end, magic) || magic != DISSASM_CODE_ZONE_CACHE_MAGIC || !read_primitive(start, end, version) || version != 3)
        return {};
    AddressKeyedZoneRecord record;
    if (!record.LoadFromBuffer(start, end))
        return {};
    return record;
}

// The cache file is untrusted: it can only rename the labels / variables found by the analysis, remove variables and add comments.
// Everything is validated against the freshly analyzed zone before anything is committed.
static bool ApplyCachedZoneData(
      DissasmCodeZone& zone, DissasmComments& comments, AnnotationContainer& annotations, DissasmLocalVariables& variables, bool& zoneLinesChanged)
{
    auto& root = zone.dissasmType;
    if (!root.internalTypes.empty())
        return false; // loaded right after the zone initialization

    // every cached variable is one of the analyzed variables (renamed or not), the missing ones were removed by the user
    for (auto& cachedFunction : variables.functions) {
        const auto freshFunction = zone.localVariables.FindFunctionByStart(cachedFunction.startAddress);
        if (!freshFunction || freshFunction->endAddress != cachedFunction.endAddress)
            return false;
        for (auto& cachedVariable : cachedFunction.variables) {
            const auto freshVariable = freshFunction->FindVariable(cachedVariable.frameOffset);
            if (!freshVariable)
                return false;
            cachedVariable.size = freshVariable->size; // the analysis is the reference for everything but the name
        }
    }

    std::vector<uint32> removedLines;
    for (const auto& [line, details] : root.annotations.mappings) {
        if (!IsLocalVariableAnnotation(details))
            continue;
        const auto function = variables.FindFunctionByStart(GetLocalVariableAnnotationFunction(details.second));
        if (!function || !function->FindVariable(GetLocalVariableAnnotationOffset(details.second)))
            removedLines.push_back(line);
    }

    // the cached layout must be the analyzed layout without the removed variables lines
    if (annotations.mappings.size() + removedLines.size() != root.annotations.mappings.size())
        return false;
    auto cachedIt        = annotations.mappings.begin();
    size_t removedBefore = 0;
    for (const auto& [line, details] : root.annotations.mappings) {
        if (removedBefore < removedLines.size() && removedLines[removedBefore] == line) {
            removedBefore++;
            continue;
        }
        if (cachedIt == annotations.mappings.end() || cachedIt->first != line - removedBefore)
            return false;
        if (IsLocalVariableAnnotation(details) != IsLocalVariableAnnotation(cachedIt->second) || details.second != cachedIt->second.second)
            return false;
        ++cachedIt;
    }

    const uint32 linesCount = zone.asmLinesCount + static_cast<uint32>(annotations.mappings.size());
    for (auto& [key, text] : comments.comments) {
        if (key + 1u < linesCount) // comments are keyed by line - 1 (line 0 wraps to UINT32_MAX)
            root.commentsData.comments.insert_or_assign(key, std::move(text));
    }
    root.annotations    = std::move(annotations);
    zone.localVariables = std::move(variables);
    if (!removedLines.empty()) {
        const auto removedCount = static_cast<uint32>(removedLines.size());
        root.indexZoneEnd -= std::min(removedCount, root.indexZoneEnd);
        root.workingIndexZoneEnd = root.indexZoneEnd;
        zone.offsetCacheMaxLine  = 0;
        zone.ResetTypesReferenceList();
        zoneLinesChanged = true;
    }
    return true;
}

// Records saved before the local variables: their lines are moved below the variables lines inserted since then.
static bool ApplyLegacyCachedZoneData(DissasmCodeZone& zone, DissasmComments& comments, AnnotationContainer& annotations)
{
    auto& root = zone.dissasmType;
    if (!root.internalTypes.empty())
        return false; // loaded right after the zone initialization

    std::vector<uint32> variableLines;
    for (const auto& [line, details] : root.annotations.mappings)
        if (IsLocalVariableAnnotation(details))
            variableLines.push_back(line);

    // the legacy line L is the analyzed line N = L + (variable lines placed before N); both sequences are sorted so one pass is enough
    size_t variableIndex = 0;
    uint32 shift         = 0;
    auto mapLine         = [&](uint32 line) {
        uint32 mapped = line + shift;
        while (variableIndex < variableLines.size() && variableLines[variableIndex] <= mapped) {
            variableIndex++;
            shift++;
            mapped++;
        }
        return mapped;
    };

    std::vector<std::pair<uint32, std::string>> labels;
    labels.reserve(annotations.mappings.size());
    for (auto& [line, details] : annotations.mappings) {
        const uint32 mapped = mapLine(line);
        const auto fresh    = root.annotations.find(mapped);
        // only the names of the analyzed labels can change, anything else is ignored (it never adds lines)
        if (IsLocalVariableAnnotation(details) || fresh == root.annotations.end() || IsLocalVariableAnnotation(fresh->second) ||
            fresh->second.second != details.second)
            continue;
        labels.emplace_back(mapped, std::move(details.first));
    }

    const uint32 linesCount = zone.asmLinesCount + static_cast<uint32>(root.annotations.size());
    std::vector<std::pair<uint32, std::string>> mappedComments;
    mappedComments.reserve(comments.comments.size());
    variableIndex = 0;
    shift         = 0;
    for (auto& [key, text] : comments.comments) {
        const uint32 line = key + 1u; // comments are keyed by line - 1 (line 0 wraps to UINT32_MAX and is the last key)
        if (line == 0) {
            mappedComments.emplace_back(key, std::move(text));
            continue;
        }
        const uint32 mapped = mapLine(line);
        if (mapped < linesCount)
            mappedComments.emplace_back(mapped - 1u, std::move(text));
    }

    for (auto& [line, name] : labels)
        root.annotations.mappings[line].first = std::move(name);
    for (auto& [initialName, currentName] : annotations.initial_name_to_current_name)
        root.annotations.initial_name_to_current_name.insert_or_assign(initialName, currentName);
    for (auto& [currentName, initialName] : annotations.current_name_to_initial_name)
        root.annotations.current_name_to_initial_name.insert_or_assign(currentName, initialName);
    for (auto& [key, text] : mappedComments)
        root.commentsData.comments.insert_or_assign(key, std::move(text));
    return true;
}

// Records saved when the analysis found fewer labels (e.g. the code after an undecodable byte was not decoded before): every cached
// line is placed on the line of the same label (address), local variable or instruction (index) of the analysis. All or nothing: when
// something can not be placed the zone is left unchanged and the record is kept aside on save.
static bool ApplyRemappedCachedZoneData(
      DissasmCodeZone& zone, DissasmComments& comments, AnnotationContainer& annotations, DissasmLocalVariables& variables, bool& zoneLinesChanged)
{
    auto& root = zone.dissasmType;
    if (!root.internalTypes.empty())
        return false; // loaded right after the zone initialization

    // the lines of the analysis: one label per address, one line per local variable
    std::unordered_map<uint64, uint32> freshLabelLines;
    std::unordered_map<uint64, uint32> freshVariableLines;
    std::vector<uint32> freshAnnotationLines;
    for (const auto& [line, details] : root.annotations.mappings) {
        (IsLocalVariableAnnotation(details) ? freshVariableLines : freshLabelLines).emplace(details.second, line);
        freshAnnotationLines.push_back(line);
    }

    // every cached label and variable exists in the analysis
    std::vector<uint32> cachedAnnotationLines;
    for (const auto& [line, details] : annotations.mappings) {
        cachedAnnotationLines.push_back(line);
        if (IsLocalVariableAnnotation(details)) {
            const auto function = variables.FindFunctionByStart(GetLocalVariableAnnotationFunction(details.second));
            if (!freshVariableLines.contains(details.second) || !function || !function->FindVariable(GetLocalVariableAnnotationOffset(details.second)))
                return false;
        } else if (!freshLabelLines.contains(details.second)) {
            return false;
        }
    }
    for (const auto& cachedFunction : variables.functions) {
        const auto freshFunction = zone.localVariables.FindFunctionByStart(cachedFunction.startAddress);
        if (!freshFunction)
            return false;
        for (const auto& cachedVariable : cachedFunction.variables)
            if (!freshFunction->FindVariable(cachedVariable.frameOffset))
                return false;
    }

    // the variables removed by the user: the analyzed variables of a cached function that the record does not have (the functions
    // the record does not know are new, their variables stay)
    std::vector<uint32> removedLines;
    for (const auto& [line, details] : root.annotations.mappings) {
        if (!IsLocalVariableAnnotation(details))
            continue;
        const auto cachedFunction = variables.FindFunctionByStart(GetLocalVariableAnnotationFunction(details.second));
        if (cachedFunction && !cachedFunction->FindVariable(GetLocalVariableAnnotationOffset(details.second)))
            removedLines.push_back(line); // sorted: the annotations are ordered by line
    }

    // cached line -> line of the analysis (without the removed variable lines)
    auto mapLine = [&](uint32 line) -> std::optional<uint32> {
        uint32 freshLine   = 0;
        const auto cached  = annotations.mappings.find(line);
        if (cached != annotations.mappings.end()) {
            const auto& lines = IsLocalVariableAnnotation(cached->second) ? freshVariableLines : freshLabelLines;
            freshLine         = lines.at(cached->second.second); // checked above
        } else {
            // the instruction index: the line without the text lines placed before it
            const auto textLinesBefore = static_cast<uint32>(
                  std::lower_bound(cachedAnnotationLines.begin(), cachedAnnotationLines.end(), line) - cachedAnnotationLines.begin());
            const uint32 instruction = line - textLinesBefore;
            if (instruction >= zone.asmLinesCount)
                return {};
            // the same instruction moved down by every text line of the analysis placed before it
            freshLine = instruction;
            for (const uint32 annotationLine : freshAnnotationLines) {
                if (annotationLine > freshLine)
                    break;
                freshLine++;
            }
        }
        return freshLine - static_cast<uint32>(std::lower_bound(removedLines.begin(), removedLines.end(), freshLine) - removedLines.begin());
    };

    // comments are keyed by line - 1 (line 0 lives at UINT32_MAX); the comments after the last instruction are ignored (as for the
    // records that match the analysis)
    std::vector<std::pair<uint32, std::string>> mappedComments;
    mappedComments.reserve(comments.comments.size());
    for (auto& [key, text] : comments.comments) {
        const auto mapped = mapLine(key + 1u);
        if (mapped.has_value())
            mappedComments.emplace_back(mapped.value() - 1u, std::move(text));
    }

    // the labels renamed by the user (the cached name is not its initial name), on the line of the same label of the analysis
    std::vector<std::pair<uint32, std::string>> renamedLabels;
    for (const auto& [line, details] : annotations.mappings) {
        if (IsLocalVariableAnnotation(details))
            continue;
        const auto initialName = annotations.current_name_to_initial_name.find(details.first);
        if (initialName == annotations.current_name_to_initial_name.end() || initialName->second == details.first)
            continue;
        const uint32 freshLine = freshLabelLines.at(details.second);
        if (root.annotations.mappings.at(freshLine).first == details.first)
            continue;
        if (root.annotations.contains_annotation_name(details.first))
            return false; // the analysis has another label with this name
        renamedLabels.emplace_back(freshLine, details.first);
    }

    // nothing can fail from here on
    for (const auto& [line, name] : renamedLabels) {
        const std::string freshName = root.annotations.mappings.at(line).first;
        root.annotations.add_name_change(freshName, name, line);
    }
    for (const auto& cachedFunction : variables.functions) {
        auto freshFunction = zone.localVariables.FindFunctionByStart(cachedFunction.startAddress);
        for (const auto& cachedVariable : cachedFunction.variables)
            freshFunction->FindVariable(cachedVariable.frameOffset)->name = cachedVariable.name;
    }
    if (!removedLines.empty()) {
        for (const uint32 line : removedLines) {
            const auto value    = root.annotations.mappings.at(line).second;
            const auto function = zone.localVariables.FindFunctionByStart(GetLocalVariableAnnotationFunction(value));
            if (!function)
                continue;
            if (const auto variable = function->FindVariable(GetLocalVariableAnnotationOffset(value)))
                function->variables.erase(function->variables.begin() + (variable - function->variables.data()));
            if (function->variables.empty())
                zone.localVariables.functions.erase(zone.localVariables.functions.begin() + (function - zone.localVariables.functions.data()));
        }
        zone.RemoveRootAnnotationLines(removedLines);
        zoneLinesChanged = true;
    }
    for (auto& [key, text] : mappedComments)
        root.commentsData.comments.insert_or_assign(key, std::move(text));
    return true;
}

bool DissasmCodeZone::TryLoadDataFromCache(DissasmCache& cache, bool& zoneLinesChanged)
{
    zoneLinesChanged      = false;
    cacheRecordRejected   = false;
    mergedUnappliedRecord = false;
    if (!cache.hasCache)
        return true;
    if (zoneType != DissasmParseZoneType::DissasmCodeParseZone)
        return false;
    const bool loaded = TryLoadCodeZoneRecord(cache, zoneLinesChanged);
    // a record that an older version could not apply (it was kept aside): its comments and names come back
    MergeUnappliedRecord(cache);
    return loaded;
}

bool DissasmCodeZone::TryLoadCodeZoneRecord(DissasmCache& cache, bool& zoneLinesChanged)
{
    auto it = FindCodeZoneRecord(cache, *this);
    if (it == cache.zonesData.end())
        return false;
    // until it is applied: a record that can not be applied is kept aside by the next save (SaveCacheData)
    cacheRecordRejected = true;
    if (!dissasmType.internalTypes.empty())
        return false; // loaded right after the zone initialization

    // version 3: everything is keyed by address / anchor, it applies to this analysis whatever its lines are
    if (auto record = ReadAddressKeyedZoneRecord(it->second); record.has_value()) {
        ApplyAddressKeyedVariables(*this, record->variables, zoneLinesChanged);
        for (const auto& [address, name] : record->labelNames)
            ApplyUserLabelName(address, name);
        userComments = std::move(record->comments);
        const uint64 codeSize = GetCodeSize();
        for (const auto& [address, mask] : record->decimalOperands)
            if (codeSize == 0 || address < codeSize)
                decimalOperands[address] = mask;
        cacheRecordRejected = false;
        return true;
    }

    const std::byte* dataPtr    = it->second.data.get();
    const std::byte* dataPtrEnd = dataPtr + it->second.size;

    DissasmComments comments;
    AnnotationContainer annotations;

    uint32 magic = 0;
    if (!read_primitive(dataPtr, dataPtrEnd, magic))
        return false;
    if (magic == DISSASM_CODE_ZONE_CACHE_MAGIC) {
        uint32 version = 0;
        if (!read_primitive(dataPtr, dataPtrEnd, version) || version < 1 || version > 2) // a corrupted version 3 record, or a newer one
            return false;
        DissasmLocalVariables variables;
        if (!comments.LoadFromBuffer(dataPtr, dataPtrEnd) || !annotations.LoadFromBuffer(dataPtr, dataPtrEnd) || !variables.LoadFromBuffer(dataPtr, dataPtrEnd))
            return false;
        std::map<uint64, uint32> cachedDecimalOperands; // version 1 records do not have them
        if (version >= 2 && !DecimalOperandsFromBuffer(dataPtr, dataPtrEnd, cachedDecimalOperands))
            return false;
        // the same layout as the analysis, or (the analysis found more labels since the record was saved) the same labels and
        // instructions placed on their new lines
        if (!ApplyCachedZoneData(*this, comments, annotations, variables, zoneLinesChanged) &&
            !ApplyRemappedCachedZoneData(*this, comments, annotations, variables, zoneLinesChanged))
            return false;
        // the addresses are only display preferences: the ones outside of the code are ignored
        const uint64 codeSize = GetCodeSize();
        for (const auto& [address, mask] : cachedDecimalOperands)
            if (codeSize == 0 || address < codeSize)
                decimalOperands[address] = mask;
        MigrateLegacyLabelNames(); // the records saved before the VA names
        MoveLineCommentsToAnchors();
        cacheRecordRejected = false;
        return true;
    }

    // legacy record: the first value was the comments count
    dataPtr = it->second.data.get();
    if (!comments.LoadFromBuffer(dataPtr, dataPtrEnd))
        return false;
    if (!annotations.LoadFromBuffer(dataPtr, dataPtrEnd))
        return false;
    if (!ApplyLegacyCachedZoneData(*this, comments, annotations))
        return false;
    MigrateLegacyLabelNames();
    MoveLineCommentsToAnchors();
    cacheRecordRejected = false;
    return true;
}

void DissasmCodeZone::MergeUnappliedRecord(DissasmCache& cache)
{
    LocalString<64> recordName;
    recordName.SetFormat("%.*s%llu",
                         static_cast<int>(UNAPPLIED_CODE_ZONE_RECORD_PREFIX.size()),
                         UNAPPLIED_CODE_ZONE_RECORD_PREFIX.data(),
                         static_cast<unsigned long long>(zoneDetails.startingZonePoint));
    const auto it = cache.zonesData.find(recordName.GetText());
    if (it == cache.zonesData.end() || !it->second.data || !CanReachAsmLines())
        return;
    // only the address keyed records can be merged into an analysis that already has its data (the line keyed ones need their layout)
    auto record = ReadAddressKeyedZoneRecord(it->second);
    if (!record.has_value())
        return;
    // the data of the zone wins: only what it does not have is added
    for (auto& [anchor, text] : record->comments.comments)
        userComments.comments.try_emplace(anchor, std::move(text));
    const auto currentNames = GetUserLabelNames();
    for (const auto& [address, name] : record->labelNames) {
        const bool named = std::any_of(currentNames.begin(), currentNames.end(), [address](const auto& entry) { return entry.first == address; });
        if (!named)
            ApplyUserLabelName(address, name);
    }
    for (const auto& [address, mask] : record->decimalOperands)
        decimalOperands.try_emplace(address, mask);
    mergedUnappliedRecord = true;
}
