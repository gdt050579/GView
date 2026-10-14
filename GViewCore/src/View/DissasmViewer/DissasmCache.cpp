#include <filesystem>

#include "DissasmCache.hpp"
#include "DissasmViewer.hpp"
#include "DissasmCodeZone.hpp"
#include "DissasmIOHelpers.hpp"

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

std::filesystem::path DissasmCache::GetCacheFilePath(std::u16string_view fileLocation, bool cacheSameLocationAsAnalyzedFile)
{
    constexpr char16 currentLoc  = '.';
    const auto cacheDataLocation = cacheSameLocationAsAnalyzedFile ? fileLocation : std::u16string_view(&currentLoc, 1);

    std::filesystem::path path = cacheDataLocation;
    path += ".dissasm.cache";
    return path;
}
    
bool DissasmCache::SaveCacheFile(std::u16string_view location)
{
    if (zonesData.empty())
        return false;
    const std::filesystem::path filePath(location.begin(), location.end());
    bool created = cacheFile.Create(filePath, true);
    if (!created)
        return false;
    const uint32 zonesCount = (uint32) zonesData.size();
    uint32 entrySize;
    cacheFile.Write((const char*) &zonesCount, sizeof(zonesCount));
    for (auto& [name, entry] : zonesData) {
        entrySize = (uint32) name.size();
        cacheFile.Write((const char*) &entrySize, sizeof(entrySize));
        cacheFile.Write(name.data(), entrySize);

        entrySize = entry.size;
        cacheFile.Write((const char*) &entrySize, sizeof(entrySize));
        cacheFile.Write(reinterpret_cast<const char*>(entry.data.get()), entry.size);
    }
    cacheFile.Close();
    return true;
}

bool DissasmCache::LoadCacheFile(std::u16string_view location)
{
    const std::filesystem::path filePath(location.begin(), location.end());
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

        auto newCacheEntry = DissasmCacheEntry{ std::make_unique<std::byte[]>(entrySize), entrySize };
        memcpy(newCacheEntry.data.get(), entryData, entrySize);
        zonesData.emplace(entryName, std::move(newCacheEntry));
    }
    return true;
}

bool DisassemblyZone::ToBuffer(std::vector<std::byte>& buffer, Reference<GView::Object> obj) const
{
    Hashes::OpenSSLHash hash(Hashes::OpenSSLHashKind::Md5);
    const auto zoneData = obj->GetData().Get(startingZonePoint, (uint32) size, false);
    if (zoneData.Empty())
        return false;
    if (!hash.Update(zoneData.GetData(), (uint32) zoneData.GetLength()))
        return false;
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
    zoneName.SetFormat("DissasmParseZoneType.%u", zone.startLineIndex); // legacy key
    return cache.zonesData.find(zoneName.GetText());
}

void Instance::LoadCacheData()
{
    if (!config.EnableDeepScanDissasmOnStart)
        return;
    // memory-only task content: no disk interaction at all (a stale cache could also belong to another file)
    if (GView::Security::Learning::Hooks::IsMemoryOnlyObject(obj))
        return;
    const std::filesystem::path path = DissasmCache::GetCacheFilePath(obj->GetPath(), config.CacheSameLocationAsAnalyzedFile);
    if (!cacheData.LoadCacheFile(path.u16string())) {
        cacheData.ClearCache(true);
        return;
    }
    if (!settings->ValidateCacheData(cacheData, obj)) {
        cacheData.ClearCache(true);
        return;
    }
    cacheData.hasCache = true;
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
    // kept as they are instead of being overwritten with empty records
    LocalString<64> zoneName;
    std::unordered_map<std::string, DissasmCacheEntry> keptRecords;
    for (auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto* dissasmZone = (DissasmCodeZone*) zone.get();
        if (dissasmZone->CanReachAsmLines())
            continue;
        auto record = FindCodeZoneRecord(cacheData, *dissasmZone);
        if (record == cacheData.zonesData.end())
            continue;
        FormatCodeZoneRecordName(zoneName, *dissasmZone);
        keptRecords.insert_or_assign(zoneName.GetText(), std::move(record->second));
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
            if (kept != keptRecords.end())
                cacheData.zonesData.insert_or_assign(kept->first, std::move(kept->second));
            continue;
        }
        if (!dissasmZone->ToBuffer(buffer))
            return;
        if (!cacheData.AddRegion(zoneName.GetText(), buffer.data(), (uint32) buffer.size()))
            return;
    }

    const std::filesystem::path path = DissasmCache::GetCacheFilePath(obj->GetPath(), config.CacheSameLocationAsAnalyzedFile);
    cacheData.SaveCacheFile(path.u16string());
}

bool SettingsData::SaveToCache(DissasmCache& cache, Reference<GView::Object> obj)
{
    std::vector<std::byte> buffer;
    LocalString<64> zoneName;
    for (auto& [start, zone] : disassemblyZones) {
        if (!zone.ToBuffer(buffer, obj))
            return false;
        zoneName.SetFormat("DisassemblyZone.%llu", start);
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
        zoneName.SetFormat("DisassemblyZone.%llu", start);
        if (!cache.zonesData.contains(zoneName.GetText()))
            return false;
        const auto& entry = cache.zonesData[zoneName.GetText()];
        if (!zone.ToBuffer(buffer, obj))
            return false;
        if (IsSameLegacyDisassemblyZone(entry, buffer, zone))
            continue;
        if (entry.size != buffer.size())
            return false;
        if (memcmp(entry.data.get(), buffer.data(), buffer.size()) != 0)
            return false;
    }
    return true;
}

// Code zone records: [magic][version][comments][annotations][local variables] and, from version 2, [decimal operands]. The records saved
// before the local variables existed start directly with the comments count (a count equal to the magic is not a realistic value) and
// their lines do not contain the variable lines.
constexpr uint32 DISSASM_CODE_ZONE_CACHE_MAGIC   = 0x5A434447; // "GDCZ"
constexpr uint32 DISSASM_CODE_ZONE_CACHE_VERSION = 2;

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

bool DissasmCodeZone::ToBuffer(std::vector<std::byte>& buffer) const
{
    buffer.clear(); // the same buffer is used for every zone
    uint32 reserveSize = 2 * sizeof(uint32) + dissasmType.commentsData.GetRequiredSizeForSerialization();
    reserveSize += dissasmType.annotations.GetRequiredSizeForSerialization();
    buffer.reserve(reserveSize);

    append_bytes(buffer, DISSASM_CODE_ZONE_CACHE_MAGIC);
    append_bytes(buffer, DISSASM_CODE_ZONE_CACHE_VERSION);
    // comments
    dissasmType.commentsData.ToBuffer(buffer);
    // annotations
    dissasmType.annotations.ToBuffer(buffer);
    // local variables
    localVariables.ToBuffer(buffer);
    // numbers shown as decimal (version 2)
    DecimalOperandsToBuffer(decimalOperands, buffer);
    return true;
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

bool DissasmCodeZone::TryLoadDataFromCache(DissasmCache& cache, bool& zoneLinesChanged)
{
    zoneLinesChanged = false;
    if (!cache.hasCache)
        return true;
    if (zoneType != DissasmParseZoneType::DissasmCodeParseZone)
        return false;

    auto it = FindCodeZoneRecord(cache, *this);
    if (it == cache.zonesData.end())
        return false;
    const std::byte* dataPtr    = it->second.data.get();
    const std::byte* dataPtrEnd = dataPtr + it->second.size;

    DissasmComments comments;
    AnnotationContainer annotations;

    uint32 magic = 0;
    if (!read_primitive(dataPtr, dataPtrEnd, magic))
        return false;
    if (magic == DISSASM_CODE_ZONE_CACHE_MAGIC) {
        uint32 version = 0;
        if (!read_primitive(dataPtr, dataPtrEnd, version) || version < 1 || version > DISSASM_CODE_ZONE_CACHE_VERSION)
            return false;
        DissasmLocalVariables variables;
        if (!comments.LoadFromBuffer(dataPtr, dataPtrEnd) || !annotations.LoadFromBuffer(dataPtr, dataPtrEnd) || !variables.LoadFromBuffer(dataPtr, dataPtrEnd))
            return false;
        std::map<uint64, uint32> cachedDecimalOperands; // version 1 records do not have them
        if (version >= 2 && !DecimalOperandsFromBuffer(dataPtr, dataPtrEnd, cachedDecimalOperands))
            return false;
        if (!ApplyCachedZoneData(*this, comments, annotations, variables, zoneLinesChanged))
            return false;
        // the addresses are only display preferences: the ones outside of the code are ignored
        const uint64 codeSize = GetCodeSize();
        for (const auto& [address, mask] : cachedDecimalOperands)
            if (codeSize == 0 || address < codeSize)
                decimalOperands[address] = mask;
        return true;
    }

    // legacy record: the first value was the comments count
    dataPtr = it->second.data.get();
    if (!comments.LoadFromBuffer(dataPtr, dataPtrEnd))
        return false;
    if (!annotations.LoadFromBuffer(dataPtr, dataPtrEnd))
        return false;
    return ApplyLegacyCachedZoneData(*this, comments, annotations);
}