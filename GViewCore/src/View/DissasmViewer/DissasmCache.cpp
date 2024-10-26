#include "DissasmCache.hpp"
#include "DissasmViewer.hpp"
#include "DissasmCodeZone.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

void DissasmCache::ClearCache(bool forceClear)
{
    if (!hasCache && !forceClear)
        return;
    zonesData.clear();
    if (cacheFile.is_open())
        cacheFile.close();
    zonesData.clear();
}

bool DissasmCache::AddRegion(std::string regionName, const AppCUI::uint8* data, AppCUI::uint32 size)
{
    if (zonesData.contains(regionName))
        return false;
    DissasmCacheEntry entry = { std::make_unique<uint8[]>(size), size };
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
    cacheFile.open(location, std::ios::out | std::ios::binary);
    if (!cacheFile.is_open())
        return false;
    const uint32 zonesCount = (uint32) zonesData.size();
    uint32 entrySize;
    cacheFile.write((const char*) &zonesCount, sizeof(zonesCount));
    for (auto& [name, entry] : zonesData) {
        entrySize = (uint32) name.size();
        cacheFile.write((const char*) &entrySize, sizeof(entrySize));
        cacheFile.write(name.data(), entrySize);

        entrySize = entry.size;
        cacheFile.write((const char*) &entrySize, sizeof(entrySize));
        cacheFile.write(reinterpret_cast<const char*>(entry.data.get()), entry.size);
    }
    cacheFile.close();
    return true;
}

bool DissasmCache::LoadCacheFile(std::u16string_view location)
{
    cacheFile.open(location, std::ios::in | std::ios::binary);
    if (!cacheFile.is_open())
        return false;
    cacheFile.seekg(0, std::ios::end);
    const auto fileSize = cacheFile.tellg();
    cacheFile.seekg(0, std::ios::beg);
    if (fileSize == -1)
        return false;
    if (fileSize == 0)
        return true;
    std::vector<uint8> buffer;
    buffer.resize((uint32) fileSize);
    cacheFile.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    cacheFile.close();

    if (fileSize < sizeof(uint32))
        return false;

    uint32 offset     = 0;
    uint32 zonesCount = 0;
    memcpy(&zonesCount, buffer.data() + offset, sizeof(zonesCount));
    offset += sizeof(zonesCount);

    while (offset < buffer.size()) {
        if (zonesCount-- == 0)
            return false;
        uint32 entrySize;
        memcpy(&entrySize, buffer.data() + offset, sizeof(entrySize));
        offset += sizeof(entrySize);
        if (offset + entrySize > buffer.size())
            return false;
        const auto entryDataName = buffer.data() + offset;
        offset += entrySize;
        if (offset > buffer.size())
            return false;
        std::string_view entryName = { (const char*) entryDataName, entrySize };

        if (offset + sizeof(uint32) > buffer.size())
            return false;
        memcpy(&entrySize, buffer.data() + offset, sizeof(entrySize));
        offset += sizeof(entrySize);
        if (offset + entrySize > buffer.size())
            return false;
        const auto entryData = buffer.data() + offset;
        offset += entrySize;
        if (offset > buffer.size())
            return false;

        auto newCacheEntry = DissasmCacheEntry{ std::make_unique<uint8[]>(entrySize), entrySize };
        memcpy(newCacheEntry.data.get(), entryData, entrySize);
        zonesData.emplace(entryName, std::move(newCacheEntry));
    }
    return true;
}

bool DisassemblyZone::ToBuffer(std::vector<uint8>& buffer, Reference<GView::Object> obj) const
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
    buffer.insert(buffer.end(), hashValue.data(), hashValue.data() + hashValue.size());
    buffer.insert(buffer.end(), reinterpret_cast<const uint8*>(this), reinterpret_cast<const uint8*>(this) + sizeof(DisassemblyZone));
    return true;
}

void Instance::LoadCacheData()
{
    if (!config.EnableDeepScanDissasmOnStart)
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
    cacheData.ClearCache(); // TODO: optimise this better? maybe clear cache after loading
    if (!settings->SaveToCache(cacheData, obj))
        return;

    std::vector<uint8> buffer;
    LocalString<64> zoneName;
    for (auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto* dissasmZone = (DissasmCodeZone*) zone.get();
        if (!dissasmZone->ToBuffer(buffer))
            return;
        zoneName.SetFormat("DissasmParseZoneType.%llu", zone->startLineIndex);
        if (!cacheData.AddRegion(zoneName.GetText(), buffer.data(), (uint32) buffer.size()))
            return;
    }

    constexpr char16 currentLoc  = '.';
    const auto cacheDataLocation = config.CacheSameLocationAsAnalyzedFile ? obj->GetPath() : std::u16string_view(&currentLoc, 1);

    const std::filesystem::path path = DissasmCache::GetCacheFilePath(obj->GetPath(), config.CacheSameLocationAsAnalyzedFile);
    cacheData.SaveCacheFile(path.u16string());
}

bool SettingsData::SaveToCache(DissasmCache& cache, Reference<GView::Object> obj)
{
    std::vector<uint8> buffer;
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
    std::vector<uint8> buffer;
    LocalString<64> zoneName;
    for (auto& [start, zone] : disassemblyZones) {
        zoneName.SetFormat("DisassemblyZone.%llu", start);
        if (!cache.zonesData.contains(zoneName.GetText()))
            return false;
        const auto& entry = cache.zonesData[zoneName.GetText()];
        if (!zone.ToBuffer(buffer, obj))
            return false;
        if (entry.size != buffer.size())
            return false;
        auto data1 = entry.data.get();
        auto data2 = buffer.data();
        if (memcmp(entry.data.get(), buffer.data(), buffer.size()) != 0)
            return false;
    }
    return true;
}

bool DissasmCodeZone::ToBuffer(std::vector<uint8>& buffer) const
{
    uint32 reserveSize = 0;
    for (const auto& comment : dissasmType.commentsData.comments) {
        reserveSize += sizeof(comment.first) + sizeof(uint32) + comment.second.size();
    }
    for (const auto& annotation : dissasmType.annotations) {
        reserveSize += sizeof(annotation.first) + sizeof(uint32) + annotation.second.first.size() + sizeof(annotation.second.second);
    }
    buffer.reserve(reserveSize);

    // comments
    uint32 entriesCount = (uint32) dissasmType.commentsData.comments.size();
    uint32 entryStringSizeCount;
    buffer.insert(buffer.end(), (const char*) &entriesCount, (const char*) &entriesCount + sizeof(entriesCount));
    for (const auto& comment : dissasmType.commentsData.comments) {
        buffer.insert(buffer.end(), (const char*) &comment.first, (const char*) &comment.first + sizeof(comment.first));
        entryStringSizeCount = (uint32) comment.second.size();
        buffer.insert(buffer.end(), (const char*) &entryStringSizeCount, (const char*) &entryStringSizeCount + sizeof(entryStringSizeCount));
        buffer.insert(buffer.end(), comment.second.data(), comment.second.data() + entryStringSizeCount);
    }

    // annotations
    entriesCount = (uint32) dissasmType.annotations.size();
    buffer.insert(buffer.end(), (const char*) &entriesCount, (const char*) &entriesCount + sizeof(entriesCount));
    for (const auto& annotation : dissasmType.annotations) {
        buffer.insert(buffer.end(), (const char*) &annotation.first, (const char*) &annotation.first + sizeof(annotation.first));

        entryStringSizeCount = (uint32) annotation.second.first.size();
        buffer.insert(buffer.end(), (const char*) &entryStringSizeCount, (const char*) &entryStringSizeCount + sizeof(entryStringSizeCount));
        buffer.insert(buffer.end(), annotation.second.first.data(), annotation.second.first.data() + entryStringSizeCount);

        buffer.insert(buffer.end(), (const char*) &annotation.second.second, (const char*) &annotation.second.second + sizeof(annotation.second.second));
    }

    return true;
}

bool DissasmCodeZone::TryLoadDataFromCache(DissasmCache& cache)
{
    if (!cache.hasCache)
        return true;
    if (zoneType != DissasmParseZoneType::DissasmCodeParseZone)
        return false;
    LocalString<64> zoneName;
    zoneName.SetFormat("DissasmParseZoneType.%llu", startLineIndex);

    auto it = cache.zonesData.find(zoneName.GetText());
    if (it == cache.zonesData.end())
        return false;
    auto dataPtr          = it->second.data.get();
    const auto dataPtrEnd = dataPtr + it->second.size;

    if (dataPtr + sizeof(uint32) > dataPtrEnd)
        return false;

    std::vector<uint8> buffer;
    buffer.reserve(512);

    uint32 commentsCount = *(uint32*) dataPtr;
    dataPtr += sizeof(uint32);

    while (commentsCount > 0) {
        if (dataPtr + sizeof(uint32) > dataPtrEnd)
            return false;
        const uint32 offset = *(uint32*) dataPtr;
        dataPtr += sizeof(uint32);

        if (dataPtr + sizeof(uint32) > dataPtrEnd)
            return false;
        const uint32 commLen = *(uint32*) dataPtr;
        if (dataPtr + commLen > dataPtrEnd)
            return false;
        dataPtr += sizeof(uint32);
        buffer.clear();
        buffer.insert(buffer.end(), dataPtr, dataPtr + commLen);
        dataPtr += commLen;

        dissasmType.commentsData.comments[offset] = std::string((const char*)buffer.data(), commLen);
        --commentsCount;
    }

    if (dataPtr + sizeof(uint32) > dataPtrEnd)
        return false;
    uint32 annotationsCount = *(uint32*) dataPtr;
    dataPtr += sizeof(uint32);
    while (annotationsCount > 0) {
        if (dataPtr + sizeof(uint32) > dataPtrEnd)
            return false;
        const uint32 offset = *(uint32*) dataPtr;
        dataPtr += sizeof(uint32);

        if (dataPtr + sizeof(uint32) > dataPtrEnd)
            return false;
        const uint32 annLen = *(uint32*) dataPtr;
        if (dataPtr + annLen > dataPtrEnd)
            return false;
        dataPtr += sizeof(uint32);

        buffer.clear();
        buffer.insert(buffer.end(), dataPtr, dataPtr + annLen);
        dataPtr += annLen;

        if (dataPtr + sizeof(uint64) > dataPtrEnd)
            return false;
        const uint64 annValue = *(uint64*) dataPtr;
        dataPtr += sizeof(uint64);
        --annotationsCount;

        std::string annName((const char*)buffer.data(), annLen);
        dissasmType.annotations[offset] = { std::move(annName), annValue };
    }

    return true;
}