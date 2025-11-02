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
    std::vector<uint8> buffer;
    buffer.resize((uint32) fileSize);
    cacheFile.Read(reinterpret_cast<char*>(buffer.data()), (uint32)fileSize);
    cacheFile.Close();

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
    buffer.insert(buffer.end(), reinterpret_cast<const std::byte*>(this), reinterpret_cast<const std::byte*>(this) + sizeof(DisassemblyZone));
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

    std::vector<std::byte> buffer;
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
        if (entry.size != buffer.size())
            return false;
        if (memcmp(entry.data.get(), buffer.data(), buffer.size()) != 0)
            return false;
    }
    return true;
}

bool DissasmCodeZone::ToBuffer(std::vector<std::byte>& buffer) const
{
    uint32 reserveSize = dissasmType.commentsData.GetRequiredSizeForSerialization();
    reserveSize += dissasmType.annotations.GetRequiredSizeForSerialization();
    buffer.reserve(reserveSize);

    // comments
    dissasmType.commentsData.ToBuffer(buffer);
    // annotations
    dissasmType.annotations.ToBuffer(buffer);
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
    const std::byte* dataPtr    = it->second.data.get();
    const std::byte* dataPtrEnd = dataPtr + it->second.size;

    if (dataPtr + sizeof(uint32) > dataPtrEnd)
        return false;

        // comments
    if (!dissasmType.commentsData.LoadFromBuffer(dataPtr, dataPtrEnd))
        return false;
    // annotations
    if (!dissasmType.annotations.LoadFromBuffer(dataPtr, dataPtrEnd))
        return false;

    return true;
}