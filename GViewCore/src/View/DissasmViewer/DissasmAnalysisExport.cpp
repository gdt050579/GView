#include "DissasmAnalysisExport.hpp"
#include "DissasmCodeZone.hpp"
#include "x86_x64/X86InstructionInfo.hpp"

#include <nlohmann/json.hpp>

using namespace GView::View::DissasmViewer;
using nlohmann::json;

namespace
{
std::string Hex(uint64 value)
{
    char text[24];
    snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
    return text;
}

std::string_view AnchorKindName(DissasmCommentAnchor::Kind kind)
{
    switch (kind) {
    case DissasmCommentAnchor::Kind::Label:
        return "label";
    case DissasmCommentAnchor::Kind::Variable:
        return "variable";
    default:
        return "instruction";
    }
}

json CommentsToJson(const DissasmUserComments& comments, uint64 labelBase)
{
    json list = json::array();
    for (const auto& [anchor, text] : comments.comments) {
        json item = { { "address", Hex(labelBase + anchor.address) }, { "kind", AnchorKindName(anchor.kind) }, { "text", text } };
        if (anchor.kind == DissasmCommentAnchor::Kind::Variable)
            item["frameOffset"] = anchor.frameOffset;
        list.push_back(std::move(item));
    }
    return list;
}

// the cache of the file (next to it, or in the folder of the user): the comments and the names of the user
void LoadAnalysisCache(DissasmCache& cache, Reference<GView::Object> obj, SettingsData* settings)
{
    for (const bool sameLocation : { true, false }) {
        const auto path = DissasmCache::GetCacheFilePath(obj->GetPath(), sameLocation);
        std::error_code error;
        if (!std::filesystem::exists(path, error))
            continue;
        if (cache.LoadCacheFile(path.u16string()) && settings->ValidateCacheData(cache, obj)) {
            cache.hasCache = true;
            MigrateLegacyCodeZoneRecords(cache, settings->parseZones);
            return;
        }
        cache.ClearCache(true);
    }
}

json ZoneToJson(DissasmCodeZone& zone, SettingsData* settings, const DissasmCodeZoneInitData& initData)
{
    const uint64 base       = zone.labelAddressBase;
    const auto& details     = zone.zoneDetails;
    const auto findImport   = [settings, &zone](const X86OperandsInfo& operands) { return FindX86OperandsImport(settings, &zone, operands); };
    json result             = { { "language", details.language == DisassemblyLanguage::x64 ? "x64" : "x86" },
                                { "fileOffset", Hex(details.startingZonePoint) },
                                { "size", Hex(details.size) },
                                { "entryPoint", Hex(base + (details.entryPoint - details.startingZonePoint)) },
                                { "addresses", base != details.startingZonePoint ? "VA" : "file offset" } };

    json functions = json::array();
    for (const auto& function : zone.GetFunctions(&settings->functionEntries)) {
        json item = { { "address", Hex(base + function.start) }, { "name", function.name }, { "size", function.size }, { "xrefs", function.xrefs } };
        item["kind"] = function.isEntryPoint ? "entry" : (function.isExport ? "export" : (function.isThunk ? "thunk" : "function"));
        json callers = json::array();
        for (const auto& caller : zone.GetCallers(function.start))
            callers.push_back({ { "function", caller.function }, { "site", Hex(base + caller.site) }, { "tailJump", caller.isTailJump } });
        json callees = json::array();
        for (const auto& callee : zone.GetCallees(function.start, findImport)) {
            json entry = { { "function", callee.function }, { "site", Hex(base + callee.site) }, { "tailJump", callee.isTailJump } };
            entry["address"] = callee.functionStart.has_value() ? json(Hex(base + callee.functionStart.value())) : json(nullptr); // an import
            callees.push_back(std::move(entry));
        }
        item["callers"] = std::move(callers);
        item["callees"] = std::move(callees);
        if (const auto name = zone.suggestedNames.find(function.start); name != zone.suggestedNames.end())
            item["suggestedName"] = name->second;
        functions.push_back(std::move(item));
    }
    result["functions"] = std::move(functions);

    json strings = json::array();
    for (const auto& string : zone.GetReferencedStrings(initData.addressToFileOffset)) {
        // the preview is quoted: "ascii" or L"utf-16"
        const bool isWide     = string.text.starts_with("L\"");
        const size_t skip     = isWide ? 2u : 1u;
        const std::string text = string.text.size() > skip ? string.text.substr(skip, string.text.size() - skip - 1u) : std::string();
        strings.push_back({ { "address", Hex(string.address) }, { "encoding", isWide ? "utf-16" : "ascii" }, { "text", text }, { "xrefs", string.xrefs } });
    }
    result["strings"] = std::move(strings);

    std::vector<std::pair<uint64, uint32>> switchJumps(zone.switchJumps.begin(), zone.switchJumps.end());
    std::sort(switchJumps.begin(), switchJumps.end());
    json switches = json::array();
    for (const auto& [address, cases] : switchJumps)
        switches.push_back({ { "address", Hex(base + address) }, { "cases", cases } });
    result["switches"] = std::move(switches);

    json names = json::array();
    for (const auto& [address, name] : zone.GetUserLabelNames())
        names.push_back({ { "address", Hex(base + address) }, { "name", name } });
    result["names"]      = std::move(names);
    result["comments"]   = CommentsToJson(zone.userComments, base);
    result["aiComments"] = CommentsToJson(zone.aiComments, base);
    return result;
}
} // namespace

bool GView::View::DissasmViewer::BuildAnalysisJson(Reference<GView::Object> obj, Settings& viewerSettings, std::string& json, std::string& error)
{
    std::unique_ptr<SettingsData> settings(static_cast<SettingsData*>(viewerSettings.data));
    viewerSettings.data = nullptr;
    if (!settings || !obj.IsValid()) {
        error = "There is no disassembly to analyze!";
        return false;
    }
    if (settings->disassemblyZones.empty()) {
        error = "The file has no disassembly zone!";
        return false;
    }
    // the code zones of the viewer
    for (const auto& [start, details] : settings->disassemblyZones) {
        auto zone         = std::make_unique<DissasmCodeZone>();
        zone->zoneType    = DissasmParseZoneType::DissasmCodeParseZone;
        zone->zoneDetails = details;
        settings->parseZones.push_back(std::move(zone));
    }
    DissasmCache cache;
    LoadAnalysisCache(cache, obj, settings.get());

    const auto pathText = std::filesystem::path(obj->GetPath()).u8string();
    nlohmann::json root = { { "file", std::string(reinterpret_cast<const char*>(pathText.data()), pathText.size()) } };
    nlohmann::json zones = nlohmann::json::array();
    for (const auto& parseZone : settings->parseZones) {
        const auto zone = static_cast<DissasmCodeZone*>(parseZone.get());
        DissasmCodeZoneInitData initData{};
        initData.enableDeepScanDissasmOnStart  = true; // at once: there is no window to show a partial analysis
        initData.enableLocalVariablesDetection = true;
        initData.visibleRows                   = 1;
        PrepareCodeZoneInitData(settings.get(), obj, zone, initData);
        if (!zone->InitZone(initData)) {
            zones.push_back({ { "fileOffset", Hex(zone->zoneDetails.startingZonePoint) }, { "error", "the zone could not be disassembled" } });
            continue;
        }
        bool zoneLinesChanged = false;
        if (cache.hasCache)
            zone->TryLoadDataFromCache(cache, zoneLinesChanged);
        zones.push_back(ZoneToJson(*zone, settings.get(), initData));
    }
    root["zones"] = std::move(zones);
    json          = root.dump(2);
    return true;
}
