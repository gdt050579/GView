#include "DissasmAnalysisExport.hpp"
#include "DissasmCodeZone.hpp"
#include "DissasmChainedFixups.hpp"
#include "DissasmObjC.hpp"
#include "DissasmRtti.hpp"
#include "DissasmAnnotations.hpp"
#include "DissasmSignatures.hpp"
#include "DissasmFunctionUtils.hpp"
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
    json result             = { { "language", zone.GetArchitectureName() },
                                { "name", details.name },
                                { "kind", details.isData ? "data" : "code" },
                                { "fileOffset", details.isUninitialized ? json(nullptr) : json(Hex(details.startingZonePoint)) },
                                { "uninitialized", details.isUninitialized },
                                { "size", Hex(details.size) },
                                { "entryPoint", details.HasEntryPoint() ? json(Hex(base + (details.entryPoint - details.startingZonePoint))) : json(nullptr) },
                                { "addresses", base != details.startingZonePoint ? "VA" : "file offset" } };

    json functions = json::array();
    for (const auto& function : zone.GetFunctions(&settings->functionEntries)) {
        json item = { { "address", Hex(base + function.start) }, { "name", function.name }, { "size", function.size }, { "xrefs", function.xrefs } };
        item["kind"] = function.isEntryPoint ? "entry" : (function.isExport ? "export" : (function.isThunk ? "thunk" : "function"));
        if (function.isNoReturn)
            item["noreturn"] = true;
        if (function.apiCategories != 0) { // the triage: "net", "crypto", ...
            json tags        = json::array();
            const auto names = FormatApiCategories(function.apiCategories);
            for (size_t start = 0; start < names.size();) {
                const size_t end = std::min(names.find(' ', start), names.size());
                tags.push_back(names.substr(start, end - start));
                start = end + 1;
            }
            item["tags"] = std::move(tags);
        }
        if (!function.chunks.empty()) { // IDA: the function chunks (tails)
            json chunks = json::array();
            for (const auto& [chunkStart, chunkEnd] : function.chunks)
                chunks.push_back({ { "address", Hex(base + chunkStart) }, { "size", chunkEnd - chunkStart } });
            item["chunks"] = std::move(chunks);
        }
        if (const auto* frame = zone.localVariables.FindFunctionByStart(function.start)) { // the variables the APIs tell something about, the structures
            json variables = json::array();
            for (const auto& variable : frame->variables)
                if (!variable.origin.empty() || variable.structure)
                    variables.push_back(
                          { { "name", variable.name }, { "frameOffset", variable.frameOffset }, { "type", variable.type }, { "origin", variable.origin } });
            if (!variables.empty())
                item["variables"] = std::move(variables);
        }
        json callers = json::array();
        for (const auto& caller : zone.GetCallers(function.start))
            callers.push_back({ { "function", caller.function },
                                { "site", Hex((caller.zone ? caller.zone->labelAddressBase : base) + caller.site) },
                                { "tailJump", caller.isTailJump } });
        json callees = json::array();
        for (const auto& callee : zone.GetCallees(function.start, findImport)) {
            json entry = { { "function", callee.function }, { "site", Hex(base + callee.site) }, { "tailJump", callee.isTailJump } };
            const uint64 calleeBase = callee.zone ? callee.zone->labelAddressBase : base; // a function of another section
            entry["address"]        = callee.functionStart.has_value() ? json(Hex(calleeBase + callee.functionStart.value())) : json(nullptr); // an import
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

bool GView::View::DissasmViewer::BuildAnalysisJson(
      Reference<GView::Object> obj, Settings& viewerSettings, std::string& json, std::string& error, const DissasmAnalysisOptions& options)
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
    ApplyChainedFixups(*settings, obj); // Mach-O: the pointers and the import slots that dyld writes
    ApplyObjCMetadata(*settings, obj);  // Mach-O: the Objective-C methods, the selector / class references
    ApplyCppRtti(*settings, obj);       // C++: the vtables, the type descriptors / typeinfo objects
    // the code zones of the viewer
    for (const auto& [start, details] : settings->disassemblyZones) {
        auto zone         = std::make_unique<DissasmCodeZone>();
        zone->zoneType    = DissasmParseZoneType::DissasmCodeParseZone;
        zone->zoneDetails = details;
        settings->parseZones.push_back(std::move(zone));
    }
    LinkCodeZones(settings->parseZones);
    DissasmCache cache;
    LoadAnalysisCache(cache, obj, settings.get());

    const auto pathText = std::filesystem::path(obj->GetPath()).u8string();
    nlohmann::json root = { { "file", std::string(reinterpret_cast<const char*>(pathText.data()), pathText.size()) } };
    // every zone is analyzed first: the annotations and the signatures apply to all of them; the code zones before the data zones (their
    // labels are the places the code refers to)
    std::vector<DissasmCodeZoneInitData> initDatas(settings->parseZones.size());
    std::vector<DissasmCodeZone*> analyzedZones;
    std::vector<size_t> order;
    for (const bool data : { false, true })
        for (size_t index = 0; index < settings->parseZones.size(); index++)
            if (static_cast<DissasmCodeZone*>(settings->parseZones[index].get())->zoneDetails.isData == data)
                order.push_back(index);
    for (const size_t index : order) {
        const auto zone = static_cast<DissasmCodeZone*>(settings->parseZones[index].get());
        auto& initData  = initDatas[index];
        initData.enableDeepScanDissasmOnStart  = true; // at once: there is no window to show a partial analysis
        initData.enableLocalVariablesDetection = true;
        initData.visibleRows                   = 1;
        PrepareCodeZoneInitData(settings.get(), obj, zone, initData);
        if (cache.hasCache) { // the data defined by the user (D / A): the lines are counted with them; the functions of the user (P)
            zone->userDataRanges = ReadUserDataRanges(cache, *zone);
            zone->userFunctions  = ReadUserFunctions(cache, *zone);
            zone->userVariableStructures = ReadUserVariableStructures(cache, *zone);
            zone->operandStructures      = ReadOperandStructures(cache, *zone);
            zone->bookmarks              = ReadBookmarks(cache, *zone);
            zone->repeatableComments     = ReadRepeatableComments(cache, *zone);
            zone->userPrototypes         = ReadUserPrototypes(cache, *zone);
        }
        if (!zone->InitZone(initData))
            continue;
        bool zoneLinesChanged = false;
        if (cache.hasCache)
            zone->TryLoadDataFromCache(cache, zoneLinesChanged);
        analyzedZones.push_back(zone);
    }

    std::string optionError;
    if (options.annotations) {
        DissasmAnnotationsImport result;
        const auto reanalyze = [&](DissasmCodeZone& zone) { // the data ranges of the document: a new analysis of the zone
            for (size_t index = 0; index < settings->parseZones.size(); index++)
                if (settings->parseZones[index].get() == &zone) {
                    DissasmAnnotationsImport imported;
                    return ReanalyzeCodeZone(zone, initDatas[index], imported);
                }
            return false;
        };
        if (ImportAnnotationsDocument(*options.annotations, analyzedZones, result, optionError, reanalyze))
            root["annotationsImport"] = { { "zones", result.zones },
                                          { "names", result.names },
                                          { "comments", result.comments },
                                          { "variables", result.variables },
                                          { "decimalOperands", result.decimalOperands },
                                          { "collapsibleZones", result.collapsibleZones },
                                          { "suggestions", result.suggestedNames + result.aiComments },
                                          { "dataRanges", result.dataRanges },
                                          { "functions", result.functions },
                                          { "variableStructures", result.structures },
                                          { "operandStructures", result.operandStructures },
                                          { "bookmarks", result.bookmarks },
                                          { "repeatableComments", result.repeatableComments },
                                          { "prototypes", result.prototypes },
                                          { "skipped", result.skipped } };
        else
            root["annotationsImport"] = { { "error", optionError } };
    }
    if (options.signatures) {
        DissasmSignaturesApply result;
        if (ApplySignaturesDocument(*options.signatures, analyzedZones, result, optionError))
            root["signaturesApply"] = { { "signatures", result.signatures }, { "named", result.named }, { "ambiguous", result.ambiguous } };
        else
            root["signaturesApply"] = { { "error", optionError } };
    }
    if (options.signaturesOutput)
        *options.signaturesOutput = BuildSignaturesDocument(analyzedZones);
    // the listings (IDA's .asm of a batch run): the zones in the order of the file, with the names, the comments and the arguments of the
    // known APIs (the known functions of the view: AddKnownFunctions) as the F8 export writes them
    if (options.listingOutput) {
        options.listingOutput->clear();
        AsmData asmData;
        AddKnownFunctions(asmData);
        std::string listing;
        for (const auto& parseZone : settings->parseZones) {
            auto* zone = static_cast<DissasmCodeZone*>(parseZone.get());
            if (std::find(analyzedZones.begin(), analyzedZones.end(), zone) == analyzedZones.end() ||
                !DissasmCodeZone::IsNativeCodeLanguage(zone->zoneDetails.language) || !zone->CanReachAsmLines())
                continue;
            if (BuildX86AsmListing(*zone, obj, settings.get(), &asmData, listing))
                options.listingOutput->append(listing).append("\n");
        }
    }

    nlohmann::json zones = nlohmann::json::array();
    for (size_t index = 0; index < settings->parseZones.size(); index++) {
        const auto zone = static_cast<DissasmCodeZone*>(settings->parseZones[index].get());
        if (std::find(analyzedZones.begin(), analyzedZones.end(), zone) == analyzedZones.end())
            zones.push_back({ { "fileOffset", Hex(zone->zoneDetails.startingZonePoint) }, { "error", "the zone could not be disassembled" } });
        else
            zones.push_back(ZoneToJson(*zone, settings.get(), initDatas[index]));
    }
    root["zones"] = std::move(zones);
    // the names come from the file: a damaged file has names that are not UTF-8 (U+FFFD in the document, dump would throw)
    json          = root.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
    return true;
}
