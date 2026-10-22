#include "DissasmAnnotations.hpp"
#include "DissasmCodeZone.hpp"
#include "x86_x64/DissasmX86LocalVariables.hpp"

using namespace GView::View::DissasmViewer;
using nlohmann::json;

namespace
{
constexpr size_t MAX_NAME_SIZE    = 1024;
constexpr size_t MAX_COMMENT_SIZE = 64 * 1024;

std::string Hex(uint64 value)
{
    char text[24];
    snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
    return text;
}

// the fields of the document (untrusted): the value of its type, the default for any other type (json::value throws for another type)
std::string JsonText(const json& item, const char* name, std::string_view fallback)
{
    const auto field = item.is_object() ? item.find(name) : item.end();
    return field != item.end() && field->is_string() ? field->get<std::string>() : std::string(fallback);
}

bool JsonBool(const json& item, const char* name)
{
    const auto field = item.is_object() ? item.find(name) : item.end();
    return field != item.end() && field->is_boolean() && field->get<bool>();
}

// "0x140001000" / "5368713216" / a number
std::optional<uint64> ParseAddress(const json& value)
{
    if (value.is_number_unsigned())
        return value.get<uint64>();
    if (!value.is_string())
        return {};
    const auto text = value.get<std::string>();
    if (text.empty())
        return {};
    try {
        size_t used        = 0;
        const uint64 result = std::stoull(text, &used, 0);
        return used == text.size() ? std::optional<uint64>(result) : std::nullopt;
    } catch (...) {
        return {};
    }
}

std::optional<std::string> StringField(const json& item, const char* name, size_t maxSize)
{
    const auto field = item.find(name);
    if (field == item.end() || !field->is_string())
        return {};
    auto text = field->get<std::string>();
    if (text.empty() || text.size() > maxSize)
        return {};
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

json AnchorToJson(const DissasmCommentAnchor& anchor, uint64 base)
{
    json item = { { "address", Hex(base + anchor.address) }, { "kind", AnchorKindName(anchor.kind) } };
    if (anchor.kind == DissasmCommentAnchor::Kind::Variable)
        item["frameOffset"] = anchor.frameOffset;
    return item;
}

json CommentsToJson(const DissasmUserComments& comments, uint64 base)
{
    json list = json::array();
    for (const auto& [anchor, text] : comments.comments) {
        auto item    = AnchorToJson(anchor, base);
        item["text"] = text;
        list.push_back(std::move(item));
    }
    return list;
}

// the relative address of an address of the document (rebased by the addressBase of the document); none outside the code
struct Rebase {
    uint64 documentBase;
    uint64 codeSize;
    std::optional<uint64> operator()(const json& value) const
    {
        const auto address = ParseAddress(value);
        if (!address.has_value())
            return {};
        const uint64 relative = address.value() - documentBase;
        return relative < codeSize ? std::optional<uint64>(relative) : std::nullopt;
    }
};

std::optional<DissasmCommentAnchor> AnchorFromJson(const json& item, const Rebase& rebase)
{
    if (!item.is_object() || !item.contains("address"))
        return {};
    const auto address = rebase(item["address"]);
    if (!address.has_value())
        return {};
    DissasmCommentAnchor anchor;
    anchor.address    = address.value();
    const auto kind   = JsonText(item, "kind", "instruction");
    if (kind == "label")
        anchor.kind = DissasmCommentAnchor::Kind::Label;
    else if (kind == "variable") {
        anchor.kind = DissasmCommentAnchor::Kind::Variable;
        if (!item.contains("frameOffset") || !item["frameOffset"].is_number_integer())
            return {};
        anchor.frameOffset = item["frameOffset"].get<int32>();
    } else if (kind != "instruction")
        return {};
    return anchor;
}

const json& ArrayField(const json& zoneJson, const char* name)
{
    static const json empty = json::array();
    const auto field        = zoneJson.find(name);
    return field != zoneJson.end() && field->is_array() ? *field : empty;
}
} // namespace

json GView::View::DissasmViewer::ExportZoneAnnotations(DissasmCodeZone& zone)
{
    const uint64 base = zone.labelAddressBase;
    json result       = { { "fileOffset", Hex(zone.zoneDetails.startingZonePoint) },
                          { "language", zone.GetArchitectureName() },
                          { "addressBase", Hex(base) } };

    json dataRanges = json::array();
    for (const auto& range : zone.userDataRanges)
        dataRanges.push_back({ { "address", Hex(base + range.start) }, { "size", range.end - range.start }, { "unit", range.unit } });
    if (!dataRanges.empty())
        result["dataRanges"] = std::move(dataRanges);

    // the functions of the user: created (P), deleted, their noreturn attribute (none: the one of the analysis)
    json functions = json::array();
    for (const auto& [address, flags] : zone.userFunctions) {
        json item = { { "address", Hex(base + address) } };
        if (flags & USER_FUNCTION_CREATE)
            item["create"] = true;
        if (flags & USER_FUNCTION_DELETE)
            item["delete"] = true;
        if (flags & (USER_FUNCTION_NORETURN | USER_FUNCTION_RETURNS))
            item["noreturn"] = (flags & USER_FUNCTION_NORETURN) != 0;
        functions.push_back(std::move(item));
    }
    if (!functions.empty())
        result["functions"] = std::move(functions);

    // the structures the user gave to the variables (Alt+Q; "": none, the one of the analysis is removed)
    json structures = json::array();
    for (const auto& [key, structure] : zone.userVariableStructures)
        structures.push_back({ { "function", Hex(base + key.first) }, { "frameOffset", key.second }, { "structure", structure } });
    if (!structures.empty())
        result["variableStructures"] = std::move(structures);

    // the structure offsets of the operands (T)
    json operands = json::array();
    for (const auto& [address, structure] : zone.operandStructures)
        operands.push_back({ { "address", Hex(base + address) }, { "structure", structure } });
    if (!operands.empty())
        result["operandStructures"] = std::move(operands);

    // the symbolic constants of the operands (M)
    json constants = json::array();
    for (const auto& [address, set] : zone.operandConstants)
        constants.push_back({ { "address", Hex(base + address) }, { "set", set } });
    if (!constants.empty())
        result["operandConstants"] = std::move(constants);

    // the bookmarks (Alt+M)
    json bookmarks = json::array();
    for (const auto& [address, description] : zone.bookmarks)
        bookmarks.push_back({ { "address", Hex(base + address) }, { "description", description } });
    if (!bookmarks.empty())
        result["bookmarks"] = std::move(bookmarks);

    // the repeatable comments (;)
    json repeatable = json::array();
    for (const auto& [address, text] : zone.repeatableComments)
        repeatable.push_back({ { "address", Hex(base + address) }, { "text", text } });
    if (!repeatable.empty())
        result["repeatableComments"] = std::move(repeatable);

    // the prototypes of the functions (Y)
    json prototypes = json::array();
    for (const auto& [address, text] : zone.userPrototypes)
        prototypes.push_back({ { "function", Hex(base + address) }, { "prototype", text } });
    if (!prototypes.empty())
        result["prototypes"] = std::move(prototypes);

    json names = json::array();
    for (const auto& [address, name] : zone.GetUserLabelNames())
        names.push_back({ { "address", Hex(base + address) }, { "name", name } });
    if (!names.empty())
        result["names"] = std::move(names);
    if (!zone.userComments.comments.empty())
        result["comments"] = CommentsToJson(zone.userComments, base);

    // the variables the user renamed (the others keep the names of the analysis)
    json variables = json::array();
    std::string defaultName;
    for (const auto& function : zone.localVariables.functions)
        for (const auto& variable : function.variables) {
            FormatDefaultLocalVariableName(variable.frameOffset, zone.Is64BitCode(), defaultName);
            if (variable.name != (variable.analysisName.empty() ? defaultName : variable.analysisName))
                variables.push_back({ { "function", Hex(base + function.startAddress) }, { "frameOffset", variable.frameOffset }, { "name", variable.name } });
        }
    if (!variables.empty())
        result["variables"] = std::move(variables);

    json decimals = json::array();
    for (const auto& [address, mask] : zone.decimalOperands)
        if (mask != 0)
            decimals.push_back({ { "address", Hex(base + address) }, { "mask", mask } });
    if (!decimals.empty())
        result["decimalOperands"] = std::move(decimals);

    json zones = json::array();
    for (const auto& collapsible : zone.GetCollapsibleZoneAnchors())
        zones.push_back({ { "first", AnchorToJson(collapsible.first, base) },
                          { "last", AnchorToJson(collapsible.last, base) },
                          { "name", collapsible.name },
                          { "collapsed", collapsible.isCollapsed } });
    if (!zones.empty())
        result["collapsibleZones"] = std::move(zones);

    if (!zone.aiComments.comments.empty())
        result["aiComments"] = CommentsToJson(zone.aiComments, base);
    json suggested = json::array();
    for (const auto& [address, name] : zone.suggestedNames)
        suggested.push_back({ { "address", Hex(base + address) }, { "name", name } });
    if (!suggested.empty())
        result["suggestedNames"] = std::move(suggested);
    return result;
}

json GView::View::DissasmViewer::BuildAnnotationsDocument(const std::vector<DissasmCodeZone*>& zones, std::string_view fileName)
{
    json document = { { "format", DISSASM_ANNOTATIONS_FORMAT }, { "version", DISSASM_ANNOTATIONS_VERSION }, { "file", fileName } };
    json list     = json::array();
    for (auto* zone : zones)
        list.push_back(ExportZoneAnnotations(*zone));
    document["zones"] = std::move(list);
    return document;
}

void GView::View::DissasmViewer::ImportZoneAnnotations(DissasmCodeZone& zone, const json& zoneJson, DissasmAnnotationsImport& result)
{
    const auto documentBase = zoneJson.contains("addressBase") ? ParseAddress(zoneJson["addressBase"]) : std::nullopt;
    const Rebase rebase{ documentBase.value_or(zone.labelAddressBase), zone.GetCodeSize() };

    // the data defined by the user: the zone needs a new analysis when they change
    if (zoneJson.contains("dataRanges")) {
        auto ranges = zone.userDataRanges;
        for (const auto& item : ArrayField(zoneJson, "dataRanges")) {
            const auto start = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
            const uint64 size = item.is_object() && item.contains("size") && item["size"].is_number_unsigned() ? item["size"].get<uint64>() : 0;
            const uint64 unit = item.is_object() && item.contains("unit") && item["unit"].is_number_unsigned() ? item["unit"].get<uint64>() : 99;
            const bool validUnit = DissasmInstructionSet::IsValidDataUnit(unit);
            if (!start.has_value() || size == 0 || size > zone.GetCodeSize() - start.value() || !validUnit) {
                result.skipped++;
                continue;
            }
            const DissasmInstructionSet::DataRange range{ start.value(), start.value() + size, static_cast<uint8>(unit) };
            ranges.erase(std::remove_if(ranges.begin(), ranges.end(), [&range](const auto& other) { return other.start < range.end && range.start < other.end; }),
                         ranges.end());
            ranges.insert(std::upper_bound(ranges.begin(), ranges.end(), range.start, [](uint64 value, const auto& other) { return value < other.start; }), range);
            result.dataRanges++;
        }
        if (ranges != zone.userDataRanges) {
            zone.userDataRanges = std::move(ranges);
            result.zonesToReanalyze.push_back(&zone);
        }
    }
    if (zoneJson.contains("functions")) {
        auto functions = zone.userFunctions;
        for (const auto& item : ArrayField(zoneJson, "functions")) {
            const auto address = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
            uint8 flags        = 0;
            if (item.is_object()) {
                if (JsonBool(item, "create"))
                    flags |= USER_FUNCTION_CREATE;
                if (JsonBool(item, "delete"))
                    flags |= USER_FUNCTION_DELETE;
                if (item.contains("noreturn") && item["noreturn"].is_boolean())
                    flags |= item["noreturn"].get<bool>() ? USER_FUNCTION_NORETURN : USER_FUNCTION_RETURNS;
            }
            if (!address.has_value() || flags == 0 || ((flags & USER_FUNCTION_CREATE) && (flags & USER_FUNCTION_DELETE))) {
                result.skipped++;
                continue;
            }
            functions[address.value()] = flags;
            result.functions++;
        }
        if (functions != zone.userFunctions) {
            zone.userFunctions = std::move(functions);
            if (std::find(result.zonesToReanalyze.begin(), result.zonesToReanalyze.end(), &zone) == result.zonesToReanalyze.end())
                result.zonesToReanalyze.push_back(&zone);
        }
    }

    if (zoneJson.contains("variableStructures")) {
        auto structures = zone.userVariableStructures;
        for (const auto& item : ArrayField(zoneJson, "variableStructures")) {
            const auto function  = item.is_object() && item.contains("function") ? rebase(item["function"]) : std::nullopt;
            const bool hasOffset = item.is_object() && item.contains("frameOffset") && item["frameOffset"].is_number_integer();
            const bool hasName   = item.is_object() && item.contains("structure") && item["structure"].is_string();
            const std::string name = hasName ? item["structure"].get<std::string>() : std::string();
            if (!function.has_value() || !hasOffset || !hasName || !IsValidUserStructureName(name)) {
                result.skipped++;
                continue;
            }
            structures[{ function.value(), item["frameOffset"].get<int32>() }] = name;
            result.structures++;
        }
        if (structures != zone.userVariableStructures) {
            zone.userVariableStructures = std::move(structures);
            if (std::find(result.zonesToReanalyze.begin(), result.zonesToReanalyze.end(), &zone) == result.zonesToReanalyze.end())
                result.zonesToReanalyze.push_back(&zone);
        }
    }

    for (const auto& item : ArrayField(zoneJson, "operandStructures")) {
        const auto address = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
        const bool hasName = item.is_object() && item.contains("structure") && item["structure"].is_string();
        const std::string name = hasName ? item["structure"].get<std::string>() : std::string();
        if (!address.has_value() || name.empty() || !IsValidUserStructureName(name)) {
            result.skipped++;
            continue;
        }
        zone.operandStructures[address.value()] = name;
        result.operandStructures++;
    }

    for (const auto& item : ArrayField(zoneJson, "operandConstants")) {
        const auto address = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
        const bool hasSet  = item.is_object() && item.contains("set") && item["set"].is_string();
        const std::string set = hasSet ? item["set"].get<std::string>() : std::string();
        if (!address.has_value() || !IsConstantSetName(set)) {
            result.skipped++;
            continue;
        }
        zone.operandConstants[address.value()] = set;
        result.operandConstants++;
    }

    if (zoneJson.contains("prototypes")) {
        auto prototypes = zone.userPrototypes;
        for (const auto& item : ArrayField(zoneJson, "prototypes")) {
            const auto function = item.is_object() && item.contains("function") ? rebase(item["function"]) : std::nullopt;
            const auto text     = item.is_object() ? StringField(item, "prototype", DISSASM_MAX_USER_PROTOTYPE_SIZE) : std::nullopt;
            if (!function.has_value() || !text.has_value() || !ParseUserPrototype(text.value())) {
                result.skipped++;
                continue;
            }
            prototypes[function.value()] = text.value();
            result.prototypes++;
        }
        if (prototypes != zone.userPrototypes) {
            zone.userPrototypes = std::move(prototypes);
            if (std::find(result.zonesToReanalyze.begin(), result.zonesToReanalyze.end(), &zone) == result.zonesToReanalyze.end())
                result.zonesToReanalyze.push_back(&zone);
        }
    }

    for (const auto& item : ArrayField(zoneJson, "repeatableComments")) {
        const auto address = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
        const auto text    = item.is_object() ? StringField(item, "text", DISSASM_MAX_REPEATABLE_COMMENT_SIZE) : std::nullopt;
        if (!address.has_value() || !text.has_value()) {
            result.skipped++;
            continue;
        }
        zone.repeatableComments[address.value()] = text.value();
        result.repeatableComments++;
    }

    for (const auto& item : ArrayField(zoneJson, "bookmarks")) {
        const auto address     = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
        const auto description = item.is_object() ? StringField(item, "description", DISSASM_MAX_BOOKMARK_SIZE) : std::nullopt;
        if (!address.has_value() || !description.has_value() || description->empty()) {
            result.skipped++;
            continue;
        }
        zone.bookmarks[address.value()] = description.value();
        result.bookmarks++;
    }

    for (const auto& item : ArrayField(zoneJson, "names")) {
        const auto address = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
        const auto name    = item.is_object() ? StringField(item, "name", MAX_NAME_SIZE) : std::nullopt;
        if (address.has_value() && name.has_value() && (zone.GetLabelNameAt(address.value()) == name.value() || zone.ApplyUserLabelName(address.value(), name.value())))
            result.names++;
        else
            result.skipped++;
    }
    for (const auto& item : ArrayField(zoneJson, "comments")) {
        const auto anchor = AnchorFromJson(item, rebase);
        const auto text   = item.is_object() ? StringField(item, "text", MAX_COMMENT_SIZE) : std::nullopt;
        if (anchor.has_value() && text.has_value()) {
            zone.userComments.Set(anchor.value(), text.value());
            result.comments++;
        } else
            result.skipped++;
    }
    for (const auto& item : ArrayField(zoneJson, "variables")) {
        const auto start = item.is_object() && item.contains("function") ? rebase(item["function"]) : std::nullopt;
        const auto name  = item.is_object() ? StringField(item, "name", DISSASM_MAX_LOCAL_VARIABLE_NAME_SIZE) : std::nullopt;
        auto* function   = start.has_value() ? zone.localVariables.FindFunctionByStart(start.value()) : nullptr;
        auto* variable   = function && item.contains("frameOffset") && item["frameOffset"].is_number_integer()
                                 ? function->FindVariable(item["frameOffset"].get<int32>())
                                 : nullptr;
        if (variable && name.has_value() && IsValidLocalVariableName(name.value()) && (variable->name == name.value() || !function->HasVariableNamed(name.value()))) {
            variable->name = name.value();
            result.variables++;
        } else
            result.skipped++;
    }
    for (const auto& item : ArrayField(zoneJson, "decimalOperands")) {
        const auto address = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
        if (address.has_value() && item.contains("mask") && item["mask"].is_number_unsigned() && item["mask"].get<uint64>() != 0 &&
            item["mask"].get<uint64>() <= 0xFFFFFFFFull) {
            zone.decimalOperands[address.value()] = static_cast<uint32>(item["mask"].get<uint64>());
            result.decimalOperands++;
        } else
            result.skipped++;
    }
    for (const auto& item : ArrayField(zoneJson, "aiComments")) {
        const auto anchor = AnchorFromJson(item, rebase);
        const auto text   = item.is_object() ? StringField(item, "text", MAX_COMMENT_SIZE) : std::nullopt;
        if (anchor.has_value() && text.has_value()) {
            zone.aiComments.Set(anchor.value(), text.value());
            result.aiComments++;
        } else
            result.skipped++;
    }
    for (const auto& item : ArrayField(zoneJson, "suggestedNames")) {
        const auto address = item.is_object() && item.contains("address") ? rebase(item["address"]) : std::nullopt;
        const auto name    = item.is_object() ? StringField(item, "name", MAX_NAME_SIZE) : std::nullopt;
        if (address.has_value() && name.has_value()) {
            zone.suggestedNames[address.value()] = name.value();
            result.suggestedNames++;
        } else
            result.skipped++;
    }

    // the collapsible zones are placed on the lines of their anchors (the names above are on the lines now)
    zone.RebuildLineIndex();
    std::vector<DissasmCodeZone::CollapsibleZoneAnchors> collapsibles;
    for (const auto& item : ArrayField(zoneJson, "collapsibleZones")) {
        const auto first = item.is_object() && item.contains("first") ? AnchorFromJson(item["first"], rebase) : std::nullopt;
        const auto last  = item.is_object() && item.contains("last") ? AnchorFromJson(item["last"], rebase) : std::nullopt;
        const auto name  = item.is_object() && item.contains("name") && item["name"].is_string() ? item["name"].get<std::string>() : std::string();
        if (first.has_value() && last.has_value() && name.size() <= MAX_NAME_SIZE)
            collapsibles.push_back({ first.value(), last.value(), name, JsonBool(item, "collapsed") });
        else
            result.skipped++;
    }
    if (!collapsibles.empty()) {
        const size_t before = zone.collapsibleZones.size();
        if (zone.ApplyCollapsibleZoneAnchors(collapsibles))
            result.zonesWithNewLines.push_back(&zone);
        const size_t placed = zone.collapsibleZones.size() - before;
        result.collapsibleZones += static_cast<uint32>(placed);
        result.skipped += static_cast<uint32>(collapsibles.size() - std::min(collapsibles.size(), placed));
        zone.RebuildLineIndex();
    }
    zone.ClearEditHistory();
    zone.asmPreCacheData.Clear();
    result.zones++;
}

bool GView::View::DissasmViewer::BeginCodeZoneReanalysis(DissasmCodeZone& zone, DissasmCodeZoneInitData& initData, DissasmReanalysis& state)
{
    state.annotations            = ExportZoneAnnotations(zone); // the data of the user, by address
    state.history                = zone.TakeEditHistory();
    zone.dissasmType.annotations = {}; // the labels of the previous analysis (the deep scan gives new ones)
    if (zone.InitZone(initData))
        return true;
    zone.RestoreEditHistory(std::move(state.history));
    return false;
}

void GView::View::DissasmViewer::FinishCodeZoneReanalysis(DissasmCodeZone& zone, DissasmReanalysis& state, DissasmAnnotationsImport& imported)
{
    ImportZoneAnnotations(zone, state.annotations, imported); // clears the history: it comes back after
    zone.RestoreEditHistory(std::move(state.history));
}

bool GView::View::DissasmViewer::ReanalyzeCodeZone(DissasmCodeZone& zone, DissasmCodeZoneInitData& initData, DissasmAnnotationsImport& imported)
{
    initData.deepScanBudget.reset(); // at once: the annotations need the labels
    initData.lineCountBudget.reset();
    DissasmReanalysis state;
    if (!BeginCodeZoneReanalysis(zone, initData, state))
        return false;
    FinishCodeZoneReanalysis(zone, state, imported);
    return true;
}

bool GView::View::DissasmViewer::ImportAnnotationsDocument(
      const json& document,
      const std::vector<DissasmCodeZone*>& zones,
      DissasmAnnotationsImport& result,
      std::string& error,
      const std::function<bool(DissasmCodeZone&)>& reanalyze)
{
    if (!ImportAnnotationsDocument(document, zones, result, error))
        return false;
    if (result.zonesToReanalyze.empty() || !reanalyze)
        return true;
    // the zones with new data ranges: a new analysis, then the document again (its names apply to the new labels)
    const auto zonesToReanalyze = result.zonesToReanalyze;
    std::vector<DissasmCodeZone*> reanalyzed;
    for (auto* zone : zonesToReanalyze)
        if (reanalyze(*zone))
            reanalyzed.push_back(zone);
    const uint32 dataRanges = result.dataRanges;
    const uint32 functions  = result.functions;
    const uint32 structures = result.structures;
    const uint32 prototypes = result.prototypes;
    result                  = {};
    if (!ImportAnnotationsDocument(document, zones, result, error))
        return false;
    result.dataRanges = dataRanges;
    result.functions  = functions;
    result.structures = structures;
    result.prototypes = prototypes;
    for (auto* zone : reanalyzed)
        if (std::find(result.zonesWithNewLines.begin(), result.zonesWithNewLines.end(), zone) == result.zonesWithNewLines.end())
            result.zonesWithNewLines.push_back(zone); // its lines changed
    return true;
}

bool GView::View::DissasmViewer::ImportAnnotationsDocument(
      const json& document, const std::vector<DissasmCodeZone*>& zones, DissasmAnnotationsImport& result, std::string& error)
{
    // the document is untrusted: a field of an unexpected type that a check missed is an invalid document, never an exception out of here
    try {
        return ImportAnnotationsDocumentFields(document, zones, result, error);
    } catch (const json::exception&) {
        error = "The annotations file has a field of an unexpected type!";
        return false;
    }
}

bool GView::View::DissasmViewer::ImportAnnotationsDocumentFields(
      const json& document, const std::vector<DissasmCodeZone*>& zones, DissasmAnnotationsImport& result, std::string& error)
{
    if (!document.is_object() || JsonText(document, "format", "") != DISSASM_ANNOTATIONS_FORMAT) {
        error = "This is not a GView annotations file!";
        return false;
    }
    if (!document.contains("version") || !document["version"].is_number_unsigned() || document["version"].get<uint64>() > DISSASM_ANNOTATIONS_VERSION) {
        error = "The annotations file was written by a newer GView!";
        return false;
    }
    for (const auto& zoneJson : ArrayField(document, "zones")) {
        const auto fileOffset = zoneJson.is_object() && zoneJson.contains("fileOffset") ? ParseAddress(zoneJson["fileOffset"]) : std::nullopt;
        const auto zone       = std::find_if(zones.begin(), zones.end(), [&fileOffset](const DissasmCodeZone* candidate) {
            return fileOffset.has_value() && candidate->zoneDetails.startingZonePoint == fileOffset.value();
        });
        if (zone == zones.end()) {
            result.skipped++;
            continue;
        }
        ImportZoneAnnotations(**zone, zoneJson, result);
    }
    if (result.zones == 0) {
        error = "No disassembly zone of this file matches the zones of the annotations file!";
        return false;
    }
    return true;
}
