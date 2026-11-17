#include "DissasmWorkDocument.hpp"

#include <cstdio>

using namespace GView::View::DissasmViewer;
using nlohmann::json;

namespace
{
using Kind     = DissasmReplayEvent::Kind;
using EditKind = DissasmEdit::Kind;

constexpr size_t MAX_META_TEXT = 256;

// the same forms as the annotations: "0x401000" (any base of std::stoull) or a number
std::string Hex(uint64 value)
{
    char text[24];
    snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
    return text;
}

// a number that is not negative (the parser gives the unsigned numbers, a document built in memory may hold signed ones)
std::optional<uint64> UnsignedOf(const json& value)
{
    if (value.is_number_unsigned())
        return value.get<uint64>();
    if (value.is_number_integer() && value.get<int64>() >= 0)
        return static_cast<uint64>(value.get<int64>());
    return {};
}

std::optional<uint64> ParseAddress(const json& value)
{
    if (value.is_number())
        return UnsignedOf(value);
    if (!value.is_string())
        return {};
    const auto text = value.get<std::string>();
    if (text.empty() || text.front() == '-' || text.front() == '+' || text.front() == ' ')
        return {};
    try {
        size_t used         = 0;
        const uint64 result = std::stoull(text, &used, 0);
        return used == text.size() ? std::optional<uint64>(result) : std::nullopt;
    } catch (...) {
        return {};
    }
}

std::optional<int32> ParseInt32(const json& value)
{
    if (!value.is_number_integer() || (value.is_number_unsigned() && value.get<uint64>() > static_cast<uint64>(INT32_MAX)))
        return {};
    const auto number = value.get<int64>();
    if (number < INT32_MIN || number > INT32_MAX)
        return {};
    return static_cast<int32>(number);
}

std::optional<uint64> ParseUnsigned(const json& value, uint64 max)
{
    const auto number = UnsignedOf(value);
    if (!number.has_value() || number.value() > max)
        return {};
    return number;
}

std::optional<std::string> ParseText(const json& value, size_t maxSize)
{
    if (!value.is_string())
        return {};
    auto text = value.get<std::string>();
    if (text.size() > maxSize || text.find('\0') != std::string::npos)
        return {};
    return text;
}

std::string_view JumpKindName(DissasmReplayJumpKind kind)
{
    switch (kind) {
    case DissasmReplayJumpKind::Follow:
        return "follow";
    case DissasmReplayJumpKind::Entry:
        return "entry";
    case DissasmReplayJumpKind::GoTo:
        return "goto";
    case DissasmReplayJumpKind::Xref:
        return "xref";
    case DissasmReplayJumpKind::Band:
        return "band";
    case DissasmReplayJumpKind::Search:
        return "search";
    case DissasmReplayJumpKind::Bookmark:
        return "bookmark";
    default:
        return "other";
    }
}

std::string_view ImportSourceName(DissasmReplayImportSource source)
{
    switch (source) {
    case DissasmReplayImportSource::ServerWork:
        return "server-work";
    case DissasmReplayImportSource::ServerSolution:
        return "server-solution";
    default:
        return "file";
    }
}

char AnchorLetter(DissasmCommentAnchor::Kind kind)
{
    return kind == DissasmCommentAnchor::Kind::Label ? 'l' : (kind == DissasmCommentAnchor::Kind::Variable ? 'v' : 'i');
}

std::string_view AnchorKindName(DissasmCommentAnchor::Kind kind)
{
    return kind == DissasmCommentAnchor::Kind::Label ? "label" : (kind == DissasmCommentAnchor::Kind::Variable ? "variable" : "instruction");
}

// ------------------------------------------------------------------ to JSON

class JsonWriter
{
    const DissasmReplayJournal& journal;

  public:
    explicit JsonWriter(const DissasmReplayJournal& journal) : journal(journal)
    {
    }
    uint64 Base(uint32 zone) const
    {
        return zone < journal.zones.size() ? journal.zones[zone].addressBase : 0;
    }
    void Place(json& item, const DissasmReplayPlace& place) const
    {
        item.push_back(place.zone);
        item.push_back(Hex(Base(place.zone) + place.anchor.address));
        item.push_back(std::string(1, AnchorLetter(place.anchor.kind)));
        if (place.anchor.kind == DissasmCommentAnchor::Kind::Variable)
            item.push_back(place.anchor.frameOffset);
    }
    json Anchor(const DissasmCommentAnchor& anchor, uint64 base) const
    {
        json item = { { "address", Hex(base + anchor.address) }, { "kind", AnchorKindName(anchor.kind) } };
        if (anchor.kind == DissasmCommentAnchor::Kind::Variable)
            item["frameOffset"] = anchor.frameOffset;
        return item;
    }
    json Payload(const DissasmReplayEdit& edit, uint64 base) const
    {
        json payload = json::object();
        if (IsReplayTextEdit(edit.kind)) {
            if (edit.before.has_value())
                payload["before"] = edit.before.value();
            if (edit.after.has_value())
                payload["after"] = edit.after.value();
            return payload;
        }
        switch (edit.kind) {
        case EditKind::DecimalOperand:
            payload["operand"] = edit.numberIndex;
            break;
        case EditKind::AddZone:
        case EditKind::RemoveZone:
            payload["first"]     = Anchor(edit.zone.first, base);
            payload["last"]      = Anchor(edit.zone.last, base);
            payload["name"]      = edit.zone.name;
            payload["collapsed"] = edit.zone.isCollapsed;
            break;
        case EditKind::DataRanges:
            for (const auto& [key, ranges] : { std::make_pair("before", &edit.rangesBefore), std::make_pair("after", &edit.rangesAfter) }) {
                json list = json::array();
                for (const auto& range : *ranges)
                    list.push_back({ { "address", Hex(base + range.start) },
                                     { "size", range.end - range.start },
                                     { "unit", range.unit },
                                     { "offset", range.isOffset },
                                     { "reference", range.reference } });
                payload[key] = std::move(list);
            }
            break;
        case EditKind::UserFunctions:
            for (const auto& [key, functions] : { std::make_pair("before", &edit.functionsBefore), std::make_pair("after", &edit.functionsAfter) }) {
                json list = json::array();
                for (const auto& [address, flags] : *functions)
                    list.push_back({ { "address", Hex(base + address) }, { "flags", flags } });
                payload[key] = std::move(list);
            }
            break;
        case EditKind::VariableStructures:
            for (const auto& [key, structures] :
                 { std::make_pair("before", &edit.structuresBefore), std::make_pair("after", &edit.structuresAfter) }) {
                json list = json::array();
                for (const auto& [variable, name] : *structures)
                    list.push_back({ { "function", Hex(base + variable.first) }, { "frameOffset", variable.second }, { "structure", name } });
                payload[key] = std::move(list);
            }
            break;
        case EditKind::UserPrototypes:
            for (const auto& [key, prototypes] : { std::make_pair("before", &edit.prototypesBefore), std::make_pair("after", &edit.prototypesAfter) }) {
                json list = json::array();
                for (const auto& [address, text] : *prototypes)
                    list.push_back({ { "function", Hex(base + address) }, { "prototype", text } });
                payload[key] = std::move(list);
            }
            break;
        default:
            break;
        }
        return payload;
    }
    json Event(const DissasmReplayEvent& event, uint32 dt) const
    {
        json item = json::array();
        switch (event.kind) {
        case Kind::Visit:
            item.push_back("v");
            item.push_back(dt);
            Place(item, event.place);
            item.push_back(event.source == DissasmReplayVisitSource::Mouse ? "m" : "k");
            break;
        case Kind::Jump:
            item.push_back("j");
            item.push_back(dt);
            Place(item, event.from);
            Place(item, event.place);
            item.push_back(event.mnemonic);
            item.push_back(JumpKindName(event.jumpKind));
            break;
        case Kind::JumpBack:
        case Kind::JumpForward:
            item.push_back(event.kind == Kind::JumpBack ? "b" : "f");
            item.push_back(dt);
            Place(item, event.place);
            break;
        case Kind::Edit:
        case Kind::Undo:
        case Kind::Redo: {
            item.push_back(event.kind == Kind::Edit ? "e" : (event.kind == Kind::Undo ? "u" : "r"));
            item.push_back(dt);
            Place(item, event.place);
            const DissasmReplayEdit empty;
            const auto& edit = event.edit.has_value() ? event.edit.value() : empty;
            item.push_back(ReplayEditKindName(edit.kind));
            if (event.kind != Kind::Edit)
                item.push_back(event.ref == DISSASM_REPLAY_NO_REF ? json(nullptr) : json(event.ref));
            item.push_back(Payload(edit, Base(event.place.zone)));
            break;
        }
        case Kind::Import:
            item.push_back("i");
            item.push_back(dt);
            item.push_back(ImportSourceName(event.importSource));
            break;
        case Kind::Reanalysis:
            item.push_back("a");
            item.push_back(dt);
            item.push_back(event.place.zone);
            break;
        }
        return item;
    }
};

// ------------------------------------------------------------------ from JSON

// the reader of one event (an array): every field is checked, the first one that does not fit rejects the event
class JsonEventReader
{
    const json& item;
    size_t at = 2; // after the tag and dt
    const DissasmReplayJournal& journal;
    const std::vector<uint32>& zoneMap; // the zones of the document -> the zones of the journal

  public:
    JsonEventReader(const json& item, const DissasmReplayJournal& journal, const std::vector<uint32>& zoneMap)
        : item(item), journal(journal), zoneMap(zoneMap)
    {
    }
    const json* Next()
    {
        return at < item.size() ? &item[at++] : nullptr;
    }
    bool AtEnd() const
    {
        return at == item.size();
    }
    std::optional<uint32> Zone()
    {
        const auto* value = Next();
        const auto index  = value ? ParseUnsigned(*value, UINT32_MAX) : std::nullopt;
        if (!index.has_value() || index.value() >= zoneMap.size() || zoneMap[index.value()] == DISSASM_REPLAY_NO_ZONE)
            return {};
        return zoneMap[index.value()];
    }
    bool Place(DissasmReplayPlace& place)
    {
        const auto zone    = Zone();
        const auto* value  = Next();
        const auto address = value ? ParseAddress(*value) : std::nullopt;
        const auto* kind   = Next();
        if (!zone.has_value() || !address.has_value() || !kind || !kind->is_string())
            return false;
        place.zone           = zone.value();
        place.anchor.address = address.value() - journal.zones[zone.value()].addressBase;
        const auto letter    = kind->get<std::string>();
        if (letter == "i")
            place.anchor.kind = DissasmCommentAnchor::Kind::Instruction;
        else if (letter == "l")
            place.anchor.kind = DissasmCommentAnchor::Kind::Label;
        else if (letter == "v") {
            place.anchor.kind      = DissasmCommentAnchor::Kind::Variable;
            const auto* offset     = Next();
            const auto frameOffset = offset ? ParseInt32(*offset) : std::nullopt;
            if (!frameOffset.has_value())
                return false;
            place.anchor.frameOffset = frameOffset.value();
        } else
            return false;
        return true;
    }
    static std::optional<DissasmCommentAnchor> Anchor(const json& value, uint64 base)
    {
        if (!value.is_object() || !value.contains("address") || !value.contains("kind") || !value["kind"].is_string())
            return {};
        const auto address = ParseAddress(value["address"]);
        if (!address.has_value())
            return {};
        DissasmCommentAnchor anchor;
        anchor.address    = address.value() - base;
        const auto kind   = value["kind"].get<std::string>();
        if (kind == "label")
            anchor.kind = DissasmCommentAnchor::Kind::Label;
        else if (kind == "variable") {
            anchor.kind            = DissasmCommentAnchor::Kind::Variable;
            const auto frameOffset = value.contains("frameOffset") ? ParseInt32(value["frameOffset"]) : std::nullopt;
            if (!frameOffset.has_value())
                return {};
            anchor.frameOffset = frameOffset.value();
        } else if (kind != "instruction")
            return {};
        return anchor;
    }
    static const json* List(const json& payload, const char* key)
    {
        const auto field = payload.find(key);
        return field != payload.end() && field->is_array() && field->size() <= DISSASM_REPLAY_MAX_LIST ? &*field : nullptr;
    }
    static bool Payload(const json& payload, uint64 base, DissasmReplayEdit& edit)
    {
        if (!payload.is_object())
            return false;
        if (IsReplayTextEdit(edit.kind)) {
            for (const auto& [key, text] : { std::make_pair("before", &edit.before), std::make_pair("after", &edit.after) }) {
                if (!payload.contains(key))
                    continue;
                *text = ParseText(payload[key], DISSASM_REPLAY_MAX_TEXT);
                if (!text->has_value())
                    return false;
            }
            return true;
        }
        switch (edit.kind) {
        case EditKind::DecimalOperand: {
            const auto operand = payload.contains("operand") ? ParseUnsigned(payload["operand"], 31) : std::nullopt;
            if (!operand.has_value())
                return false;
            edit.numberIndex = static_cast<uint32>(operand.value());
            return true;
        }
        case EditKind::AddZone:
        case EditKind::RemoveZone: {
            const auto first = payload.contains("first") ? Anchor(payload["first"], base) : std::nullopt;
            const auto last  = payload.contains("last") ? Anchor(payload["last"], base) : std::nullopt;
            const auto name  = payload.contains("name") ? ParseText(payload["name"], DISSASM_REPLAY_MAX_TEXT) : std::nullopt;
            if (!first.has_value() || !last.has_value() || !name.has_value())
                return false;
            edit.zone = { first.value(), last.value(), name.value(), payload.contains("collapsed") && payload["collapsed"].is_boolean() &&
                                                                           payload["collapsed"].get<bool>() };
            return true;
        }
        case EditKind::DataRanges:
            for (const auto& [key, ranges] : { std::make_pair("before", &edit.rangesBefore), std::make_pair("after", &edit.rangesAfter) }) {
                const auto* list = List(payload, key);
                if (!list)
                    return false;
                for (const auto& entry : *list) {
                    if (!entry.is_object() || !entry.contains("address") || !entry.contains("size") || !entry.contains("unit"))
                        return false;
                    const auto start     = ParseAddress(entry["address"]);
                    const auto size      = ParseUnsigned(entry["size"], UINT64_MAX);
                    const auto unit      = ParseUnsigned(entry["unit"], 0xFF);
                    const auto reference = entry.contains("reference") ? ParseUnsigned(entry["reference"], DissasmInstructionSet::REFERENCE_RELATIVE)
                                                                       : std::optional<uint64>(DissasmInstructionSet::REFERENCE_VA);
                    if (!start.has_value() || !size.has_value() || !unit.has_value() || !reference.has_value() || size.value() == 0 ||
                        size.value() > UINT64_MAX - (start.value() - base))
                        return false;
                    DissasmInstructionSet::DataRange range{};
                    range.start     = start.value() - base;
                    range.end       = range.start + size.value();
                    range.unit      = static_cast<uint8>(unit.value());
                    range.isOffset  = entry.contains("offset") && entry["offset"].is_boolean() && entry["offset"].get<bool>();
                    range.reference = static_cast<uint8>(reference.value());
                    ranges->push_back(range);
                }
            }
            return true;
        case EditKind::UserFunctions:
            for (const auto& [key, functions] : { std::make_pair("before", &edit.functionsBefore), std::make_pair("after", &edit.functionsAfter) }) {
                const auto* list = List(payload, key);
                if (!list)
                    return false;
                for (const auto& entry : *list) {
                    const auto address = entry.is_object() && entry.contains("address") ? ParseAddress(entry["address"]) : std::nullopt;
                    const auto flags   = entry.is_object() && entry.contains("flags") ? ParseUnsigned(entry["flags"], 0xFF) : std::nullopt;
                    if (!address.has_value() || !flags.has_value() || !functions->emplace(address.value() - base, static_cast<uint8>(flags.value())).second)
                        return false;
                }
            }
            return true;
        case EditKind::VariableStructures:
            for (const auto& [key, structures] :
                 { std::make_pair("before", &edit.structuresBefore), std::make_pair("after", &edit.structuresAfter) }) {
                const auto* list = List(payload, key);
                if (!list)
                    return false;
                for (const auto& entry : *list) {
                    const bool object    = entry.is_object();
                    const auto function  = object && entry.contains("function") ? ParseAddress(entry["function"]) : std::nullopt;
                    const auto offset    = object && entry.contains("frameOffset") ? ParseInt32(entry["frameOffset"]) : std::nullopt;
                    const auto structure = object && entry.contains("structure") ? ParseText(entry["structure"], DISSASM_REPLAY_MAX_TEXT) : std::nullopt;
                    if (!function.has_value() || !offset.has_value() || !structure.has_value() ||
                        !structures->emplace(std::make_pair(function.value() - base, offset.value()), structure.value()).second)
                        return false;
                }
            }
            return true;
        case EditKind::UserPrototypes:
            for (const auto& [key, prototypes] : { std::make_pair("before", &edit.prototypesBefore), std::make_pair("after", &edit.prototypesAfter) }) {
                const auto* list = List(payload, key);
                if (!list)
                    return false;
                for (const auto& entry : *list) {
                    const auto function  = entry.is_object() && entry.contains("function") ? ParseAddress(entry["function"]) : std::nullopt;
                    const auto prototype = entry.is_object() && entry.contains("prototype") ? ParseText(entry["prototype"], DISSASM_REPLAY_MAX_TEXT) : std::nullopt;
                    if (!function.has_value() || !prototype.has_value() || !prototypes->emplace(function.value() - base, prototype.value()).second)
                        return false;
                }
            }
            return true;
        default:
            return false;
        }
    }
    // the fields after the tag and dt; false when they do not form an event of the tag
    bool Event(const std::string& tag, DissasmReplayEvent& event, const std::vector<uint32>& eventMap)
    {
        if (tag == "v") {
            event.kind        = Kind::Visit;
            const auto* value = Place(event.place) ? Next() : nullptr;
            if (!value || !value->is_string() || (*value != "k" && *value != "m"))
                return false;
            event.source = *value == "m" ? DissasmReplayVisitSource::Mouse : DissasmReplayVisitSource::Keyboard;
        } else if (tag == "j") {
            event.kind = Kind::Jump;
            if (!Place(event.from) || !Place(event.place))
                return false;
            const auto* mnemonic = Next();
            const auto* kind     = Next();
            const auto text      = mnemonic ? ParseText(*mnemonic, DISSASM_REPLAY_MAX_MNEMONIC) : std::nullopt;
            if (!text.has_value() || !kind || !kind->is_string())
                return false;
            event.mnemonic         = text.value();
            const auto kindName    = kind->get<std::string>();
            std::optional<DissasmReplayJumpKind> jumpKind;
            for (uint8 value = 0; value <= static_cast<uint8>(DissasmReplayJumpKind::Other); value++)
                if (JumpKindName(static_cast<DissasmReplayJumpKind>(value)) == kindName)
                    jumpKind = static_cast<DissasmReplayJumpKind>(value);
            if (!jumpKind.has_value())
                return false;
            event.jumpKind = jumpKind.value();
        } else if (tag == "b" || tag == "f") {
            event.kind = tag == "b" ? Kind::JumpBack : Kind::JumpForward;
            if (!Place(event.place))
                return false;
        } else if (tag == "e" || tag == "u" || tag == "r") {
            event.kind = tag == "e" ? Kind::Edit : (tag == "u" ? Kind::Undo : Kind::Redo);
            if (!Place(event.place))
                return false;
            const auto* kind = Next();
            const auto editKind = kind && kind->is_string() ? ReplayEditKindFromName(kind->get<std::string>()) : std::nullopt;
            if (!editKind.has_value())
                return false;
            if (event.kind != Kind::Edit) {
                const auto* ref = Next();
                if (!ref)
                    return false;
                if (!ref->is_null()) {
                    // the index in the document: the event it became, none when it was skipped
                    const auto index = ParseUnsigned(*ref, UINT32_MAX);
                    if (!index.has_value())
                        return false;
                    event.ref = index.value() < eventMap.size() ? eventMap[index.value()] : DISSASM_REPLAY_NO_REF;
                }
            }
            const auto* payload = Next();
            DissasmReplayEdit edit;
            edit.kind = editKind.value();
            if (!payload || !Payload(*payload, journal.zones[event.place.zone].addressBase, edit))
                return false;
            event.edit = std::move(edit);
        } else if (tag == "i") {
            event.kind        = Kind::Import;
            const auto* value = Next();
            if (!value || !value->is_string())
                return false;
            const auto name = value->get<std::string>();
            if (name == "file")
                event.importSource = DissasmReplayImportSource::File;
            else if (name == "server-work")
                event.importSource = DissasmReplayImportSource::ServerWork;
            else if (name == "server-solution")
                event.importSource = DissasmReplayImportSource::ServerSolution;
            else
                return false;
        } else if (tag == "a") {
            event.kind      = Kind::Reanalysis;
            const auto zone = Zone();
            if (!zone.has_value())
                return false;
            event.place.zone = zone.value();
        } else
            return false;
        return AtEnd();
    }
};

DissasmReplayJournal ReadJournal(const json& replay, uint32& skipped)
{
    DissasmReplayJournal journal;
    const auto version = replay.is_object() && replay.contains("version") ? ParseUnsigned(replay["version"], DISSASM_REPLAY_JSON_VERSION) : std::nullopt;
    if (!version.has_value()) {
        skipped++;
        return journal;
    }
    if (replay.contains("startedAt"))
        journal.startedAt = UnsignedOf(replay["startedAt"]).value_or(0);
    std::vector<uint32> zoneMap;
    const auto zones = replay.find("zones");
    if (zones != replay.end() && zones->is_array()) {
        for (const auto& zone : *zones) {
            const auto fileOffset  = zone.is_object() && zone.contains("fileOffset") ? ParseAddress(zone["fileOffset"]) : std::nullopt;
            const auto addressBase = zone.is_object() && zone.contains("addressBase") ? ParseAddress(zone["addressBase"]) : std::nullopt;
            const uint32 index     = fileOffset.has_value() && addressBase.has_value() ? journal.ZoneIndexOf(fileOffset.value(), addressBase.value())
                                                                                       : DISSASM_REPLAY_NO_ZONE;
            if (index == DISSASM_REPLAY_NO_ZONE)
                skipped++;
            zoneMap.push_back(index);
        }
    }
    const auto events = replay.find("events");
    if (events == replay.end() || !events->is_array())
        return journal;
    std::vector<uint32> eventMap; // the events of the document -> the events of the journal
    uint64 time = 0;
    for (const auto& item : *events) {
        uint32 index  = DISSASM_REPLAY_NO_REF;
        const auto dt = item.is_array() && item.size() >= 2 && item[0].is_string() ? ParseUnsigned(item[1], UINT32_MAX) : std::nullopt;
        if (dt.has_value()) {
            time = std::min<uint64>(time + dt.value(), UINT32_MAX);
            DissasmReplayEvent event;
            JsonEventReader reader(item, journal, zoneMap);
            bool read = false;
            try {
                read = reader.Event(item[0].get<std::string>(), event, eventMap);
            } catch (const json::exception&) {
                read = false;
            }
            event.time = static_cast<uint32>(time);
            if (read && journal.events.size() < DISSASM_REPLAY_MAX_EVENTS && IsValidReplayEvent(event, journal.zones.size(), journal.events.size())) {
                index = static_cast<uint32>(journal.events.size());
                journal.events.push_back(std::move(event));
            }
        }
        if (index == DISSASM_REPLAY_NO_REF)
            skipped++;
        eventMap.push_back(index);
    }
    return journal;
}
} // namespace

json GView::View::DissasmViewer::ReplayJournalToJson(const DissasmReplayJournal& journal)
{
    JsonWriter writer(journal);
    json zones = json::array();
    for (const auto& zone : journal.zones)
        zones.push_back({ { "fileOffset", Hex(zone.fileOffset) }, { "addressBase", Hex(zone.addressBase) } });
    json events = json::array();
    uint32 time = 0;
    for (const auto& event : journal.events) {
        const uint32 eventTime = std::max(time, event.time);
        events.push_back(writer.Event(event, eventTime - time));
        time = eventTime;
    }
    return { { "version", DISSASM_REPLAY_JSON_VERSION }, { "startedAt", journal.startedAt }, { "zones", std::move(zones) }, { "events", std::move(events) } };
}

DissasmReplayJournal GView::View::DissasmViewer::ReplayJournalFromJson(const json& replay, uint32& skipped)
{
    try {
        return ReadJournal(replay, skipped);
    } catch (...) { // a field of an unexpected type that a check missed, bad_alloc: no journal
        skipped++;
        return {};
    }
}

json GView::View::DissasmViewer::BuildWorkDocument(
      const std::vector<DissasmCodeZone*>& zones, std::string_view fileName, const DissasmReplayJournal& journal, const DissasmWorkMeta& meta)
{
    json document    = BuildAnnotationsDocument(zones, fileName);
    document["meta"] = { { "kind", meta.kind },
                         { "clientVersion", meta.clientVersion },
                         { "savedAt", meta.savedAt },
                         { "problem", meta.problem },
                         { "itemVersion", meta.itemVersion },
                         { "sha256", meta.sha256 } };
    if (!journal.events.empty())
        document["replay"] = ReplayJournalToJson(journal);
    return document;
}

bool GView::View::DissasmViewer::ParseWorkDocument(const json& document, DissasmWorkDocument& result, std::string& error)
{
    result = {};
    if (!document.is_object() || !document.contains("format") || !document["format"].is_string() ||
        document["format"].get<std::string>() != DISSASM_ANNOTATIONS_FORMAT) {
        error = "This is not a GView annotations document!";
        return false;
    }
    if (!document.contains("version") || !ParseUnsigned(document["version"], DISSASM_ANNOTATIONS_VERSION).has_value()) {
        error = "The document was written by a newer GView!";
        return false;
    }
    const auto meta = document.find("meta");
    if (meta != document.end() && meta->is_object()) {
        for (const auto& [key, text] : { std::make_pair("kind", &result.meta.kind),
                                         std::make_pair("clientVersion", &result.meta.clientVersion),
                                         std::make_pair("problem", &result.meta.problem),
                                         std::make_pair("sha256", &result.meta.sha256) }) {
            const auto value = meta->contains(key) ? ParseText((*meta)[key], MAX_META_TEXT) : std::nullopt;
            *text            = value.value_or(std::string());
        }
        if (meta->contains("savedAt"))
            result.meta.savedAt = ParseUnsigned((*meta)["savedAt"], UINT64_MAX).value_or(0);
        if (meta->contains("itemVersion"))
            result.meta.itemVersion = static_cast<uint32>(ParseUnsigned((*meta)["itemVersion"], UINT32_MAX).value_or(0));
    }
    const auto replay = document.find("replay");
    if (replay != document.end()) {
        result.hasReplay = true;
        result.journal   = ReplayJournalFromJson(*replay, result.skipped);
    }
    return true;
}
