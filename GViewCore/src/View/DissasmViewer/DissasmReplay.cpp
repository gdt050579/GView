#include "DissasmReplay.hpp"
#include "DissasmIOHelpers.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

using namespace GView::View::DissasmViewer;

namespace
{
using Kind     = DissasmReplayEvent::Kind;
using EditKind = DissasmEdit::Kind;

constexpr uint8 TEXT_HAS_BEFORE = 1;
constexpr uint8 TEXT_HAS_AFTER  = 2;

bool IsValidText(std::string_view text)
{
    return text.size() <= DISSASM_REPLAY_MAX_TEXT && text.find('\0') == std::string_view::npos;
}

bool IsValidOptionalText(const std::optional<std::string>& text)
{
    return !text.has_value() || IsValidText(text.value());
}

bool IsValidAnchor(const DissasmCommentAnchor& anchor)
{
    return anchor.kind <= DissasmCommentAnchor::Kind::Variable && (anchor.kind == DissasmCommentAnchor::Kind::Variable || anchor.frameOffset == 0);
}

bool IsValidRange(const DissasmInstructionSet::DataRange& range)
{
    return range.start < range.end && DissasmInstructionSet::IsValidDataUnit(range.unit) && range.reference <= DissasmInstructionSet::REFERENCE_RELATIVE;
}

bool IsValidFunctionFlags(uint8 flags)
{
    return flags != 0 && (flags & ~USER_FUNCTION_ALL) == 0;
}

// the edit with only the fields of its kind
DissasmReplayEdit NormalizedEdit(const DissasmReplayEdit& edit)
{
    DissasmReplayEdit result;
    result.kind = edit.kind;
    if (IsReplayTextEdit(edit.kind)) {
        result.before = edit.before;
        result.after  = edit.after;
        return result;
    }
    switch (edit.kind) {
    case EditKind::DecimalOperand:
        result.numberIndex = edit.numberIndex;
        break;
    case EditKind::AddZone:
    case EditKind::RemoveZone:
        result.zone = edit.zone;
        break;
    case EditKind::DataRanges:
        result.rangesBefore = edit.rangesBefore;
        result.rangesAfter  = edit.rangesAfter;
        break;
    case EditKind::UserFunctions:
        result.functionsBefore = edit.functionsBefore;
        result.functionsAfter  = edit.functionsAfter;
        break;
    case EditKind::VariableStructures:
        result.structuresBefore = edit.structuresBefore;
        result.structuresAfter  = edit.structuresAfter;
        break;
    case EditKind::UserPrototypes:
        result.prototypesBefore = edit.prototypesBefore;
        result.prototypesAfter  = edit.prototypesAfter;
        break;
    default:
        break;
    }
    return result;
}

bool IsValidEdit(const DissasmReplayEdit& edit)
{
    if (edit.kind > EditKind::UserPrototypes || !(NormalizedEdit(edit) == edit))
        return false;
    if (!IsValidOptionalText(edit.before) || !IsValidOptionalText(edit.after) || edit.numberIndex >= 32)
        return false;
    if ((edit.kind == EditKind::AddZone || edit.kind == EditKind::RemoveZone) &&
        (!IsValidAnchor(edit.zone.first) || !IsValidAnchor(edit.zone.last) || !IsValidText(edit.zone.name)))
        return false;
    for (const auto* ranges : { &edit.rangesBefore, &edit.rangesAfter })
        if (ranges->size() > DISSASM_REPLAY_MAX_LIST || !std::all_of(ranges->begin(), ranges->end(), IsValidRange))
            return false;
    for (const auto* functions : { &edit.functionsBefore, &edit.functionsAfter }) {
        if (functions->size() > DISSASM_REPLAY_MAX_LIST)
            return false;
        for (const auto& [address, flags] : *functions)
            if (!IsValidFunctionFlags(flags))
                return false;
    }
    for (const auto* structures : { &edit.structuresBefore, &edit.structuresAfter }) {
        if (structures->size() > DISSASM_REPLAY_MAX_LIST)
            return false;
        for (const auto& [key, name] : *structures)
            if (!IsValidText(name))
                return false;
    }
    for (const auto* prototypes : { &edit.prototypesBefore, &edit.prototypesAfter }) {
        if (prototypes->size() > DISSASM_REPLAY_MAX_LIST)
            return false;
        for (const auto& [address, text] : *prototypes)
            if (!IsValidText(text))
                return false;
    }
    return true;
}

// removes the events whose `remove` is set; the references follow their events (a reference to a removed event is dropped)
size_t RemoveEvents(std::vector<DissasmReplayEvent>& events, const std::vector<bool>& remove)
{
    std::vector<uint32> newIndex(events.size(), DISSASM_REPLAY_NO_REF);
    std::vector<DissasmReplayEvent> kept;
    kept.reserve(events.size());
    for (size_t index = 0; index < events.size(); index++) {
        if (remove[index])
            continue;
        newIndex[index] = static_cast<uint32>(kept.size());
        kept.push_back(std::move(events[index]));
    }
    const size_t removed = events.size() - kept.size();
    for (auto& event : kept)
        if (event.ref != DISSASM_REPLAY_NO_REF)
            event.ref = event.ref < newIndex.size() ? newIndex[event.ref] : DISSASM_REPLAY_NO_REF;
    events = std::move(kept);
    return removed;
}

// ------------------------------------------------------------------ the record

void WriteAnchor(std::vector<std::byte>& buffer, const DissasmCommentAnchor& anchor)
{
    append_bytes(buffer, static_cast<uint8>(anchor.kind));
    append_varint(buffer, anchor.address);
    if (anchor.kind == DissasmCommentAnchor::Kind::Variable)
        append_svarint(buffer, anchor.frameOffset);
}

void WritePlace(std::vector<std::byte>& buffer, const DissasmReplayPlace& place)
{
    append_varint(buffer, place.zone);
    WriteAnchor(buffer, place.anchor);
}

void WriteRanges(std::vector<std::byte>& buffer, const std::vector<DissasmInstructionSet::DataRange>& ranges)
{
    append_varint(buffer, ranges.size());
    for (const auto& range : ranges) {
        append_varint(buffer, range.start);
        append_varint(buffer, range.end - range.start);
        append_bytes(buffer, range.unit);
        append_bytes(buffer, static_cast<uint8>(range.isOffset ? 1 : 0));
        append_bytes(buffer, range.reference);
    }
}

void WritePayload(std::vector<std::byte>& buffer, const DissasmReplayEdit& edit)
{
    if (IsReplayTextEdit(edit.kind)) {
        const uint8 flags = (edit.before.has_value() ? TEXT_HAS_BEFORE : 0) | (edit.after.has_value() ? TEXT_HAS_AFTER : 0);
        append_bytes(buffer, flags);
        if (edit.before.has_value())
            append_varint_string(buffer, edit.before.value());
        if (edit.after.has_value())
            append_varint_string(buffer, edit.after.value());
        return;
    }
    switch (edit.kind) {
    case EditKind::DecimalOperand:
        append_varint(buffer, edit.numberIndex);
        break;
    case EditKind::AddZone:
    case EditKind::RemoveZone:
        WriteAnchor(buffer, edit.zone.first);
        WriteAnchor(buffer, edit.zone.last);
        append_varint_string(buffer, edit.zone.name);
        append_bytes(buffer, static_cast<uint8>(edit.zone.isCollapsed ? 1 : 0));
        break;
    case EditKind::DataRanges:
        WriteRanges(buffer, edit.rangesBefore);
        WriteRanges(buffer, edit.rangesAfter);
        break;
    case EditKind::UserFunctions:
        for (const auto* functions : { &edit.functionsBefore, &edit.functionsAfter }) {
            append_varint(buffer, functions->size());
            for (const auto& [address, flags] : *functions) {
                append_varint(buffer, address);
                append_bytes(buffer, flags);
            }
        }
        break;
    case EditKind::VariableStructures:
        for (const auto* structures : { &edit.structuresBefore, &edit.structuresAfter }) {
            append_varint(buffer, structures->size());
            for (const auto& [key, name] : *structures) {
                append_varint(buffer, key.first);
                append_svarint(buffer, key.second);
                append_varint_string(buffer, name);
            }
        }
        break;
    case EditKind::UserPrototypes:
        for (const auto* prototypes : { &edit.prototypesBefore, &edit.prototypesAfter }) {
            append_varint(buffer, prototypes->size());
            for (const auto& [address, text] : *prototypes) {
                append_varint(buffer, address);
                append_varint_string(buffer, text);
            }
        }
        break;
    default:
        break;
    }
}

// the reader of a record: every read checks the end of the record and the limits, the first failure fails the record
struct RecordReader {
    const std::byte* p;
    const std::byte* end;

    bool U8(uint8& value, uint8 max)
    {
        return read_primitive(p, end, value) && value <= max;
    }
    bool Varint(uint64& value, uint64 max = UINT64_MAX)
    {
        return read_varint(p, end, value) && value <= max;
    }
    bool Int32(int32& value)
    {
        int64 wide = 0;
        if (!read_svarint(p, end, wide) || wide < INT32_MIN || wide > INT32_MAX)
            return false;
        value = static_cast<int32>(wide);
        return true;
    }
    bool Text(std::string& text)
    {
        return read_varint_string(p, end, DISSASM_REPLAY_MAX_TEXT, text);
    }
    bool Anchor(DissasmCommentAnchor& anchor)
    {
        uint8 kind = 0;
        if (!U8(kind, static_cast<uint8>(DissasmCommentAnchor::Kind::Variable)) || !Varint(anchor.address))
            return false;
        anchor.kind        = static_cast<DissasmCommentAnchor::Kind>(kind);
        anchor.frameOffset = 0;
        return anchor.kind != DissasmCommentAnchor::Kind::Variable || Int32(anchor.frameOffset);
    }
    bool Place(DissasmReplayPlace& place, size_t zoneCount)
    {
        uint64 zone = 0;
        if (!Varint(zone) || zone >= zoneCount)
            return false;
        place.zone = static_cast<uint32>(zone);
        return Anchor(place.anchor);
    }
    bool Count(size_t& count)
    {
        uint64 value = 0;
        if (!Varint(value, DISSASM_REPLAY_MAX_LIST))
            return false;
        count = static_cast<size_t>(value);
        return true;
    }
    bool Ranges(std::vector<DissasmInstructionSet::DataRange>& ranges)
    {
        size_t count = 0;
        if (!Count(count))
            return false;
        for (size_t index = 0; index < count; index++) { // no reserve: a corrupted count fails at the end of the record
            DissasmInstructionSet::DataRange range{};
            uint64 size  = 0;
            uint8 offset = 0;
            if (!Varint(range.start) || !Varint(size) || size == 0 || size > UINT64_MAX - range.start || !U8(range.unit, 0xFF) || !U8(offset, 1) ||
                !U8(range.reference, DissasmInstructionSet::REFERENCE_RELATIVE))
                return false;
            range.end      = range.start + size;
            range.isOffset = offset != 0;
            if (!IsValidRange(range))
                return false;
            ranges.push_back(range);
        }
        return true;
    }
    bool Functions(std::map<uint64, uint8>& functions)
    {
        size_t count = 0;
        if (!Count(count))
            return false;
        for (size_t index = 0; index < count; index++) {
            uint64 address = 0;
            uint8 flags    = 0;
            if (!Varint(address) || !U8(flags, USER_FUNCTION_ALL) || !IsValidFunctionFlags(flags) || !functions.emplace(address, flags).second)
                return false; // a duplicated address: the record does not come from a map
        }
        return true;
    }
    bool Structures(std::map<std::pair<uint64, int32>, std::string>& structures)
    {
        size_t count = 0;
        if (!Count(count))
            return false;
        for (size_t index = 0; index < count; index++) {
            uint64 function = 0;
            int32 offset    = 0;
            std::string name;
            if (!Varint(function) || !Int32(offset) || !Text(name) || !structures.emplace(std::make_pair(function, offset), std::move(name)).second)
                return false;
        }
        return true;
    }
    bool Prototypes(std::map<uint64, std::string>& prototypes)
    {
        size_t count = 0;
        if (!Count(count))
            return false;
        for (size_t index = 0; index < count; index++) {
            uint64 function = 0;
            std::string text;
            if (!Varint(function) || !Text(text) || !prototypes.emplace(function, std::move(text)).second)
                return false;
        }
        return true;
    }
    bool Payload(DissasmReplayEdit& edit)
    {
        if (IsReplayTextEdit(edit.kind)) {
            uint8 flags = 0;
            if (!U8(flags, TEXT_HAS_BEFORE | TEXT_HAS_AFTER))
                return false;
            std::string text;
            if ((flags & TEXT_HAS_BEFORE) != 0) {
                if (!Text(text))
                    return false;
                edit.before = std::move(text);
            }
            if ((flags & TEXT_HAS_AFTER) != 0) {
                if (!Text(text))
                    return false;
                edit.after = std::move(text);
            }
            return true;
        }
        switch (edit.kind) {
        case EditKind::DecimalOperand: {
            uint64 number = 0;
            if (!Varint(number, 31))
                return false;
            edit.numberIndex = static_cast<uint32>(number);
            return true;
        }
        case EditKind::AddZone:
        case EditKind::RemoveZone: {
            uint8 collapsed = 0;
            if (!Anchor(edit.zone.first) || !Anchor(edit.zone.last) || !Text(edit.zone.name) || !U8(collapsed, 1))
                return false;
            edit.zone.isCollapsed = collapsed != 0;
            return true;
        }
        case EditKind::DataRanges:
            return Ranges(edit.rangesBefore) && Ranges(edit.rangesAfter);
        case EditKind::UserFunctions:
            return Functions(edit.functionsBefore) && Functions(edit.functionsAfter);
        case EditKind::VariableStructures:
            return Structures(edit.structuresBefore) && Structures(edit.structuresAfter);
        case EditKind::UserPrototypes:
            return Prototypes(edit.prototypesBefore) && Prototypes(edit.prototypesAfter);
        default:
            return false;
        }
    }
    bool Event(DissasmReplayEvent& event, size_t zoneCount, size_t index)
    {
        switch (event.kind) {
        case Kind::Visit: {
            uint8 source = 0;
            if (!Place(event.place, zoneCount) || !U8(source, static_cast<uint8>(DissasmReplayVisitSource::Mouse)))
                return false;
            event.source = static_cast<DissasmReplayVisitSource>(source);
            return true;
        }
        case Kind::Jump: {
            uint8 jumpKind = 0, size = 0;
            if (!Place(event.place, zoneCount) || !Place(event.from, zoneCount) || !U8(jumpKind, static_cast<uint8>(DissasmReplayJumpKind::Other)) ||
                !U8(size, DISSASM_REPLAY_MAX_MNEMONIC))
                return false;
            const std::byte* text = nullptr;
            if (!read_text_bytes(p, end, size, text))
                return false;
            event.jumpKind = static_cast<DissasmReplayJumpKind>(jumpKind);
            event.mnemonic.assign(reinterpret_cast<const char*>(text), size);
            return true;
        }
        case Kind::JumpBack:
        case Kind::JumpForward:
            return Place(event.place, zoneCount);
        case Kind::Edit:
        case Kind::Undo:
        case Kind::Redo: {
            uint8 editKind = 0;
            if (!Place(event.place, zoneCount) || !U8(editKind, static_cast<uint8>(EditKind::UserPrototypes)))
                return false;
            DissasmReplayEdit edit;
            edit.kind = static_cast<EditKind>(editKind);
            if (event.kind != Kind::Edit) {
                uint64 ref = 0;
                if (!Varint(ref, index)) // ref + 1: an event before this one, 0 for none
                    return false;
                event.ref = ref == 0 ? DISSASM_REPLAY_NO_REF : static_cast<uint32>(ref - 1);
            }
            if (!Payload(edit))
                return false;
            event.edit = std::move(edit);
            return true;
        }
        case Kind::Import: {
            uint8 source = 0;
            if (!U8(source, static_cast<uint8>(DissasmReplayImportSource::ServerSolution)))
                return false;
            event.importSource = static_cast<DissasmReplayImportSource>(source);
            return true;
        }
        case Kind::Reanalysis: {
            uint64 zone = 0;
            if (!Varint(zone) || zone >= zoneCount)
                return false;
            event.place.zone = static_cast<uint32>(zone);
            return true;
        }
        }
        return false;
    }
};

bool ReadJournal(const std::byte* data, size_t size, DissasmReplayJournal& journal)
{
    RecordReader reader{ data, data + size };
    uint32 magic = 0, version = 0;
    uint64 zoneCount = 0, eventCount = 0;
    if (!read_primitive(reader.p, reader.end, magic) || magic != DISSASM_REPLAY_MAGIC || !read_primitive(reader.p, reader.end, version) ||
        version != DISSASM_REPLAY_VERSION || !read_primitive(reader.p, reader.end, journal.startedAt) ||
        !reader.Varint(zoneCount, DISSASM_REPLAY_MAX_ZONES))
        return false;
    for (uint64 index = 0; index < zoneCount; index++) {
        DissasmReplayZone zone;
        if (!reader.Varint(zone.fileOffset) || !reader.Varint(zone.addressBase))
            return false;
        // the same zone twice: not a record of the recorder (ZoneIndexOf finds the first one)
        if (std::find(journal.zones.begin(), journal.zones.end(), zone) != journal.zones.end())
            return false;
        journal.zones.push_back(zone);
    }
    if (!reader.Varint(eventCount, DISSASM_REPLAY_MAX_EVENTS))
        return false;
    uint64 time = 0;
    for (uint64 index = 0; index < eventCount; index++) {
        DissasmReplayEvent event;
        uint8 kind = 0;
        uint64 dt  = 0;
        if (!reader.U8(kind, static_cast<uint8>(Kind::Reanalysis)) || !reader.Varint(dt, UINT32_MAX) || time + dt > UINT32_MAX)
            return false;
        time += dt;
        event.kind = static_cast<Kind>(kind);
        event.time = static_cast<uint32>(time);
        if (!reader.Event(event, journal.zones.size(), static_cast<size_t>(index)))
            return false;
        journal.events.push_back(std::move(event));
    }
    return reader.p == reader.end; // anything after the events: not a record of this version
}

// ------------------------------------------------------------------ the descriptions

std::string Hex(uint64 value)
{
    char text[24];
    snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
    return text;
}

// a text of the user in a description: one line, at most 40 characters
std::string Quote(const std::optional<std::string>& text)
{
    if (!text.has_value())
        return "(none)";
    constexpr size_t MAX_SHOWN = 40;
    std::string result;
    for (const char c : text.value()) {
        if (result.size() == MAX_SHOWN) {
            result += "...";
            break;
        }
        result += (c == '\r' || c == '\n' || c == '\t') ? ' ' : c;
    }
    return result;
}

std::string DescribeAnchor(const DissasmReplayJournal& journal, const DissasmReplayPlace& place)
{
    std::string text = Hex(ReplayPlaceAddress(journal, place));
    if (place.anchor.kind == DissasmCommentAnchor::Kind::Variable) {
        char offset[24];
        snprintf(offset, sizeof(offset), "[%s0x%x]", place.anchor.frameOffset < 0 ? "-" : "+", static_cast<unsigned>(std::abs(static_cast<int64>(place.anchor.frameOffset))));
        text += offset;
    } else if (place.anchor.kind == DissasmCommentAnchor::Kind::Label)
        text += " (label)";
    return text;
}

std::string DescribeEdit(const DissasmReplayJournal& journal, const DissasmReplayPlace& place, const DissasmReplayEdit& edit)
{
    const std::string at = DescribeAnchor(journal, place);
    switch (edit.kind) {
    case EditKind::Comment:
    case EditKind::RepeatableComment: {
        const char* what = edit.kind == EditKind::Comment ? "comment" : "repeatable comment";
        if (!edit.after.has_value())
            return std::string(what) + " removed at " + at;
        return std::string(what) + (edit.before.has_value() ? " changed at " : " added at ") + at + ": " + Quote(edit.after);
    }
    case EditKind::LabelName: // the place is the label: its address is enough
        return "rename " + Hex(ReplayPlaceAddress(journal, place)) + " " + Quote(edit.before) + " -> " + Quote(edit.after);
    case EditKind::VariableName:
        return "rename variable " + at + " " + Quote(edit.before) + " -> " + Quote(edit.after);
    case EditKind::DecimalOperand:
        return "number base of operand " + std::to_string(edit.numberIndex) + " at " + at;
    case EditKind::AddZone:
        return "collapsible zone added at " + at + ": " + Quote(edit.zone.name);
    case EditKind::RemoveZone:
        return "collapsible zone removed at " + at + ": " + Quote(edit.zone.name);
    case EditKind::DataRanges:
        return "data defined at " + at + " (" + std::to_string(edit.rangesAfter.size()) + " ranges)";
    case EditKind::UserFunctions:
        return "functions edited at " + at;
    case EditKind::VariableStructures:
        return "variable structures edited at " + at;
    case EditKind::OperandStructure:
        return "operand structure at " + at + ": " + Quote(edit.after);
    case EditKind::OperandConstant:
        return "operand constant at " + at + ": " + Quote(edit.after);
    case EditKind::UserPrototypes:
        return "prototype edited at " + at;
    }
    return "edit at " + at;
}

std::string_view JumpKindName(DissasmReplayJumpKind kind)
{
    switch (kind) {
    case DissasmReplayJumpKind::Follow:
        return "follow";
    case DissasmReplayJumpKind::Entry:
        return "entry point";
    case DissasmReplayJumpKind::GoTo:
        return "go to";
    case DissasmReplayJumpKind::Xref:
        return "cross reference";
    case DissasmReplayJumpKind::Band:
        return "navigation band";
    case DissasmReplayJumpKind::Search:
        return "search";
    case DissasmReplayJumpKind::Bookmark:
        return "bookmark";
    default:
        return "jump";
    }
}
} // namespace

// ------------------------------------------------------------------ the journal

bool GView::View::DissasmViewer::IsReplayTextEdit(DissasmEdit::Kind kind)
{
    return kind == EditKind::Comment || kind == EditKind::LabelName || kind == EditKind::VariableName || kind == EditKind::OperandStructure ||
           kind == EditKind::OperandConstant || kind == EditKind::RepeatableComment;
}

bool GView::View::DissasmViewer::ReplayEditNeedsReanalysis(DissasmEdit::Kind kind)
{
    return kind == EditKind::DataRanges || kind == EditKind::UserFunctions || kind == EditKind::VariableStructures || kind == EditKind::UserPrototypes;
}

std::string_view GView::View::DissasmViewer::ReplayEditKindName(DissasmEdit::Kind kind)
{
    switch (kind) {
    case EditKind::Comment:
        return "comment";
    case EditKind::LabelName:
        return "name";
    case EditKind::VariableName:
        return "variable";
    case EditKind::DecimalOperand:
        return "decimal";
    case EditKind::AddZone:
        return "zoneAdd";
    case EditKind::RemoveZone:
        return "zoneRemove";
    case EditKind::DataRanges:
        return "dataRanges";
    case EditKind::UserFunctions:
        return "functions";
    case EditKind::VariableStructures:
        return "variableStructures";
    case EditKind::OperandStructure:
        return "operandStructure";
    case EditKind::OperandConstant:
        return "operandConstant";
    case EditKind::RepeatableComment:
        return "repeatableComment";
    case EditKind::UserPrototypes:
        return "prototypes";
    }
    return "comment";
}

std::optional<DissasmEdit::Kind> GView::View::DissasmViewer::ReplayEditKindFromName(std::string_view name)
{
    for (uint8 kind = 0; kind <= static_cast<uint8>(EditKind::UserPrototypes); kind++)
        if (ReplayEditKindName(static_cast<EditKind>(kind)) == name)
            return static_cast<EditKind>(kind);
    return {};
}

DissasmReplayEvent GView::View::DissasmViewer::NormalizedReplayEvent(const DissasmReplayEvent& event)
{
    DissasmReplayEvent result;
    result.kind = event.kind;
    result.time = event.time;
    if (event.HasPlace())
        result.place = event.place;
    switch (event.kind) {
    case Kind::Visit:
        result.source = event.source;
        break;
    case Kind::Jump:
        result.from     = event.from;
        result.jumpKind = event.jumpKind;
        result.mnemonic = event.mnemonic;
        break;
    case Kind::Undo:
    case Kind::Redo:
        result.ref = event.ref;
        break;
    case Kind::Import:
        result.importSource = event.importSource;
        break;
    case Kind::Reanalysis:
        result.place.anchor = {};
        break;
    default:
        break;
    }
    if (event.HasEdit() && event.edit.has_value())
        result.edit = NormalizedEdit(event.edit.value());
    return result;
}

bool GView::View::DissasmViewer::IsValidReplayEvent(const DissasmReplayEvent& event, size_t zoneCount, size_t index)
{
    if (event.kind > Kind::Reanalysis || !(NormalizedReplayEvent(event) == event))
        return false;
    if (event.HasPlace() && (event.place.zone >= zoneCount || !IsValidAnchor(event.place.anchor)))
        return false;
    switch (event.kind) {
    case Kind::Visit:
        return event.source <= DissasmReplayVisitSource::Mouse;
    case Kind::Jump:
        return event.from.zone < zoneCount && IsValidAnchor(event.from.anchor) && event.jumpKind <= DissasmReplayJumpKind::Other &&
               event.mnemonic.size() <= DISSASM_REPLAY_MAX_MNEMONIC && event.mnemonic.find('\0') == std::string::npos;
    case Kind::Edit:
    case Kind::Undo:
    case Kind::Redo:
        return event.edit.has_value() && IsValidEdit(event.edit.value()) && (event.ref == DISSASM_REPLAY_NO_REF || event.ref < index);
    case Kind::Import:
        return event.importSource <= DissasmReplayImportSource::ServerSolution;
    default:
        return true;
    }
}

uint32 DissasmReplayJournal::ZoneIndexOf(const DissasmCodeZone& zone)
{
    return ZoneIndexOf(zone.zoneDetails.startingZonePoint, zone.labelAddressBase);
}

uint32 DissasmReplayJournal::ZoneIndexOf(uint64 fileOffset, uint64 addressBase)
{
    const DissasmReplayZone zone{ fileOffset, addressBase };
    const auto found = std::find(zones.begin(), zones.end(), zone);
    if (found != zones.end())
        return static_cast<uint32>(found - zones.begin());
    if (zones.size() >= DISSASM_REPLAY_MAX_ZONES)
        return DISSASM_REPLAY_NO_ZONE;
    zones.push_back(zone);
    return static_cast<uint32>(zones.size() - 1);
}

bool DissasmReplayJournal::Erase(size_t index)
{
    if (index >= events.size())
        return false;
    std::vector<bool> remove(events.size(), false);
    remove[index] = true;
    RemoveEvents(events, remove);
    return true;
}

size_t DissasmReplayJournal::EraseVisits(size_t first, size_t last)
{
    last = std::min(last, events.size());
    std::vector<bool> remove(events.size(), false);
    for (size_t index = first; index < last; index++)
        remove[index] = events[index].kind == Kind::Visit;
    return RemoveEvents(events, remove);
}

size_t DissasmReplayJournal::Compact()
{
    return CompactReplayEvents(events);
}

void DissasmReplayJournal::Clear()
{
    startedAt = 0;
    zones.clear();
    events.clear();
}

size_t GView::View::DissasmViewer::CompactReplayEvents(std::vector<DissasmReplayEvent>& events)
{
    constexpr size_t KEPT_VISITS = 3;
    std::vector<bool> remove(events.size(), false);
    size_t index = 0;
    while (index < events.size()) {
        if (events[index].kind != Kind::Visit) {
            index++;
            continue;
        }
        size_t end = index; // the run of visits [index, end)
        while (end < events.size() && events[end].kind == Kind::Visit)
            end++;
        if (end == events.size()) { // nothing was done after them
            for (size_t visit = index; visit < end; visit++)
                remove[visit] = true;
            break;
        }
        std::vector<size_t> visits; // the run without the same place visited again right after
        for (size_t visit = index; visit < end; visit++) {
            if (!visits.empty() && events[visits.back()].place == events[visit].place)
                remove[visit] = true;
            else
                visits.push_back(visit);
        }
        for (size_t kept = 0; kept + KEPT_VISITS < visits.size(); kept++)
            remove[visits[kept]] = true;
        index = end;
    }
    return RemoveEvents(events, remove);
}

void GView::View::DissasmViewer::ReplayJournalToBuffer(const DissasmReplayJournal& journal, std::vector<std::byte>& buffer)
{
    buffer.clear();
    append_bytes(buffer, DISSASM_REPLAY_MAGIC);
    append_bytes(buffer, DISSASM_REPLAY_VERSION);
    append_bytes(buffer, journal.startedAt);
    append_varint(buffer, journal.zones.size());
    for (const auto& zone : journal.zones) {
        append_varint(buffer, zone.fileOffset);
        append_varint(buffer, zone.addressBase);
    }
    append_varint(buffer, journal.events.size());
    uint32 time = 0;
    for (const auto& event : journal.events) {
        append_bytes(buffer, static_cast<uint8>(event.kind));
        const uint32 eventTime = std::max(time, event.time); // never decreasing (the recorder keeps it so)
        append_varint(buffer, eventTime - time);
        time = eventTime;
        switch (event.kind) {
        case Kind::Visit:
            WritePlace(buffer, event.place);
            append_bytes(buffer, static_cast<uint8>(event.source));
            break;
        case Kind::Jump: {
            WritePlace(buffer, event.place);
            WritePlace(buffer, event.from);
            append_bytes(buffer, static_cast<uint8>(event.jumpKind));
            const size_t size = std::min(event.mnemonic.size(), DISSASM_REPLAY_MAX_MNEMONIC);
            append_bytes(buffer, static_cast<uint8>(size));
            buffer.insert(buffer.end(), reinterpret_cast<const std::byte*>(event.mnemonic.data()), reinterpret_cast<const std::byte*>(event.mnemonic.data()) + size);
            break;
        }
        case Kind::JumpBack:
        case Kind::JumpForward:
            WritePlace(buffer, event.place);
            break;
        case Kind::Edit:
        case Kind::Undo:
        case Kind::Redo: {
            WritePlace(buffer, event.place);
            const DissasmReplayEdit empty;
            const auto& edit = event.edit.has_value() ? event.edit.value() : empty;
            append_bytes(buffer, static_cast<uint8>(edit.kind));
            if (event.kind != Kind::Edit)
                append_varint(buffer, event.ref == DISSASM_REPLAY_NO_REF ? 0 : static_cast<uint64>(event.ref) + 1);
            WritePayload(buffer, edit);
            break;
        }
        case Kind::Import:
            append_bytes(buffer, static_cast<uint8>(event.importSource));
            break;
        case Kind::Reanalysis:
            append_varint(buffer, event.place.zone);
            break;
        }
    }
}

bool GView::View::DissasmViewer::ReplayJournalFromBuffer(const std::byte* data, size_t size, DissasmReplayJournal& journal)
{
    journal.Clear();
    bool ok = false;
    try {
        ok = data != nullptr && ReadJournal(data, size, journal);
    } catch (...) { // bad_alloc of a huge (corrupted) record
        ok = false;
    }
    if (!ok)
        journal.Clear();
    return ok;
}

uint64 GView::View::DissasmViewer::ReplayPlaceAddress(const DissasmReplayJournal& journal, const DissasmReplayPlace& place)
{
    const uint64 base = place.zone < journal.zones.size() ? journal.zones[place.zone].addressBase : 0;
    return base + place.anchor.address;
}

std::string GView::View::DissasmViewer::DescribeReplayEvent(const DissasmReplayJournal& journal, size_t index, bool withTime)
{
    if (index >= journal.events.size())
        return {};
    const auto& event = journal.events[index];
    char time[32];
    snprintf(time, sizeof(time), "%02u:%02u:%02u ", event.time / 3600, (event.time / 60) % 60, event.time % 60);
    std::string text = withTime ? time : "";
    switch (event.kind) {
    case Kind::Visit:
        text += "visit " + DescribeAnchor(journal, event.place);
        if (event.source == DissasmReplayVisitSource::Mouse)
            text += " (mouse)";
        break;
    case Kind::Jump:
        text += std::string(JumpKindName(event.jumpKind));
        if (!event.mnemonic.empty())
            text += " " + event.mnemonic;
        text += " " + DescribeAnchor(journal, event.from) + " -> " + DescribeAnchor(journal, event.place);
        break;
    case Kind::JumpBack:
        text += "back to " + DescribeAnchor(journal, event.place);
        break;
    case Kind::JumpForward:
        text += "forward to " + DescribeAnchor(journal, event.place);
        break;
    case Kind::Edit:
    case Kind::Undo:
    case Kind::Redo:
        if (event.kind != Kind::Edit)
            text += event.kind == Kind::Undo ? "undo: " : "redo: ";
        text += event.edit.has_value() ? DescribeEdit(journal, event.place, event.edit.value()) : std::string("edit");
        break;
    case Kind::Import:
        text += event.importSource == DissasmReplayImportSource::File
                      ? "annotations imported from a file"
                      : (event.importSource == DissasmReplayImportSource::ServerWork ? "saved work loaded from the course" : "teacher solution loaded");
        break;
    case Kind::Reanalysis:
        text += "new analysis of the zone at file offset " +
                Hex(event.place.zone < journal.zones.size() ? journal.zones[event.place.zone].fileOffset : 0);
        break;
    }
    return text;
}

std::optional<std::pair<DissasmCommentAnchor, DissasmReplayEdit>> GView::View::DissasmViewer::MakeReplayEdit(DissasmCodeZone& zone, const DissasmEdit& edit)
{
    DissasmCommentAnchor at;
    at.address = edit.address;
    DissasmReplayEdit result;
    result.kind = edit.kind;
    if (IsReplayTextEdit(edit.kind)) {
        result.before = edit.before;
        result.after  = edit.after;
    }
    switch (edit.kind) {
    case EditKind::Comment:
        at = edit.anchor;
        break;
    case EditKind::LabelName:
        at.kind = DissasmCommentAnchor::Kind::Label;
        break;
    case EditKind::VariableName:
        at.kind        = DissasmCommentAnchor::Kind::Variable;
        at.frameOffset = edit.frameOffset;
        break;
    case EditKind::DecimalOperand:
        result.numberIndex = edit.numberIndex;
        break;
    case EditKind::AddZone:
    case EditKind::RemoveZone: {
        const auto anchors = zone.GetAnchorsOfCollapsibleZone(edit.zone);
        if (!anchors.has_value())
            return {};
        result.zone = anchors.value();
        at          = anchors->first;
        break;
    }
    case EditKind::DataRanges:
        result.rangesBefore = edit.rangesBefore;
        result.rangesAfter  = edit.rangesAfter;
        break;
    case EditKind::UserFunctions:
        result.functionsBefore = edit.functionsBefore;
        result.functionsAfter  = edit.functionsAfter;
        break;
    case EditKind::VariableStructures:
        result.structuresBefore = edit.structuresBefore;
        result.structuresAfter  = edit.structuresAfter;
        break;
    case EditKind::UserPrototypes:
        result.prototypesBefore = edit.prototypesBefore;
        result.prototypesAfter  = edit.prototypesAfter;
        break;
    default:
        break;
    }
    if (at.kind != DissasmCommentAnchor::Kind::Variable)
        at.frameOffset = 0;
    if (!IsValidAnchor(at) || !IsValidEdit(result))
        return {};
    return std::make_pair(at, std::move(result));
}

DissasmEdit GView::View::DissasmViewer::ToDissasmEdit(const DissasmReplayEdit& edit, const DissasmCommentAnchor& at)
{
    DissasmEdit result;
    result.kind             = edit.kind;
    result.anchor           = at;
    result.address          = at.address;
    result.frameOffset      = at.frameOffset;
    result.numberIndex      = edit.numberIndex;
    result.before           = edit.before;
    result.after            = edit.after;
    result.rangesBefore     = edit.rangesBefore;
    result.rangesAfter      = edit.rangesAfter;
    result.functionsBefore  = edit.functionsBefore;
    result.functionsAfter   = edit.functionsAfter;
    result.structuresBefore = edit.structuresBefore;
    result.structuresAfter  = edit.structuresAfter;
    result.prototypesBefore = edit.prototypesBefore;
    result.prototypesAfter  = edit.prototypesAfter;
    return result;
}
