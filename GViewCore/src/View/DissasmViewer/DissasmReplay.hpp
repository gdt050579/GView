#pragma once

#include "DissasmCodeZone.hpp"

#include <optional>
#include <string>
#include <vector>

namespace GView::View::DissasmViewer
{
// The replay journal: what the user did in the view, in order (the lines visited, the jumps followed, the edits, the undos and the redos, the
// imports, the new analyses), so that another user can step through it (DissasmReplayController). One journal per file; the places are kept
// by the anchors of their lines (an instruction, a label, a local variable) in a zone of the journal (its file offset and the address of its
// first decoded instruction), so they survive a new analysis. It is saved in the cache file (the "DissasmReplayJournal" record) and in the
// work documents of the courses (DissasmWorkDocument.hpp).
constexpr std::string_view DISSASM_REPLAY_RECORD = "DissasmReplayJournal";
constexpr uint32 DISSASM_REPLAY_MAGIC            = 0x4A524447; // "GDRJ"
constexpr uint32 DISSASM_REPLAY_VERSION          = 1;
// the limits of a journal: the recorder stops at them, a record above them is corrupted
constexpr size_t DISSASM_REPLAY_MAX_EVENTS   = 200000;
constexpr size_t DISSASM_REPLAY_MAX_ZONES    = 4096;
constexpr size_t DISSASM_REPLAY_MAX_TEXT     = 64 * 1024; // a comment, a name, a prototype
constexpr size_t DISSASM_REPLAY_MAX_MNEMONIC = 15;
constexpr size_t DISSASM_REPLAY_MAX_LIST     = 0x100000; // the entries of a list of an edit (data ranges, functions, structures, prototypes)
constexpr uint32 DISSASM_REPLAY_NO_REF       = 0xFFFFFFFFu;
constexpr uint32 DISSASM_REPLAY_NO_ZONE      = 0xFFFFFFFFu;

// a zone of the file: its file offset (as DissasmCodeZone::zoneDetails.startingZonePoint) and the address of its first decoded instruction
// (DissasmCodeZone::labelAddressBase, the VA): the anchors are relative to it
struct DissasmReplayZone {
    uint64 fileOffset  = 0;
    uint64 addressBase = 0;
    bool operator==(const DissasmReplayZone&) const = default;
};

// a place of the journal: the anchor of a line of a zone of the journal (frameOffset is 0 unless the anchor is a variable)
struct DissasmReplayPlace {
    uint32 zone = 0;
    DissasmCommentAnchor anchor;
    bool operator==(const DissasmReplayPlace&) const = default;
};

enum class DissasmReplayVisitSource : uint8 { Keyboard, Mouse };
// what made a jump: Space / Enter on a call / jump (Follow), the entry point (Entry), the GoTo dialog, the cross references, the navigation
// band, a search, the bookmarks, another window of the view (Other: the functions, the strings, the imports, the call tree ...)
enum class DissasmReplayJumpKind : uint8 { Follow, Entry, GoTo, Xref, Band, Search, Bookmark, Other };
// where imported annotations came from: an annotations file, the work saved on the course server, a solution of the teacher
enum class DissasmReplayImportSource : uint8 { File, ServerWork, ServerSolution };

// An edit of the journal, self-contained (it is applied / undone without the history of the zone). Its place (the anchor of its line) is the
// place of its event: the comment anchor of a Comment, the label of a LabelName, the variable of a VariableName (its frame offset), the
// instruction (or the line) of the other edits, the first line of a collapsible zone.
struct DissasmReplayEdit {
    DissasmEdit::Kind kind = DissasmEdit::Kind::Comment;
    uint32 numberIndex     = 0; // DecimalOperand: the operand number (< 32)
    // Comment / RepeatableComment (none: no comment), LabelName, VariableName, OperandStructure (none: no structure), OperandConstant (none:
    // the number)
    std::optional<std::string> before, after;
    DissasmCodeZone::CollapsibleZoneAnchors zone; // AddZone / RemoveZone
    std::vector<DissasmInstructionSet::DataRange> rangesBefore, rangesAfter;
    std::map<uint64, uint8> functionsBefore, functionsAfter;
    std::map<std::pair<uint64, int32>, std::string> structuresBefore, structuresAfter;
    std::map<uint64, std::string> prototypesBefore, prototypesAfter;
    bool operator==(const DissasmReplayEdit&) const = default;
};

// An event of the journal. The fields that its kind does not use keep their default values (the records do not store them).
struct DissasmReplayEvent {
    enum class Kind : uint8 { Visit, Jump, JumpBack, JumpForward, Edit, Undo, Redo, Import, Reanalysis };
    Kind kind   = Kind::Visit;
    uint32 time = 0; // seconds since DissasmReplayJournal::startedAt (never decreasing along the journal)
    // Visit, JumpBack / JumpForward: the place reached; Jump: the destination; Edit / Undo / Redo: the place of the edit; Reanalysis: only
    // the zone (a default anchor); Import: unused
    DissasmReplayPlace place;
    DissasmReplayPlace from;                                              // Jump: where the jump started
    DissasmReplayVisitSource source        = DissasmReplayVisitSource::Keyboard; // Visit
    DissasmReplayJumpKind jumpKind         = DissasmReplayJumpKind::Follow;     // Jump
    std::string mnemonic;                                                       // Jump Follow: the instruction followed (call, jz)
    DissasmReplayImportSource importSource = DissasmReplayImportSource::File;  // Import
    uint32 ref = DISSASM_REPLAY_NO_REF; // Undo / Redo: the index of the event they undo / redo (informational, the payload is complete)
    std::optional<DissasmReplayEdit> edit; // Edit / Undo / Redo
    bool operator==(const DissasmReplayEvent&) const = default;

    bool HasPlace() const
    {
        return kind != Kind::Import;
    }
    bool HasEdit() const
    {
        return kind == Kind::Edit || kind == Kind::Undo || kind == Kind::Redo;
    }
};

struct DissasmReplayJournal {
    uint64 startedAt = 0; // UNIX time of the first event (0: an empty journal that never started)
    std::vector<DissasmReplayZone> zones;
    std::vector<DissasmReplayEvent> events;

    // the index of the zone (added when it is not there yet); DISSASM_REPLAY_NO_ZONE when the journal has DISSASM_REPLAY_MAX_ZONES zones
    uint32 ZoneIndexOf(const DissasmCodeZone& zone);
    uint32 ZoneIndexOf(uint64 fileOffset, uint64 addressBase);
    // the replay editor: removes an event (the references to it are dropped, the later ones move); false outside the journal
    bool Erase(size_t index);
    // removes the visits of [first, last); the number removed
    size_t EraseVisits(size_t first, size_t last);
    // the rule of the recorder applied again (CompactReplayEvents); the number of events removed
    size_t Compact();
    void Clear();
    bool operator==(const DissasmReplayJournal&) const = default;
};

// The visits between two operations (every other kind): the same place visited again right after is one visit (the first), a run of visits
// before an operation keeps its last 3, the visits after the last operation are dropped (nothing was done there). The references of the
// Undo / Redo events follow their events. Idempotent; the number of events removed.
size_t CompactReplayEvents(std::vector<DissasmReplayEvent>& events);

// an event that a journal of `zoneCount` zones can hold at `index` (its zones exist, its references point before it, its texts and lists are
// within the limits, its unused fields are defaults): what the records accept and what the recorder writes
bool IsValidReplayEvent(const DissasmReplayEvent& event, size_t zoneCount, size_t index);

// The "DissasmReplayJournal" record (little endian, LEB128 varints, zigzag for the signed numbers, the texts as [varint size][bytes]):
//   [u32 magic GDRJ][u32 version][u64 startedAt][varint zoneCount] zoneCount x [varint fileOffset][varint addressBase]
//   [varint eventCount] eventCount x [u8 kind][varint dt] (dt: the seconds since the previous event) then by kind:
//     place = [varint zone][u8 anchorKind][varint address][svarint frameOffset: Variable only]
//     Visit: place [u8 source] | Jump: place(to) place(from) [u8 jumpKind][u8 size][mnemonic] | JumpBack / JumpForward: place
//     Edit: place [u8 editKind] payload | Undo / Redo: place [u8 editKind][varint ref + 1 (0: none)] payload
//     Import: [u8 source] | Reanalysis: [varint zone]
//   payload: the texts (Comment, LabelName, VariableName, OperandStructure, OperandConstant, RepeatableComment): [u8 flags: 1 before, 2 after]
//            [before][after]; DecimalOperand: [varint numberIndex]; AddZone / RemoveZone: anchor(first) anchor(last) [name][u8 collapsed];
//            DataRanges: twice (before, after) [varint n] n x [varint start][varint size][u8 unit][u8 isOffset][u8 reference];
//            UserFunctions: twice [varint n] n x [varint address][u8 flags]; VariableStructures: twice [varint n] n x [varint function]
//            [svarint frameOffset][name]; UserPrototypes: twice [varint n] n x [varint function][text]
//     anchor = [u8 anchorKind][varint address][svarint frameOffset: Variable only]
void ReplayJournalToBuffer(const DissasmReplayJournal& journal, std::vector<std::byte>& buffer);
// all or nothing: false (and an empty journal) for a record that is not entirely valid
bool ReplayJournalFromBuffer(const std::byte* data, size_t size, DissasmReplayJournal& journal);

// "00:12:05 rename 0x401080 sub_401080 -> decrypt": the time since the start (withTime), what the event did and where (the VA of its
// place)
std::string DescribeReplayEvent(const DissasmReplayJournal& journal, size_t index, bool withTime = true);
// the VA of a place of the journal
uint64 ReplayPlaceAddress(const DissasmReplayJournal& journal, const DissasmReplayPlace& place);

// an edit of a zone as an edit of the journal and its place; none when it can not be kept (the lines of a collapsible zone can not be
// decoded, a text or a list above the limits)
std::optional<std::pair<DissasmCommentAnchor, DissasmReplayEdit>> MakeReplayEdit(DissasmCodeZone& zone, const DissasmEdit& edit);
// the edit of the zone of an edit of the journal at its place (the collapsible zones: their lines are not known, ApplyReplayZoneEdit)
DissasmEdit ToDissasmEdit(const DissasmReplayEdit& edit, const DissasmCommentAnchor& at);
// the edits that need a new analysis of their zone (DissasmEditPlace::reanalyze)
bool ReplayEditNeedsReanalysis(DissasmEdit::Kind kind);
// the edits of a text (before / after): Comment, LabelName, VariableName, OperandStructure, OperandConstant, RepeatableComment
bool IsReplayTextEdit(DissasmEdit::Kind kind);
// the names of the kinds of the edits in the work documents (the vocabulary of the annotations: comment, name, variable, decimal, zoneAdd,
// zoneRemove, dataRanges, functions, variableStructures, operandStructure, operandConstant, repeatableComment, prototypes)
std::string_view ReplayEditKindName(DissasmEdit::Kind kind);
std::optional<DissasmEdit::Kind> ReplayEditKindFromName(std::string_view name);
// the event with the fields that its kind does not use reset (and the same for its edit)
DissasmReplayEvent NormalizedReplayEvent(const DissasmReplayEvent& event);
} // namespace GView::View::DissasmViewer
