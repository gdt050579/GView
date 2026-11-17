#pragma once

#include "DissasmReplay.hpp"
#include "DissasmAnnotations.hpp"

#include <nlohmann/json.hpp>

namespace GView::View::DissasmViewer
{
// The work document of a course (the work of a student, a solution of the teacher): the annotations document (BuildAnnotationsDocument,
// keyed by the VAs: only the changes of the user, never the cache file) with two more keys that ImportAnnotationsDocument ignores:
//   "meta":   {"kind": "work" | "solution", "clientVersion", "savedAt", "problem", "itemVersion", "sha256"}
//   "replay": {"version": 1, "startedAt", "zones": [{"fileOffset": "0x400", "addressBase": "0x401000"}], "events": [...]}
// An event is a compact array: [tag, dt (the seconds since the previous event), ...]. A place is "zone, address (the VA, hex), anchor kind
// (i: instruction, l: label, v: variable)[, frameOffset (v only)]":
//   ["v", dt, place, "k" | "m"]                       a visit (keyboard / mouse)
//   ["j", dt, place(from), place(to), mnemonic, kind] a jump (kind: follow, entry, goto, xref, band, search, bookmark, other)
//   ["b", dt, place] / ["f", dt, place]               back / forward in the jumps history
//   ["e", dt, place, editKind, payload]               an edit (editKind: the names of ReplayEditKindName)
//   ["u", dt, place, editKind, ref, payload]          an undo / a redo (["r", ...]): ref is the index of the event it undoes / redoes or null
//   ["i", dt, "file" | "server-work" | "server-solution"] an import
//   ["a", dt, zone]                                   a new analysis of the zone
// payload: {"before", "after"} (texts; a missing key: none), {"operand"} (decimal), {"first", "last", "name", "collapsed"} (zoneAdd /
// zoneRemove, the anchors as in the annotations), {"before": [...], "after": [...]} (dataRanges: {"address", "size", "unit", "offset",
// "reference"}, functions: {"address", "flags"}, variableStructures: {"function", "frameOffset", "structure"}, prototypes: {"function",
// "prototype"}).
constexpr uint32 DISSASM_REPLAY_JSON_VERSION = 1;

struct DissasmWorkMeta {
    std::string kind; // "work" / "solution"
    std::string clientVersion;
    uint64 savedAt = 0; // UNIX time
    std::string problem;
    uint32 itemVersion = 0;
    std::string sha256; // the SHA-256 of the analysed file given by the catalogue
    bool operator==(const DissasmWorkMeta&) const = default;
};

struct DissasmWorkDocument {
    DissasmWorkMeta meta;
    DissasmReplayJournal journal;
    bool hasReplay = false; // the document has a "replay" object
    uint32 skipped = 0;     // the zones / the events of the replay that could not be read (or a replay of a newer version)
};

nlohmann::json ReplayJournalToJson(const DissasmReplayJournal& journal);
// tolerant (the document is untrusted): an entry that can not be read is skipped and counted, the references follow their events; never
// throws. A replay of a newer version: an empty journal, skipped 1
DissasmReplayJournal ReplayJournalFromJson(const nlohmann::json& replay, uint32& skipped);

// BuildAnnotationsDocument + "meta" + "replay" (none for a journal without events)
nlohmann::json BuildWorkDocument(
      const std::vector<DissasmCodeZone*>& zones, std::string_view fileName, const DissasmReplayJournal& journal, const DissasmWorkMeta& meta);
// the meta and the journal of a work document (its annotations: ImportAnnotationsDocument); false and the reason when it is not an annotations
// document or a newer version
bool ParseWorkDocument(const nlohmann::json& document, DissasmWorkDocument& result, std::string& error);
} // namespace GView::View::DissasmViewer
