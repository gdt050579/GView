#include "DissasmReplay.hpp"
#include "DissasmReplayRecorder.hpp"
#include "DissasmReplayController.hpp"
#include "DissasmWorkDocument.hpp"
#include "DissasmAnnotations.hpp"
#include "DissasmIOHelpers.hpp"
#include "tests_dissasm_fixture.hpp"
#include "tests_dissasm_fuzz.hpp"

#include <catch.hpp>
#include <cstdlib>
#include <random>

using namespace GView::View::DissasmViewer;

namespace
{
using Kind     = DissasmReplayEvent::Kind;
using EditKind = DissasmEdit::Kind;
using Anchor   = DissasmCommentAnchor::Kind;

DissasmReplayPlace MakePlace(uint32 zone, uint64 address, Anchor kind = Anchor::Instruction, int32 frameOffset = 0)
{
    DissasmReplayPlace place;
    place.zone               = zone;
    place.anchor.kind        = kind;
    place.anchor.address     = address;
    place.anchor.frameOffset = kind == Anchor::Variable ? frameOffset : 0;
    return place;
}

DissasmReplayEvent Visit(uint32 time, DissasmReplayPlace place, DissasmReplayVisitSource source = DissasmReplayVisitSource::Keyboard)
{
    DissasmReplayEvent event;
    event.kind   = Kind::Visit;
    event.time   = time;
    event.place  = place;
    event.source = source;
    return event;
}

DissasmReplayEvent Jump(uint32 time, DissasmReplayPlace to, DissasmReplayPlace from, DissasmReplayJumpKind kind, std::string mnemonic = {})
{
    DissasmReplayEvent event;
    event.kind     = Kind::Jump;
    event.time     = time;
    event.place    = to;
    event.from     = from;
    event.jumpKind = kind;
    event.mnemonic = std::move(mnemonic);
    return event;
}

DissasmReplayEvent Navigation(Kind kind, uint32 time, DissasmReplayPlace place)
{
    DissasmReplayEvent event;
    event.kind  = kind;
    event.time  = time;
    event.place = place;
    return event;
}

DissasmReplayEvent EditEvent(Kind kind, uint32 time, DissasmReplayPlace place, DissasmReplayEdit edit, uint32 ref = DISSASM_REPLAY_NO_REF)
{
    DissasmReplayEvent event;
    event.kind  = kind;
    event.time  = time;
    event.place = place;
    event.edit  = std::move(edit);
    event.ref   = kind == Kind::Edit ? DISSASM_REPLAY_NO_REF : ref;
    return event;
}

DissasmReplayEvent Import(uint32 time, DissasmReplayImportSource source)
{
    DissasmReplayEvent event;
    event.kind         = Kind::Import;
    event.time         = time;
    event.importSource = source;
    return event;
}

DissasmReplayEvent Reanalysis(uint32 time, uint32 zone)
{
    DissasmReplayEvent event;
    event.kind       = Kind::Reanalysis;
    event.time       = time;
    event.place.zone = zone;
    return event;
}

DissasmReplayEdit TextEdit(EditKind kind, std::optional<std::string> before, std::optional<std::string> after)
{
    DissasmReplayEdit edit;
    edit.kind   = kind;
    edit.before = std::move(before);
    edit.after  = std::move(after);
    return edit;
}

// the events of FullJournal used by the tests
constexpr size_t FULL_FOLLOW  = 3;  // the Follow jump ("vpunpckhqdq")
constexpr size_t FULL_COMMENT = 13; // a comment of 64 KiB
constexpr size_t FULL_RENAME  = 14; // the rename of a label
constexpr size_t FULL_DECIMAL = 16; // the number base of the operand 31

// a journal with every kind of event and edit, 64 bit addresses, negative frame offsets, 64 KiB texts, references and none
DissasmReplayJournal FullJournal()
{
    DissasmReplayJournal journal;
    journal.startedAt = 0xFEDCBA9876543210ull;
    journal.zones     = { { 0x400, 0x401000 }, { 0xFFFFFFFFFFFF0000ull, 0xFFFF800000001000ull } };
    const std::string big(DISSASM_REPLAY_MAX_TEXT, 'x');
    auto& events = journal.events;
    uint32 time  = 0;
    events.push_back(Visit(time += 3, MakePlace(0, 0x10)));
    events.push_back(Visit(time += 1, MakePlace(1, 0xFFFFFFFFFFFFFF00ull, Anchor::Label), DissasmReplayVisitSource::Mouse));
    events.push_back(Visit(time, MakePlace(0, 0x30, Anchor::Variable, -0x7FFFFFFF - 1)));
    for (uint8 kind = 0; kind <= static_cast<uint8>(DissasmReplayJumpKind::Other); kind++)
        events.push_back(Jump(time += 100000, MakePlace(0, 0x80 + kind), MakePlace(1, 0x40, Anchor::Variable, 0x7FFFFFFF),
                              static_cast<DissasmReplayJumpKind>(kind), kind == 0 ? "vpunpckhqdq" : ""));
    events.push_back(Navigation(Kind::JumpBack, time, MakePlace(0, 0x10)));
    events.push_back(Navigation(Kind::JumpForward, time += 7, MakePlace(0, 0x87, Anchor::Label)));

    events.push_back(EditEvent(Kind::Edit, time += 1, MakePlace(0, 0x10), TextEdit(EditKind::Comment, std::nullopt, big)));
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x30, Anchor::Label), TextEdit(EditKind::LabelName, "sub_401030", "decrypt")));
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x30, Anchor::Variable, -8), TextEdit(EditKind::VariableName, "var_8", "count")));
    DissasmReplayEdit decimal;
    decimal.kind        = EditKind::DecimalOperand;
    decimal.numberIndex = 31;
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x38), decimal));
    for (const auto kind : { EditKind::AddZone, EditKind::RemoveZone }) {
        DissasmReplayEdit zone;
        zone.kind = kind;
        zone.zone = { MakePlace(0, 0x40).anchor, MakePlace(0, 0x30, Anchor::Variable, -12).anchor, "Zone-IndexStart 1 -IndexEnd 9", kind == EditKind::RemoveZone };
        events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x40), zone));
    }
    DissasmReplayEdit ranges;
    ranges.kind         = EditKind::DataRanges;
    ranges.rangesBefore = { { 0x10, 0x18, 4, false, 0 } };
    ranges.rangesAfter  = { { 0x10, 0x18, 4, true, 2 }, { 0x20, 0xFFFFFFFFFFFFFFFFull, 0x10, false, 1 } };
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x10), ranges));
    DissasmReplayEdit functions;
    functions.kind           = EditKind::UserFunctions;
    functions.functionsAfter = { { 0x30, USER_FUNCTION_CREATE }, { 0xFFFFFFFFFFFFFFF0ull, USER_FUNCTION_ALL } };
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x30), functions));
    DissasmReplayEdit structures;
    structures.kind             = EditKind::VariableStructures;
    structures.structuresBefore = { { { 0x30, -0x20 }, "SYSTEMTIME" } };
    structures.structuresAfter  = { { { 0x30, -0x20 }, "" }, { { 0x30, 0x7FFFFFFF }, big } };
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x30), structures));
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x44), TextEdit(EditKind::OperandStructure, std::nullopt, "STARTUPINFOW")));
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x44), TextEdit(EditKind::OperandConstant, "HRESULTS", std::nullopt)));
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x44), TextEdit(EditKind::RepeatableComment, "", "decrypts the configuration")));
    DissasmReplayEdit prototypes;
    prototypes.kind            = EditKind::UserPrototypes;
    prototypes.prototypesAfter = { { 0x30, "int decrypt(char* buffer, int size)" } };
    events.push_back(EditEvent(Kind::Edit, time, MakePlace(0, 0x30), prototypes));

    const uint32 renameIndex = FULL_RENAME;
    REQUIRE(events[FULL_FOLLOW].jumpKind == DissasmReplayJumpKind::Follow);
    REQUIRE(events[FULL_COMMENT].edit->kind == EditKind::Comment);
    REQUIRE(events[renameIndex].edit->kind == EditKind::LabelName);
    REQUIRE(events[FULL_DECIMAL].edit->kind == EditKind::DecimalOperand);
    events.push_back(EditEvent(Kind::Undo, time += 2, events[renameIndex].place, events[renameIndex].edit.value(), renameIndex));
    events.push_back(EditEvent(Kind::Redo, time, events[renameIndex].place, events[renameIndex].edit.value(), static_cast<uint32>(events.size() - 1)));
    events.push_back(EditEvent(Kind::Undo, time, MakePlace(0, 0x10), TextEdit(EditKind::Comment, "a", std::nullopt)));
    for (const auto source : { DissasmReplayImportSource::File, DissasmReplayImportSource::ServerWork, DissasmReplayImportSource::ServerSolution })
        events.push_back(Import(time += 60, source));
    events.push_back(Reanalysis(time, 1));
    events.push_back(Visit(time, MakePlace(0, 0x10)));
    return journal;
}

std::vector<std::byte> Encode(const DissasmReplayJournal& journal)
{
    std::vector<std::byte> buffer;
    ReplayJournalToBuffer(journal, buffer);
    return buffer;
}

// a decoded journal: what the recorder writes (the limits, the references, the zones) and what can be written again
void CheckInvariants(const DissasmReplayJournal& journal)
{
    REQUIRE(journal.zones.size() <= DISSASM_REPLAY_MAX_ZONES);
    REQUIRE(journal.events.size() <= DISSASM_REPLAY_MAX_EVENTS);
    uint32 time = 0;
    for (size_t index = 0; index < journal.events.size(); index++) {
        REQUIRE(IsValidReplayEvent(journal.events[index], journal.zones.size(), index));
        REQUIRE(journal.events[index].time >= time);
        time = journal.events[index].time;
        DescribeReplayEvent(journal, index); // never fails
    }
    DissasmReplayJournal again;
    REQUIRE(ReplayJournalFromBuffer(Encode(journal).data(), Encode(journal).size(), again));
    REQUIRE(again == journal);
}

std::vector<Kind> KindsOf(const std::vector<DissasmReplayEvent>& events)
{
    std::vector<Kind> kinds;
    for (const auto& event : events)
        kinds.push_back(event.kind);
    return kinds;
}

// the recorder over a code zone without a view: the cursor is a line of the zone (none: a line outside the code), fake clocks
struct RecorderView {
    DissasmTestInstance test;
    std::optional<uint32> cursorLine;
    uint64 ms       = 5000;
    uint64 unixTime = 1700000000; // not "unix": GCC predefines it as a macro in its GNU modes
    DissasmReplayRecorder recorder;

    explicit RecorderView(bool localVariables = false)
        : test(exampleTest1BinaryCode, exampleTest1BinaryCodeSize, localVariables), recorder(MakeResolver())
    {
        test.zone->editObserver = &recorder;
    }
    DissasmReplayRecorder::Resolver MakeResolver()
    {
        DissasmReplayRecorder::Resolver resolver;
        resolver.cursorPlace = [this]() { return PlaceOfLine(cursorLine); };
        resolver.placeOf     = [this](const CursorState& state) {
            return PlaceOfLine(state.lineInZone >= 2 ? std::optional<uint32>(state.lineInZone - 2) : std::nullopt);
        };
        resolver.nowMs   = [this]() { return ms; };
        resolver.nowUnix = [this]() { return unixTime; };
        return resolver;
    }
    std::optional<DissasmReplayRecorder::ResolvedPlace> PlaceOfLine(std::optional<uint32> line)
    {
        if (!line.has_value())
            return {};
        const auto anchor = test.zone->GetAnchorOfLine(line.value());
        if (!anchor.has_value())
            return {};
        return DissasmReplayRecorder::ResolvedPlace{ test.zone.get(), anchor.value() };
    }
    DissasmReplayPlace PlaceOf(uint32 line)
    {
        const auto anchor = test.zone->GetAnchorOfLine(line);
        REQUIRE(anchor.has_value());
        return { 0, anchor.value() };
    }
    CursorState StateOf(uint32 line) const
    {
        CursorState state;
        state.zoneIndex  = 0;
        state.lineInZone = line + 2; // the title and the columns header
        return state;
    }
    void Key(uint32 line)
    {
        cursorLine = line;
        recorder.NoteCursorMoved(false);
    }
    void Click(uint32 line)
    {
        cursorLine = line;
        recorder.NoteCursorMoved(true);
    }
    void Wait(uint64 milliseconds)
    {
        ms += milliseconds;
        unixTime += milliseconds / 1000;
        recorder.Poll();
    }
    const std::vector<DissasmReplayEvent>& Events() const
    {
        return recorder.Journal().events;
    }
};

// the view of a playback: one zone of the test (found by its file offset); the new analyses are done at once (ReanalyzeCodeZone)
struct PlaybackHost : public DissasmReplayHost {
    DissasmTestInstance& test;
    uint32 moves = 0, linesChanged = 0, reanalyses = 0;
    std::optional<DissasmCommentAnchor> cursor;

    explicit PlaybackHost(DissasmTestInstance& test) : test(test)
    {
    }
    DissasmCodeZone* FindZone(uint64 fileOffset) override
    {
        return test.zone->zoneDetails.startingZonePoint == fileOffset ? test.zone.get() : nullptr;
    }
    bool MoveCursor(DissasmCodeZone& zone, const DissasmCommentAnchor& anchor) override
    {
        if (!zone.GetExpandedLineOfAnchor(anchor).has_value())
            return false;
        moves++;
        cursor = anchor;
        return true;
    }
    void ZoneLinesChanged(DissasmCodeZone&) override
    {
        linesChanged++;
    }
    void Reanalyze(DissasmCodeZone& zone, std::optional<uint64>) override
    {
        reanalyses++;
        DissasmAnnotationsImport imported;
        REQUIRE(ReanalyzeCodeZone(zone, test.lastInitData, imported));
    }
};

// the first line (display) of the zone whose mnemonic is `mnemonic`, from `start`
uint32 FindLine(DissasmTestInstance& test, std::string_view mnemonic, uint32 start = 0)
{
    for (uint32 line = start; line < 400; line++)
        if (test.GetCurrentAsmLine(line).mnemonic == mnemonic)
            return line;
    FAIL("no such line");
    return 0;
}
} // namespace

TEST_CASE("ReplayVarints", "[Dissasm]Replay")
{
    // typed list: UINT64_MAX is unsigned long (not unsigned long long) on LP64 Linux/macOS
    for (const uint64 value : std::initializer_list<uint64>{ 0, 1, 127, 128, 16383, 16384, 0xFFFFFFFFull, 0x123456789ABCDEFull, UINT64_MAX }) {
        std::vector<std::byte> buffer;
        append_varint(buffer, value);
        const std::byte* p = buffer.data();
        uint64 read        = 0;
        REQUIRE(read_varint(p, buffer.data() + buffer.size(), read));
        REQUIRE(read == value);
        REQUIRE(p == buffer.data() + buffer.size());
    }
    const auto sizeOf = [](uint64 value) {
        std::vector<std::byte> buffer;
        append_varint(buffer, value);
        return buffer.size();
    };
    REQUIRE(sizeOf(0) == 1);
    REQUIRE(sizeOf(127) == 1);
    REQUIRE(sizeOf(128) == 2);
    REQUIRE(sizeOf(UINT64_MAX) == 10);
    // typed list: INT64_MIN / INT64_MAX are long (not long long) on LP64 Linux/macOS
    for (const int64 value : std::initializer_list<int64>{ 0, -1, 1, -64, 64, INT32_MIN, INT32_MAX, INT64_MIN, INT64_MAX }) {
        std::vector<std::byte> buffer;
        append_svarint(buffer, value);
        const std::byte* p = buffer.data();
        int64 read         = 0;
        REQUIRE(read_svarint(p, buffer.data() + buffer.size(), read));
        REQUIRE(read == value);
    }
    {
        std::vector<std::byte> small; // zigzag: a small negative number is one byte
        append_svarint(small, -64);
        REQUIRE(small.size() == 1);
    }
    // truncated, longer than 10 bytes, above 64 bits
    const auto fails = [](std::vector<uint8> bytes) {
        std::vector<std::byte> buffer(bytes.size());
        memcpy(buffer.data(), bytes.data(), bytes.size());
        const std::byte* p = buffer.data();
        uint64 value       = 0;
        return !read_varint(p, buffer.data() + buffer.size(), value);
    };
    REQUIRE(fails({}));
    REQUIRE(fails({ 0x80 }));
    REQUIRE(fails({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 }));
    REQUIRE(fails({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02 }));
    REQUIRE_FALSE(fails({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 }));

    // the texts: [varint size][bytes], no NUL, at most maxSize
    std::vector<std::byte> buffer;
    append_varint_string(buffer, "decrypt");
    append_varint_string(buffer, "");
    const std::byte* p = buffer.data();
    std::string text;
    REQUIRE(read_varint_string(p, buffer.data() + buffer.size(), 64, text));
    REQUIRE(text == "decrypt");
    REQUIRE(read_varint_string(p, buffer.data() + buffer.size(), 64, text));
    REQUIRE(text.empty());
    p = buffer.data();
    REQUIRE_FALSE(read_varint_string(p, buffer.data() + buffer.size(), 6, text)); // above the maximum
    buffer.clear();
    append_varint_string(buffer, std::string("a\0b", 3));
    p = buffer.data();
    REQUIRE_FALSE(read_varint_string(p, buffer.data() + buffer.size(), 64, text)); // a NUL
    buffer.clear();
    append_varint_string(buffer, "abc");
    buffer.pop_back();
    p = buffer.data();
    REQUIRE_FALSE(read_varint_string(p, buffer.data() + buffer.size(), 64, text)); // truncated
}

TEST_CASE("ReplayRecordRoundTrip", "[Dissasm]Replay")
{
    const auto journal = FullJournal();
    for (size_t index = 0; index < journal.events.size(); index++) {
        INFO(index);
        REQUIRE(IsValidReplayEvent(journal.events[index], journal.zones.size(), index));
    }
    const auto buffer = Encode(journal);
    DissasmReplayJournal decoded;
    REQUIRE(ReplayJournalFromBuffer(buffer.data(), buffer.size(), decoded));
    REQUIRE(decoded == journal);
    CheckInvariants(decoded);
    for (size_t index = 0; index < decoded.events.size(); index++)
        REQUIRE(!DescribeReplayEvent(decoded, index).empty());

    // the empty journal (and the one that never started)
    for (const auto& empty : { DissasmReplayJournal{}, DissasmReplayJournal{ 1234, { { 1, 2 } }, {} } }) {
        const auto data = Encode(empty);
        DissasmReplayJournal read;
        REQUIRE(ReplayJournalFromBuffer(data.data(), data.size(), read));
        REQUIRE(read == empty);
    }

    // all or nothing: a record that is not entirely valid gives an empty journal
    const auto rejected = [](const std::vector<std::byte>& data) {
        DissasmReplayJournal read = FullJournal();
        const bool ok             = ReplayJournalFromBuffer(data.data(), data.size(), read);
        return !ok && read == DissasmReplayJournal{};
    };
    auto truncated = buffer;
    truncated.pop_back();
    REQUIRE(rejected(truncated));
    auto trailing = buffer;
    trailing.push_back(std::byte{ 0 });
    REQUIRE(rejected(trailing));
    auto otherVersion = buffer;
    otherVersion[4]   = std::byte{ 2 };
    REQUIRE(rejected(otherVersion));
    REQUIRE(rejected({}));

    // the limits: a text above 64 KiB, a mnemonic above 15, an operand number above 31, a reference after its event, a zone that does not exist
    auto tooLong = journal;
    tooLong.events[FULL_COMMENT].edit->after->push_back('y');
    REQUIRE_FALSE(IsValidReplayEvent(tooLong.events[FULL_COMMENT], tooLong.zones.size(), FULL_COMMENT));
    REQUIRE(rejected(Encode(tooLong)));
    auto mnemonic                         = journal;
    mnemonic.events[FULL_FOLLOW].mnemonic = "0123456789abcdef";
    REQUIRE_FALSE(IsValidReplayEvent(mnemonic.events[FULL_FOLLOW], mnemonic.zones.size(), FULL_FOLLOW));
    auto number                                   = journal;
    number.events[FULL_DECIMAL].edit->numberIndex = 32;
    REQUIRE(rejected(Encode(number)));
    auto reference          = journal;
    reference.events.back() = EditEvent(Kind::Undo, reference.events.back().time, MakePlace(0, 0x10), TextEdit(EditKind::Comment, "a", "b"),
                                        static_cast<uint32>(reference.events.size() - 1));
    REQUIRE(rejected(Encode(reference)));
    auto zone                   = journal;
    zone.events[0].place.zone   = 2;
    REQUIRE(rejected(Encode(zone)));
    auto unused                 = journal;
    unused.events[0].mnemonic   = "call"; // a field that a visit does not use
    REQUIRE_FALSE(IsValidReplayEvent(unused.events[0], unused.zones.size(), 0));
}

TEST_CASE("ReplayRecordFuzz", "[Dissasm]Replay")
{
    // GVIEW_FUZZ_ROUNDS=<rounds> [GVIEW_FUZZ_SEED=<seed>]: a longer run with other mutants (a local fuzzing campaign)
    const char* roundsText = std::getenv("GVIEW_FUZZ_ROUNDS");
    const char* seedText   = std::getenv("GVIEW_FUZZ_SEED");
    const uint32 ROUNDS    = roundsText ? static_cast<uint32>(std::strtoul(roundsText, nullptr, 10)) : 3000u;
    std::mt19937 random(seedText ? static_cast<uint32>(std::strtoul(seedText, nullptr, 10)) : 0x52504C59u);
    // a smaller journal too: the mutations reach its later fields more often
    DissasmReplayJournal small;
    small.startedAt = 1700000000;
    small.zones     = { { 0x400, 0x401000 } };
    small.events    = { Visit(1, MakePlace(0, 0x10)),
                        Jump(2, MakePlace(0, 0x80), MakePlace(0, 0x10), DissasmReplayJumpKind::Follow, "call"),
                        EditEvent(Kind::Edit, 3, MakePlace(0, 0x80, Anchor::Label), TextEdit(EditKind::LabelName, "sub_401080", "decrypt")),
                        EditEvent(Kind::Undo, 4, MakePlace(0, 0x80, Anchor::Label), TextEdit(EditKind::LabelName, "sub_401080", "decrypt"), 2),
                        Import(5, DissasmReplayImportSource::ServerWork),
                        Reanalysis(6, 0) };
    const std::vector<std::byte> seeds[] = { Encode(FullJournal()), Encode(small) };
    uint32 accepted = 0;
    for (const auto& seed : seeds) {
        for (uint32 round = 0; round < ROUNDS; round++) {
            const auto mutant = MutateRecord(seed, random);
            DissasmReplayJournal journal;
            if (!ReplayJournalFromBuffer(mutant.data(), mutant.size(), journal)) {
                REQUIRE(journal == DissasmReplayJournal{});
                continue;
            }
            accepted++;
            CheckInvariants(journal);
            CompactReplayEvents(journal.events); // still valid once compacted
            CheckInvariants(journal);
        }
    }
    INFO(accepted);
    REQUIRE(accepted > 0); // some mutants are still valid records (the decoder was reached)
    if (roundsText)
        WARN("replay record mutants accepted: " << accepted << " of " << 2 * ROUNDS);
}

TEST_CASE("ReplayCompaction", "[Dissasm]Replay")
{
    const auto a = MakePlace(0, 0x10), b = MakePlace(0, 0x20), c = MakePlace(0, 0x30), d = MakePlace(0, 0x40), e = MakePlace(0, 0x50);
    const auto edit = EditEvent(Kind::Edit, 9, a, TextEdit(EditKind::Comment, std::nullopt, "x"));
    const auto jump = Jump(9, b, a, DissasmReplayJumpKind::GoTo);
    struct Row {
        std::vector<DissasmReplayEvent> events, expected;
        size_t removed;
    };
    const std::vector<Row> rows = {
        // V V V V E -> V V V E
        { { Visit(1, a), Visit(2, b), Visit(3, c), Visit(4, d), edit }, { Visit(2, b), Visit(3, c), Visit(4, d), edit }, 1 },
        // the same place again right after: one visit, the first
        { { Visit(1, a), Visit(2, a), Visit(3, b), edit }, { Visit(1, a), Visit(3, b), edit }, 1 },
        // the same place again later: a visit of its own
        { { Visit(1, a), Visit(2, b), Visit(3, a), edit }, { Visit(1, a), Visit(2, b), Visit(3, a), edit }, 0 },
        // coalesced first, then the last 3
        { { Visit(1, a), Visit(2, b), Visit(3, b), Visit(4, c), Visit(5, d), jump }, { Visit(2, b), Visit(4, c), Visit(5, d), jump }, 2 },
        // the visits after the last operation are dropped
        { { edit, Visit(1, a), Visit(2, b) }, { edit }, 2 },
        { { Visit(1, a) }, {}, 1 },
        // two runs
        { { Visit(1, a), Visit(2, b), Visit(3, c), Visit(4, d), Visit(5, e), edit, Visit(6, a), Visit(7, b), jump },
          { Visit(3, c), Visit(4, d), Visit(5, e), edit, Visit(6, a), Visit(7, b), jump },
          2 },
        { {}, {}, 0 },
    };
    for (size_t index = 0; index < rows.size(); index++) {
        INFO(index);
        auto events = rows[index].events;
        REQUIRE(CompactReplayEvents(events) == rows[index].removed);
        REQUIRE(events == rows[index].expected);
        REQUIRE(CompactReplayEvents(events) == 0); // idempotent
        REQUIRE(events == rows[index].expected);
    }

    // the references follow their events
    DissasmReplayJournal journal;
    journal.zones  = { { 0x400, 0x401000 } };
    journal.events = { Visit(1, a), Visit(2, b), Visit(3, c), Visit(4, d), edit, Visit(10, a), EditEvent(Kind::Undo, 11, a, edit.edit.value(), 4) };
    REQUIRE(journal.Compact() == 1);
    REQUIRE(journal.events.size() == 6);
    REQUIRE(journal.events[3].kind == Kind::Edit);
    REQUIRE(journal.events[5].ref == 3);
    CheckInvariants(journal);

    // Erase: a reference to the erased event is dropped, the later ones move
    auto erased = journal;
    REQUIRE(erased.Erase(3));
    REQUIRE(erased.events.back().ref == DISSASM_REPLAY_NO_REF);
    erased = journal;
    REQUIRE(erased.Erase(0));
    REQUIRE(erased.events.back().ref == 2);
    REQUIRE_FALSE(erased.Erase(100));
    CheckInvariants(erased);
    // EraseVisits: only the visits of the range
    erased = journal;
    REQUIRE(erased.EraseVisits(0, 3) == 3); // the visits before the edit
    REQUIRE(KindsOf(erased.events) == std::vector<Kind>{ Kind::Edit, Kind::Visit, Kind::Undo });
    REQUIRE(erased.events.back().ref == 0);
    REQUIRE(erased.EraseVisits(0, 100) == 1);
    erased.Clear();
    REQUIRE(erased == DissasmReplayJournal{});
}

TEST_CASE("ReplayDescriptions", "[Dissasm]Replay")
{
    DissasmReplayJournal journal;
    journal.zones = { { 0x400, 0x401000 } };
    journal.events.push_back(EditEvent(Kind::Edit, 12 * 60 + 5, MakePlace(0, 0x80, Anchor::Label), TextEdit(EditKind::LabelName, "sub_401080", "decrypt")));
    journal.events.push_back(Jump(3 * 3600 + 7, MakePlace(0, 0x80), MakePlace(0, 0x10), DissasmReplayJumpKind::Follow, "call"));
    journal.events.push_back(EditEvent(Kind::Undo, 3 * 3600 + 8, MakePlace(0, 0x40), TextEdit(EditKind::Comment, std::nullopt, "loop\nover the key")));
    journal.events.push_back(Visit(3 * 3600 + 9, MakePlace(0, 0x30, Anchor::Variable, -8), DissasmReplayVisitSource::Mouse));
    REQUIRE(DescribeReplayEvent(journal, 0) == "00:12:05 rename 0x401080 sub_401080 -> decrypt");
    REQUIRE(DescribeReplayEvent(journal, 1) == "03:00:07 follow call 0x401010 -> 0x401080");
    REQUIRE(DescribeReplayEvent(journal, 2) == "03:00:08 undo: comment added at 0x401040: loop over the key");
    REQUIRE(DescribeReplayEvent(journal, 3) == "03:00:09 visit 0x401030[-0x8] (mouse)");
    REQUIRE(DescribeReplayEvent(journal, 4).empty());
}

TEST_CASE("ReplayRecorderVisits", "[Dissasm]Replay")
{
    RecorderView view;
    // a keyboard move becomes a visit when the cursor rests VISIT_REST_MS on the line
    view.Key(40);
    view.Wait(DissasmReplayRecorder::VISIT_REST_MS - 1);
    REQUIRE(view.recorder.PendingVisits() == 0);
    view.Wait(1);
    REQUIRE(view.recorder.PendingVisits() == 1);
    // moves that do not rest are not visits
    view.Key(41);
    view.Wait(100);
    view.Key(42);
    view.Wait(100);
    REQUIRE(view.recorder.PendingVisits() == 1);
    view.Wait(DissasmReplayRecorder::VISIT_REST_MS);
    REQUIRE(view.recorder.PendingVisits() == 2);
    // a click is a visit at once; the same place again is one visit
    view.Click(50);
    REQUIRE(view.recorder.PendingVisits() == 3);
    view.Click(50);
    view.Key(50);
    view.Wait(DissasmReplayRecorder::VISIT_REST_MS);
    REQUIRE(view.recorder.PendingVisits() == 3);
    // a line outside the code is not a visit
    view.cursorLine.reset();
    view.recorder.NoteCursorMoved(true);
    REQUIRE(view.recorder.PendingVisits() == 3);
    // nothing is written while no operation follows the visits
    REQUIRE(view.Events().empty());
    REQUIRE_FALSE(view.recorder.IsDirty());

    // 5 visits then a comment: the last 3 visits and the edit
    RecorderView edited;
    for (uint32 line = 40; line < 45; line++) {
        edited.Click(line);
        edited.unixTime += 2;
    }
    REQUIRE(edited.recorder.PendingVisits() == 3);
    REQUIRE(edited.test.AddOrUpdateComment(44, "the key"));
    REQUIRE(KindsOf(edited.Events()) == std::vector<Kind>{ Kind::Visit, Kind::Visit, Kind::Visit, Kind::Edit });
    REQUIRE(edited.Events()[0].place == edited.PlaceOf(42));
    REQUIRE(edited.Events()[0].source == DissasmReplayVisitSource::Mouse);
    REQUIRE(edited.Events()[3].place == edited.PlaceOf(44));
    REQUIRE(edited.Events()[3].edit->kind == EditKind::Comment);
    REQUIRE(edited.Events()[3].edit->after == "the key");
    REQUIRE(edited.Events()[0].time == 4); // the seconds since the first visit
    REQUIRE(edited.Events()[3].time == 10);
    REQUIRE(edited.recorder.Journal().startedAt == 1700000000);
    REQUIRE(edited.recorder.IsDirty());
    edited.recorder.ClearDirty();
    REQUIRE_FALSE(edited.recorder.IsDirty());

    // a keyboard move that did not rest yet is a visit when an edit follows it on its line
    edited.Key(60);
    REQUIRE(edited.test.AddOrUpdateComment(60, "c60"));
    REQUIRE(KindsOf(edited.Events()).size() == 6);
    REQUIRE(edited.Events()[4].kind == Kind::Visit);
    REQUIRE(edited.Events()[4].place == edited.PlaceOf(60));
    REQUIRE(edited.Events()[5].kind == Kind::Edit);
    CheckInvariants(edited.recorder.Journal());

    // suspended: nothing is recorded
    edited.recorder.Suspend(true);
    edited.Click(70);
    REQUIRE(edited.test.AddOrUpdateComment(70, "c70"));
    edited.recorder.Suspend(false);
    REQUIRE(edited.Events().size() == 6);
    REQUIRE(edited.recorder.PendingVisits() == 0);
}

TEST_CASE("ReplayRecorderJumps", "[Dissasm]Replay")
{
    RecorderView view;
    view.Click(40);
    // Follow with the mnemonic (DissasmReplayJumpScope as Instance::DissasmZoneProcessSpaceKey)
    {
        DissasmReplayJumpScope scope(&view.recorder, DissasmReplayJumpKind::Follow, "call");
        view.cursorLine = 100;
        view.recorder.OnJumpRecorded(view.StateOf(40));
    }
    REQUIRE(KindsOf(view.Events()) == std::vector<Kind>{ Kind::Visit, Kind::Jump });
    REQUIRE(view.Events()[1].jumpKind == DissasmReplayJumpKind::Follow);
    REQUIRE(view.Events()[1].mnemonic == "call");
    REQUIRE(view.Events()[1].from == view.PlaceOf(40));
    REQUIRE(view.Events()[1].place == view.PlaceOf(100));
    // the scope ended: the next jump is another one
    view.cursorLine = 120;
    view.recorder.OnJumpRecorded(view.StateOf(100));
    REQUIRE(view.Events()[2].jumpKind == DissasmReplayJumpKind::Other);
    REQUIRE(view.Events()[2].mnemonic.empty());
    // the same line: no jump
    view.recorder.OnJumpRecorded(view.StateOf(120));
    REQUIRE(view.Events().size() == 3);
    // a keyboard move before the jump is its start, not a visit
    view.Key(130);
    view.cursorLine = 140;
    view.recorder.OnJumpRecorded(view.StateOf(130));
    REQUIRE(KindsOf(view.Events()).back() == Kind::Jump);
    REQUIRE(view.recorder.PendingVisits() == 0);
    // a destination reached later (a zone prepared when it is drawn): the next jump completes it
    {
        DissasmReplayJumpScope scope(&view.recorder, DissasmReplayJumpKind::GoTo);
        view.cursorLine.reset(); // the title of the zone
        view.recorder.OnJumpRecorded(view.StateOf(140), true);
    }
    REQUIRE(view.Events().size() == 4);
    view.cursorLine = 200;
    CursorState title;
    title.zoneIndex  = 0;
    title.lineInZone = 0;
    view.recorder.OnJumpRecorded(title);
    REQUIRE(view.Events().size() == 5);
    REQUIRE(view.Events()[4].jumpKind == DissasmReplayJumpKind::GoTo);
    REQUIRE(view.Events()[4].from == view.PlaceOf(140));
    REQUIRE(view.Events()[4].place == view.PlaceOf(200));
    // back / forward in the history
    view.cursorLine = 140;
    view.recorder.OnHistoryJump(true);
    view.cursorLine = 200;
    view.recorder.OnHistoryJump(false);
    REQUIRE(view.Events()[5].kind == Kind::JumpBack);
    REQUIRE(view.Events()[6].kind == Kind::JumpForward);
    // the markers
    view.recorder.OnImport(DissasmReplayImportSource::File);
    view.recorder.OnReanalysis(*view.test.zone);
    REQUIRE(view.Events()[7].kind == Kind::Import);
    REQUIRE(view.Events()[8].kind == Kind::Reanalysis);
    REQUIRE(view.Events()[8].place.zone == 0);
    CheckInvariants(view.recorder.Journal());
}

TEST_CASE("ReplayRecorderEdits", "[Dissasm]Replay")
{
    RecorderView view(true);
    // a rename, a variable, a number base, a collapsible zone, data ranges: what the observer receives
    std::string_view name = "isPrime";
    REQUIRE(view.test.zone->TryRenameLine(35, &view.test.objects[0], &name).ok);
    REQUIRE(view.test.RenameLocalVariable(36, "count").ok);
    const uint32 subLine = FindLine(view.test, "sub", 36);
    const uint64 subAddress = view.test.GetCurrentAsmLine(subLine).address;
    view.test.zone->ToggleDecimalOperand(subAddress, 1);
    REQUIRE(view.test.zone->AddCollapsibleZone(120, 130));
    const auto rangesBefore     = view.test.zone->userDataRanges;
    view.test.zone->userDataRanges = { { 0x700, 0x710, 4, false, 0 } };
    view.test.zone->RecordUserDataEdit(rangesBefore, 0x700);
    const auto& events = view.Events();
    REQUIRE(events.size() == 5);
    REQUIRE(events[0].edit->kind == EditKind::LabelName);
    REQUIRE(events[0].place.anchor.kind == Anchor::Label);
    REQUIRE(events[0].edit->after == "isPrime");
    REQUIRE(events[1].edit->kind == EditKind::VariableName);
    REQUIRE(events[1].place.anchor.kind == Anchor::Variable);
    REQUIRE(events[1].place.anchor.frameOffset != 0);
    REQUIRE(events[1].edit->after == "count");
    REQUIRE(events[2].edit->kind == EditKind::DecimalOperand);
    REQUIRE(events[2].edit->numberIndex == 1);
    REQUIRE(events[2].place.anchor.address == subAddress);
    REQUIRE(events[3].edit->kind == EditKind::AddZone);
    REQUIRE(events[3].place.anchor == events[3].edit->zone.first);
    REQUIRE(events[3].edit->zone == view.test.zone->GetCollapsibleZoneAnchors()[0]);
    REQUIRE(events[4].edit->kind == EditKind::DataRanges);
    REQUIRE(events[4].edit->rangesAfter == view.test.zone->userDataRanges);

    // undo / redo: their full edit, the reference to the edit they undo / the undo they redo
    REQUIRE(view.test.zone->UndoEdit().has_value()); // the data ranges
    REQUIRE(view.test.zone->UndoEdit().has_value()); // the zone
    REQUIRE(view.test.zone->RedoEdit().has_value());
    REQUIRE(events.size() == 8);
    REQUIRE(events[5].kind == Kind::Undo);
    REQUIRE(events[5].ref == 4);
    REQUIRE(events[5].edit == events[4].edit);
    REQUIRE(events[6].kind == Kind::Undo);
    REQUIRE(events[6].ref == 3);
    REQUIRE(events[7].kind == Kind::Redo);
    REQUIRE(events[7].ref == 6);
    REQUIRE(events[7].edit == events[3].edit);
    CheckInvariants(view.recorder.Journal());
}

TEST_CASE("ReplayRecorderCache", "[Dissasm]Replay")
{
    RecorderView view;
    view.Click(40);
    REQUIRE(view.test.AddOrUpdateComment(40, "c40"));
    // the record of the cache, read again
    DissasmCache cache;
    REQUIRE(view.recorder.ToCache(cache));
    REQUIRE(cache.zonesData.contains(std::string(DISSASM_REPLAY_RECORD)));
    DissasmReplayRecorder restored;
    restored.LoadFromCache(cache);
    REQUIRE(restored.Journal() == view.recorder.Journal());
    REQUIRE_FALSE(restored.IsDirty());
    REQUIRE_FALSE(restored.HasRejectedRecord());
    // no event: no record
    DissasmCache none;
    REQUIRE(DissasmReplayRecorder().ToCache(none));
    REQUIRE(none.zonesData.empty());

    // a record that can not be read is written back as it was, until events are recorded
    const uint8 garbage[] = { 'G', 'D', 'R', 'J', 9, 9, 9, 9, 1, 2, 3 };
    DissasmCache corrupted;
    REQUIRE(corrupted.AddRegion(std::string(DISSASM_REPLAY_RECORD), reinterpret_cast<const std::byte*>(garbage), sizeof(garbage)));
    RecorderView other;
    other.recorder.LoadFromCache(corrupted);
    REQUIRE(other.recorder.HasRejectedRecord());
    REQUIRE(other.Events().empty());
    DissasmCache saved;
    REQUIRE(other.recorder.ToCache(saved));
    const auto& kept = saved.zonesData.at(std::string(DISSASM_REPLAY_RECORD));
    REQUIRE(kept.size == sizeof(garbage));
    REQUIRE(memcmp(kept.data.get(), garbage, sizeof(garbage)) == 0);
    other.Click(50);
    REQUIRE(other.test.AddOrUpdateComment(50, "c50"));
    DissasmCache replaced;
    REQUIRE(other.recorder.ToCache(replaced));
    DissasmReplayRecorder reread;
    reread.LoadFromCache(replaced);
    REQUIRE_FALSE(reread.HasRejectedRecord());
    REQUIRE(reread.Journal() == other.recorder.Journal());

    // a replaced journal (a work document, the replay editor): dirty, the visits waiting are dropped
    view.recorder.ClearDirty();
    view.Click(60);
    view.recorder.ReplaceJournal(FullJournal());
    REQUIRE(view.recorder.IsDirty());
    REQUIRE(view.recorder.PendingVisits() == 0);
    REQUIRE(view.recorder.Journal() == FullJournal());
}

TEST_CASE("ReplayWorkDocument", "[Dissasm]Replay")
{
    // the JSON of a journal, read again
    const auto journal = FullJournal();
    uint32 skipped     = 0;
    REQUIRE(ReplayJournalFromJson(ReplayJournalToJson(journal), skipped) == journal);
    REQUIRE(skipped == 0);
    const auto text = ReplayJournalToJson(journal).dump();
    REQUIRE(ReplayJournalFromJson(nlohmann::json::parse(text), skipped) == journal);
    REQUIRE(skipped == 0);

    // tolerant: the entries that can not be read are skipped, the references follow their events
    auto json      = ReplayJournalToJson(journal);
    auto& events   = json["events"];
    const auto jump = events[FULL_FOLLOW];
    nlohmann::json edited = nlohmann::json::array();
    edited.push_back(nlohmann::json::array({ "x", 1 }));                  // an unknown tag
    edited.push_back(nlohmann::json::array({ "v", 1, 7, "0x10", "i", "k" })); // a zone that does not exist
    edited.push_back(nlohmann::json::array({ "v", "1", 0, "0x10", "i", "k" })); // dt of another type
    edited.push_back(events[FULL_RENAME]);                                  // the rename (index 3 here)
    edited.push_back(nlohmann::json::array({ "e", 1, 0, "0x401010", "i", "comment", nlohmann::json::array() })); // a payload that is not an object
    edited.push_back(nlohmann::json::array({ "u", 1, 0, "0x401030", "l", "name", 3, { { "before", "sub_401030" }, { "after", "decrypt" } } }));
    edited.push_back(nlohmann::json::array({ "u", 1, 0, "0x401030", "l", "name", 2, { { "after", "decrypt" } } })); // a reference to a skipped event
    edited.push_back(jump);
    edited.push_back(nlohmann::json::array({ "v", 1, 0, "0x401010", "i", "k", "extra" })); // a field more
    json["events"] = edited;
    const auto tolerant = ReplayJournalFromJson(json, skipped = 0);
    REQUIRE(skipped == 5);
    REQUIRE(KindsOf(tolerant.events) == std::vector<Kind>{ Kind::Edit, Kind::Undo, Kind::Undo, Kind::Jump });
    REQUIRE(tolerant.events[1].ref == 0);
    REQUIRE(tolerant.events[2].ref == DISSASM_REPLAY_NO_REF);
    REQUIRE(tolerant.events[0].edit == journal.events[FULL_RENAME].edit);
    auto followed = journal.events[FULL_FOLLOW];
    followed.time = tolerant.events[3].time; // the times come from the dt of the edited list
    REQUIRE(tolerant.events[3] == followed);
    // a replay of a newer version: no journal
    json["version"] = DISSASM_REPLAY_JSON_VERSION + 1;
    REQUIRE(ReplayJournalFromJson(json, skipped = 0) == DissasmReplayJournal{});
    REQUIRE(skipped == 1);
    REQUIRE(ReplayJournalFromJson(nlohmann::json("text"), skipped = 0) == DissasmReplayJournal{});

    // the work document: the annotations document (imported as one) with the meta and the journal
    RecorderView view;
    std::string_view name = "isPrime";
    REQUIRE(view.test.zone->TryRenameLine(35, &view.test.objects[0], &name).ok);
    REQUIRE(view.test.AddOrUpdateComment(100, "c100"));
    DissasmWorkMeta meta{ "solution", "0.409.0", 1760000000, "w1_stack_var", 3, "ab12" };
    const auto document = BuildWorkDocument({ view.test.zone.get() }, "p16.exe", view.recorder.Journal(), meta);
    REQUIRE(document["format"].get<std::string>() == DISSASM_ANNOTATIONS_FORMAT);
    REQUIRE(document["replay"]["events"].size() == 2);
    REQUIRE(document["meta"]["kind"].get<std::string>() == "solution");
    const auto parsedText = nlohmann::json::parse(document.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
    DissasmWorkDocument work;
    std::string error;
    REQUIRE(ParseWorkDocument(parsedText, work, error));
    REQUIRE(work.meta == meta);
    REQUIRE(work.hasReplay);
    REQUIRE(work.skipped == 0);
    REQUIRE(work.journal == view.recorder.Journal());
    DissasmTestInstance fresh(exampleTest1BinaryCode, exampleTest1BinaryCodeSize);
    DissasmAnnotationsImport imported;
    REQUIRE(ImportAnnotationsDocument(parsedText, { fresh.zone.get() }, imported, error));
    REQUIRE(imported.names == 1);
    REQUIRE(imported.comments == 1);
    REQUIRE(fresh.CheckComment(100, "c100"));
    REQUIRE(ExportZoneAnnotations(*fresh.zone) == ExportZoneAnnotations(*view.test.zone));
    // without a journal: no "replay"
    REQUIRE_FALSE(BuildWorkDocument({ view.test.zone.get() }, "p16.exe", {}, meta).contains("replay"));
    // not a work document
    REQUIRE_FALSE(ParseWorkDocument(nlohmann::json{ { "format", "other" }, { "version", 1 } }, work, error));
    REQUIRE_FALSE(ParseWorkDocument(nlohmann::json{ { "format", DISSASM_ANNOTATIONS_FORMAT }, { "version", DISSASM_ANNOTATIONS_VERSION + 1 } }, work, error));
    REQUIRE(ParseWorkDocument(nlohmann::json{ { "format", DISSASM_ANNOTATIONS_FORMAT }, { "version", 1 }, { "meta", 5 } }, work, error));
    REQUIRE_FALSE(work.hasReplay);
}

TEST_CASE("ReplayPlayback", "[Dissasm]Replay")
{
    // the work of a teacher, recorded
    RecorderView teacher(true);
    std::string_view name = "isPrime";
    teacher.Click(35);
    REQUIRE(teacher.test.zone->TryRenameLine(35, &teacher.test.objects[0], &name).ok);
    teacher.Click(100);
    REQUIRE(teacher.test.AddOrUpdateComment(100, "c100"));
    REQUIRE(teacher.test.RenameLocalVariable(36, "count").ok);
    const uint32 subLine = FindLine(teacher.test, "sub", 36);
    teacher.test.zone->ToggleDecimalOperand(teacher.test.GetCurrentAsmLine(subLine).address, 1);
    REQUIRE(teacher.test.zone->AddCollapsibleZone(120, 130));
    REQUIRE(teacher.test.AddOrUpdateComment(140, "removed later"));
    REQUIRE(teacher.test.zone->UndoEdit().has_value()); // the comment of line 140
    REQUIRE(teacher.test.AddOrUpdateComment(150, "c150"));
    REQUIRE(teacher.test.zone->UndoEdit().has_value());
    REQUIRE(teacher.test.zone->RedoEdit().has_value()); // c150 again
    const auto journal = teacher.recorder.Journal();
    CheckInvariants(journal);

    // played back on a fresh analysis of the same file
    DissasmTestInstance student(exampleTest1BinaryCode, exampleTest1BinaryCodeSize, true);
    DissasmTestInstance pristine(exampleTest1BinaryCode, exampleTest1BinaryCodeSize, true);
    PlaybackHost host(student);
    DissasmReplayController controller(journal, host);
    REQUIRE(controller.Count() == journal.events.size());
    REQUIRE(controller.Position() == 0);
    REQUIRE_FALSE(controller.StepBack());
    REQUIRE(controller.StepForward());
    REQUIRE(controller.Position() == 1);
    REQUIRE(host.cursor == journal.events[0].place.anchor); // the visit of line 35
    REQUIRE(controller.GoToEnd());
    REQUIRE_FALSE(controller.StepForward());
    REQUIRE(controller.SkippedCount() == 0);
    REQUIRE(ExportZoneAnnotations(*student.zone) == ExportZoneAnnotations(*teacher.test.zone));
    REQUIRE(student.CheckComment(150, "c150"));
    REQUIRE_FALSE(student.HasComment(140));
    REQUIRE_FALSE(student.zone->CanUndoEdit()); // the playback is not in the history of the zone
    REQUIRE(host.linesChanged > 0);
    // back to the start: the fresh analysis again
    REQUIRE(controller.GoToStart());
    REQUIRE(controller.Position() == 0);
    REQUIRE(ExportZoneAnnotations(*student.zone) == ExportZoneAnnotations(*pristine.zone));
    // a step back after an undo applies the edit again
    size_t undo = 0;
    while (journal.events[undo].kind != Kind::Undo)
        undo++;
    REQUIRE(controller.Seek(undo + 1));
    REQUIRE_FALSE(student.HasComment(140));
    REQUIRE(controller.StepBack());
    REQUIRE(student.CheckComment(140, "removed later"));
    REQUIRE(controller.Seek(undo + 1));
    REQUIRE_FALSE(controller.Seek(undo + 1));
    REQUIRE(controller.Describe(undo).find("undo: comment") != std::string::npos);

    // a jump back moves the cursor to the start of the jump
    DissasmReplayJournal jumps;
    jumps.zones  = journal.zones;
    const auto from = teacher.PlaceOf(40), to = teacher.PlaceOf(100);
    jumps.events = { Visit(1, from), Jump(2, to, from, DissasmReplayJumpKind::Follow, "call") };
    DissasmReplayController jumping(jumps, host);
    REQUIRE(jumping.GoToEnd());
    REQUIRE(host.cursor == to.anchor);
    REQUIRE(jumping.StepBack());
    REQUIRE(host.cursor == from.anchor);

    // the places this analysis does not have are skipped, never an error
    DissasmReplayJournal missing;
    missing.zones  = { journal.zones[0], { 0x123456, 0x500000 } };
    missing.events = { EditEvent(Kind::Edit, 1, MakePlace(0, 0x7, Anchor::Label), TextEdit(EditKind::LabelName, "sub_7", "nothing")),
                       Visit(2, MakePlace(1, 0x10)),
                       EditEvent(Kind::Edit, 3, from, TextEdit(EditKind::Comment, std::nullopt, "kept")) };
    DissasmReplayController skipping(missing, host);
    REQUIRE(skipping.GoToEnd());
    REQUIRE(skipping.IsSkipped(0));
    REQUIRE(skipping.IsSkipped(1));
    REQUIRE_FALSE(skipping.IsSkipped(2));
    REQUIRE(skipping.SkippedCount() == 2);
    REQUIRE(skipping.Describe(1).find("skipped") != std::string::npos);
    REQUIRE(skipping.GoToStart());
    REQUIRE(skipping.SkippedCount() == 0);
    REQUIRE_FALSE(student.HasComment(40));

    // the data ranges: applied, then the zone is analyzed again (Host::Reanalyze); back: the previous ranges, analyzed again
    DissasmReplayEdit ranges;
    ranges.kind        = EditKind::DataRanges;
    ranges.rangesAfter = { { 0x700, 0x710, 4, false, 0 } };
    DissasmReplayJournal data;
    data.zones  = journal.zones;
    data.events = { EditEvent(Kind::Edit, 1, MakePlace(0, 0x700), ranges) };
    DissasmReplayController defining(data, host);
    REQUIRE(defining.StepForward());
    REQUIRE(host.reanalyses == 1);
    REQUIRE(student.zone->userDataRanges == ranges.rangesAfter);
    REQUIRE(defining.StepBack());
    REQUIRE(host.reanalyses == 2);
    REQUIRE(student.zone->userDataRanges.empty());
}
