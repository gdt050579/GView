#include "DissasmReplayRecorder.hpp"
#include "DissasmCache.hpp"

#include <chrono>

using namespace GView::View::DissasmViewer;

namespace
{
using Kind = DissasmReplayEvent::Kind;

uint64 SystemMonotonicMs()
{
    return static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

uint64 SystemUnixTime()
{
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    return seconds > 0 ? static_cast<uint64>(seconds) : 0;
}
} // namespace

DissasmReplayRecorder::DissasmReplayRecorder() : DissasmReplayRecorder(Resolver{})
{
}

DissasmReplayRecorder::DissasmReplayRecorder(Resolver resolver)
{
    SetResolver(std::move(resolver));
}

void DissasmReplayRecorder::SetResolver(Resolver replacement)
{
    resolver = std::move(replacement);
    if (!resolver.nowMs)
        resolver.nowMs = SystemMonotonicMs;
    if (!resolver.nowUnix)
        resolver.nowUnix = SystemUnixTime;
}

std::optional<DissasmReplayPlace> DissasmReplayRecorder::ToPlace(const std::optional<ResolvedPlace>& resolved)
{
    if (!resolved.has_value() || resolved->zone == nullptr)
        return {};
    const uint32 zone = journal.ZoneIndexOf(*resolved->zone);
    if (zone == DISSASM_REPLAY_NO_ZONE)
        return {};
    DissasmReplayPlace place{ zone, resolved->anchor };
    if (place.anchor.kind != DissasmCommentAnchor::Kind::Variable)
        place.anchor.frameOffset = 0;
    return place;
}

uint32 DissasmReplayRecorder::Now()
{
    const uint64 unixTime = resolver.nowUnix();
    if (journal.startedAt == 0)
        journal.startedAt = unixTime;
    const uint64 elapsed = unixTime > journal.startedAt ? std::min<uint64>(unixTime - journal.startedAt, UINT32_MAX) : 0;
    // never before the events already taken (a clock moved back)
    uint32 last = journal.events.empty() ? 0 : journal.events.back().time;
    if (!pendingVisits.empty())
        last = std::max(last, pendingVisits.back().time);
    return std::max(static_cast<uint32>(elapsed), last);
}

void DissasmReplayRecorder::AddVisit(const DissasmReplayPlace& place, DissasmReplayVisitSource source)
{
    if (!pendingVisits.empty() && pendingVisits.back().place == place)
        return; // the same place again: one visit (the first)
    DissasmReplayEvent visit;
    visit.kind   = Kind::Visit;
    visit.time   = Now();
    visit.place  = place;
    visit.source = source;
    pendingVisits.push_back(std::move(visit));
    while (pendingVisits.size() > PENDING_VISITS)
        pendingVisits.pop_front();
}

bool DissasmReplayRecorder::TakeKeyboardMove()
{
    if (!keyboardMoveSince.has_value())
        return false;
    keyboardMoveSince.reset();
    const auto place = ToPlace(resolver.cursorPlace ? resolver.cursorPlace() : std::nullopt);
    if (!place.has_value())
        return false;
    AddVisit(place.value(), DissasmReplayVisitSource::Keyboard);
    return true;
}

void DissasmReplayRecorder::FlushVisits()
{
    while (!pendingVisits.empty()) {
        Append(std::move(pendingVisits.front()));
        pendingVisits.pop_front();
    }
}

bool DissasmReplayRecorder::Append(DissasmReplayEvent event)
{
    // the recorder stops at the limit; an event that a record could not hold is never written (the record must load again)
    if (journal.events.size() >= DISSASM_REPLAY_MAX_EVENTS || !IsValidReplayEvent(event, journal.zones.size(), journal.events.size()))
        return false;
    // the course work has unsaved changes when the annotations changed (an edit, an undo / a redo, an import): the visits and the jumps
    // of the journal alone do not ask the student to save
    if (event.HasEdit() || event.kind == Kind::Import)
        dirty = true;
    journal.events.push_back(std::move(event));
    recordedSinceLoad = true;
    return true;
}

void DissasmReplayRecorder::NoteCursorMoved(bool mouse)
{
    if (IsSuspended())
        return;
    if (!mouse) {
        keyboardMoveSince = resolver.nowMs(); // a new rest starts
        return;
    }
    keyboardMoveSince.reset();
    if (const auto place = ToPlace(resolver.cursorPlace ? resolver.cursorPlace() : std::nullopt))
        AddVisit(place.value(), DissasmReplayVisitSource::Mouse);
}

bool DissasmReplayRecorder::Poll()
{
    if (IsSuspended() || !keyboardMoveSince.has_value() || resolver.nowMs() - keyboardMoveSince.value() < VISIT_REST_MS)
        return false;
    return TakeKeyboardMove();
}

void DissasmReplayRecorder::BeginJump(DissasmReplayJumpKind kind, std::string_view mnemonic)
{
    if (IsSuspended())
        return;
    JumpContext context;
    context.kind = kind;
    for (const char c : mnemonic.substr(0, DISSASM_REPLAY_MAX_MNEMONIC)) {
        if (c == '\0')
            break;
        context.mnemonic += c;
    }
    jumpContext = std::move(context);
}

void DissasmReplayRecorder::EndJump()
{
    if (jumpContext.has_value() && !jumpContext->waiting)
        jumpContext.reset();
}

void DissasmReplayRecorder::OnJumpRecorded(const CursorState& from, bool destinationPending)
{
    if (IsSuspended())
        return;
    keyboardMoveSince.reset(); // the place it reached is the start of the jump
    if (jumpContext.has_value() && jumpContext->waiting && resolver.nowMs() - jumpContext->waitingSince > PENDING_JUMP_MS)
        jumpContext.reset(); // its destination was never reached
    const auto to = ToPlace(resolver.cursorPlace ? resolver.cursorPlace() : std::nullopt);
    if (!to.has_value()) {
        if (destinationPending) {
            // the destination comes once its zone is prepared: the next jump (to it) is this one
            if (!jumpContext.has_value())
                jumpContext = JumpContext{};
            if (!jumpContext->waiting) {
                jumpContext->waiting      = true;
                jumpContext->waitingSince = resolver.nowMs();
                jumpContext->from         = ToPlace(resolver.placeOf ? resolver.placeOf(from) : std::nullopt);
            }
        }
        return; // not a line of a code zone: not a place of the journal
    }
    std::optional<DissasmReplayPlace> start;
    if (jumpContext.has_value() && jumpContext->waiting)
        start = jumpContext->from;
    if (!start.has_value())
        start = ToPlace(resolver.placeOf ? resolver.placeOf(from) : std::nullopt);
    DissasmReplayEvent jump;
    jump.kind     = Kind::Jump;
    jump.place    = to.value();
    jump.from     = start.value_or(to.value()); // it started outside of the code zones: back goes to its destination
    jump.jumpKind = jumpContext.has_value() ? jumpContext->kind : DissasmReplayJumpKind::Other;
    jump.mnemonic = jumpContext.has_value() ? jumpContext->mnemonic : std::string();
    jumpContext.reset();
    if (start.has_value() && start.value() == to.value())
        return; // the cursor did not leave its line
    FlushVisits();
    jump.time = Now();
    Append(std::move(jump));
}

void DissasmReplayRecorder::OnHistoryJump(bool back)
{
    if (IsSuspended())
        return;
    keyboardMoveSince.reset();
    const auto to = ToPlace(resolver.cursorPlace ? resolver.cursorPlace() : std::nullopt);
    if (!to.has_value())
        return;
    FlushVisits();
    DissasmReplayEvent jump;
    jump.kind  = back ? Kind::JumpBack : Kind::JumpForward;
    jump.time  = Now();
    jump.place = to.value();
    Append(std::move(jump));
}

void DissasmReplayRecorder::OnImport(DissasmReplayImportSource source)
{
    if (IsSuspended())
        return;
    TakeKeyboardMove();
    FlushVisits();
    DissasmReplayEvent import;
    import.kind         = Kind::Import;
    import.time         = Now();
    import.importSource = source;
    Append(std::move(import));
}

void DissasmReplayRecorder::OnReanalysis(const DissasmCodeZone& zone)
{
    if (IsSuspended())
        return;
    const uint32 index = journal.ZoneIndexOf(zone);
    if (index == DISSASM_REPLAY_NO_ZONE)
        return;
    TakeKeyboardMove();
    FlushVisits();
    DissasmReplayEvent reanalysis;
    reanalysis.kind       = Kind::Reanalysis;
    reanalysis.time       = Now();
    reanalysis.place.zone = index;
    Append(std::move(reanalysis));
}

void DissasmReplayRecorder::RecordEdit(DissasmReplayEvent::Kind kind, DissasmCodeZone& zone, const DissasmEdit& edit)
{
    if (IsSuspended())
        return;
    dirty = true; // the annotations changed, even when the journal can not hold the edit (its limits)
    auto converted = MakeReplayEdit(zone, edit);
    if (!converted.has_value())
        return;
    const uint32 index = journal.ZoneIndexOf(zone);
    if (index == DISSASM_REPLAY_NO_ZONE)
        return;
    TakeKeyboardMove(); // the cursor is still on the edited line
    FlushVisits();
    DissasmReplayEvent event;
    event.kind  = kind;
    event.time  = Now();
    event.place = { index, converted->first };
    event.edit  = std::move(converted->second);
    if (kind != Kind::Edit) {
        // informational: the last event with the same edit that this one undoes (an edit / a redo) or redoes (an undo)
        for (size_t at = journal.events.size(); at > 0; at--) {
            const auto& previous = journal.events[at - 1];
            const bool matches   = kind == Kind::Undo ? (previous.kind == Kind::Edit || previous.kind == Kind::Redo) : previous.kind == Kind::Undo;
            if (matches && previous.place == event.place && previous.edit == event.edit) {
                event.ref = static_cast<uint32>(at - 1);
                break;
            }
        }
    }
    Append(std::move(event));
}

void DissasmReplayRecorder::OnEdit(DissasmCodeZone& zone, const DissasmEdit& edit)
{
    RecordEdit(Kind::Edit, zone, edit);
}

void DissasmReplayRecorder::OnUndo(DissasmCodeZone& zone, const DissasmEdit& edit)
{
    RecordEdit(Kind::Undo, zone, edit);
}

void DissasmReplayRecorder::OnRedo(DissasmCodeZone& zone, const DissasmEdit& edit)
{
    RecordEdit(Kind::Redo, zone, edit);
}

void DissasmReplayRecorder::Suspend(bool on)
{
    if (on) {
        suspended++;
        keyboardMoveSince.reset(); // the moves of a playback are not visits
        if (jumpContext.has_value() && !jumpContext->waiting)
            jumpContext.reset(); // a jump waiting for its destination stays (the destination is reached while drawing)
    } else if (suspended > 0)
        suspended--;
}

void DissasmReplayRecorder::ReplaceJournal(DissasmReplayJournal replacement)
{
    journal = std::move(replacement);
    pendingVisits.clear();
    keyboardMoveSince.reset();
    jumpContext.reset();
    rejectedRecord.reset();
    dirty             = true;
    recordedSinceLoad = true;
}

void DissasmReplayRecorder::LoadFromCache(const DissasmCache& cache)
{
    journal.Clear();
    pendingVisits.clear();
    keyboardMoveSince.reset();
    jumpContext.reset();
    rejectedRecord.reset();
    dirty             = false;
    recordedSinceLoad = false;
    const auto entry  = cache.zonesData.find(std::string(DISSASM_REPLAY_RECORD));
    if (entry == cache.zonesData.end() || !entry->second.data)
        return;
    if (!ReplayJournalFromBuffer(entry->second.data.get(), entry->second.size, journal))
        rejectedRecord = std::vector<std::byte>(entry->second.data.get(), entry->second.data.get() + entry->second.size);
}

bool DissasmReplayRecorder::ToCache(DissasmCache& cache) const
{
    if (rejectedRecord.has_value() && !recordedSinceLoad) // a record of another version / corrupted: kept as it was
        return cache.AddRegion(std::string(DISSASM_REPLAY_RECORD), rejectedRecord->data(), static_cast<uint32>(rejectedRecord->size()));
    if (journal.events.empty())
        return true;
    std::vector<std::byte> buffer;
    ReplayJournalToBuffer(journal, buffer);
    return cache.AddRegion(std::string(DISSASM_REPLAY_RECORD), buffer.data(), static_cast<uint32>(buffer.size()));
}
