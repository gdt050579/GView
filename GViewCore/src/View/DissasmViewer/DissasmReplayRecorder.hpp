#pragma once

#include "DissasmReplay.hpp"

#include <deque>
#include <functional>

namespace GView::View::DissasmViewer
{
// Records the replay journal of a view while the user works (one per Instance; the observer of the edits of its zones).
//  - visits: a mouse click on a line is a visit at once, a keyboard move becomes one when the cursor rests VISIT_REST_MS on the line (Poll,
//    from the frame updates) or when an operation follows it; only the lines of the code zones are visits
//  - the visits wait in pendingVisits (the same place again is one visit, the last PENDING_VISITS are kept): every operation (a jump, an edit,
//    an undo / a redo, an import, a new analysis) writes them before itself, the visits that no operation follows are never written. This is
//    CompactReplayEvents applied while recording.
//  - jumps: RecordJump (the funnel of every jump of the view) calls OnJumpRecorded; what made the jump is given before by BeginJump (a
//    DissasmReplayJumpScope around the jump), the other jumps are DissasmReplayJumpKind::Other
//  - Suspend: nothing is recorded (the playback of a journal, a work document being applied, the windows of a solution)
class DissasmReplayRecorder : public DissasmEditObserver
{
  public:
    static constexpr uint64 VISIT_REST_MS  = 600;
    static constexpr size_t PENDING_VISITS = 3;
    // a jump whose destination is not known yet (a zone prepared when it is drawn, Instance::pendingGoTo) waits at most this long
    static constexpr uint64 PENDING_JUMP_MS = 10000;

    // a line of a code zone of the view
    struct ResolvedPlace {
        DissasmCodeZone* zone;
        DissasmCommentAnchor anchor;
    };
    // what the recorder asks the view (the tests give their own): the place of the cursor line / of a saved cursor, none for a line that is
    // not a line of a code zone; the monotonic clock (milliseconds) and the UNIX time (seconds)
    struct Resolver {
        std::function<std::optional<ResolvedPlace>()> cursorPlace;
        std::function<std::optional<ResolvedPlace>(const CursorState&)> placeOf;
        std::function<uint64()> nowMs;
        std::function<uint64()> nowUnix;
    };

    DissasmReplayRecorder(); // the clocks of the system, no place (nothing but the edits is recorded until SetResolver)
    explicit DissasmReplayRecorder(Resolver resolver);
    void SetResolver(Resolver resolver);

    // the cursor moved (Instance::MoveScrollTo): a mouse click is a visit now, a keyboard move once the cursor rests
    void NoteCursorMoved(bool mouse);
    // the keyboard move that rested VISIT_REST_MS becomes a visit; true when it did
    bool Poll();
    // what makes the next jump (the jump itself calls OnJumpRecorded); EndJump forgets it unless the jump waits for its destination
    void BeginJump(DissasmReplayJumpKind kind, std::string_view mnemonic = {});
    void EndJump();
    // a jump of the view from `from` to the cursor; destinationPending: the cursor is not on the destination yet (Instance::pendingGoTo), the
    // next jump completes this one
    void OnJumpRecorded(const CursorState& from, bool destinationPending = false);
    // Ctrl+Q / Ctrl+Shift+Q (Instance::JumpInHistory) reached the cursor
    void OnHistoryJump(bool back);
    void OnImport(DissasmReplayImportSource source);
    void OnReanalysis(const DissasmCodeZone& zone);
    // nested: every Suspend(true) needs its Suspend(false)
    void Suspend(bool on);
    bool IsSuspended() const
    {
        return suspended > 0;
    }

    const DissasmReplayJournal& Journal() const
    {
        return journal;
    }
    size_t PendingVisits() const
    {
        return pendingVisits.size();
    }
    // the annotations changed since ClearDirty (an edit, an undo / a redo, an import was written, the journal was replaced): the course
    // work has unsaved changes (the visits and the jumps alone do not)
    bool IsDirty() const
    {
        return dirty;
    }
    void MarkDirty()
    {
        dirty = true;
    }
    void ClearDirty()
    {
        dirty = false;
    }
    // another journal (a work document, the replay editor); the visits waiting are dropped, the journal is dirty
    void ReplaceJournal(DissasmReplayJournal replacement);

    // the record of the cache file; a record that can not be read is kept as it is and written back by ToCache, unless events were written
    // since (then the journal of this session replaces it)
    void LoadFromCache(const DissasmCache& cache);
    bool ToCache(DissasmCache& cache) const;
    bool HasRejectedRecord() const
    {
        return rejectedRecord.has_value();
    }

    void OnEdit(DissasmCodeZone& zone, const DissasmEdit& edit) override;
    void OnUndo(DissasmCodeZone& zone, const DissasmEdit& edit) override;
    void OnRedo(DissasmCodeZone& zone, const DissasmEdit& edit) override;

  private:
    struct JumpContext {
        DissasmReplayJumpKind kind = DissasmReplayJumpKind::Other;
        std::string mnemonic;
        bool waiting = false; // the destination is not reached yet
        uint64 waitingSince = 0;
        std::optional<DissasmReplayPlace> from; // taken when it started waiting
    };

    Resolver resolver;
    DissasmReplayJournal journal;
    std::deque<DissasmReplayEvent> pendingVisits;
    std::optional<uint64> keyboardMoveSince; // a keyboard move that did not rest yet
    std::optional<JumpContext> jumpContext;
    std::optional<std::vector<std::byte>> rejectedRecord;
    uint32 suspended         = 0;
    bool dirty               = false;
    bool recordedSinceLoad   = false;

    std::optional<DissasmReplayPlace> ToPlace(const std::optional<ResolvedPlace>& resolved);
    uint32 Now();
    void AddVisit(const DissasmReplayPlace& place, DissasmReplayVisitSource source);
    // the keyboard move that did not rest: a visit now (an operation on the line of the cursor follows it); true when the cursor was on a
    // place (the same place again is still one visit)
    bool TakeKeyboardMove();
    void FlushVisits();
    bool Append(DissasmReplayEvent event);
    void RecordEdit(DissasmReplayEvent::Kind kind, DissasmCodeZone& zone, const DissasmEdit& edit);
};

// BeginJump / EndJump around a jump of the view
class DissasmReplayJumpScope
{
    DissasmReplayRecorder* recorder;

  public:
    DissasmReplayJumpScope(DissasmReplayRecorder* recorder, DissasmReplayJumpKind kind, std::string_view mnemonic = {}) : recorder(recorder)
    {
        if (recorder)
            recorder->BeginJump(kind, mnemonic);
    }
    ~DissasmReplayJumpScope()
    {
        if (recorder)
            recorder->EndJump();
    }
    DissasmReplayJumpScope(const DissasmReplayJumpScope&)            = delete;
    DissasmReplayJumpScope& operator=(const DissasmReplayJumpScope&) = delete;
};

// Suspend(true) / Suspend(false) around what the user did not do himself (the cursor moved to an undone edit, a document being applied)
class DissasmReplaySuspendScope
{
    DissasmReplayRecorder* recorder;

  public:
    explicit DissasmReplaySuspendScope(DissasmReplayRecorder* recorder) : recorder(recorder)
    {
        if (recorder)
            recorder->Suspend(true);
    }
    ~DissasmReplaySuspendScope()
    {
        if (recorder)
            recorder->Suspend(false);
    }
    DissasmReplaySuspendScope(const DissasmReplaySuspendScope&)            = delete;
    DissasmReplaySuspendScope& operator=(const DissasmReplaySuspendScope&) = delete;
};
} // namespace GView::View::DissasmViewer
