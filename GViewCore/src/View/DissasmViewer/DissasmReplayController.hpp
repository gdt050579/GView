#pragma once

#include "DissasmReplay.hpp"
#include "DissasmReplayHost.hpp"

namespace GView::View::DissasmViewer
{
// The playback of a replay journal in a view: the events [0, Position()) are applied. A step forward applies the next event (a visit / a jump
// moves the cursor to its place, an edit / a redo is applied, an undo is undone, an import / a new analysis is a marker), a step back undoes
// the last applied one (an edit is undone, an undo applied again) and moves the cursor to the previous place (to the start of a jump). The
// edits are applied to the zones without their history and without the recorder (DissasmCodeZone::ApplyReplayEdit / ApplyReplayZoneEdit);
// the edits of the data / the functions of the user analyze their zone again (Host::Reanalyze). An event whose zone or anchor this analysis
// does not have is skipped (IsSkipped), never an error.
class DissasmReplayController
{
  public:
    using Host = DissasmReplayHost;

    DissasmReplayController(DissasmReplayJournal journal, Host& host);

    size_t Count() const
    {
        return journal.events.size();
    }
    size_t Position() const
    {
        return position;
    }
    // false when there is nothing to do (at the end / at the start)
    bool StepForward();
    bool StepBack();
    bool GoToStart();
    bool GoToEnd();
    // to the position (clamped to Count); false when it did not change
    bool Seek(size_t target);

    std::string Describe(size_t index, bool withTime = true) const; // DescribeReplayEvent, "(skipped)" for a skipped event
    const DissasmReplayEvent& At(size_t index) const
    {
        return journal.events.at(index);
    }
    // the event was applied (it is before Position()) and could not be: its zone / its anchor is not in this analysis
    bool IsSkipped(size_t index) const
    {
        return index < skipped.size() && skipped[index];
    }
    size_t SkippedCount() const;
    const DissasmReplayJournal& Journal() const
    {
        return journal;
    }

  private:
    DissasmReplayJournal journal;
    Host& host;
    size_t position = 0;
    std::vector<bool> skipped;

    DissasmCodeZone* ZoneOf(const DissasmReplayPlace& place) const;
    bool MoveCursor(const DissasmReplayPlace& place);
    // forward: as recorded (an undo undoes its edit); false when it could not be applied
    bool ApplyEdit(const DissasmReplayEvent& event, bool forward);
    bool Apply(size_t index, bool forward);
};

// The status line of a window that plays a replay back: where it is and how to move, then the step shown
// ("Replay 12/57 ([ ] step, { } start / end): comment added at 0x401040"). The bracket keys are characters, so they work
// on every terminal and keyboard (the Alt+arrows do not reach GView from macOS Terminal by default).
std::string ReplayStatusLine(size_t position, size_t count, bool waitingForAnalysis, std::string_view stepDescription);
} // namespace GView::View::DissasmViewer
