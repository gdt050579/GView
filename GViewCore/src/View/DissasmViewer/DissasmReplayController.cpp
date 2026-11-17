#include "DissasmReplayController.hpp"

#include <algorithm>

using namespace GView::View::DissasmViewer;

namespace
{
using Kind = DissasmReplayEvent::Kind;

bool IsNavigation(Kind kind)
{
    return kind == Kind::Visit || kind == Kind::Jump || kind == Kind::JumpBack || kind == Kind::JumpForward;
}
} // namespace

DissasmReplayController::DissasmReplayController(DissasmReplayJournal replayJournal, Host& replayHost)
    : journal(std::move(replayJournal)), host(replayHost), skipped(journal.events.size(), false)
{
}

DissasmCodeZone* DissasmReplayController::ZoneOf(const DissasmReplayPlace& place) const
{
    if (place.zone >= journal.zones.size())
        return nullptr;
    return host.FindZone(journal.zones[place.zone].fileOffset);
}

bool DissasmReplayController::MoveCursor(const DissasmReplayPlace& place)
{
    auto* zone = ZoneOf(place);
    return zone != nullptr && host.MoveCursor(*zone, place.anchor);
}

bool DissasmReplayController::ApplyEdit(const DissasmReplayEvent& event, bool forward)
{
    auto* zone = ZoneOf(event.place);
    if (!zone || !event.edit.has_value())
        return false;
    const auto& edit = event.edit.value();
    // an undo is recorded as the edit it undid: applying the undo is applying that edit backward
    const bool direction = event.kind == Kind::Undo ? !forward : forward;
    bool applied         = false;
    if (edit.kind == DissasmEdit::Kind::AddZone || edit.kind == DissasmEdit::Kind::RemoveZone)
        applied = zone->ApplyReplayZoneEdit(edit.zone, (edit.kind == DissasmEdit::Kind::AddZone) == direction);
    else
        applied = zone->ApplyReplayEdit(ToDissasmEdit(edit, event.place.anchor), direction);
    if (!applied)
        return false;
    if (ReplayEditNeedsReanalysis(edit.kind))
        host.Reanalyze(*zone, event.place.anchor.address);
    else
        host.ZoneLinesChanged(*zone);
    return true;
}

bool DissasmReplayController::Apply(size_t index, bool forward)
{
    const auto& event = journal.events[index];
    if (IsNavigation(event.kind))
        return !forward || MoveCursor(event.place); // backward: StepBack moves the cursor
    if (event.HasEdit()) {
        if (!ApplyEdit(event, forward))
            return false;
        if (forward)
            MoveCursor(event.place); // the cursor shows the edit (its line may be hidden: not an error)
        return true;
    }
    return true; // Import / Reanalysis: markers
}

bool DissasmReplayController::StepForward()
{
    if (position >= journal.events.size())
        return false;
    skipped[position] = !Apply(position, true);
    position++;
    return true;
}

bool DissasmReplayController::StepBack()
{
    if (position == 0)
        return false;
    position--;
    const auto& event = journal.events[position];
    if (!skipped[position])
        Apply(position, false);
    skipped[position] = false; // not applied any more
    // the cursor where it was before this event: the start of a jump, else the place of the last applied event that has one
    if (event.kind == Kind::Jump) {
        MoveCursor(event.from);
        return true;
    }
    for (size_t index = position; index > 0; index--) {
        const auto& previous = journal.events[index - 1];
        if (previous.HasPlace() && previous.kind != Kind::Reanalysis && !skipped[index - 1]) {
            MoveCursor(previous.place);
            break;
        }
    }
    return true;
}

bool DissasmReplayController::Seek(size_t target)
{
    target              = std::min(target, journal.events.size());
    const size_t before = position;
    while (position < target && StepForward()) {
    }
    while (position > target && StepBack()) {
    }
    return position != before;
}

bool DissasmReplayController::GoToStart()
{
    return Seek(0);
}

bool DissasmReplayController::GoToEnd()
{
    return Seek(journal.events.size());
}

std::string DissasmReplayController::Describe(size_t index, bool withTime) const
{
    std::string text = DescribeReplayEvent(journal, index, withTime);
    if (IsSkipped(index))
        text += " (skipped: not in this analysis)";
    return text;
}

size_t DissasmReplayController::SkippedCount() const
{
    return static_cast<size_t>(std::count(skipped.begin(), skipped.end(), true));
}
