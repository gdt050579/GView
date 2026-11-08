#pragma once

#include "DissasmReplay.hpp"

#include <array>
#include <string>

namespace GView::View::DissasmViewer
{
// The replay journal editor (Instance::ShowReplayJournalEditor, DissasmReplayEditor.cpp): one row per event of the journal.
// Columns: # (1 based) | +time (since the previous event: "+0s", "+42s", "+3m05s", "+1h02m") | Kind (visit, jump, back,
// forward, edit, undo, redo, import, analysis) | Address / label (the VA of the place; a rename: the new name too; an import:
// empty; a new analysis: the file offset of its zone) | Text (DescribeReplayEvent without its time). Pure.
constexpr size_t REPLAY_ROW_COLUMNS = 5;
std::array<std::string, REPLAY_ROW_COLUMNS> FormatReplayRow(const DissasmReplayJournal& journal, size_t index);
// "+0s", "+42s", "+3m05s", "+1h02m"
std::string FormatReplayDelta(uint32 seconds);
std::string_view ReplayEventKindName(DissasmReplayEvent::Kind kind);
} // namespace GView::View::DissasmViewer
