// The replay journal editor: the teacher removes the steps that should not be played back (a wrong turn, idle visits) before
// the journal is published with a solution. It works on a copy; the journal of the view changes only when the changes are
// applied (then it is dirty: Ctrl+S / the course save keep it).

#include "DissasmViewer.hpp"
#include "DissasmReplayEditor.hpp"
#include "DissasmReplayRecorder.hpp"

#include <cstdio>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Controls;
using namespace AppCUI::Utils;

std::string_view GView::View::DissasmViewer::ReplayEventKindName(DissasmReplayEvent::Kind kind)
{
    switch (kind) {
    case DissasmReplayEvent::Kind::Visit:
        return "visit";
    case DissasmReplayEvent::Kind::Jump:
        return "jump";
    case DissasmReplayEvent::Kind::JumpBack:
        return "back";
    case DissasmReplayEvent::Kind::JumpForward:
        return "forward";
    case DissasmReplayEvent::Kind::Edit:
        return "edit";
    case DissasmReplayEvent::Kind::Undo:
        return "undo";
    case DissasmReplayEvent::Kind::Redo:
        return "redo";
    case DissasmReplayEvent::Kind::Import:
        return "import";
    case DissasmReplayEvent::Kind::Reanalysis:
        return "analysis";
    }
    return "?";
}

std::string GView::View::DissasmViewer::FormatReplayDelta(uint32 seconds)
{
    char buf[32];
    if (seconds < 60)
        snprintf(buf, sizeof(buf), "+%us", seconds);
    else if (seconds < 3600)
        snprintf(buf, sizeof(buf), "+%um%02us", seconds / 60, seconds % 60);
    else
        snprintf(buf, sizeof(buf), "+%uh%02um", seconds / 3600, (seconds / 60) % 60);
    return buf;
}

std::array<std::string, REPLAY_ROW_COLUMNS> GView::View::DissasmViewer::FormatReplayRow(const DissasmReplayJournal& journal, size_t index)
{
    std::array<std::string, REPLAY_ROW_COLUMNS> row;
    if (index >= journal.events.size())
        return row;
    const auto& event   = journal.events[index];
    const uint32 before = index > 0 ? journal.events[index - 1].time : 0;
    row[0]              = std::to_string(index + 1);
    row[1]              = FormatReplayDelta(event.time >= before ? event.time - before : 0);
    row[2]              = std::string(ReplayEventKindName(event.kind));

    char buf[48];
    switch (event.kind) {
    case DissasmReplayEvent::Kind::Import:
        break;
    case DissasmReplayEvent::Kind::Reanalysis:
        snprintf(
              buf,
              sizeof(buf),
              "zone @ 0x%llx",
              static_cast<unsigned long long>(event.place.zone < journal.zones.size() ? journal.zones[event.place.zone].fileOffset : 0));
        row[3] = buf;
        break;
    default:
        snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(ReplayPlaceAddress(journal, event.place)));
        row[3] = buf;
        // a rename: the new name says more than the address
        if (event.edit.has_value() && event.edit->kind == DissasmEdit::Kind::LabelName && event.edit->after.has_value() &&
            !event.edit->after->empty()) {
            constexpr size_t MAX_LABEL = 32;
            const auto& name           = event.edit->after.value();
            row[3] += " " + (name.size() > MAX_LABEL ? name.substr(0, MAX_LABEL) + "..." : name);
        }
        break;
    }

    row[4] = DescribeReplayEvent(journal, index, false); // the +time column says when
    return row;
}

namespace
{
class ReplayJournalWindow : public Window
{
    static constexpr int BTN_DELETE        = 1;
    static constexpr int BTN_DELETE_VISITS = 2;
    static constexpr int BTN_COMPACT       = 3;
    static constexpr int BTN_CLOSE         = 4;

    DissasmReplayJournal journal; // the copy that is edited
    const size_t originalCount;
    Reference<ListView> list;
    Reference<Label> info;

    // the list has no removal of one item: it is filled again (the current row stays at the same index)
    void Fill(size_t current)
    {
        list->DeleteAllItems();
        std::optional<ListViewItem> currentItem;
        for (size_t index = 0; index < journal.events.size(); index++) {
            const auto row = FormatReplayRow(journal, index);
            auto item      = list->AddItem({ std::string_view(row[0]), std::string_view(row[1]), std::string_view(row[2]), std::string_view(row[3]),
                                             std::string_view(row[4]) });
            item.SetData(static_cast<uint64>(index));
            if (index == current)
                currentItem = item;
        }
        if (currentItem.has_value())
            list->SetCurrentItem(currentItem.value());
        LocalString<128> text;
        text.SetFormat("%zu steps, %zu removed", journal.events.size(), Removed());
        info->SetText(text);
    }

    std::optional<size_t> CurrentIndex()
    {
        if (journal.events.empty() || list->GetItemsCount() == 0)
            return std::nullopt;
        auto item = list->GetCurrentItem();
        if (!item.IsValid())
            return std::nullopt;
        const uint64 index = item.GetData(UINT64_MAX);
        return index < journal.events.size() ? std::optional<size_t>(static_cast<size_t>(index)) : std::nullopt;
    }

  public:
    explicit ReplayJournalWindow(DissasmReplayJournal copy)
        : Window("Replay journal", "d:c,w:95%,h:80%", WindowFlags::Sizeable), journal(std::move(copy)), originalCount(journal.events.size())
    {
        list = Factory::ListView::Create(
              this,
              "l:1,t:1,r:1,b:4",
              { "n:#,w:8", "n:+time,w:9", "n:Kind,w:9", "n:Address / label,w:30", "n:Text,w:120" },
              ListViewFlags::PopupSearchBar);
        info = Factory::Label::Create(this, "", "l:1,b:2,r:1,h:1");
        Factory::Button::Create(this, "&Delete", "l:1,b:0,w:12", BTN_DELETE);
        Factory::Button::Create(this, "Delete &visits before", "l:14,b:0,w:24", BTN_DELETE_VISITS);
        Factory::Button::Create(this, "C&ompact", "l:39,b:0,w:13", BTN_COMPACT);
        Factory::Button::Create(this, "&Close", "r:1,b:0,w:10", BTN_CLOSE);
        Fill(0);
        list->SetFocus();
    }

    size_t Removed() const
    {
        return originalCount - journal.events.size();
    }
    DissasmReplayJournal TakeJournal()
    {
        return std::move(journal);
    }

    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        if (eventType == Event::ButtonClicked && ID == BTN_DELETE) {
            if (const auto index = CurrentIndex(); index.has_value() && journal.Erase(index.value()))
                Fill(std::min(index.value(), journal.events.empty() ? 0 : journal.events.size() - 1));
            list->SetFocus();
            return true;
        }
        if (eventType == Event::ButtonClicked && ID == BTN_DELETE_VISITS) {
            // the visits before the current step (the way to it), the step itself stays
            if (const auto index = CurrentIndex(); index.has_value()) {
                const size_t removed = journal.EraseVisits(0, index.value());
                Fill(index.value() - std::min(index.value(), removed));
            }
            list->SetFocus();
            return true;
        }
        if (eventType == Event::ButtonClicked && ID == BTN_COMPACT) {
            journal.Compact(); // the rule of the recorder: at most 3 visits before an operation, none after the last one
            Fill(0);
            list->SetFocus();
            return true;
        }
        if ((eventType == Event::ButtonClicked && ID == BTN_CLOSE) || eventType == Event::WindowClose) {
            if (Removed() == 0) {
                Exit(Dialogs::Result::Cancel);
                return true;
            }
            LocalString<128> question;
            question.SetFormat("Apply the changes (%zu entries removed)?", Removed());
            const auto answer = Dialogs::MessageBox::ShowYesNoCancel("Replay journal", question);
            if (answer == Dialogs::Result::Yes)
                Exit(Dialogs::Result::Ok);
            else if (answer == Dialogs::Result::No)
                Exit(Dialogs::Result::Cancel);
            return true; // Cancel: the editor stays open
        }
        return Window::OnEvent(control, eventType, ID);
    }
};
} // namespace

void Instance::ShowReplayJournalEditor()
{
    if (IsReadOnlyRole()) {
        Dialogs::MessageBox::ShowNotification("Replay journal", "This window shows the teacher's solution: its journal can not be edited here.");
        return;
    }
    // a student's task: the journal is part of the work handed to the course; only course staff edit it (their own solutions)
    if (role == GView::Security::Learning::WorkspaceRole::Student && !GView::Security::Learning::Hooks::IsCourseStaff()) {
        Dialogs::MessageBox::ShowNotification("Replay journal", "The replay journal of a course task can be edited by course staff only.");
        return;
    }
    if (replay->Journal().events.empty()) {
        Dialogs::MessageBox::ShowNotification("Replay journal", "The replay journal of this file is empty: it records the lines visited, the jumps and the edits.");
        return;
    }
    ReplayJournalWindow window(replay->Journal());
    if (window.Show() != Dialogs::Result::Ok)
        return;
    replay->ReplaceJournal(window.TakeJournal());
    replay->MarkDirty(); // Ctrl+S writes it to the cache; a course window: not on the server yet
}
