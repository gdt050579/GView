#include "prefetch.hpp"

namespace GView::Type::Prefetch::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class Action : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

TraceChains::TraceChains(Reference<PrefetchFile> _prefetch, Reference<GView::View::WindowInterface> _win) : TabPage("&BSection")
{
    prefetch = _prefetch;
    win      = _win;
    base     = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { { "Next Entry Index", TextAlignament::Right, 14 },
            { "Blocks Fetched", TextAlignament::Right, 10 },
            { "Unknown", TextAlignament::Right, 18 },
            { "Duration", TextAlignament::Right, 10 },
            { "Unknown2", TextAlignament::Right, 18 } },
          ListViewFlags::None);

    Update();
}

std::string_view TraceChains::GetValue(NumericFormatter& n, uint64 value)
{
    if (base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void TraceChains::GoToSelectedSection()
{
    win->GetCurrentView()->GoTo(0);
}

void TraceChains::SelectCurrentSection()
{
    win->GetCurrentView()->Select(0, 0);
}

void TraceChains::Update_17()
{
    auto& fileInformation = std::get<FileInformation_17>(prefetch->fileInformation);

    for (auto i = 0U; i < fileInformation.sectionB.entries; i++)
    {
        auto entry = prefetch->bufferSectionBEntries.GetObject<TraceChainEntry_17_23_26>(sizeof(TraceChainEntry_17_23_26) * i);
        AddItem_17_23_26(entry, i);
    }
}

void TraceChains::Update_23()
{
    auto& fileInformation = std::get<FileInformation_23>(prefetch->fileInformation);

    for (auto i = 0U; i < fileInformation.sectionB.entries; i++)
    {
        auto entry = prefetch->bufferSectionBEntries.GetObject<TraceChainEntry_17_23_26>(sizeof(TraceChainEntry_17_23_26) * i);
        AddItem_17_23_26(entry, i);
    }
}

void TraceChains::Update_26()
{
    auto& fileInformation = std::get<FileInformation_26>(prefetch->fileInformation);

    for (auto i = 0U; i < fileInformation.sectionB.entries; i++)
    {
        auto entry = prefetch->bufferSectionBEntries.GetObject<TraceChainEntry_17_23_26>(sizeof(TraceChainEntry_17_23_26) * i);
        AddItem_17_23_26(entry, i);
    }
}

void TraceChains::AddItem_17_23_26(const TraceChainEntry_17_23_26& tc, uint32 i)
{
    LocalString<128> tmp;
    NumericFormatter n;

    auto item = list->AddItem({ tmp.Format("%s", GetValue(n, tc.nextEntryIndex).data()) });
    item.SetText(1, tmp.Format("%s", GetValue(n, tc.blocksFetched).data()));
    item.SetText(2, tmp.Format("%s", GetValue(n, tc.unknown).data()));
    item.SetText(3, tmp.Format("%s", GetValue(n, tc.duration).data()));
    item.SetText(4, tmp.Format("%s", GetValue(n, tc.unknown2).data()));

    item.SetData<TraceChainEntry_17_23_26>(
          (TraceChainEntry_17_23_26*) (prefetch->bufferSectionAEntries.GetData() + sizeof(TraceChainEntry_17_23_26) * i));
}

void TraceChains::Update()
{
    list->DeleteAllItems();

    switch (prefetch->header.version)
    {
    case Magic::WIN_XP_2003:
        Update_17();
        break;
    case Magic::WIN_VISTA_7:
        Update_23();
        break;
    case Magic::WIN_8:
        Update_26();
        break;
    case Magic::WIN_10:
    default:
        break;
    }
}

bool TraceChains::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool TraceChains::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemPressed)
    {
        GoToSelectedSection();
        return true;
    }

    if (evnt == Event::Command)
    {
        switch (static_cast<Action>(controlID))
        {
        case Action::GoTo:
            GoToSelectedSection();
            return true;
        case Action::ChangeBase:
            base = 26 - base;
            Update();
            return true;
        case Action::Select:
            SelectCurrentSection();
            return true;
        }
    }

    return false;
}
} // namespace GView::Type::Prefetch::Panels
