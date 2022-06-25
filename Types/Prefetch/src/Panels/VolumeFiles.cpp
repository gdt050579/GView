#include "Prefetch.hpp"

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

VolumeFiles::VolumeFiles(Reference<PrefetchFile> _prefetch, Reference<GView::View::WindowInterface> _win) : TabPage("VolumeFile&s")
{
    prefetch = _prefetch;
    win      = _win;
    base     = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          {
                "n:Volume #,a:r,w:14",
                "n:MFT entry index,a:r,w:20",
                "n:Sequence number,a:r,w:20",
          },
          ListViewFlags::None);

    Update();
}

std::string_view VolumeFiles::GetValue(NumericFormatter& n, uint64 value)
{
    if (base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void VolumeFiles::GoToSelectedSection()
{
    win->GetCurrentView()->GoTo(0);
}

void VolumeFiles::SelectCurrentSection()
{
    win->GetCurrentView()->Select(0, 0);
}

void VolumeFiles::Update_17()
{
    LocalString<1024> ls;
    NumericFormatter nf;

    for (auto i = 0U; i < prefetch->area.sectionD.entries; i++)
    {
        auto& filesBuffer = prefetch->volumeEntries.at(i).files;
        auto frs          = (FileReferences_17*) filesBuffer.GetData();

        for (uint32 j = 0; j < frs->numberOfFileReferences; j++)
        {
            auto& fr = frs->fileReferences[j];

            auto item = list->AddItem({ ls.Format("%s", GetValue(nf, i).data()) });

            item.SetText(1, ls.Format("0x%02X%02X%02X", fr.entryIndex[0], fr.entryIndex[1], fr.entryIndex[2]));
            item.SetText(2, ls.Format("%-20s", GetValue(nf, fr.sequenceNumber).data()));

            item.SetData<FileReference>(&fr);
        }
    }
}

void VolumeFiles::Update_23_26_30()
{
    LocalString<1024> ls;
    NumericFormatter nf;

    for (auto i = 0U; i < prefetch->area.sectionD.entries; i++)
    {
        auto& filesBuffer = prefetch->volumeEntries.at(i).files;
        auto frs          = (FileReferences_23_26_30*) filesBuffer.GetData();

        for (uint32 j = 0; j < frs->numberOfFileReferences; j++)
        {
            auto& fr = frs->fileReferences[j];

            auto item = list->AddItem({ ls.Format("%s", GetValue(nf, i).data()) });

            item.SetText(1, ls.Format("0x%02X%02X%02X", fr.entryIndex[0], fr.entryIndex[1], fr.entryIndex[2]));
            item.SetText(2, ls.Format("%-20s", GetValue(nf, fr.sequenceNumber).data()));

            item.SetData<FileReference>(&fr);
        }
    }
}

void VolumeFiles::Update()
{
    list->DeleteAllItems();

    switch (prefetch->header.version)
    {
    case Magic::WIN_XP_2003:
        Update_17();
        break;
    case Magic::WIN_VISTA_7:
    case Magic::WIN_8:
    case Magic::WIN_10:
        Update_23_26_30();
        break;
    default:
        break;
    }
}

bool VolumeFiles::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool VolumeFiles::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
