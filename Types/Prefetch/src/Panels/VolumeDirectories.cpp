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

VolumeDirectories::VolumeDirectories(Reference<PrefetchFile> _prefetch, Reference<GView::View::WindowInterface> _win)
    : TabPage("&VolumeDirectories")
{
    prefetch = _prefetch;
    win      = _win;
    base     = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          {
                { "Volume #", TextAlignament::Right, 14 },
                { "Path Length", TextAlignament::Right, 14 },
                { "Path", TextAlignament::Right, 160 },
          },
          ListViewFlags::None);

    Update();
}

std::string_view VolumeDirectories::GetValue(NumericFormatter& n, uint64 value)
{
    if (base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void VolumeDirectories::GoToSelectedSection()
{
    win->GetCurrentView()->GoTo(0);
}

void VolumeDirectories::SelectCurrentSection()
{
    win->GetCurrentView()->Select(0, 0);
}

void VolumeDirectories::Update_17()
{
    LocalString<1024> ls;
    NumericFormatter nf;

    auto& fileInformation = std::get<FileInformation_17>(prefetch->fileInformation);

    for (auto i = 0U; i < fileInformation.sectionD.entries; i++)
    {
        auto entry      = prefetch->bufferSectionD.GetObject<VolumeInformationEntry_17>(sizeof(VolumeInformationEntry_17) * i);
        auto& dirBuffer = prefetch->volumeEntries.at(i).directories;

        auto offset  = 0U;
        auto entries = 0U;
        while (entries < entry->directoryStringsEntries)
        {
            auto item = list->AddItem({ ls.Format("%s", GetValue(nf, i).data()) });

            auto dse = (DirectoryStringEntry*) (dirBuffer.GetData() + offset);

            item.SetText(1, ls.Format("%s", GetValue(nf, dse->size).data()));
            item.SetText(2, ls.Format("%-20S", dse->path));

            item.SetData<DirectoryStringEntry>(dse);

            offset += sizeof(DirectoryStringEntry::size) + (dse->size + 1ULL) * sizeof(char16_t);
            entries++;
        }
    }
}

void VolumeDirectories::Update_23()
{
    LocalString<1024> ls;
    NumericFormatter nf;

    auto& fileInformation = std::get<FileInformation_23>(prefetch->fileInformation);

    for (auto i = 0U; i < fileInformation.sectionD.entries; i++)
    {
        auto entry      = prefetch->bufferSectionD.GetObject<VolumeInformationEntry_23_26>(sizeof(VolumeInformationEntry_23_26) * i);
        auto& dirBuffer = prefetch->volumeEntries.at(i).directories;

        auto offset  = 0U;
        auto entries = 0U;
        while (entries < entry->directoryStringsEntries)
        {
            auto item = list->AddItem({ ls.Format("%s", GetValue(nf, i).data()) });

            auto dse = (DirectoryStringEntry*) (dirBuffer.GetData() + offset);

            item.SetText(1, ls.Format("%s", GetValue(nf, dse->size).data()));
            item.SetText(2, ls.Format("%-20S", dse->path));

            item.SetData<DirectoryStringEntry>(dse);

            offset += sizeof(DirectoryStringEntry::size) + (dse->size + 1ULL) * sizeof(char16_t);
            entries++;
        }
    }
}

void VolumeDirectories::Update()
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
    case Magic::WIN_10:
    default:
        break;
    }
}

bool VolumeDirectories::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool VolumeDirectories::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
