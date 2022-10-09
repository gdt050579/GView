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

VolumeInformation::VolumeInformation(Reference<PrefetchFile> _prefetch, Reference<GView::View::WindowInterface> _win)
    : TabPage("&DSection (Volume Paths)")
{
    prefetch = _prefetch;
    win      = _win;
    base     = 16;

    switch (prefetch->header.version)
    {
    case Magic::WIN_XP_2003:
        list = Factory::ListView::Create(
              this,
              "d:c",
              {
                    "n:Path Offset,a:r,w:14",
                    "n:Path Length,a:r,w:14",
                    "n:Path,a:l,w:40",
                    "n:Creation Time,a:r,w:20",
                    "n:Serial Number,a:r,w:16",
                    "n:File References Offset,a:r,w:30",
                    "n:File References Size,a:r,w:30",
                    "n:Directory Strings Offset,a:r,w:30",
                    "n:Directory Strings Size,a:r,w:30",
                    "n:VI9,a:r,w:10",
              },
              ListViewFlags::None);
        break;
    case Magic::WIN_VISTA_7:
    case Magic::WIN_8:
    case Magic::WIN_10:
        list = Factory::ListView::Create(
              this,
              "d:c",
              {
                    "n:Path Offset,a:r,w:14",
                    "n:Path Length,a:r,w:14",
                    "n:Path,a:l,w:40",
                    "n:Creation Time,a:r,w:20",
                    "n:Serial Number,a:r,w:16",
                    "n:File References Offset,a:r,w:30",
                    "n:File References Size,a:r,w:30",
                    "n:Directory Strings Offset,a:r,w:30",
                    "n:Directory Strings Size,a:r,w:30",
                    "n:VI9,a:r,w:10",
                    "n:Unknown,a:r,w:10",
                    "n:Unknown0,a:r,w:10",
                    "n:Unknown1,a:r,w:10",
                    "n:Unknown2,a:r,w:10",
              },
              ListViewFlags::None);
        break;
    default:
        break;
    }

    Update();
}

std::string_view VolumeInformation::GetValue(NumericFormatter& n, uint64 value)
{
    if (base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void VolumeInformation::GoToSelectedSection()
{
    win->GetCurrentView()->GoTo(0);
}

void VolumeInformation::SelectCurrentSection()
{
    win->GetCurrentView()->Select(0, 0);
}

void VolumeInformation::Update_17()
{
    LocalString<1024> ls;
    NumericFormatter nf;

    for (auto i = 0U; i < prefetch->area.sectionD.entries; i++)
    {
        auto entry = prefetch->bufferSectionD.GetObject<VolumeInformationEntry_17>(sizeof(VolumeInformationEntry_17) * i);

        auto item = list->AddItem({ ls.Format("%s", GetValue(nf, entry->devicePathOffset).data()) });
        item.SetText(1, ls.Format("%s", GetValue(nf, entry->devicePathLength).data()));

        const auto& path = prefetch->volumeEntries.at(i).name;
        item.SetText(2, ls.Format("%.*s", path.size(), path.data()));

        AppCUI::OS::DateTime dt;
        dt.CreateFromFileTime(entry->creationTime);
        item.SetText(3, ls.Format("%-20s", dt.GetStringRepresentation().data()));

        item.SetText(4, ls.Format("%s", GetValue(nf, entry->serialNumber).data()));
        item.SetText(5, ls.Format("%s", GetValue(nf, entry->fileReferencesOffset).data()));
        item.SetText(6, ls.Format("%s", GetValue(nf, entry->fileReferencesSize).data()));
        item.SetText(7, ls.Format("%s", GetValue(nf, entry->directoryStringsOffset).data()));
        item.SetText(8, ls.Format("%s", GetValue(nf, entry->directoryStringsEntries).data()));
        item.SetText(9, ls.Format("%s", GetValue(nf, entry->VI9).data()));

        item.SetData<VolumeInformationEntry_17>(
              (VolumeInformationEntry_17*) (prefetch->bufferSectionA.GetData() + sizeof(VolumeInformationEntry_17) * i));
    }
}

void VolumeInformation::Update_23_26()
{
    LocalString<1024> ls;
    NumericFormatter nf;

    for (auto i = 0U; i < prefetch->area.sectionD.entries; i++)
    {
        auto entry = prefetch->bufferSectionD.GetObject<VolumeInformationEntry_23_26>(sizeof(VolumeInformationEntry_23_26) * i);

        auto item = list->AddItem({ ls.Format("%s", GetValue(nf, entry->devicePathOffset).data()) });
        item.SetText(1, ls.Format("%s", GetValue(nf, entry->devicePathLength).data()));

        const auto& path = prefetch->volumeEntries.at(i).name;
        item.SetText(2, ls.Format("%.*s", path.size(), path.data()));

        AppCUI::OS::DateTime dt;
        dt.CreateFromFileTime(entry->creationTime);
        item.SetText(3, ls.Format("%-20s", dt.GetStringRepresentation().data()));

        item.SetText(4, ls.Format("%s", GetValue(nf, entry->serialNumber).data()));
        item.SetText(5, ls.Format("%s", GetValue(nf, entry->fileReferencesOffset).data()));
        item.SetText(6, ls.Format("%s", GetValue(nf, entry->fileReferencesSize).data()));
        item.SetText(7, ls.Format("%s", GetValue(nf, entry->directoryStringsOffset).data()));
        item.SetText(8, ls.Format("%s", GetValue(nf, entry->directoryStringsEntries).data()));
        item.SetText(9, ls.Format("%s", GetValue(nf, entry->VI9).data()));
        item.SetText(10, "Unknown array (28 bytes)");
        item.SetText(11, ls.Format("%s", GetValue(nf, entry->unknown0).data()));
        item.SetText(12, "Unknown array (28 bytes)");
        item.SetText(13, ls.Format("%s", GetValue(nf, entry->unknown2).data()));

        item.SetData<VolumeInformationEntry_23_26>(
              (VolumeInformationEntry_23_26*) (prefetch->bufferSectionA.GetData() + sizeof(VolumeInformationEntry_23_26) * i));
    }
}

void VolumeInformation::Update_30()
{
    LocalString<1024> ls;
    NumericFormatter nf;

    for (auto i = 0U; i < prefetch->area.sectionD.entries; i++)
    {
        auto entry = prefetch->bufferSectionD.GetObject<VolumeInformationEntry_30>(sizeof(VolumeInformationEntry_30) * i);

        auto item = list->AddItem({ ls.Format("%s", GetValue(nf, entry->devicePathOffset).data()) });
        item.SetText(1, ls.Format("%s", GetValue(nf, entry->devicePathLength).data()));

        const auto& path = prefetch->volumeEntries.at(i).name;
        item.SetText(2, ls.Format("%.*s", path.size(), path.data()));

        AppCUI::OS::DateTime dt;
        dt.CreateFromFileTime(entry->creationTime);
        item.SetText(3, ls.Format("%-20s", dt.GetStringRepresentation().data()));

        item.SetText(4, ls.Format("%s", GetValue(nf, entry->serialNumber).data()));
        item.SetText(5, ls.Format("%s", GetValue(nf, entry->fileReferencesOffset).data()));
        item.SetText(6, ls.Format("%s", GetValue(nf, entry->fileReferencesSize).data()));
        item.SetText(7, ls.Format("%s", GetValue(nf, entry->directoryStringsOffset).data()));
        item.SetText(8, ls.Format("%s", GetValue(nf, entry->directoryStringsEntries).data()));
        item.SetText(9, ls.Format("%s", GetValue(nf, entry->VI9).data()));
        item.SetText(10, "Unknown array (24 bytes)");
        item.SetText(11, ls.Format("%s", GetValue(nf, entry->unknown0).data()));
        item.SetText(12, "Unknown array (24 bytes)");
        item.SetText(13, ls.Format("%s", GetValue(nf, entry->unknown2).data()));

        item.SetData<VolumeInformationEntry_30>(
              (VolumeInformationEntry_30*) (prefetch->bufferSectionA.GetData() + sizeof(VolumeInformationEntry_30) * i));
    }
}

void VolumeInformation::Update()
{
    list->DeleteAllItems();

    CHECKRET(prefetch->bufferSectionD.IsValid(), "");

    switch (prefetch->header.version)
    {
    case Magic::WIN_XP_2003:
        Update_17();
        break;
    case Magic::WIN_VISTA_7:
    case Magic::WIN_8:
        Update_23_26();
        break;
    case Magic::WIN_10:
        Update_30();
        break;
    default:
        break;
    }
}

bool VolumeInformation::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool VolumeInformation::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
