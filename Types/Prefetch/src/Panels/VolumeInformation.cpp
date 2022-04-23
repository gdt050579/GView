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

VolumeInformation::VolumeInformation(Reference<PrefetchFile> _prefetch, Reference<GView::View::WindowInterface> _win) : TabPage("&DSection")
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
                    { "Path Offset", TextAlignament::Right, 14 },
                    { "Path Length", TextAlignament::Right, 14 },
                    { "Creation Time", TextAlignament::Right, 20 },
                    { "Serial Number", TextAlignament::Right, 16 },
                    { "File References Offset", TextAlignament::Right, 30 },
                    { "File References Size", TextAlignament::Right, 30 },
                    { "Directory Strings Offset", TextAlignament::Right, 30 },
                    { "Directory Strings Size", TextAlignament::Right, 30 },
                    { "VI9", TextAlignament::Right, 10 },
              },
              ListViewFlags::None);
    case Magic::WIN_VISTA_7:
    case Magic::WIN_8:
        list = Factory::ListView::Create(
              this,
              "d:c",
              {
                    { "Path Offset", TextAlignament::Right, 14 },
                    { "Path Length", TextAlignament::Right, 14 },
                    { "Creation Time", TextAlignament::Right, 20 },
                    { "Serial Number", TextAlignament::Right, 16 },
                    { "File References Offset", TextAlignament::Right, 30 },
                    { "File References Size", TextAlignament::Right, 30 },
                    { "Directory Strings Offset", TextAlignament::Right, 30 },
                    { "Directory Strings Size", TextAlignament::Right, 30 },
                    { "VI9", TextAlignament::Right, 10 },
                    { "Unknown", TextAlignament::Right, 10 },
                    { "Unknown0", TextAlignament::Right, 10 },
                    { "Unknown1", TextAlignament::Right, 10 },
                    { "Unknown2", TextAlignament::Right, 10 },
              },
              ListViewFlags::None);
        break;
    case Magic::WIN_10:
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

    auto& fileInformation = std::get<FileInformation_17>(prefetch->fileInformation);

    for (auto i = 0U; i < fileInformation.sectionD.entries; i++)
    {
        auto entry = prefetch->bufferSectionD.GetObject<VolumeInformationEntry_17>(sizeof(VolumeInformationEntry_17) * i);

        auto item = list->AddItem({ ls.Format("%s", GetValue(nf, entry->devicePathOffset).data()) });
        item.SetText(1, ls.Format("%s", GetValue(nf, entry->devicePathLength).data()));

        AppCUI::OS::DateTime dt;
        dt.CreateFromFileTime(entry->creationTime);
        item.SetText(2, ls.Format("%-20s", dt.GetStringRepresentation().data()));

        item.SetText(3, ls.Format("%s", GetValue(nf, entry->serialNumber).data()));
        item.SetText(4, ls.Format("%s", GetValue(nf, entry->fileReferencesOffset).data()));
        item.SetText(5, ls.Format("%s", GetValue(nf, entry->fileReferencesSize).data()));
        item.SetText(6, ls.Format("%s", GetValue(nf, entry->directoryStringsOffset).data()));
        item.SetText(7, ls.Format("%s", GetValue(nf, entry->directoryStringsEntries).data()));
        item.SetText(8, ls.Format("%s", GetValue(nf, entry->VI9).data()));

        item.SetData<VolumeInformationEntry_17>(
              (VolumeInformationEntry_17*) (prefetch->bufferSectionAEntries.GetData() + sizeof(VolumeInformationEntry_17) * i));
    }
}

void VolumeInformation::Update_23()
{
    auto& fileInformation = std::get<FileInformation_23>(prefetch->fileInformation);
    Update_23_26(fileInformation.sectionD.entries);
}

void VolumeInformation::Update_26()
{
    auto& fileInformation = std::get<FileInformation_26>(prefetch->fileInformation);
    Update_23_26(fileInformation.sectionD.entries);
}

void VolumeInformation::Update_23_26(uint32 sectionDEntries)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    for (auto i = 0U; i < sectionDEntries; i++)
    {
        auto entry = prefetch->bufferSectionD.GetObject<VolumeInformationEntry_23_26>(sizeof(VolumeInformationEntry_23_26) * i);

        auto item = list->AddItem({ ls.Format("%s", GetValue(nf, entry->devicePathOffset).data()) });
        item.SetText(1, ls.Format("%s", GetValue(nf, entry->devicePathLength).data()));

        AppCUI::OS::DateTime dt;
        dt.CreateFromFileTime(entry->creationTime);
        item.SetText(2, ls.Format("%-20s", dt.GetStringRepresentation().data()));

        item.SetText(3, ls.Format("%s", GetValue(nf, entry->serialNumber).data()));
        item.SetText(4, ls.Format("%s", GetValue(nf, entry->fileReferencesOffset).data()));
        item.SetText(5, ls.Format("%s", GetValue(nf, entry->fileReferencesSize).data()));
        item.SetText(6, ls.Format("%s", GetValue(nf, entry->directoryStringsOffset).data()));
        item.SetText(7, ls.Format("%s", GetValue(nf, entry->directoryStringsEntries).data()));
        item.SetText(8, ls.Format("%s", GetValue(nf, entry->VI9).data()));
        item.SetText(9, "Unknown array (28 bytes)");
        item.SetText(10, ls.Format("%s", GetValue(nf, entry->unknown0).data()));
        item.SetText(11, "Unknown array (28 bytes)");
        item.SetText(12, ls.Format("%s", GetValue(nf, entry->unknown2).data()));

        item.SetData<VolumeInformationEntry_23_26>(
              (VolumeInformationEntry_23_26*) (prefetch->bufferSectionAEntries.GetData() + sizeof(VolumeInformationEntry_23_26) * i));
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
