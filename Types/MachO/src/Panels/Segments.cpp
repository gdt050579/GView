#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class Action : int32_t
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

Segments::Segments(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("Se&gments")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("Name", TextAlignament::Left, 14);
    list->AddColumn("Type", TextAlignament::Left, 18);
    list->AddColumn("Command Size", TextAlignament::Right, 14);
    list->AddColumn("Memory Address", TextAlignament::Right, 18);
    list->AddColumn("Memory Size", TextAlignament::Right, 14);
    list->AddColumn("File Offset", TextAlignament::Right, 14);
    list->AddColumn("File Size", TextAlignament::Right, 14);
    list->AddColumn("Max VM Prot", TextAlignament::Right, 26);
    list->AddColumn("Ini VM Prot", TextAlignament::Right, 26);
    list->AddColumn("Sections count", TextAlignament::Right, 18);
    list->AddColumn("Flags", TextAlignament::Right, 10);

    Update();
}

std::string_view Segments::GetValue(NumericFormatter& n, uint64_t value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Segments::GoToSelectedSection()
{
    auto s = list->GetItemData<const MachOFile::Segment>(list->GetCurrentItem());
    if (s->x86.cmd == MAC::LoadCommandType::SEGMENT)
    {
        win->GetCurrentView()->GoTo(s->x86.fileoff);
        return;
    }
    win->GetCurrentView()->GoTo(s->x64.fileoff);
}

void Panels::Segments::SelectCurrentSection()
{
    auto s = list->GetItemData<const MachOFile::Segment>(list->GetCurrentItem());
    if (s->x86.cmd == MAC::LoadCommandType::SEGMENT)
    {
        win->GetCurrentView()->Select(s->x86.fileoff, s->x86.filesize);
        return;
    }
    win->GetCurrentView()->Select(s->x64.fileoff, s->x64.filesize);
}

void Panels::Segments::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    uint32_t i = 0;
    for (const auto& s : machO->segments)
    {
        if (s.x86.cmd == MAC::LoadCommandType::SEGMENT)
        {
            auto item = list->AddItem(s.x86.segname); // name

            list->SetItemData<MachOFile::Segment>(item, const_cast<MachOFile::Segment*>(&s));

            list->SetItemText(
                  item,
                  1,
                  temp.Format(
                        "%s (%s)",
                        std::string(MAC::LoadCommandNames.at(s.x86.cmd)).c_str(),
                        GetValue(n, static_cast<uint32_t>(s.x86.cmd)).data()));
            list->SetItemText(item, 2, GetValue(n, s.x86.cmdsize));
            list->SetItemText(item, 3, GetValue(n, s.x86.vmaddr));
            list->SetItemText(item, 4, GetValue(n, s.x86.vmsize));
            list->SetItemText(item, 5, GetValue(n, s.x86.fileoff));
            list->SetItemText(item, 6, GetValue(n, s.x86.filesize));

            const auto vmMaxProtectionNames       = MAC::GetVMProtectionNamesFromFlags(s.x86.maxprot);
            const auto vmMaxProtectionStringValue = std::string{ GetValue(n, s.x86.maxprot) };
            list->SetItemText(item, 7, temp.Format("%s (%s)", vmMaxProtectionNames.c_str(), vmMaxProtectionStringValue.c_str()));
            const auto vmInitProtectionNames       = MAC::GetVMProtectionNamesFromFlags(s.x86.initprot);
            const auto vmInitProtectionStringValue = std::string{ GetValue(n, s.x86.initprot) };
            list->SetItemText(item, 8, temp.Format("%s (%s)", vmInitProtectionNames.c_str(), vmInitProtectionStringValue.c_str()));
            list->SetItemText(item, 9, GetValue(n, s.x86.nsects));
            const auto segmentsFlagsNames = MAC::GetSegmentCommandNamesFromFlags(s.x86.flags);
            const auto segmentsFlagsValue = std::string{ GetValue(n, s.x86.flags) };
            list->SetItemText(item, 10, temp.Format("%s (%s)", segmentsFlagsNames.c_str(), segmentsFlagsValue.c_str()));
        }
        else if (s.x86.cmd == MAC::LoadCommandType::SEGMENT_64)
        {
            auto item = list->AddItem(s.x64.segname); // name

            list->SetItemData<MachOFile::Segment>(item, const_cast<MachOFile::Segment*>(&s));

            list->SetItemText(
                  item,
                  1,
                  temp.Format(
                        "%s (%s)",
                        std::string(MAC::LoadCommandNames.at(s.x64.cmd)).c_str(),
                        GetValue(n, static_cast<uint32_t>(s.x64.cmd)).data()));
            list->SetItemText(item, 2, GetValue(n, s.x64.cmdsize));
            list->SetItemText(item, 3, GetValue(n, s.x64.vmaddr));
            list->SetItemText(item, 4, GetValue(n, s.x64.vmsize));
            list->SetItemText(item, 5, GetValue(n, s.x64.fileoff));
            list->SetItemText(item, 6, GetValue(n, s.x64.filesize));

            const auto vmMaxProtectionNames = MAC::GetVMProtectionNamesFromFlags(s.x64.maxprot);
            const auto vmMaxProtectionValue = std::string{ GetValue(n, s.x64.maxprot) };
            list->SetItemText(item, 7, temp.Format("%s (%s)", vmMaxProtectionNames.c_str(), vmMaxProtectionValue.c_str()));
            const auto vmInitProtectionNames = MAC::GetVMProtectionNamesFromFlags(s.x64.initprot);
            const auto vmInitProtectionValue = std::string{ GetValue(n, s.x64.maxprot) };
            list->SetItemText(item, 8, temp.Format("%s (%s)", vmInitProtectionNames.c_str(), vmInitProtectionValue.c_str()));
            list->SetItemText(item, 9, GetValue(n, s.x64.nsects));
            const auto segmentsFlagsNames = MAC::GetSegmentCommandNamesFromFlags(s.x64.flags);
            const auto segmentsFlagsValue = std::string{ GetValue(n, s.x64.flags) };
            list->SetItemText(item, 10, temp.Format("%s (%s)", segmentsFlagsNames.c_str(), segmentsFlagsValue.c_str()));
        }

        i++;
    }
}

bool Segments::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool Segments::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemClicked)
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
            Base = 26 - Base;
            Update();
            return true;
        case Action::Select:
            SelectCurrentSection();
            return true;
        }
    }

    return false;
}

} // namespace GView::Type::MachO::Panels
