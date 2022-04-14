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

    list = Factory::ListView::Create(
          this,
          "d:c",
          { { "Name", TextAlignament::Left, 14 },
            { "Type", TextAlignament::Left, 18 },
            { "Command Size", TextAlignament::Right, 14 },
            { "Memory Address", TextAlignament::Right, 18 },
            { "Memory Size", TextAlignament::Right, 14 },
            { "File Offset", TextAlignament::Right, 14 },
            { "File Size", TextAlignament::Right, 14 },
            { "Max VM Prot", TextAlignament::Right, 26 },
            { "Ini VM Prot", TextAlignament::Right, 26 },
            { "Sections count", TextAlignament::Right, 18 },
            { "Flags", TextAlignament::Right, 10 } },
          ListViewFlags::None);
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
    auto s = list->GetCurrentItem().GetData<const MachOFile::Segment>();
    win->GetCurrentView()->GoTo(s->fileoff);
}

void Panels::Segments::SelectCurrentSection()
{
    auto s = list->GetCurrentItem().GetData<const MachOFile::Segment>();
    win->GetCurrentView()->Select(s->fileoff, s->filesize);
}

void Panels::Segments::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    uint32_t i = 0;
    for (const auto& s : machO->segments)
    {
        auto item = list->AddItem(s.segname); // name

        item.SetData<MachOFile::Segment>(const_cast<MachOFile::Segment*>(&s));

        item.SetText(
              1,
              temp.Format(
                    "%s (%s)", std::string(MAC::LoadCommandNames.at(s.cmd)).c_str(), GetValue(n, static_cast<uint32_t>(s.cmd)).data()));
        item.SetText(2, GetValue(n, s.cmdsize));
        item.SetText(3, GetValue(n, s.vmaddr));
        item.SetText(4, GetValue(n, s.vmsize));
        item.SetText(5, GetValue(n, s.fileoff));
        item.SetText(6, GetValue(n, s.filesize));

        const auto vmMaxProtectionNames = MAC::GetVMProtectionNamesFromFlags(s.maxprot);
        const auto vmMaxProtectionValue = std::string{ GetValue(n, s.maxprot) };
        item.SetText(7, temp.Format("%s (%s)", vmMaxProtectionNames.c_str(), vmMaxProtectionValue.c_str()));
        const auto vmInitProtectionNames = MAC::GetVMProtectionNamesFromFlags(s.initprot);
        const auto vmInitProtectionValue = std::string{ GetValue(n, s.maxprot) };
        item.SetText(8, temp.Format("%s (%s)", vmInitProtectionNames.c_str(), vmInitProtectionValue.c_str()));
        item.SetText(9, GetValue(n, s.nsects));
        const auto segmentsFlagsNames = MAC::GetSegmentCommandNamesFromFlags(s.flags);
        const auto segmentsFlagsValue = std::string{ GetValue(n, s.flags) };
        item.SetText(10, temp.Format("%s (%s)", segmentsFlagsNames.c_str(), segmentsFlagsValue.c_str()));

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
