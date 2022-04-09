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

Sections::Sections(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("&Sections")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = CreateChildControl<ListView>(
          "d:c",
          { { "Section name", TextAlignament::Left, 16 },
            { "Segment name", TextAlignament::Left, 16 },
            { "Memory Address", TextAlignament::Right, 18 },
            { "Size", TextAlignament::Right, 14 },
            { "File Offset", TextAlignament::Right, 14 },
            { "Align", TextAlignament::Right, 10 },
            { "Real Align", TextAlignament::Right, 12 },
            { "Reloc Offset", TextAlignament::Right, 14 },
            { "Reloc Entries Count", TextAlignament::Right, 22 },
            { "Flags", TextAlignament::Right, 30 },
            { "Reserved1", TextAlignament::Right, 12 },
            { "Reserved2", TextAlignament::Right, 12 } },
          ListViewFlags::None);
    if (machO->is64)
    {
        list->AddColumn("Reserved3", TextAlignament::Right, 12);
    }

    Update();
}

std::string_view Sections::GetValue(NumericFormatter& n, uint64_t value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Sections::GoToSelectedSection()
{
    auto s = list->GetItemData<const MachOFile::Section>(list->GetCurrentItem());
    win->GetCurrentView()->GoTo(s->offset != 0 ? s->offset : s->addr /* handling __bss section */);
}

void Panels::Sections::SelectCurrentSection()
{
    auto s = list->GetItemData<const MachOFile::Section>(list->GetCurrentItem());
    win->GetCurrentView()->Select(s->offset != 0 ? s->offset : s->addr /* handling __bss section */, s->size);
}

void Panels::Sections::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    uint32_t i = 0;
    for (const auto& segment : machO->segments)
    {
        for (const auto& s : segment.sections)
        {
            auto item = list->AddItem(s.sectname);

            item.SetData<MachOFile::Section>(const_cast<MachOFile::Section*>(&s));
            item.SetText(1, s.segname);
            item.SetText(2, GetValue(n, s.addr));
            item.SetText(3, GetValue(n, s.size));
            item.SetText(4, GetValue(n, s.offset));
            item.SetText(5, GetValue(n, s.align));
            item.SetText(6, GetValue(n, 1ULL << s.align));
            item.SetText(7, GetValue(n, s.reloff));
            item.SetText(8, GetValue(n, s.nreloc));

            const auto flagsNames = MAC::GetSectionTypeAndAttributesFromFlags(s.flags);
            const auto flagsValue = std::string{ GetValue(n, s.flags) };
            item.SetText(9, temp.Format("%s (%s)", flagsNames.c_str(), flagsValue.c_str()));
            item.SetText(10, GetValue(n, s.reserved1));
            item.SetText(11, GetValue(n, s.reserved2));
            if (machO->is64)
            {
                item.SetText(12, GetValue(n, s.reserved3));
            }

            i++;
        }
    }
}

bool Panels::Sections::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool Panels::Sections::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
