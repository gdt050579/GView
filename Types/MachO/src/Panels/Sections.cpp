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

    list = CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("Section name", TextAlignament::Left, 16);
    list->AddColumn("Segment name", TextAlignament::Left, 16);
    list->AddColumn("Memory Address", TextAlignament::Right, 18);
    list->AddColumn("Size", TextAlignament::Right, 14);
    list->AddColumn("File Offset", TextAlignament::Right, 14);
    list->AddColumn("Align", TextAlignament::Right, 10);
    list->AddColumn("Reloc Offset", TextAlignament::Right, 14);
    list->AddColumn("Flags", TextAlignament::Right, 10);
    list->AddColumn("Reserved1", TextAlignament::Right, 12);
    list->AddColumn("Reserved2", TextAlignament::Right, 12);
    list->AddColumn("Reserved3", TextAlignament::Right, 12);

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
    if (machO->is64)
    {
        win->GetCurrentView()->GoTo(s->x64.offset);
        return;
    }
    win->GetCurrentView()->GoTo(s->x86.offset);
}

void Panels::Sections::SelectCurrentSection()
{
    auto s = list->GetItemData<const MachOFile::Section>(list->GetCurrentItem());
    if (machO->is64)
    {
        win->GetCurrentView()->Select(s->x64.offset, s->x64.size);
        return;
    }
    win->GetCurrentView()->Select(s->x86.offset, s->x86.size);
}

void Panels::Sections::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    uint32_t i = 0;
    for (const auto& s : machO->sections)
    {
        if (machO->is64)
        {
            auto item = list->AddItem(s.x64.sectname); // name

            list->SetItemData<MachOFile::Section>(item, const_cast<MachOFile::Section*>(&s));
            list->SetItemText(item, 1, s.x64.segname);
            list->SetItemText(item, 2, GetValue(n, s.x64.addr));
            list->SetItemText(item, 3, GetValue(n, s.x64.size));
            list->SetItemText(item, 4, GetValue(n, s.x64.offset));
            list->SetItemText(item, 5, GetValue(n, s.x64.align));
            list->SetItemText(item, 6, GetValue(n, s.x64.reloff));
            list->SetItemText(item, 7, GetValue(n, s.x64.nreloc));
            list->SetItemText(item, 8, GetValue(n, s.x64.flags));
            list->SetItemText(item, 9, GetValue(n, s.x64.reserved1));
            list->SetItemText(item, 10, GetValue(n, s.x64.reserved2));
            list->SetItemText(item, 11, GetValue(n, s.x64.reserved3));
        }
        else
        {
            auto item = list->AddItem(s.x86.sectname); // name

            list->SetItemData<MachOFile::Section>(item, const_cast<MachOFile::Section*>(&s));
            list->SetItemText(item, 1, s.x86.segname);
            list->SetItemText(item, 2, GetValue(n, s.x86.addr));
            list->SetItemText(item, 3, GetValue(n, s.x86.size));
            list->SetItemText(item, 4, GetValue(n, s.x86.offset));
            list->SetItemText(item, 5, GetValue(n, s.x86.align));
            list->SetItemText(item, 6, GetValue(n, s.x86.reloff));
            list->SetItemText(item, 7, GetValue(n, s.x86.nreloc));
            list->SetItemText(item, 8, GetValue(n, s.x86.flags));
            list->SetItemText(item, 9, GetValue(n, s.x86.reserved1));
            list->SetItemText(item, 10, GetValue(n, s.x86.reserved2));
        }

        i++;
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
