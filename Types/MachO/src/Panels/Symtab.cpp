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

SymTab::SymTab(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("SymTa&b")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("Index", TextAlignament::Left, 12);
    list->AddColumn("Name", TextAlignament::Left, 30);
    list->AddColumn("Type", TextAlignament::Right, 8);
    list->AddColumn("Section", TextAlignament::Left, 20);
    list->AddColumn("Timestamp", TextAlignament::Left, 24);
    list->AddColumn("Desc", TextAlignament::Right, 25);
    list->AddColumn("Value", TextAlignament::Right, 25);

    Update();
}

std::string_view SymTab::GetValue(NumericFormatter& n, uint64_t value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void SymTab::GoToSelectedSection()
{
    auto di = list->GetItemData<const MachOFile::Dylib>(list->GetCurrentItem());
    win->GetCurrentView()->GoTo(di->offset);
}

void SymTab::SelectCurrentSection()
{
    auto di = list->GetItemData<const MachOFile::Dylib>(list->GetCurrentItem());
    win->GetCurrentView()->Select(di->offset, di->value.cmdsize);
}

void SymTab::Update()
{
    LocalString<128> tmp;
    NumericFormatter n;
    list->DeleteAllItems();

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    union
    {
        uint32_t n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;   /* type flag, see below */
    uint8_t n_sect;   /* section number or NO_SECT */
    uint16_t n_desc;  /* see <mach-o/stab.h> */
    uint64_t n_value; /* value of this symbol (or stab offset) */

    for (auto i = 0U; i < machO->dySymTab.sc.nsyms; i++)
    {
        auto item = list->AddItem(GetValue(n, static_cast<uint32_t>(i)));
        list->SetItemData<uint32_t>(item, &i);

        if (machO->is64)
        {
            list->SetItemText(
                  item, 1, machO->dySymTab.stringTable.get() + ((MAC::nlist_64*) machO->dySymTab.symbolTable.get())[i].n_un.n_strx);
        }
        else
        {
            list->SetItemText(
                  item, 1, machO->dySymTab.stringTable.get() + ((MAC::nlist*) machO->dySymTab.symbolTable.get())[i].n_un.n_strx);
        }
    }
}

bool SymTab::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool SymTab::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
