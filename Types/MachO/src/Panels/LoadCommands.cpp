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

LoadCommands::LoadCommands(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("&LoadCommands")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("Index", TextAlignament::Right, 8);
    list->AddColumn("Type", TextAlignament::Left, 30);
    list->AddColumn("File Offset", TextAlignament::Right, 14);
    list->AddColumn("Size", TextAlignament::Right, 14);
    list->AddColumn("Description", TextAlignament::Left, 50);

    Update();
}

std::string_view LoadCommands::GetValue(NumericFormatter& n, uint64_t value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::LoadCommands::GoToSelectedSection()
{
    auto lc = list->GetItemData<const MachOFile::LoadCommand>(list->GetCurrentItem());
    win->GetCurrentView()->GoTo(lc->offset);
}

void Panels::LoadCommands::SelectCurrentSection()
{
    auto lc = list->GetItemData<const MachOFile::LoadCommand>(list->GetCurrentItem());
    win->GetCurrentView()->Select(lc->offset, lc->value.cmdsize);
}

void Panels::LoadCommands::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    uint32_t i = 0;
    for (const auto& lc : machO->loadCommands)
    {
        temp.Format("#%lu", i);
        auto item = list->AddItem(temp); // index

        list->SetItemData<MachOFile::LoadCommand>(item, const_cast<MachOFile::LoadCommand*>(&lc));

        list->SetItemText(
              item,
              1,
              temp.Format(
                    "%s (%s)",
                    std::string(MAC::LoadCommandNames.at(lc.value.cmd)).c_str(),
                    GetValue(n, static_cast<uint32_t>(lc.value.cmd)).data()));
        list->SetItemText(item, 2, GetValue(n, lc.offset));
        list->SetItemText(item, 3, GetValue(n, lc.value.cmdsize));
        list->SetItemText(item, 4, MAC::LoadCommandDescriptions.at(lc.value.cmd));

        i++;
    }
}

bool Panels::LoadCommands::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool Panels::LoadCommands::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
