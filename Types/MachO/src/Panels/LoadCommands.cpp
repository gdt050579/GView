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

LoadCommands::LoadCommands(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("&Commands")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          {
                "n:Index,a:r,w:8",
                "n:Type,w:30",
                "n:File Offset,a:r,w:14",
                "n:Size,a:r,w:14",
                "n:Description,w:50",
          },
          ListViewFlags::None);

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
    auto lc = list->GetCurrentItem().GetData<const MachOFile::LoadCommand>();
    win->GetCurrentView()->GoTo(lc->offset);
}

void Panels::LoadCommands::SelectCurrentSection()
{
    auto lc = list->GetCurrentItem().GetData<const MachOFile::LoadCommand>();
    win->GetCurrentView()->Select(lc->offset, lc->value.cmdsize);
}

void Panels::LoadCommands::Update()
{
    LocalString<128> ls;
    NumericFormatter nf;
    list->DeleteAllItems();

    uint32_t i = 0;
    for (const auto& lc : machO->loadCommands)
    {
        auto item = list->AddItem(ls.Format("#%lu", i));
        item.SetData<MachOFile::LoadCommand>(const_cast<MachOFile::LoadCommand*>(&lc));

        const auto& lcName     = MAC::LoadCommandNames.at(lc.value.cmd);
        const auto& lcHexValue = GetValue(nf, static_cast<uint32_t>(lc.value.cmd));
        item.SetText(1, ls.Format("%s (%s)", lcName.data(), lcHexValue.data()));
        item.SetText(2, GetValue(nf, lc.offset));
        item.SetText(3, GetValue(nf, lc.value.cmdsize));
        item.SetText(4, MAC::LoadCommandDescriptions.at(lc.value.cmd));

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
