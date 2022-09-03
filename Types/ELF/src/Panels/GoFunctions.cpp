#include "elf.hpp"

namespace GView::Type::ELF::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class ObjectAction : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

GoFunctions::GoFunctions(Reference<ELFFile> _elf, Reference<GView::View::WindowInterface> _win) : TabPage("G&oFunctions")
{
    elf  = _elf;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:#,a:r,w:6",
            "n:Entry,a:r,w:16",
            "n:Name,a:l,w:60",
            "n:Name Offset,a:r,w:20",
            "n:Args,a:r,w:10",
            "n:Frame,a:r,w:8",
            "n:Pcsp,a:r,w:12",
            "n:Pcfile,a:r,w:12",
            "n:Pcln,a:r,w:12",
            "n:Nfuncdata,a:r,w:12",
            "n:Npcdata,a:r,w:12" },
          ListViewFlags::None);

    Update();
}

std::string_view GoFunctions::GetValue(NumericFormatter& n, uint64 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void GoFunctions::GoToSelectedSection()
{
    auto i = list->GetCurrentItem().GetData(-1);
    CHECKRET(i != -1, "");

    Golang::Function f{};
    CHECKRET(elf->pclntab112.GetFunction(i, f), "");

    win->GetCurrentView()->GoTo(f.func.entry);
}

void GoFunctions::SelectCurrentSection()
{
    auto i = list->GetCurrentItem().GetData(-1);
    CHECKRET(i != -1, "");

    Golang::Function f1{};
    CHECKRET(elf->pclntab112.GetFunction(i, f1), "");
    const auto offset = elf->VAToFileOffset(f1.func.entry);

    Golang::Function f2{};
    CHECKRET(elf->pclntab112.GetFunction(i + 1, f2), "");
    const auto size = offset - f2.func.entry;

    win->GetCurrentView()->Select(offset, size);
}

void GoFunctions::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;
    NumericFormatter n2;

    for (auto i = 0ULL; i < elf->pclntab112.GetFunctionsCount(); i++)
    {
        Golang::Function f{};
        CHECKRET(elf->pclntab112.GetFunction(i, f), "");
        auto item = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

        item.SetText(1, tmp.Format("%s", GetValue(n, f.func.entry).data()));

        item.SetText(2, tmp.Format("%s", f.name));

        item.SetText(3, tmp.Format("%s", GetValue(n, f.func.name).data()));
        item.SetText(4, tmp.Format("%s", GetValue(n, f.func.args).data()));
        item.SetText(5, tmp.Format("%s", GetValue(n, f.func.frame).data()));
        item.SetText(6, tmp.Format("%s", GetValue(n, f.func.pcsp).data()));
        item.SetText(7, tmp.Format("%s", GetValue(n, f.func.pcfile).data()));
        item.SetText(8, tmp.Format("%s", GetValue(n, f.func.pcln).data()));
        item.SetText(9, tmp.Format("%s", GetValue(n, f.func.nfuncdata).data()));
        item.SetText(10, tmp.Format("%s", GetValue(n, f.func.npcdata).data()));

        item.SetData(i);
    }
}

bool GoFunctions::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32>(ObjectAction::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32>(ObjectAction::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32>(ObjectAction::ChangeBase));

    return true;
}

bool GoFunctions::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemPressed)
    {
        GoToSelectedSection();
        return true;
    }

    if (evnt == Event::Command)
    {
        switch (static_cast<ObjectAction>(controlID))
        {
        case ObjectAction::GoTo:
            GoToSelectedSection();
            return true;
        case ObjectAction::ChangeBase:
            Base = 26 - Base;
            Update();
            return true;
        case ObjectAction::Select:
            SelectCurrentSection();
            return true;
        }
    }

    return false;
}
} // namespace GView::Type::ELF::Panels
