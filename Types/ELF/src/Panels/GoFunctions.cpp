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
            "n:Name,a:l,w:40",
            "n:Name Offset,a:r,w:14",
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

    auto offset = 0ULL;
    if (elf->is64)
    {
        const auto& record = elf->functions64.at(i);
        offset             = elf->VAToFileOffset(record.entry);
    }
    else
    {
        const auto& record = elf->functions32.at(i);
        offset             = elf->VAToFileOffset(record.entry);
    }

    win->GetCurrentView()->GoTo(offset);
}

void GoFunctions::SelectCurrentSection()
{
    auto offset = 0ULL;
    auto size   = 0ULL;

    auto i = list->GetCurrentItem().GetData(-1);
    CHECKRET(i != -1, "");

    if (elf->is64)
    {
        const auto& record = elf->functions64.at(i);
        offset             = elf->VAToFileOffset(record.entry);
        size               = elf->functions64.at(i + 1).entry - record.entry;
    }
    else
    {
        const auto& record = elf->functions32.at(i);
        offset             = elf->VAToFileOffset(record.entry);
        size               = (uint64) elf->functions32.at(i + 1).entry - record.entry;
    }

    win->GetCurrentView()->Select(offset, size);
}

void GoFunctions::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;
    NumericFormatter n2;

    if (elf->is64)
    {
        for (auto i = 0ULL; i < elf->functions64.size(); i++)
        {
            const auto& record = elf->functions64[i];
            auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

            item.SetText(1, tmp.Format("%s", GetValue(n, record.entry).data()));

            const auto& name = elf->functionsNames.at(i);
            item.SetText(2, tmp.Format("%s", name.c_str()));

            item.SetText(3, tmp.Format("%s", GetValue(n, record.name).data()));
            item.SetText(4, tmp.Format("%s", GetValue(n, record.args).data()));
            item.SetText(5, tmp.Format("%s", GetValue(n, record.frame).data()));
            item.SetText(6, tmp.Format("%s", GetValue(n, record.pcsp).data()));
            item.SetText(7, tmp.Format("%s", GetValue(n, record.pcfile).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.pcln).data()));
            item.SetText(9, tmp.Format("%s", GetValue(n, record.nfuncdata).data()));
            item.SetText(10, tmp.Format("%s", GetValue(n, record.npcdata).data()));

            item.SetData(i);
        }
    }
    else
    {
        for (auto i = 0ULL; i < elf->functions32.size(); i++)
        {
            const auto& record = elf->functions32[i];
            auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

            item.SetText(1, tmp.Format("%s", GetValue(n, record.entry).data()));

            const auto& name = elf->functionsNames.at(i);
            item.SetText(2, tmp.Format("%s", name.c_str()));

            item.SetText(3, tmp.Format("%s", GetValue(n, record.name).data()));
            item.SetText(4, tmp.Format("%s", GetValue(n, record.args).data()));
            item.SetText(5, tmp.Format("%s", GetValue(n, record.frame).data()));
            item.SetText(6, tmp.Format("%s", GetValue(n, record.pcsp).data()));
            item.SetText(7, tmp.Format("%s", GetValue(n, record.pcfile).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.pcln).data()));
            item.SetText(9, tmp.Format("%s", GetValue(n, record.nfuncdata).data()));
            item.SetText(10, tmp.Format("%s", GetValue(n, record.npcdata).data()));

            item.SetData(i);
        }
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
