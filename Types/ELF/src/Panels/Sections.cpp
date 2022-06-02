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

Sections::Sections(Reference<ELFFile> _elf, Reference<GView::View::WindowInterface> _win) : TabPage("&Sections")
{
    elf  = _elf;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:#,a:r,w:10",
            "n:Name Index,a:r,w:24",
            "n:Type,a:r,w:24",
            "n:Flags,a:r,w:50",
            "n:VA,a:r,w:14",
            "n:FA,a:r,w:14",
            "n:Size in File,a:r,w:14",
            "n:SHT Index,a:r,w:14",
            "n:Info,a:r,w:16",
            "n:Table Entry Size,a:r,w:14" },
          ListViewFlags::None);

    Update();
}

std::string_view Sections::GetValue(NumericFormatter& n, uint64 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Sections::GoToSelectedSection()
{
    auto offset = 0ULL;
    if (elf->is64)
    {
        auto record = list->GetCurrentItem().GetData<Elf64_Shdr>();
        offset      = record->sh_offset;
    }
    else
    {
        auto record = list->GetCurrentItem().GetData<Elf32_Shdr>();
        offset      = record->sh_offset;
    }

    win->GetCurrentView()->GoTo(offset);
}

void Sections::SelectCurrentSection()
{
    auto offset = 0ULL;
    auto size   = 0ULL;
    if (elf->is64)
    {
        auto record = list->GetCurrentItem().GetData<Elf64_Shdr>();
        offset      = record->sh_offset;
        size        = record->sh_size;
    }
    else
    {
        auto record = list->GetCurrentItem().GetData<Elf32_Shdr>();
        offset      = record->sh_offset;
        size        = record->sh_size;
    }

    win->GetCurrentView()->Select(offset, size);
}

void Sections::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;

    if (elf->is64)
    {
        for (auto i = 0ULL; i < elf->sections64.size(); i++)
        {
            const auto& record = elf->sections64[i];
            auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

            item.SetText(1, tmp.Format("%s", GetValue(n, record.sh_name).data()));
            item.SetText(2, tmp.Format("%s", GetValue(n, record.sh_type).data()));
            item.SetText(3, tmp.Format("%s", GetValue(n, record.sh_flags).data()));
            item.SetText(4, tmp.Format("%s", GetValue(n, record.sh_addr).data()));
            item.SetText(5, tmp.Format("%s", GetValue(n, record.sh_offset).data()));
            item.SetText(6, tmp.Format("%s", GetValue(n, record.sh_size).data()));
            item.SetText(7, tmp.Format("%s", GetValue(n, record.sh_link).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.sh_info).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.sh_addralign).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.sh_entsize).data()));

            item.SetData<Elf64_Shdr>(&elf->sections64[i]);
        }
    }
    else
    {
        for (auto i = 0ULL; i < elf->sections32.size(); i++)
        {
            const auto& record = elf->sections32[i];
            auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

            item.SetText(1, tmp.Format("%s", GetValue(n, record.sh_name).data()));
            item.SetText(2, tmp.Format("%s", GetValue(n, record.sh_type).data()));
            item.SetText(3, tmp.Format("%s", GetValue(n, record.sh_flags).data()));
            item.SetText(4, tmp.Format("%s", GetValue(n, record.sh_addr).data()));
            item.SetText(5, tmp.Format("%s", GetValue(n, record.sh_offset).data()));
            item.SetText(6, tmp.Format("%s", GetValue(n, record.sh_size).data()));
            item.SetText(7, tmp.Format("%s", GetValue(n, record.sh_link).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.sh_info).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.sh_addralign).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.sh_entsize).data()));

            item.SetData<Elf32_Shdr>(&elf->sections32[i]);
        }
    }
}

bool Sections::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(ObjectAction::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(ObjectAction::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(ObjectAction::ChangeBase));

    return true;
}

bool Sections::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
