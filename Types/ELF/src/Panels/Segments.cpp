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

Segments::Segments(Reference<ELFFile> _elf, Reference<GView::View::WindowInterface> _win) : TabPage("Se&gments")
{
    elf  = _elf;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:#,a:r,w:10",
            "n:Type,a:r,w:24",
            "n:Flags,a:r,w:50",
            "n:FA,a:r,w:14",
            "n:VA,a:r,w:14",
            "n:PA,a:r,w:14",
            "n:Size in File,a:r,w:14",
            "n:Size in Memory,a:r,w:16",
            "n:Alignment,a:r,w:14" },
          ListViewFlags::None);

    Update();
}

std::string_view Segments::GetValue(NumericFormatter& n, uint64 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Segments::GoToSelectedSection()
{
    auto offset = 0ULL;
    if (elf->is64)
    {
        auto record = list->GetCurrentItem().GetData<Elf64_Phdr>();
        offset      = record->p_offset;
    }
    else
    {
        auto record = list->GetCurrentItem().GetData<Elf32_Phdr>();
        offset      = record->p_offset;
    }

    win->GetCurrentView()->GoTo(offset);
}

void Panels::Segments::SelectCurrentSection()
{
    auto offset = 0ULL;
    auto size   = 0ULL;
    if (elf->is64)
    {
        auto record = list->GetCurrentItem().GetData<Elf64_Phdr>();
        offset      = record->p_offset;
        size        = record->p_filesz;
    }
    else
    {
        auto record = list->GetCurrentItem().GetData<Elf32_Phdr>();
        offset      = record->p_offset;
        size        = record->p_filesz;
    }

    win->GetCurrentView()->Select(offset, size);
}

void Panels::Segments::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;

    if (elf->is64)
    {
        for (auto i = 0ULL; i < elf->segments64.size(); i++)
        {
            const auto& record = elf->segments64[i];
            auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

            item.SetText(
                  1, tmp.Format("%s (%s)", ELF::GetNameFromElfProgramHeaderType(record.p_type).data(), GetValue(n, record.p_type).data()));
            if (record.p_type == PT_PAX_FLAGS)
            {
                item.SetText(
                      2,
                      tmp.Format(
                            "%s (%s)", ELF::GetPermissionsFromSegmentPaxFlags(record.p_flags).data(), GetValue(n, record.p_flags).data()));
            }
            else
            {
                item.SetText(
                      2,
                      tmp.Format(
                            "%s (%s)", ELF::GetPermissionsFromSegmentFlags(record.p_flags).data(), GetValue(n, record.p_flags).data()));
            }
            item.SetText(3, tmp.Format("%s", GetValue(n, record.p_offset).data()));
            item.SetText(4, tmp.Format("%s", GetValue(n, record.p_vaddr).data()));
            item.SetText(5, tmp.Format("%s", GetValue(n, record.p_paddr).data()));
            item.SetText(6, tmp.Format("%s", GetValue(n, record.p_filesz).data()));
            item.SetText(7, tmp.Format("%s", GetValue(n, record.p_memsz).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.p_align).data()));

            item.SetData<Elf64_Phdr>(&elf->segments64[i]);
        }
    }
    else
    {
        for (auto i = 0ULL; i < elf->segments32.size(); i++)
        {
            const auto& record = elf->segments32[i];
            auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

            item.SetText(
                  1, tmp.Format("%s (%s)", ELF::GetNameFromElfProgramHeaderType(record.p_type).data(), GetValue(n, record.p_type).data()));
            if (record.p_type == PT_PAX_FLAGS)
            {
                item.SetText(
                      2,
                      tmp.Format(
                            "%s (%s)", ELF::GetPermissionsFromSegmentPaxFlags(record.p_flags).data(), GetValue(n, record.p_flags).data()));
            }
            else
            {
                item.SetText(
                      2,
                      tmp.Format(
                            "%s (%s)", ELF::GetPermissionsFromSegmentFlags(record.p_flags).data(), GetValue(n, record.p_flags).data()));
            }
            item.SetText(3, tmp.Format("%s", GetValue(n, record.p_offset).data()));
            item.SetText(4, tmp.Format("%s", GetValue(n, record.p_vaddr).data()));
            item.SetText(5, tmp.Format("%s", GetValue(n, record.p_paddr).data()));
            item.SetText(6, tmp.Format("%s", GetValue(n, record.p_filesz).data()));
            item.SetText(7, tmp.Format("%s", GetValue(n, record.p_memsz).data()));
            item.SetText(8, tmp.Format("%s", GetValue(n, record.p_align).data()));

            item.SetData<Elf32_Phdr>(&elf->segments32[i]);
        }
    }
}

bool Panels::Segments::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(ObjectAction::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(ObjectAction::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(ObjectAction::ChangeBase));

    return true;
}

bool Panels::Segments::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
