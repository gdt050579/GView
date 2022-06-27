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

DynamicSymbols::DynamicSymbols(Reference<ELFFile> _elf, Reference<GView::View::WindowInterface> _win) : TabPage("D&ynamicSymbols")
{
    elf  = _elf;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:#,a:r,w:6",
            "n:Name,a:l,w:40",
            "n:Name Index,a:r,w:12",
            "n:Value,a:r,w:10",
            "n:Size,a:r,w:8",
            "n:(b/t/v) Info,a:r,w:40",
            "n:Other,a:r,w:12",
            "n:Section Header Index,a:r,w:24" },
          ListViewFlags::None);

    Update();
}

std::string_view DynamicSymbols::GetValue(NumericFormatter& n, uint64 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void DynamicSymbols::GoToSelectedSection()
{
    /*
       Symbol table entries for different object file types have slightly different interpretations for the st_value member.

       In relocatable files, st_value holds alignment constraints for a symbol whose section index is SHN_COMMON.

       In relocatable files, st_value holds a section offset for a defined symbol. st_value is an offset from the beginning of the section
       that st_shndx identifies.

       In executable and shared object files, st_value holds a virtual address. To make these files' symbols more useful for the runtime
       linker, the section offset (file interpretation) gives way to a virtual address (memory interpretation) for which the section number
       is irrelevant.

       TODO: handle above ^
    */

    auto i = list->GetCurrentItem().GetData(-1);
    CHECKRET(i != -1, "");

    auto offset = 0ULL;
    if (elf->is64)
    {
        const auto& record = elf->dynamicSymbols64.at(i);
        offset             = elf->VAToFileOffset(record.st_value);
    }
    else
    {
        const auto& record = elf->dynamicSymbols32.at(i);
        offset             = elf->VAToFileOffset(record.st_value);
    }

    win->GetCurrentView()->GoTo(offset);
}

void DynamicSymbols::SelectCurrentSection()
{
    auto offset = 0ULL;
    auto size   = 0ULL;

    auto i = list->GetCurrentItem().GetData(-1);
    CHECKRET(i != -1, "");

    if (elf->is64)
    {
        const auto& record = elf->dynamicSymbols64.at(i);
        offset             = elf->VAToFileOffset(record.st_value);
        size               = record.st_size;
    }
    else
    {
        const auto& record = elf->dynamicSymbols32.at(i);
        offset             = elf->VAToFileOffset(record.st_value);
        size               = record.st_size;
    }

    win->GetCurrentView()->Select(offset, size);
}

void DynamicSymbols::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;
    NumericFormatter n2;

    if (elf->is64)
    {
        for (auto i = 0ULL; i < elf->dynamicSymbols64.size(); i++)
        {
            const auto& record = elf->dynamicSymbols64[i];
            auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

            const auto& name = elf->dynamicSymbolsNames.at(i);
            item.SetText(1, tmp.Format("%s", name.c_str()));

            item.SetText(2, tmp.Format("%s", GetValue(n, record.st_name).data()));
            item.SetText(3, tmp.Format("%s", GetValue(n, record.st_value).data()));
            item.SetText(4, tmp.Format("%s", GetValue(n, record.st_size).data()));

            const auto bind           = ELF_ST_BIND(record.st_info);
            const auto bindName       = ELF::GetNameFromSymbolBinding(bind);
            const auto type           = ELF_ST_TYPE(record.st_info);
            const auto typeName       = ELF::GetNameFromSymbolType(type);
            const auto visibility     = ELF_ST_VISIBILITY(record.st_info);
            const auto visibilityName = ELF::GetNameFromSymbolVisibility(visibility);

            item.SetText(
                  5,
                  tmp.Format(
                        "[%s | %s | %s ] %s", bindName.data(), typeName.data(), visibilityName.data(), GetValue(n, record.st_info).data()));

            item.SetText(6, tmp.Format("%s", GetValue(n, record.st_other).data()));

            auto sectionType = ELF::GetSectionSpecialIndexFromSymbolIndex(record.st_shndx);
            if (sectionType == "")
            {
                sectionType = elf->sectionNames.at(record.st_shndx);
            }
            item.SetText(7, tmp.Format("[%s] %s", sectionType.data(), GetValue(n, record.st_shndx).data()));

            item.SetData(i);
        }
    }
    else
    {
        for (auto i = 0ULL; i < elf->dynamicSymbols32.size(); i++)
        {
            const auto& record = elf->dynamicSymbols32[i];
            auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

            const auto& name = elf->dynamicSymbolsNames.at(i);
            item.SetText(1, tmp.Format("%s", name.c_str()));

            item.SetText(2, tmp.Format("%s", GetValue(n, record.st_name).data()));
            item.SetText(3, tmp.Format("%s", GetValue(n, record.st_value).data()));
            item.SetText(4, tmp.Format("%s", GetValue(n, record.st_size).data()));

            const auto bind           = ELF_ST_BIND(record.st_info);
            const auto bindName       = ELF::GetNameFromSymbolBinding(bind);
            const auto type           = ELF_ST_TYPE(record.st_info);
            const auto typeName       = ELF::GetNameFromSymbolType(type);
            const auto visibility     = ELF_ST_VISIBILITY(record.st_info);
            const auto visibilityName = ELF::GetNameFromSymbolVisibility(visibility);

            item.SetText(
                  5,
                  tmp.Format(
                        "[%s | %s | %s ] %s", bindName.data(), typeName.data(), visibilityName.data(), GetValue(n, record.st_info).data()));

            item.SetText(6, tmp.Format("%s", GetValue(n, record.st_other).data()));

            auto sectionType = ELF::GetSectionSpecialIndexFromSymbolIndex(record.st_shndx);
            if (sectionType == "")
            {
                sectionType = elf->sectionNames.at(record.st_shndx);
            }
            item.SetText(7, tmp.Format("[%s] %s", sectionType.data(), GetValue(n, record.st_shndx).data()));

            item.SetData(i);
        }
    }
}

bool DynamicSymbols::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32>(ObjectAction::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32>(ObjectAction::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32>(ObjectAction::ChangeBase));

    return true;
}

bool DynamicSymbols::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
