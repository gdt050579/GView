#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr int PE_SECTIONS_GOTO       = 1;
constexpr int PE_SECTIONS_SELECT     = 2;
constexpr int PE_SECTIONS_EDIT       = 3;
constexpr int PE_SECTIONS_CHANGEBASE = 4;

Panels::Sections::Sections(Reference<GView::Type::PE::PEFile> _pe) : TabPage("&Sections")
{
    pe   = _pe;
    Base = 16;

    list = this->CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("Name", TextAlignament::Left, 8);
    list->AddColumn("FilePoz", TextAlignament::Right, 12);
    list->AddColumn("FileSize", TextAlignament::Right, 12);
    list->AddColumn("RVA", TextAlignament::Right, 12);
    list->AddColumn("MemSize", TextAlignament::Right, 12);
    list->AddColumn("PtrReloc", TextAlignament::Left, 10);
    list->AddColumn("NrReloc", TextAlignament::Right, 10);
    list->AddColumn("PtrLnNum", TextAlignament::Left, 10);
    list->AddColumn("NrLnNum", TextAlignament::Right, 10);
    list->AddColumn("Characteristics", TextAlignament::Left, 32);

    Update();
}
std::string_view Panels::Sections::GetValue(NumericFormatter& n, unsigned int value)
{
    if (Base == 10)
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    else
        return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}
void Panels::Sections::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    for (auto tr = 0U; tr < pe->nrSections; tr++)
    {
        pe->CopySectionName(tr, temp);
        auto item = list->AddItem(temp);
        list->SetItemText(item, 1, GetValue(n, pe->sect[tr].PointerToRawData));
        list->SetItemText(item, 2, GetValue(n, pe->sect[tr].SizeOfRawData));
        list->SetItemText(item, 3, GetValue(n, pe->sect[tr].VirtualAddress));
        list->SetItemText(item, 4, GetValue(n, pe->sect[tr].Misc.VirtualSize));
        list->SetItemText(item, 5, GetValue(n, pe->sect[tr].PointerToRelocations));
        list->SetItemText(item, 6, GetValue(n, pe->sect[tr].NumberOfRelocations));
        list->SetItemText(item, 7, GetValue(n, pe->sect[tr].PointerToLinenumbers));
        list->SetItemText(item, 8, GetValue(n, pe->sect[tr].NumberOfLinenumbers));

        // caracteristics
        const auto tmp = pe->sect[tr].Characteristics;
        temp.SetFormat("0x%08X  [", tmp);
        if ((tmp & __IMAGE_SCN_MEM_READ) != 0)
            temp.AddChar('R');
        else
            temp.AddChar('-');
        if ((tmp & __IMAGE_SCN_MEM_WRITE) != 0)
            temp.AddChar('W');
        else
            temp.AddChar('-');
        if ((tmp & __IMAGE_SCN_MEM_SHARED) != 0)
            temp.AddChar('S');
        else
            temp.AddChar('-');
        if ((tmp & __IMAGE_SCN_MEM_EXECUTE) != 0)
            temp.AddChar('X');
        else
            temp.AddChar('-');
        temp.Add("  ");
        if ((tmp & __IMAGE_SCN_CNT_CODE) != 0)
            temp.AddChar('C');
        else
            temp.AddChar('-');
        if ((tmp & __IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)
            temp.AddChar('I');
        else
            temp.AddChar('-');
        if ((tmp & __IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
            temp.AddChar('U');
        else
            temp.AddChar('-');
        temp.AddChar(']');
        if (tmp - (tmp & (__IMAGE_SCN_MEM_READ | __IMAGE_SCN_MEM_WRITE | __IMAGE_SCN_MEM_SHARED | __IMAGE_SCN_MEM_EXECUTE |
                          __IMAGE_SCN_CNT_CODE | __IMAGE_SCN_CNT_INITIALIZED_DATA | __IMAGE_SCN_CNT_UNINITIALIZED_DATA)) !=
            0)
        {
            temp.Add(" [+]");
        }
        list->SetItemText(item, 9, temp);
    }
}

bool Panels::Sections::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PE_SECTIONS_GOTO);
    commandBar.SetCommand(Key::F3, "Edit", PE_SECTIONS_EDIT);
    commandBar.SetCommand(Key::F9, "Select", PE_SECTIONS_SELECT);
    if (this->Base==10)
        commandBar.SetCommand(Key::F2, "Dec", PE_SECTIONS_CHANGEBASE);
    else
        commandBar.SetCommand(Key::F2, "Hex", PE_SECTIONS_CHANGEBASE);
    return true;
}

bool Panels::Sections::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::ListViewItemClicked)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "(Goto) Not implemented yet !");
        return true;
    }
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        case PE_SECTIONS_GOTO:
            AppCUI::Dialogs::MessageBox::ShowError("Error", "(Goto) Not implemented yet !");
            return true;
        case PE_SECTIONS_CHANGEBASE:
            this->Base = 26 - this->Base;
            Update();
            return true;
        case PE_SECTIONS_EDIT:
            AppCUI::Dialogs::MessageBox::ShowError("Error", "(Edit) Not implemented yet !");
            return true;
        case PE_SECTIONS_SELECT:
            AppCUI::Dialogs::MessageBox::ShowError("Error", "(Select) Not implemented yet !");
            return true;
        }
    }
    return false;
}