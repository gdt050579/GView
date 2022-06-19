#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr int PE_SECTIONS_GOTO       = 1;
constexpr int PE_SECTIONS_SELECT     = 2;
constexpr int PE_SECTIONS_EDIT       = 3;
constexpr int PE_SECTIONS_CHANGEBASE = 4;

Panels::Sections::Sections(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("&Sections")
{
    pe   = _pe;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:Name,w:8",
            "n:FilePoz,a:r,w:12",
            "n:FileSize,a:r,w:12",
            "n:RVA,a:r,w:12",
            "n:MemSize,a:r,w:12",
            "n:PtrReloc,w:10",
            "n:NrReloc,a:r,w:10",
            "n:PtrLnNum,w:10",
            "n:NrLnNum,a:r,w:10",
            "n:Characteristics,w:32" },
          ListViewFlags::None);

    Update();
}

std::string_view Panels::Sections::GetValue(NumericFormatter& n, uint32 value)
{
    if (Base == 10)
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    else
        return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Sections::GoToSelectedSection()
{
    auto sect = list->GetCurrentItem().GetData<PE::ImageSectionHeader>();
    if (sect.IsValid())
        win->GetCurrentView()->GoTo(sect->PointerToRawData);
}

void Panels::Sections::SelectCurrentSection()
{
    auto sect = list->GetCurrentItem().GetData<PE::ImageSectionHeader>();
    if (sect.IsValid())
        win->GetCurrentView()->Select(sect->PointerToRawData, sect->SizeOfRawData);
}

void Panels::Sections::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    for (auto tr = 0U; tr < pe->nrSections; tr++)
    {
        auto& sect = pe->sect[tr];
        pe->CopySectionName(tr, temp);
        auto item = list->AddItem(temp);

        item.SetData<PE::ImageSectionHeader>(pe->sect + tr);

        item.SetText(1, GetValue(n, sect.PointerToRawData));
        item.SetText(2, GetValue(n, sect.SizeOfRawData));
        item.SetText(3, GetValue(n, sect.VirtualAddress));
        item.SetText(4, GetValue(n, sect.Misc.VirtualSize));
        item.SetText(5, GetValue(n, sect.PointerToRelocations));
        item.SetText(6, GetValue(n, sect.NumberOfRelocations));
        item.SetText(7, GetValue(n, sect.PointerToLinenumbers));
        item.SetText(8, GetValue(n, sect.NumberOfLinenumbers));

        // caracteristics
        const auto tmp = sect.Characteristics;
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
        item.SetText(9, temp);
    }
}

bool Panels::Sections::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PE_SECTIONS_GOTO);
    commandBar.SetCommand(Key::F3, "Edit", PE_SECTIONS_EDIT);
    commandBar.SetCommand(Key::F9, "Select", PE_SECTIONS_SELECT);
    if (this->Base == 10)
        commandBar.SetCommand(Key::F2, "Dec", PE_SECTIONS_CHANGEBASE);
    else
        commandBar.SetCommand(Key::F2, "Hex", PE_SECTIONS_CHANGEBASE);
    return true;
}

bool Panels::Sections::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::ListViewItemPressed)
    {
        GoToSelectedSection();
        return true;
    }
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        case PE_SECTIONS_GOTO:
            GoToSelectedSection();
            return true;
        case PE_SECTIONS_CHANGEBASE:
            this->Base = 26 - this->Base;
            Update();
            return true;
        case PE_SECTIONS_EDIT:
            AppCUI::Dialogs::MessageBox::ShowError("Error", "(Edit) Not implemented yet !");
            return true;
        case PE_SECTIONS_SELECT:
            SelectCurrentSection();
            return true;
        }
    }
    return false;
}