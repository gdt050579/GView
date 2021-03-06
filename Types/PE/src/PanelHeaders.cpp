#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr uint32 PE_EXP_GOTO = 1;

Panels::Headers::Headers(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("&Headers")
{
    pe  = _pe;
    win = _win;

    list = Factory::ListView::Create(this, "d:c", { "n:Field,w:16", "n:Value,w:60" }, ListViewFlags::None);

    Update();
}
void Panels::Headers::AddHeader(std::string_view name)
{
    list->AddItem(name).SetType(ListViewItem::Type::Category);
}
void Panels::Headers::AddNumber(std::string_view name, uint32_t value)
{
    LocalString<128> temp;
    list->AddItem({ name, temp.Format("0x%X (Dec:%u)", value, value) });
}
void Panels::Headers::AddItem(std::string_view name, std::string_view value)
{
    list->AddItem({ name, value });
}
void Panels::Headers::AddMagic(uint8* offset, uint32 size)
{
    LocalString<128> temp;
    temp.Set("\"");
    for (uint32 tr = 0; tr < size; tr++)
    {
        if (offset[tr] > 32)
            temp.AddChar(offset[tr]);
        else
            temp.AddChar('.');
    }
    temp.Add("\"  ");
    for (uint32 tr = 0; tr < size; tr++)
        temp.AddFormat("%02X ", offset[tr]);
    list->AddItem({ "Magic", temp });
}
void Panels::Headers::Update()
{
    LocalString<128> temp;
    NumericFormatter n;

    list->DeleteAllItems();
    AddHeader("PE Header");
    AddMagic((uint8*) &pe->nth32.Signature, 4);

    AddHeader("File Header");
    AddNumber("Sections", pe->nth32.FileHeader.NumberOfSections);
    AddNumber("Symbols", pe->nth32.FileHeader.NumberOfSymbols);
    AddNumber("PointerToSymbolTable", pe->nth32.FileHeader.PointerToSymbolTable);
    AddNumber("SizeOfOptionalHeader", pe->nth32.FileHeader.SizeOfOptionalHeader);
    AddItem("Machine", pe->GetMachine());
    AddNumber("Characteristics", pe->nth32.FileHeader.Characteristics);

    AddHeader("DOS Header");
    AddMagic((uint8*) &pe->dos.e_magic, 2);
    AddNumber("Bytes on last page of file", pe->dos.e_cblp);
    AddNumber("Pages in file", pe->dos.e_cp);
    AddNumber("Relocations", pe->dos.e_crlc);
    AddNumber("Size of header in paragraphs", pe->dos.e_cparhdr);
    AddNumber("Minimum extra paragraphs needed", pe->dos.e_minalloc);
    AddNumber("Maximum extra paragraphs needed", pe->dos.e_maxalloc);
    AddNumber("Initial (relative) SS value", pe->dos.e_ss);
    AddNumber("Initial SP value", pe->dos.e_sp);
    AddNumber("Checksum", pe->dos.e_csum);
    AddNumber("Initial IP value", pe->dos.e_ip);
    AddNumber("Initial (relative) CS value", pe->dos.e_cs);
    AddNumber("File address of relocation table", pe->dos.e_lfarlc);
    AddNumber("Overlay number", pe->dos.e_ovno);
    AddNumber("OEM identifier", pe->dos.e_oemid);
    AddNumber("OEM information;", pe->dos.e_oeminfo);
    AddNumber("PE Header offset", pe->dos.e_lfanew);
}
// bool Panels::Exports::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
//{
//    commandBar.SetCommand(Key::Enter, "GoTo", PE_EXP_GOTO);
//    return true;
//}
// bool Panels::Exports::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
//{
//    if (TabPage::OnEvent(ctrl, evnt, controlID))
//        return true;
//    if ((evnt == Event::ListViewItemClicked) || ((evnt == Event::Command) && (controlID == PE_EXP_GOTO)))
//    {
//        auto addr = list->GetItemData(list->GetCurrentItem(), GView::Utils::INVALID_OFFSET);
//        if (addr != GView::Utils::INVALID_OFFSET)
//            win->GetCurrentView()->GoTo(addr);
//        return true;
//    }
//    return false;
//}