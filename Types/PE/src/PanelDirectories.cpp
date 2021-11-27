#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr unsigned int PE_DIRS_GOTO            = 1;
constexpr unsigned int PE_DIRS_EDIT            = 2;
constexpr unsigned int PE_DIRS_SELECT          = 3;
constexpr unsigned long long INVALID_DIRECTORY = 0xFFFFFFFF;

Panels::Directories::Directories(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win)
    : TabPage("&Directories")
{
    pe  = _pe;
    win = _win;

    list = this->CreateChildControl<ListView>("d:c", ListViewFlags::None);
    // columns
    list->AddColumn("Name", TextAlignament::Left);
    list->AddColumn("Sect", TextAlignament::Left, 12);
    list->AddColumn("Address", TextAlignament::Left, 20);
    list->AddColumn("Size", TextAlignament::Left, 20);
    // directories
    for (auto dirID = 0U; dirID < 15; dirID++)
    {
        list->AddItem(PEFile::DirectoryIDToName(dirID));
    }
    Update();
}
void Panels::Directories::GoToSelectedDirectory()
{
    auto idx = list->GetItemData(list->GetCurrentItem(), INVALID_DIRECTORY);
    if (idx == INVALID_DIRECTORY)
        return;
    auto* dir = &pe->dirs[idx];
    uint64_t result;
    if (idx == (uint8_t) DirectoryType::Security)
        result = dir->VirtualAddress > 0 ? dir->VirtualAddress : PE_INVALID_ADDRESS;
    else
        result = pe->ConvertAddress(dir->VirtualAddress, ADDR_RVA, ADDR_FA);
    if (result != PE_INVALID_ADDRESS)
        win->GetCurrentView()->GoTo(result);
}
void Panels::Directories::SelectCurrentDirectory()
{
    auto idx = list->GetItemData(list->GetCurrentItem(), INVALID_DIRECTORY);
    if (idx == INVALID_DIRECTORY)
        return;
    auto* dir = &pe->dirs[idx];
    auto sect = list->GetItemData<PE::ImageSectionHeader>(list->GetCurrentItem());
    uint64_t result;
    if (idx == (uint8_t) DirectoryType::Security)
        result = dir->VirtualAddress > 0 ? dir->VirtualAddress: PE_INVALID_ADDRESS;
    else
        result = pe->ConvertAddress(dir->VirtualAddress, ADDR_RVA, ADDR_FA);
    if (result != PE_INVALID_ADDRESS)
        win->GetCurrentView()->Select(result, dir->Size);
}
void Panels::Directories::Update()
{
    LocalString<128> temp;
    LocalString<16> sectName;
    unsigned int RVA, sz;


    for (auto tr = 0U; tr < 15U; tr++)
    {
        ItemHandle item = { tr };
        RVA             = pe->dirs[tr].VirtualAddress;
        sz              = pe->dirs[tr].Size;
        if ((RVA == 0) && (sz == 0))
        {
            list->SetItemText(item, 1, "");
            list->SetItemText(item, 2, "");
            list->SetItemText(item, 3, "");
            list->SetItemType(item, ListViewItemType::GrayedOut);
            list->SetItemData(item, INVALID_DIRECTORY);
        }
        else
        {
            auto sectID = 0xFFFFFFFF;
            list->SetItemType(item, ListViewItemType::Normal);
            list->SetItemData(item, (unsigned long long)tr);
            // search for a section that contains the directory
            for (auto gr = 0U; (gr < pe->nrSections) && (sectID == 0xFFFFFFFF); gr++)
            {
                if ((RVA >= pe->sect[gr].VirtualAddress) && (RVA < pe->sect[gr].VirtualAddress + pe->sect[gr].Misc.VirtualSize))
                    sectID = gr;
            }
            // if no section was found
            if (sectID == 0xFFFFFFFF)
            {
                list->SetItemText(item, 1, "<outside>");
            }
            else
            {
                temp.SetFormat("S%d:[", (sectID + 1));
                pe->CopySectionName(sectID, sectName);
                temp.Add(sectName);
                temp.Add("]");
                list->SetItemText(item, 1, temp);
            }
            list->SetItemText(item, 2, temp.Format("0x%X (%d)", RVA, RVA));
            list->SetItemText(item, 3, temp.Format("0x%X (%d)", sz, sz));
        }
    }
}

bool Panels::Directories::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PE_DIRS_GOTO);
    commandBar.SetCommand(Key::F3, "Edit", PE_DIRS_EDIT);
    commandBar.SetCommand(Key::F9, "Select", PE_DIRS_SELECT);
    return true;
}

bool Panels::Directories::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::ListViewItemClicked)
    {
        GoToSelectedDirectory();
        return true;
    }
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        case PE_DIRS_GOTO:
            GoToSelectedDirectory();
            return true;
        case PE_DIRS_EDIT:
            AppCUI::Dialogs::MessageBox::ShowError("Error", "(Edit) Not implemented yet !");
            return true;
        case PE_DIRS_SELECT:
            SelectCurrentDirectory();
            return true;
        }
    }
    return false;
}