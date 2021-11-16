#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr unsigned int PE_DIRS_GOTO            = 1;
constexpr unsigned int PE_DIRS_EDIT            = 2;
constexpr unsigned int PE_DIRS_SELECT          = 3;
constexpr unsigned long long INVALID_DIRECTORY = 0xFFFFFFFF;

Panels::Imports::Imports(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("&Imports")
{
    pe  = _pe;
    win = _win;

    list = this->CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    list->AddColumn("Name", TextAlignament::Left, 25);
    list->AddColumn("RVA", TextAlignament::Left, 12);

    dlls = this->CreateChildControl<ListView>("x:0,y:10,w:100%,h:10", ListViewFlags::HideColumns);
    dlls->AddColumn("", TextAlignament::Left, 50);

    info = this->CreateChildControl<ListView>("x:0,y:20,w:100%,h:4", ListViewFlags::HideColumns);
    info->AddColumn("", TextAlignament::Left, 12);
    info->AddColumn("", TextAlignament::Left, 25);

    Update();
}
void Panels::Imports::Update()
{
    uint32_t lastDLLIndex = 0xFFFFFFFF;
    LocalString<128> temp;

    // imports
    list->DeleteAllItems();
    for (auto& ifnc : pe->impFunc)
    {
        if (ifnc.dllIndex != lastDLLIndex)
        {
            list->SetItemType(list->AddItem(pe->impDLL[ifnc.dllIndex].Name), ListViewItemType::Highlighted);
            lastDLLIndex = ifnc.dllIndex;
        }
        auto item = list->AddItem(ifnc.Name, temp.Format("%u (0x%08X)", ifnc.RVA, ifnc.RVA));
        list->SetItemXOffset(item, 2);
    }

    // dlls
    dlls->DeleteAllItems();
    for (auto& dll : pe->impDLL)
    {
        dlls->AddItem(dll.Name);
    }

    // general infor
    info->DeleteAllItems();
    info->AddItem("Nr of DLLs", temp.Format("%u", (unsigned int) pe->impDLL.size()));
    info->AddItem("Nr of Functions", temp.Format("%u", (unsigned int) pe->impFunc.size()));
}
void Panels::Imports::OnAfterResize(int newWidth, int newHeight)
{
    auto h1 = std::max(8, ((newHeight - 4) * 6) / 10);
    auto h2 = std::max(6, ((newHeight - 4) * 4) / 10);
    auto h3 = std::max(4, newHeight - (h1 + h2));
    if (list.IsValid() && dlls.IsValid() && info.IsValid())
    {
        list->Resize(newWidth, h1);
        dlls->MoveTo(0, h1);
        dlls->Resize(newWidth, h2);
        info->MoveTo(0, h1 + h2);
        info->Resize(newWidth, h3);
    };
}