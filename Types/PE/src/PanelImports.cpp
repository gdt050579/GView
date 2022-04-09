#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

Panels::Imports::Imports(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("&Imports")
{
    pe  = _pe;
    win = _win;

    list = this->CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", { { "Name", TextAlignament::Left, 25 }, { "RVA", TextAlignament::Left, 12 } }, ListViewFlags::None);

    dlls = this->CreateChildControl<ListView>("x:0,y:10,w:100%,h:10", { { "", TextAlignament::Left, 50 } }, ListViewFlags::HideColumns);

    info = this->CreateChildControl<ListView>(
          "x:0,y:20,w:100%,h:4", { { "", TextAlignament::Left, 12 }, { "", TextAlignament::Left, 25 } }, ListViewFlags::HideColumns);


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
            list->AddItem(pe->impDLL[ifnc.dllIndex].Name).SetType(ListViewItem::Type::Highlighted);
            lastDLLIndex = ifnc.dllIndex;
        }
        list->AddItem({ ifnc.Name, temp.Format("%u (0x%08X)", ifnc.RVA, ifnc.RVA) }).SetXOffset(2);
    }

    // dlls
    dlls->DeleteAllItems();
    for (auto& dll : pe->impDLL)
    {
        dlls->AddItem(dll.Name);
    }

    // general infor
    info->DeleteAllItems();
    info->AddItem({ "Nr of DLLs", temp.Format("%u", (uint32) pe->impDLL.size()) });
    info->AddItem({ "Nr of Functions", temp.Format("%u", (uint32) pe->impFunc.size()) });
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