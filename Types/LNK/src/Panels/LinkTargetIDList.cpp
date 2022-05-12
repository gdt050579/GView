#include "LNK.hpp"

using namespace GView::Type::LNK;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

Panels::LinkTargetIDList::LinkTargetIDList(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk)
    : ShellItems("&LinkTargetIDList")
{
    lnk     = _lnk;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void Panels::LinkTargetIDList::UpdateGeneralInformation()
{
    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("ID List Size", "%-20s (%s)", lnk->linkTargetIDList.IDListSize);
    AddDecAndHexElement("ItemIDs #", "%-20s (%s)", lnk->itemIDS.size());
    UpdateLinkTargetIDList(lnk->itemIDS);
}

void Panels::LinkTargetIDList::UpdateIssues()
{
}

void Panels::LinkTargetIDList::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), std::min<>(this->GetHeight(), (int) general->GetItemsCount() + 3));

    // CHECKRET(general.IsValid() & issues.IsValid(), "");
    // issues->SetVisible(issues->GetItemsCount() > 0);
    // if (issues->IsVisible())
    //{
    //    general->Resize(GetWidth(), general->GetItemsCount() + issues->GetItemsCount() + 3);
    //}
}

bool Panels::LinkTargetIDList::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    // commandBar.SetCommand(AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10, "placeholder_name", CMD_ID);
    return true;
}

bool Panels::LinkTargetIDList::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        default:
            break;
        }
    }

    return false;
}

void Panels::LinkTargetIDList::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
