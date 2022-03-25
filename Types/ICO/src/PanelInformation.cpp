#include "ico.hpp"

using namespace GView::Type::ICO;
using namespace AppCUI::Controls;


Panels::Information::Information(Reference<GView::Type::ICO::ICOFile> _ico) : TabPage("&Information")
{
    ico      = _ico;
    general = this->CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 12);
    general->AddColumn("Value", TextAlignament::Left, 100);

    issues = this->CreateChildControl<ListView>("x:0,y:21,w:100%,h:10", ListViewFlags::HideColumns);
    issues->AddColumn("Info", TextAlignament::Left, 200);

    this->Update();
}
void Panels::Information::UpdateGeneralInformation()
{
    LocalString<256> tempStr;
    NumericFormatter n;

    general->DeleteAllItems();
    general->AddItem("File");
    //general->SetItemText(poz++, 1, (char*) pe->file->GetFileName(true));
    // size
    general->AddItem("Size", tempStr.Format("%s bytes",n.ToString(ico->file->GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()));
    // type
    if (ico->isIcoFormat)
        general->AddItem("Type", "ICON");
    else
        general->AddItem("Type", "CURSOR");
    // dirs
    general->AddItem("Images", n.ToDec(static_cast<uint64>(ico->dirs.size())));



}

void Panels::Information::UpdateIssues()
{
    //AppCUI::Controls::ItemHandle itemHandle;
    //bool hasErrors   = false;
    //bool hasWarnings = false;

    //issues->DeleteAllItems();

    //for (const auto& err : pe->errList)
    //{
    //    if (err.type != PEFile::ErrorType::Error)
    //        continue;

    //    if (!hasErrors)
    //    {
    //        itemHandle = issues->AddItem("Errors");
    //        issues->SetItemType(itemHandle, ListViewItemType::Highlighted);
    //        hasErrors = true;
    //    }
    //    itemHandle = issues->AddItem(err.text);
    //    issues->SetItemType(itemHandle, ListViewItemType::ErrorInformation);
    //    issues->SetItemXOffset(itemHandle, 2);
    //}

    //for (const auto& err : pe->errList)
    //{
    //    if (err.type != PEFile::ErrorType::Warning)
    //        continue;

    //    if (!hasWarnings)
    //    {
    //        itemHandle = issues->AddItem("Warnings");
    //        issues->SetItemType(itemHandle, ListViewItemType::Highlighted);
    //        hasWarnings = true;
    //    }
    //    itemHandle = issues->AddItem(err.text);
    //    issues->SetItemType(itemHandle, ListViewItemType::WarningInformation);
    //    issues->SetItemXOffset(itemHandle, 2);
    //}
    //// hide if no issues
    //issues->SetVisible(pe->errList.size() > 0);
}
void Panels::Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();
    
    if ((!general.IsValid()) || (!issues.IsValid()))
        return;

    issues->SetVisible(false);
    this->general->Resize(w, h);

    //if (this->version->IsVisible())
    //    last = 1;
    //if (this->issues->IsVisible())
    //    last = 2;
    // if (InfoPanelCtx.pnlIcon->IsVisible()) last = 3;
    
    // resize
/*    if (last == 0)
    {
        this->general->Resize(w, h - py);
    }
    else
    {
        if (this->general->GetItemsCount() > 15)
        {
            this->general->Resize(w, 18);
            py += 18;
        }
        else
        {
            this->general->Resize(w, this->general->GetItemsCount() + 3);
            py += (this->general->GetItemsCount() + 3);
        }
    }
    if (this->version->IsVisible())
    {
        this->version->MoveTo(0, py);
        if (last == 1)
        {
            this->version->Resize(w, h - py);
        }
        else
        {
            this->version->Resize(w, this->version->GetItemsCount() + 3);
            py += (this->version->GetItemsCount() + 3);
        }
    }
    if (this->issues->IsVisible())
    {
        this->issues->MoveTo(0, py);
        if (last == 2)
        {
            this->issues->Resize(w, h - py);
        }
        else
        {
            if (this->issues->GetItemsCount() > 6)
            {
                this->issues->Resize(w, 8);
                py += 8;
            }
            else
            {
                this->issues->Resize(w, this->issues->GetItemsCount() + 2);
                py += (this->issues->GetItemsCount() + 2);
            }
        }
    }*/
}
void Panels::Information::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

