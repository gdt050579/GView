#include "sqlite.hpp"

using namespace GView::Type::SQLite;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<GView::Type::SQLite::SQLiteFile> _sqlite) : TabPage("&Tables")
{
    sqlite = _sqlite;
    tables = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:10", { "n:Name,w:20", "n:Original SQL,w:100" }, ListViewFlags::None);

    this->Update();
}
void Panels::Information::UpdateTableInformation()
{
    LocalString<256> tempStr;
    NumericFormatter n;

    tables->DeleteAllItems();

    auto data = sqlite->db.GetTableData();

    for (auto table : data)
    {
        tables->AddItem({ table.first, table.second });
    }
}

void Panels::Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();

    if ((!tables.IsValid()))
        return;

    this->tables->Resize(w, h);

    // if (this->version->IsVisible())
    //    last = 1;
    // if (this->issues->IsVisible())
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
    UpdateTableInformation();
    RecomputePanelsPositions();
}
