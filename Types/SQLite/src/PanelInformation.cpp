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
    {
        return;
    }

    this->tables->Resize(w, h);
}
void Panels::Information::Update()
{
    UpdateTableInformation();
    RecomputePanelsPositions();
}
