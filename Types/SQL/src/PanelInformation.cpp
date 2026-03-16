#include "sql.hpp"

using namespace GView::Type::SQL;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<GView::Type::SQL::SQLFile> _sql) : TabPage("&Information")
{
    sql     = _sql;
    general = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:10", { "n:Field,w:12", "n:Value,w:100" }, ListViewFlags::None);

    issues = Factory::ListView::Create(this, "x:0,y:21,w:100%,h:10", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    this->Update();
}
void Panels::Information::UpdateGeneralInformation()
{
    LocalString<256> tempStr;
    NumericFormatter n;

    general->DeleteAllItems();
    general->AddItem("File");
    // general->SetItemText(poz++, 1, (char*) pe->obj->GetData().GetFileName(true));
    // size
    general->AddItem({ "Size", tempStr.Format("%s bytes", n.ToString(sql->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()) });
}

void Panels::Information::UpdateIssues()
{
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
}
void Panels::Information::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
