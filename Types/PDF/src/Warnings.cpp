#include "pdf.hpp"

using namespace GView::Type::PDF;
using namespace AppCUI::Controls;

Panels::Warnings::Warnings(Reference<GView::Type::PDF::PDFFile> _pdf) : TabPage("Wa&rnings")
{
    pdf     = _pdf;
    issues = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:20", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    this->Update();
}

void Panels::Warnings::UpdateIssues()
{
    pdf->errList.PopulateListView(this->issues);
    for (uint32 i = 0; i < issues->GetItemsCount(); i++) {
        auto item = issues->GetItem(i);
        auto text = item.GetText(0);

        if ((std::string) text == "Warnings") {
            item.SetText(0, "IOC");
        }
    }

    issues->SetVisible(!pdf->errList.Empty());
}

void Panels::Warnings::RecomputePanelsPositions()
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

void Panels::Warnings::Update()
{
    UpdateIssues();
    RecomputePanelsPositions();
}
