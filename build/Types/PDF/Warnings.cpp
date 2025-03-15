#include "pdf.hpp"

using namespace GView::Type::PDF;
using namespace AppCUI::Controls;

Panels::Warnings::Warnings(Reference<GView::Type::PDF::PDFFile> _pdf) : TabPage("Wa&rnings")
{
    pdf     = _pdf;
    general = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:10", { "n:Field,w:15", "n:Value,w:100" }, ListViewFlags::None);

    issues = Factory::ListView::Create(this, "x:0,y:21,w:100%,h:10", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    this->Update();
}

void Panels::Warnings::UpdateIssues()
{
}

void Panels::Warnings::UpdateGeneralInformation()
{

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
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
