#include "doc.hpp"

using namespace GView::Type::DOC;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<GView::Type::DOC::DOCFile> _doc) : TabPage("&Information")
{
    doc     = _doc;
    general = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:10", { "n:Field,w:12", "n:Value,w:100" }, ListViewFlags::None);
    headers = Factory::ListView::Create(this, "x:0,y:10,w:100%,h:20", { "n:Field,w:12", "n:Value,w:10000" }, ListViewFlags::None);

    this->Update();
}
void Panels::Information::UpdateGeneralInformation()
{
    general->DeleteAllItems();

    general->AddItem("File");
    // size
    {
        LocalString<256> tempStr;
        auto sizeString = NumericFormatter().ToString(doc->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data();
        auto value      = tempStr.Format("%s bytes", sizeString);
        general->AddItem({ "Size", value });
    }
}

void Panels::Information::UpdateIssues()
{
}
void Panels::Information::RecomputePanelsPositions()
{
    int w = this->GetWidth();
    int h = this->GetHeight();

    if (!general.IsValid())
        return;

    this->general->Resize(w, h);
}
void Panels::Information::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
