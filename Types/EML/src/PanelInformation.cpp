#include "eml.hpp"

using namespace GView::Type::EML;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<GView::Type::EML::EMLFile> _eml) : TabPage("&Information")
{
    eml    = _eml;
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
        auto sizeString = NumericFormatter().ToString(eml->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data();
        auto value      = tempStr.Format("%s bytes", sizeString);
        general->AddItem({ "Size", value });
    }

    headers->AddItem("Headers");
    for (const auto& itr : eml->headerFields)
    {
        headers->AddItem({ itr.first, itr.second });
    }
}

void Panels::Information::UpdateIssues()
{
}
void Panels::Information::RecomputePanelsPositions()
{
    int w    = this->GetWidth();
    int h    = this->GetHeight();

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
