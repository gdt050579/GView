#include "csv.hpp"

using namespace GView::Type::CSV;

namespace GView::Type::CSV::Panels
{
Information::Information(Reference<GView::Type::CSV::CSVFile> csv) : TabPage("Informa&Tion")
{
    this->csv = csv;
    general   = this->CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 12);
    general->AddColumn("Value", TextAlignament::Left, 100);

    this->Update();
}

void Information::OnAfterResize(int newWidth, int newHeight)
{
    RecomputePanelsPositions();
}

void Information::Update()
{
    UpdateGeneralInformation();
    RecomputePanelsPositions();
}

void Information::UpdateGeneralInformation()
{
    general->DeleteAllItems();

    LocalString<256> ls;
    NumericFormatter nf;
    general->AddItem("Filename", csv->obj->name);
    general->AddItem("Size", ls.Format("%s bytes", nf.ToString(csv->file->GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()));
}

void Information::RecomputePanelsPositions()
{
    if (this->general != nullptr)
    {
        if (this->general->GetItemsCount() > 15)
        {
            this->general->Resize(this->GetWidth(), 18);
        }
        else
        {
            this->general->Resize(this->GetWidth(), this->general->GetItemsCount() + 3);
        }
    }
}

} // namespace GView::Type::CSV::Panels