#include "MachO.hpp"

namespace GView::Type::MachOFB::Panels
{
using namespace AppCUI::Controls;

Information::Information(Reference<MachOFBFile> _fat) : TabPage("Informa&Tion")
{
    fat     = _fat;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 12);
    general->AddColumn("Value", TextAlignament::Left, 100);

    Update();
}

void Information::UpdateGeneralInformation()
{
    ItemHandle item;
    LocalString<256> tempStr;
    NumericFormatter n;

    general->DeleteAllItems();
    item = general->AddItem("Fat Binary Info");
    general->SetItemType(item, ListViewItemType::Category);
    general->AddItem("File");

    general->AddItem("Size", tempStr.Format("%s bytes", n.ToString(fat->file->GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()));
    general->AddItem("Architecture", fat->is64 ? "x64" : "x86");
    general->AddItem(
          "Objects count",
          tempStr.Format("%s", n.ToString(static_cast<uint64_t>(fat->header.nfat_arch), { NumericFormatFlags::None, 10, 3, ',' }).data()));
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    if (general->GetItemsCount() > 15)
    {
        general->Resize(GetWidth(), 18);
    }
    else
    {
        general->Resize(GetWidth(), general->GetItemsCount() + 3);
    }
}

void Information::Update()
{
    UpdateGeneralInformation();
    RecomputePanelsPositions();
}
} // namespace GView::Type::MachOFB::Panels
