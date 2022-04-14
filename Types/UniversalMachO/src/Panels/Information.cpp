#include "UniversalMachO.hpp"

namespace GView::Type::UniversalMachO::Panels
{
using namespace AppCUI::Controls;

Information::Information(Reference<UniversalMachOFile> _machO) : TabPage("Informa&Tion")
{
    machO   = _machO;
    general = Factory::ListView::Create(
          this,
          "x:0,y:0,w:100%,h:10", { { "Field", TextAlignament::Left, 12 }, { "Value", TextAlignament::Left, 100 } }, ListViewFlags::None);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<256> tempStr;
    NumericFormatter n;

    general->DeleteAllItems();
    general->AddItem("Fat Binary Info").SetType(ListViewItem::Type::Category);
    general->AddItem({ "File", "NOT IMPLEMENTED" });
    general->AddItem(
          { "Size", tempStr.Format("%s bytes", n.ToString(machO->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()) });
    general->AddItem({ "Arch", machO->is64 ? "x64" : "x86" });
    general->AddItem(
          { "Objects",
            tempStr.Format("%s", n.ToString(static_cast<uint64_t>(machO->header.nfat_arch), { NumericFormatFlags::None, 10 }).data()) });
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
} // namespace GView::Type::UniversalMachO::Panels
