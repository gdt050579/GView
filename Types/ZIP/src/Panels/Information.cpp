#include "zip.hpp"

using namespace GView::Type::ZIP;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<Object> _object, Reference<GView::Type::ZIP::ZIPFile> _zip) : TabPage("Informa&tion")
{
    zip     = _zip;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:100%", std::initializer_list<ConstString>{ "n:Field,w:10", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void Panels::Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });

    const auto fileSize    = nf.ToString(zip->obj->GetData().GetSize(), dec);
    const auto hexfileSize = nf2.ToString(zip->obj->GetData().GetSize(), hex);
    general->AddItem({ "Size", ls.Format("%-14s (%s)", fileSize.data(), hexfileSize.data()) });

    const auto count    = nf.ToString(zip->info.GetCount(), dec);
    const auto hexCount = nf2.ToString(zip->info.GetCount(), hex);
    general->AddItem({ "Items", ls.Format("%-14s (%s)", count.data(), hexCount.data()) });
}

void Panels::Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), std::min<int32>(general->GetHeight(), (int32) general->GetItemsCount() + 3));
}

void Panels::Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    RecomputePanelsPositions();
}
