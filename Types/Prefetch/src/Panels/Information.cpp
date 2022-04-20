#include "Prefetch.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::Prefetch::Panels
{
Information::Information(Reference<Object> _object, Reference<GView::Type::Prefetch::PrefetchFile> _prefetch) : TabPage("Informa&tion")
{
    prefetch = _prefetch;
    object   = _object;
    general  = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 100 } },
          ListViewFlags::None);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);
    general->AddItem({ "File", object->GetName() });
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), general->GetItemsCount());

    // CHECKRET(general.IsValid() & issues.IsValid(), "");
    // issues->SetVisible(issues->GetItemsCount() > 0);
    // if (issues->IsVisible())
    //{
    //    general->Resize(GetWidth(), general->GetItemsCount() + issues->GetItemsCount() + 3);
    //}
}

void Information::UpdateIssues()
{

}

void Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
} // namespace GView::Type::Prefetch::Panels
