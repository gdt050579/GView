#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;


Panels::Icons::Icons(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("I&cons")
{
    pe  = _pe;
    win = _win;

    Factory::Label::Create(this, "Icons", "x:1,y:1,w:6");
    this->iconsList = Factory::ComboBox::Create(this, "l:7,t:1,r:1");
    this->imageView = Factory::ImageViewer::Create(this, "l:1,t:3,r:1,b:1", ViewerFlags::None);
    Update();
    this->iconsList->SetCurentItemIndex(0);
    UpdateCurrentIcon();
    this->iconsList->SetFocus();
}
void Panels::Icons::Update()
{
    LocalString<128> temp;

    auto obj = this->win->GetObject();

    this->iconsList->DeleteAllItems();
    for (auto& r : pe->res)
    {
        if (r.Type != __RT_ICON)
            continue;
        if (pe->GetResourceImageInformation(r,temp))
            this->iconsList->AddItem<PEFile::ResourceInformation>(temp, &r);        
    }
}
void Panels::Icons::UpdateCurrentIcon()
{
    if (this->iconsList->GetCurrentItemIndex() != AppCUI::Controls::ComboBox::NO_ITEM_SELECTED)
    {
        auto res = this->iconsList->GetCurrentItemUserData<PEFile::ResourceInformation>();
        AppCUI::Graphics::Image img;
        if (pe->LoadIcon(res,img))
        {
            this->imageView->SetImage(img, ImageRenderingMethod::PixelTo16ColorsSmallBlock,ImageScaleMethod::NoScale);
            this->imageView->SetVisible(true);
            return;
        }
    }
    this->imageView->SetVisible(false);
}
bool Panels::Icons::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::ComboBoxSelectedItemChanged)
    {
        UpdateCurrentIcon();
        return true;
    }
    return false;
};