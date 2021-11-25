#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

struct BMP_InfoHeader
{
    uint32_t sizeOfHeader;
    uint32_t width;
    uint32_t height;
    uint16_t colorPlanes;
    uint16_t bitsPerPixel;
    uint32_t comppresionMethod;
    uint32_t imageSize;
    uint32_t horizontalResolution;
    uint32_t verticalResolution;
    uint32_t numberOfColors;
    uint32_t numberOfImportantColors;
};

Panels::Icons::Icons(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("I&cons")
{
    pe  = _pe;
    win = _win;

    Factory::Label::Create(this, "Icons", "x:1,y:1,w:6");
    this->iconsList = Factory::ComboBox::Create(this, "l:7,t:1,r:1");
    this->imageView = Factory::ImageViewer::Create(this, "l:1,t:3,r:1,b:1", ViewerFlags::None);
    Update();
}
void Panels::Icons::Update()
{
    BMP_InfoHeader iconHeader;
    LocalString<128> temp;

    auto obj = this->win->GetObject();

    this->iconsList->DeleteAllItems();
    for (auto& r : pe->res)
    {
        if (r.Type != __RT_ICON)
            continue;
        if ((obj->cache.Copy<decltype(iconHeader)>(r.Start, iconHeader)) && (iconHeader.sizeOfHeader == 40))
        {
            temp.SetFormat("%u x %u ", iconHeader.width, iconHeader.width);
            switch (iconHeader.bitsPerPixel)
            {
            case 1:
                temp.Add("(monochrome)");
                break;
            case 4:
                temp.Add("(16 colors)");
                break;
            case 8:
                temp.Add("(256 colors)");
                break;
            case 24:
                temp.Add("(RGB - 24bit)");
                break;
            default:
                temp.AddFormat("(%u bits/pixel)", iconHeader.bitsPerPixel);
                break;
            }
        }
        this->iconsList->AddItem<PEFile::ResourceInformation>(temp, &r);
    }
}
void Panels::Icons::UpdateCurrentIcon()
{
    if (this->iconsList->GetCurrentItemIndex() != AppCUI::Controls::ComboBox::NO_ITEM_SELECTED)
    {
        auto res = this->iconsList->GetCurrentItemUserData<PEFile::ResourceInformation>();
        auto buf = this->win->GetObject()->cache.CopyToBuffer(res->Start, res->Size);
        if (buf.IsValid())
        {
            AppCUI::Graphics::Image img;
            if (img.CreateFromDIB(buf.GetData(), buf.GetLength(), true))
            {
                this->imageView->SetImage(img, ImageRenderingMethod::PixelTo16ColorsSmallBlock,ImageScaleMethod::NoScale);
                this->imageView->SetVisible(true);
                return;
            }
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