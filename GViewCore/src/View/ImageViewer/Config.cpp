#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("ZoomIn", Key::F2, true);
    sect.UpdateValue("ZoomOut", Key::F3, true);
    sect.UpdateValue("ChangeImageRenderMethod", Key::F4, true);
}
void Config::Initialize()
{
    this->Colors.Line     = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.Normal   = ColorPair{ Color::Silver, Color::DarkBlue };
    this->Colors.Inactive = ColorPair{ Color::Gray, Color::DarkBlue };

    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                          = ini->GetSection("ImageView");
        this->Keys.ZoomIn                  = ini->GetValue("ZoomIn").ToKey(Key::F2);
        this->Keys.ZoomOut                 = ini->GetValue("ZoomOut").ToKey(Key::F3);
        this->Keys.ChangeImageRenderMethod = ini->GetValue("ChangeImageRenderMethod").ToKey(Key::F4);
    }
    else
    {
        this->Keys.ZoomIn                  = Key::F2;
        this->Keys.ZoomOut                 = Key::F3;
        this->Keys.ChangeImageRenderMethod = Key::F4;
    }

    this->Loaded = true;
}