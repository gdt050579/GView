#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("ZoomIn", Key::F3, true);
    sect.UpdateValue("ZoomOut", Key::F2, true);
}
void Config::Initialize()
{
    this->Colors.Line        = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.Normal      = ColorPair{ Color::Silver, Color::DarkBlue };
    this->Colors.Inactive    = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.Highlighted = ColorPair{ Color::Yellow, Color::DarkBlue };

    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect          = ini->GetSection("ImageView");
        this->Keys.ZoomIn  = sect.GetValue("ZoomIn").ToKey(Key::F3);
        this->Keys.ZoomOut = sect.GetValue("ZoomOut").ToKey(Key::F2);
    }
    else
    {
        this->Keys.ZoomIn  = Key::F3;
        this->Keys.ZoomOut = Key::F2;
    }

    this->Loaded = true;
}