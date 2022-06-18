#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("Key.ZoomIn", Key::F3, true);
    sect.UpdateValue("Key.ZoomOut", Key::F2, true);
}
void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect          = ini->GetSection("View.Image");
        this->Keys.ZoomIn  = sect.GetValue("Key.ZoomIn").ToKey(Key::F3);
        this->Keys.ZoomOut = sect.GetValue("Key.ZoomOut").ToKey(Key::F2);
    }
    else
    {
        this->Keys.ZoomIn  = Key::F3;
        this->Keys.ZoomOut = Key::F2;
    }

    this->Loaded = true;
}