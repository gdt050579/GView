#include "ContainerViewer.hpp"

using namespace GView::View::ContainerViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection)
{
    // update values
}
void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        // auto sect = ini->GetSection("ContainerView");
    }
    else
    {
        // default values
    }

    this->Loaded = true;
}
