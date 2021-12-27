#include "GridViewer.hpp"

using namespace GView::View::GridViewer;

void Config::Update(IniSection sect)
{
}

void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
    }
    else
    {
    }

    Loaded = true;
}
