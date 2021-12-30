#include "GridViewer.hpp"

using namespace GView::View::GridViewer;
using namespace AppCUI::Input;

constexpr Key KEY_TOGGLE_HEADER = Key::Space;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("ToggleHeader", KEY_TOGGLE_HEADER, true);
}

void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect = ini->GetSection("GridView");
        this->Keys.ToggleHeader = ini->GetValue("ToggleHeader").ToKey(KEY_TOGGLE_HEADER);
    }
    else
    {
        this->Keys.ToggleHeader = KEY_TOGGLE_HEADER;
    }

    Loaded = true;
}
