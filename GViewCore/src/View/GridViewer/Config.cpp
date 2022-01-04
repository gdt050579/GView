#include "GridViewer.hpp"

using namespace GView::View::GridViewer;
using namespace AppCUI::Input;

constexpr Key KEY_REPLACE_HEADER_WITH_1ST_ROW = Key::Space;
constexpr Key KEY_TOGGLE_HORIZONTAL_LINES     = Key::H;
constexpr Key KEY_TOGGLE_VERTICAL_LINES       = Key::V;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("ReplaceHeaderWith1stRow", KEY_REPLACE_HEADER_WITH_1ST_ROW, true);
    sect.UpdateValue("ToggleHorizontalLines", KEY_TOGGLE_HORIZONTAL_LINES, true);
    sect.UpdateValue("ToggleVerticalLines", KEY_TOGGLE_VERTICAL_LINES, true);
}

void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                          = ini->GetSection("GridView");
        this->keys.replaceHeaderWith1stRow = sect.GetValue("ReplaceHeaderWith1stRow").ToKey(KEY_REPLACE_HEADER_WITH_1ST_ROW);
        this->keys.toggleHorizontalLines   = sect.GetValue("ToggleHorizontalLines").ToKey(KEY_TOGGLE_HORIZONTAL_LINES);
        this->keys.toggleVerticalLines     = sect.GetValue("ToggleVerticalLines").ToKey(KEY_TOGGLE_VERTICAL_LINES);
    }
    else
    {
        this->keys.replaceHeaderWith1stRow = KEY_REPLACE_HEADER_WITH_1ST_ROW;
        this->keys.toggleHorizontalLines   = KEY_TOGGLE_HORIZONTAL_LINES;
        this->keys.toggleVerticalLines     = KEY_TOGGLE_VERTICAL_LINES;
    }

    loaded = true;
}
