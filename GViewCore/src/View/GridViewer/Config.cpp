#include "GridViewer.hpp"

using namespace GView::View::GridViewer;
using namespace AppCUI::Input;

constexpr Key KEY_REPLACE_HEADER_WITH_1ST_ROW = Key::Space;
constexpr Key KEY_TOGGLE_HORIZONTAL_LINES     = Key::H;
constexpr Key KEY_TOGGLE_VERTICAL_LINES       = Key::V;
constexpr Key KEY_VIEW_CELL_CONTENT           = Key::Enter;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("Key.ReplaceHeaderWith1stRow", KEY_REPLACE_HEADER_WITH_1ST_ROW, true);
    sect.UpdateValue("Key.ToggleHorizontalLines", KEY_TOGGLE_HORIZONTAL_LINES, true);
    sect.UpdateValue("Key.ToggleVerticalLines", KEY_TOGGLE_VERTICAL_LINES, true);
}

void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                          = ini->GetSection("View.Grid");
        this->keys.replaceHeaderWith1stRow = sect.GetValue("Key.ReplaceHeaderWith1stRow").ToKey(KEY_REPLACE_HEADER_WITH_1ST_ROW);
        this->keys.toggleHorizontalLines   = sect.GetValue("Key.ToggleHorizontalLines").ToKey(KEY_TOGGLE_HORIZONTAL_LINES);
        this->keys.toggleVerticalLines     = sect.GetValue("Key.ToggleVerticalLines").ToKey(KEY_TOGGLE_VERTICAL_LINES);
        this->keys.viewCellContent         = sect.GetValue("Key.ViewCellContent").ToKey(KEY_VIEW_CELL_CONTENT);
    }
    else
    {
        this->keys.replaceHeaderWith1stRow = KEY_REPLACE_HEADER_WITH_1ST_ROW;
        this->keys.toggleHorizontalLines   = KEY_TOGGLE_HORIZONTAL_LINES;
        this->keys.toggleVerticalLines     = KEY_TOGGLE_VERTICAL_LINES;
        this->keys.viewCellContent         = KEY_VIEW_CELL_CONTENT;
    }

    loaded = true;
}
