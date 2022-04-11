#include "ContainerViewer.hpp"

using namespace GView::View::ContainerViewer;
using namespace AppCUI::Input;

#define SD ((SettingsData*) this->data)

SettingsData::SettingsData()
{
    this->columnsCount = 0;
}
Settings::Settings()
{
    this->data = new SettingsData();
}
bool Settings::SetIcon(string_view stringFormat16x16)
{
    return SD->icon.Create(16, 16, stringFormat16x16);
}
bool Settings::AddProperty(string_view name, string_view value)
{
    NOT_IMPLEMENTED(false);
}
bool Settings::AddColumn(string_view name, TextAlignament align, uint32 width)
{
    CHECK(SD->columnsCount < SettingsData::MAX_COLUMNS, false, "");
    SD->columns[SD->columnsCount].Name = name;
    SD->columns[SD->columnsCount].Align = align;
    SD->columns[SD->columnsCount].Width = std::max<>(4U,width);
    SD->columnsCount++;
    return true;
}
void Settings::SetListItemCallback(Reference<EnumerateInterface> callback)
{
    SD->enumInterface = callback;
}

#undef SD