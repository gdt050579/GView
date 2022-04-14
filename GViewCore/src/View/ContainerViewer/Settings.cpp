#include "ContainerViewer.hpp"

using namespace GView::View::ContainerViewer;
using namespace AppCUI::Input;

#define SD ((SettingsData*) this->data)

SettingsData::SettingsData()
{
    this->columnsCount = 0;
    this->pathSeparator = '/';
}
Settings::Settings()
{
    this->data = new SettingsData();
}
bool Settings::SetIcon(string_view stringFormat16x16)
{
    return SD->icon.Create(16, 16, stringFormat16x16);
}
bool Settings::SetPathSeparator(char16 separator)
{
    if (separator > 0)
    {
        SD->pathSeparator = separator;
        return true;
    }
    return false;
}
bool Settings::AddProperty(string_view name, string_view value)
{
    NOT_IMPLEMENTED(false);
}
void Settings::SetColumns(std::initializer_list<AppCUI::Controls::ColumnBuilder> columns)
{
    LocalUnicodeStringBuilder<64> temp;
    for (const auto& col: columns)
    {
        if (temp.Set(col.name))
        {
            SD->columns[SD->columnsCount].Name = temp.ToStringView();
        }
        else
        {
            SD->columns[SD->columnsCount].Name = u"?";
        }
        
        SD->columns[SD->columnsCount].Align = col.align;
        SD->columns[SD->columnsCount].Width = col.width;
        SD->columnsCount++;
    }
}
//bool Settings::AddColumn(string_view name, TextAlignament align, uint32 width)
//{
//    CHECK(SD->columnsCount < SettingsData::MAX_COLUMNS, false, "");
//    SD->columns[SD->columnsCount].Name  = name;
//    SD->columns[SD->columnsCount].Align = align;
//    SD->columns[SD->columnsCount].Width = std::max<>(4U, width);
//    SD->columnsCount++;
//    return true;
//}
void Settings::SetEnumarateCallback(Reference<EnumerateInterface> callback)
{
    SD->enumInterface = callback;
}
void Settings::SetActionCallback(Reference<ActionInterface> callback)
{
    SD->actionInterface = callback;
}

#undef SD