#include "ContainerViewer.hpp"

using namespace GView::View::ContainerViewer;
using namespace AppCUI::Input;

#define SD ((SettingsData*) this->data)

SettingsData::SettingsData()
{
    this->columnsCount    = 0;
    this->propertiesCount = 0;
    this->pathSeparator   = char16_t(std::filesystem::path::preferred_separator);
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
    if (separator > 0) {
        SD->pathSeparator = separator;
        return true;
    }
    return false;
}
bool Settings::AddProperty(string_view name, const ConstString& value, ListViewItem::Type itemType)
{
    CHECK(SD->propertiesCount < SettingsData::MAX_PROPERTIES, false, "");
    CHECK(SD->properties[SD->propertiesCount].key.Set(name), false, "");
    CHECK(SD->properties[SD->propertiesCount].value.Set(value), false, "");
    SD->properties[SD->propertiesCount].itemType = itemType;
    SD->propertiesCount++;
    return true;
}
void Settings::SetColumns(std::initializer_list<ConstString> columns)
{
    for (const auto& col : columns) {
        SD->columns[SD->columnsCount].layout.Set(col);
        SD->columnsCount++;
    }
}
void Settings::SetEnumerateCallback(Reference<EnumerateInterface> callback)
{
    SD->enumInterface = callback;
}
void Settings::SetOpenItemCallback(Reference<OpenItemInterface> callback)
{
    SD->openItemInterface = callback;
}

bool Settings::SetName(std::string_view name)
{
    return SD->name.Set(name);
}

#undef SD