#include "GridViewer.hpp"

using namespace GView::View::GridViewer;

SettingsData::SettingsData() : tokens({}), lines({})
{
}

Settings::Settings()
{
    this->data = new SettingsData();
}

void Settings::SetSeparator(char separator[2])
{
    ((SettingsData*) (this->data))->separator[0] = separator[0];
    ((SettingsData*) (this->data))->separator[1] = separator[1];
}

bool Settings::SetName(std::string_view name)
{
    return ((SettingsData*) (this->data))->name.Set(name);
}