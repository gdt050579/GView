#include "GridViewer.hpp"

using namespace GView::View::GridViewer;

SettingsData::SettingsData() : content({})
{
}

Settings::Settings()
{
    this->data = new SettingsData();
}

void Settings::SetContent(std::vector<std::vector<std::string>>& content)
{
    ((SettingsData*) (this->data))->content = std::move(content);
}

void Settings::SetDimensions(unsigned int rows, unsigned int columns)
{
    ((SettingsData*) (this->data))->rows = rows;
    ((SettingsData*) (this->data))->cols = columns;
}
