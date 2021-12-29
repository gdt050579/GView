#include "GridViewer.hpp"

using namespace GView::View::GridViewer;

SettingsData::SettingsData() : content(nullptr)
{
}

Settings::Settings()
{
    this->data = new SettingsData();
}

void Settings::SetContent(void* content)
{
    ((SettingsData*)(this->data))->content = content;
}

void Settings::SetDimensions(unsigned int rows, unsigned int columns)
{
    ((SettingsData*)(this->data))->rows = rows;
    ((SettingsData*)(this->data))->cols = columns;
}
