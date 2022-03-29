#include "ContainerViewer.hpp"

using namespace GView::View::ContainerViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::SetIcon(string_view stringFormat16x16)
{

}
void Settings::AddProperty(string_view name, string_view value)
{

}
