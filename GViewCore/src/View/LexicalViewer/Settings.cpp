#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
    this->indentWidth = 4;
    this->maxWidth    = 120;
    this->parser      = nullptr;
    this->ignoreCase  = false;
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::SetParser(Reference<ParseInterface> _parser)
{
    ((SettingsData*) (this->data))->parser = _parser;
}
void Settings::SetCaseSensitivity(bool ignoreCase)
{
    ((SettingsData*) (this->data))->ignoreCase = ignoreCase;
}
void Settings::SetMaxWidth(uint32 width)
{
    if (width < 20)
        width = 20;
    if (width > 2000)
        width = 2000;
    ((SettingsData*) (this->data))->maxWidth = width;
}
void Settings::AddPlugin(Reference<Plugin> plugin)
{
    if (plugin.IsValid())
        ((SettingsData*) (this->data))->plugins.push_back(plugin);
}
