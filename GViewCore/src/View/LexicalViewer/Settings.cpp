#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
    this->indentWidth = 4;
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

