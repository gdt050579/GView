#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::SetParser(Reference<ParseInterface> _parser)
{
    ((SettingsData*) (this->data))->parser = _parser;
}

