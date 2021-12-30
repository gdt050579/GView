#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

#define INTERNAL_SETTINGS ((SettingsData*) this->data)

Settings::Settings()
{
    this->data = new SettingsData();
}

SettingsData::SettingsData()
{
}

//void Settings::SetDissasembleLanguage(DissamblyLanguage lang)
//{
//    INTERNAL_SETTINGS->language = lang;
//}
//void Settings::AddDissasembleZone(uint64 start, uint64 size)
//{
//}
