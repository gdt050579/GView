#include "TextViewer.hpp"

using namespace GView::View::TextViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("WordWrap", Key::F2, true);
}
void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect           = ini->GetSection("TextView");
        this->Keys.WordWrap = sect.GetValue("WordWrap").ToKey(Key::F2);
    }
    else
    {
        this->Keys.WordWrap = Key::F2;
    }

    this->Loaded = true;
}