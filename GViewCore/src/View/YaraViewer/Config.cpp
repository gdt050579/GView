#include "YaraViewer.hpp"

using namespace GView::View::YaraViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    //sect.UpdateValue("Key.WrapMethod", Key::F2, true);
}
void Config::Initialize()
{
    //auto ini = AppCUI::Application::GetAppSettings();
    //if (ini)
    //{
    //    auto sect           = ini->GetSection("View.Text");
    //    this->Keys.WordWrap = sect.GetValue("Key.WrapMethod").ToKey(Key::F2);
    //}
    //else
    //{
    //    this->Keys.WordWrap = Key::F2;
    //}

    this->Loaded = true;
}
