#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("Key.ShowMetaData", Key::F2, true);
}
void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect               = ini->GetSection("View.Lexical");
        this->Keys.showMetaData = sect.GetValue("Key.ShowMetaData").ToKey(Key::F2);
    }
    else
    {
        this->Keys.showMetaData = Key::F2;
    }

    this->Loaded = true;
}