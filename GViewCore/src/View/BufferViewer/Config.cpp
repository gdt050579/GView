#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("Key.ChangeColumnsCount", Key::F6, true);
    sect.UpdateValue("Key.ChangeValueFormatOrCP", Key::F2, true);
    sect.UpdateValue("Key.ChangeAddressMode", Key::F3, true);
    sect.UpdateValue("Key.GoToEntryPoint", Key::F7, true);
    sect.UpdateValue("Key.ChangeSelectionType", Key::F9, true);
    sect.UpdateValue("Key.ShowHideStrings", Key::F4 | Key::Alt, true);
}

void Config::Initialize()
{
    this->Colors.Ascii   = ColorPair{ Color::Red, Color::DarkBlue };
    this->Colors.Unicode = ColorPair{ Color::Yellow, Color::DarkBlue };

    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                        = ini->GetSection("View.Buffer");
        this->Keys.ChangeColumnsNumber   = sect.GetValue("Key.ChangeColumnsCount").ToKey(Key::F6);
        this->Keys.ChangeValueFormatOrCP = sect.GetValue("Key.ChangeValueFormatOrCP").ToKey(Key::F2);
        this->Keys.ChangeAddressMode     = sect.GetValue("Key.ChangeAddressMode").ToKey(Key::F3);
        this->Keys.GoToEntryPoint        = sect.GetValue("Key.GoToEntryPoint").ToKey(Key::F7);
        this->Keys.ChangeSelectionType   = sect.GetValue("Key.ChangeSelectionType").ToKey(Key::F9);
        this->Keys.ShowHideStrings       = sect.GetValue("Key.ShowHideStrings").ToKey(Key::Alt | Key::F3);
    }
    else
    {
        this->Keys.ChangeColumnsNumber   = Key::F6;
        this->Keys.ChangeValueFormatOrCP = Key::F2;
        this->Keys.ChangeAddressMode     = Key::F3;
        this->Keys.GoToEntryPoint        = Key::F7;
        this->Keys.ChangeSelectionType   = Key::F9;
        this->Keys.ShowHideStrings       = Key::Alt | Key::F3;
    }

    this->Loaded = true;
}