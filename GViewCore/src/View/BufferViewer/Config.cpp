#include "Internal.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("ChangeColumnsCount", Key::F6, true);
    sect.UpdateValue("ChangeBase", Key::F2, true);
    sect.UpdateValue("ChangeAddressMode", Key::F3, true);
    sect.UpdateValue("GoToEntryPoint", Key::F7, true);
}
void Config::Initialize()
{
    this->Colors.Ascii       = ColorPair{ Color::Red, Color::DarkBlue };
    this->Colors.Unicode     = ColorPair{ Color::Yellow, Color::DarkBlue };
    this->Colors.Selection   = ColorPair{ Color::Black, Color::White };
    this->Colors.Cursor      = ColorPair{ Color::Black, Color::Yellow };
    this->Colors.Line        = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.Header      = ColorPair{ Color::White, Color::Magenta };
    this->Colors.Normal      = ColorPair{ Color::Silver, Color::DarkBlue };
    this->Colors.Inactive    = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.OutsideZone = ColorPair{ Color::Gray, Color::DarkBlue };

    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                      = ini->GetSection("BufferView");
        this->Keys.ChangeColumnsNumber = ini->GetValue("ChangeColumnsCount").ToKey(Key::F6);
        this->Keys.ChangeBase          = ini->GetValue("ChangeBase").ToKey(Key::F2);
        this->Keys.ChangeAddressMode   = ini->GetValue("ChangeAddressMode").ToKey(Key::F3);
        this->Keys.GoToEntryPoint      = ini->GetValue("GoToEntryPoint").ToKey(Key::F7);
    }
    else
    {
        this->Keys.ChangeColumnsNumber = Key::F6;
        this->Keys.ChangeBase          = Key::F2;
        this->Keys.ChangeAddressMode   = Key::F3;
        this->Keys.GoToEntryPoint      = Key::F7;
    }

    this->Loaded = true;
}