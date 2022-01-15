#include "BufferViewer.hpp"

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
    this->Colors.Ascii         = ColorPair{ Color::Red, Color::DarkBlue };
    this->Colors.Unicode       = ColorPair{ Color::Yellow, Color::DarkBlue };
    this->Colors.Selection     = ColorPair{ Color::Black, Color::White };
    this->Colors.Cursor        = ColorPair{ Color::Black, Color::Yellow };
    this->Colors.Header        = ColorPair{ Color::White, Color::Magenta };
    this->Colors.Inactive      = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.OutsideZone   = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.SameSelection = ColorPair{ Color::Black, Color::Green };

    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                        = ini->GetSection("BufferView");
        this->Keys.ChangeColumnsNumber   = sect.GetValue("ChangeColumnsCount").ToKey(Key::F6);
        this->Keys.ChangeValueFormatOrCP = sect.GetValue("ChangeValueFormatOrCP").ToKey(Key::F2);
        this->Keys.ChangeAddressMode     = sect.GetValue("ChangeAddressMode").ToKey(Key::F3);
        this->Keys.GoToEntryPoint        = sect.GetValue("GoToEntryPoint").ToKey(Key::F7);
        this->Keys.ChangeSelectionType   = sect.GetValue("ChangeSelectionType").ToKey(Key::F9);
        this->Keys.ShowHideStrings       = sect.GetValue("ShowHideStrings").ToKey(Key::Alt | Key::F3);
        this->Keys.GoToAddress           = sect.GetValue("GoToAddress").ToKey(Key::F5);
    }
    else
    {
        this->Keys.ChangeColumnsNumber   = Key::F6;
        this->Keys.ChangeValueFormatOrCP = Key::F2;
        this->Keys.ChangeAddressMode     = Key::F3;
        this->Keys.GoToEntryPoint        = Key::F7;
        this->Keys.ChangeSelectionType   = Key::F9;
        this->Keys.ShowHideStrings       = Key::Alt | Key::F3;
        this->Keys.GoToAddress           = Key::F5;
    }

    this->Loaded = true;
}