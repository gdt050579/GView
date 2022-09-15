#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("AddNewType", Key::F5, true);
}
void Config::Initialize()
{
    this->Colors.Inactive       = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.Cursor         = ColorPair{ Color::Black, Color::Yellow };
    this->Colors.Line           = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.Normal         = ColorPair{ Color::Silver, Color::DarkBlue };
    this->Colors.Highlight      = ColorPair{ Color::Yellow, Color::DarkBlue };
    this->Colors.Selection      = ColorPair{ Color::Black, Color::White };
    this->Colors.OutsideZone    = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.StructureColor = ColorPair{ Color::Magenta, Color::DarkBlue };
    this->Colors.DataTypeColor  = ColorPair{ Color::Green, Color::DarkBlue };

    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                     = ini->GetSection("DissasmView");
        this->Keys.AddNewType         = ini->GetValue("AddNewType").ToKey(Key::F6);
        this->Keys.ShowFileContentKey = ini->GetValue("ShowFileContentKey").ToKey(Key::F9);
        this->ShowFileContent         = ini->GetValue("ShowFileContent").ToBool(true);
    }
    else
    {
        this->Keys.AddNewType = Key::F6;
        this->Keys.ShowFileContentKey = Key::F9;
        this->ShowFileContent = true;
    }

    this->Loaded = true;
}
