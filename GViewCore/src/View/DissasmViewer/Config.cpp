#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("AddNewType", Key::F5, true);
}
void Config::Initialize()
{
    this->Colors.Inactive = ColorPair{ Color::Gray, Color::DarkBlue };

    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect             = ini->GetSection("DissasmView");
        this->Keys.AddNewType = ini->GetValue("AddNewType").ToKey(Key::F5);
    }
    else
    {
        this->Keys.AddNewType = Key::F5;
    }

    this->Loaded = true;
}
