#include "GridViewer.hpp"
#include <array>
using namespace GView::View::GridViewer;
using namespace GView::View::GridViewer::Commands;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    LocalString<128> buffer;
    for (const auto& cmd : AllGridCommands) {
        buffer.SetFormat("Key.%s", cmd->Caption);
        sect.UpdateValue(buffer.GetText(), cmd->Key, true);
    }
}

void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                          = ini->GetSection("View.Grid");
        LocalString<128> buffer;
        for (auto& cmd : AllGridCommands) {
            buffer.SetFormat("Key.%s", cmd->Caption);
            cmd->Key = sect.GetValue(buffer.GetText()).ToKey(cmd->Key);
        }
    }

    loaded = true;
}
