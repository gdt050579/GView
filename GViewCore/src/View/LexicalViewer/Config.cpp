#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    LocalString<128> buffer;
    for (const auto& cmd : Commands::LexicalViewerCommands) {
        buffer.SetFormat("Key.%s", cmd->Caption);
        sect.UpdateValue(buffer.GetText(), cmd->Key, true);
    }
}
void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                      = ini->GetSection("View.Lexical");
        LocalString<128> buffer;
        for (auto& cmd : Commands::LexicalViewerCommands) {
            buffer.SetFormat("Key.%s", cmd->Caption);
            cmd->Key = sect.GetValue(buffer.GetText()).ToKey(cmd->Key);
        }
    }

    this->Loaded = true;
}