#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    LocalString<128> buffer;
    for (const auto& cmd : Commands::ImageViewCommands) {
        buffer.SetFormat("Key.%s", cmd->Caption);
        sect.UpdateValue(buffer.GetText(), cmd->Key, true);
    }
}
void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect          = ini->GetSection("View.Image");
        LocalString<128> buffer;
        for (auto& cmd : Commands::ImageViewCommands) {
            buffer.SetFormat("Key.%s", cmd->Caption);
            cmd->Key = sect.GetValue(buffer.GetText()).ToKey(cmd->Key);
        }
    }

    this->Loaded = true;
}