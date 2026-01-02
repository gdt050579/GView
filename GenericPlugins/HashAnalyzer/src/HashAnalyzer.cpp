#include "HashAnalyzer.hpp"

namespace GView::GenericPlugins::HashAnalyzer
{
constexpr int32 CMD_BUTTON_CLOSE = 1;
constexpr std::string_view CMD_SHORT_NAME = "HashAnalyzer";
constexpr std::string_view CMD_FULL_NAME = "Command.HashAnalyzer";

HashAnalyzerDialog::HashAnalyzerDialog(Reference<GView::Object> obj)
    : Window("Hash Analyzer", "d:c,w:60,h:15", WindowFlags::ProcessReturn)
{
    this->object = obj;
    Factory::Label::Create(this, "Hash Analyzer - Coming Soon", "d:c");
    close = Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE);
    close->Handlers()->OnButtonPressed = this;
}

void HashAnalyzerDialog::OnButtonPressed(Reference<Button> b)
{
    Exit();
}
} // namespace GView::GenericPlugins::HashAnalyzer

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
    {
        if (command == GView::GenericPlugins::HashAnalyzer::CMD_SHORT_NAME)
        {
            GView::GenericPlugins::HashAnalyzer::HashAnalyzerDialog dlg(object);
            dlg.Show();
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        // Register keyboard shortcut: Ctrl+Alt+H
        sect[GView::GenericPlugins::HashAnalyzer::CMD_FULL_NAME] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::H;
    }
}

