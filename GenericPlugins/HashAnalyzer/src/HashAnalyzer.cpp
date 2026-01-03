#include "HashAnalyzer.hpp"
#include "ServiceInterface.hpp"
#include "TestService.hpp" 

namespace GView::GenericPlugins::HashAnalyzer
{
constexpr int32 CMD_BUTTON_CLOSE          = 1;
constexpr std::string_view CMD_SHORT_NAME = "HashAnalyzer";
constexpr std::string_view CMD_FULL_NAME  = "Command.HashAnalyzer";

HashAnalyzerDialog::HashAnalyzerDialog(Reference<GView::Object> obj) : Window("Hash Analyzer", "d:c,w:60,h:15", WindowFlags::ProcessReturn)
{
    this->object = obj;

    auto& manager = ServiceManager::Get();
    auto count    = manager.GetServices().size();

    LocalString<128> message;
    if (count > 0) {
        auto* svc = manager.GetServices()[0].get();
        message.Format("SUCCESS! Active: %s", svc->GetName());
    } else {
        message.Set("ERROR: No services registered!");
    }

    Factory::Label::Create(this, message.GetText(), "d:c");

    close                              = Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE);
    close->Handlers()->OnButtonPressed = this;
}

void HashAnalyzerDialog::OnButtonPressed(Reference<Button> b)
{
    Exit();
}
} 

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == GView::GenericPlugins::HashAnalyzer::CMD_SHORT_NAME) {
        GView::GenericPlugins::HashAnalyzer::RegisterTestService();

        GView::GenericPlugins::HashAnalyzer::HashAnalyzerDialog dlg(object);
        dlg.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect[GView::GenericPlugins::HashAnalyzer::CMD_FULL_NAME] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::H;
}
}