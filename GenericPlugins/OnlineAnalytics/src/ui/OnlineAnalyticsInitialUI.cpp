#include <format>

#include "providers/IProvider.hpp"
#include "providers/VirusTotal.hpp"
#include "ui/OnlineAnalyticsInitialUI.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

constexpr int32 CMD_BUTTON_EXIT = 1;
constexpr int32 CMD_BUTTON_OK   = 2;

OnlineAnalyticsInitialUI::OnlineAnalyticsInitialUI(Reference<GView::Object> object)
    : Controls::Window("Online analytics", "d:c,w:60,h:30", WindowFlags::FixedPosition)
{
    this->object = object;
    this->didInit = false;

    this->providersList = Factory::ListView::Create(this, "x:1,y:1,w:50%,h:80%", { "w:100%" }, Controls::ListViewFlags::HideColumns);
    this->providersList->Handlers()->OnCurrentItemChanged = this;

    this->providerApiKeyLabel = Factory::Label::Create(this, "Api key: -", "x:55%,y:2,h:1,w:30");
    this->disclaimerLabel     = Factory::Label::Create(this, "Note: A request will be performed on your behalf", "a:l,x:1,y:85%,w:100%");

    this->exitButton                              = Factory::Button::Create(this, "&Close", "a:b,x:75%,y:100%,w:16", CMD_BUTTON_EXIT);
    this->exitButton->Handlers()->OnButtonPressed = this;

    this->okButton                              = Factory::Button::Create(this, "&Analyse", "a:b,x:25%,y:100%,w:16", CMD_BUTTON_OK);
    this->okButton->Handlers()->OnButtonPressed = this;
    this->okButton->SetFocus();
};

bool OnlineAnalyticsInitialUI::Init()
{
    CHECK(this->didInit == false, NULL, "Initial UI was already inited");

    AppCUI::Utils::IniObject* ini = Application::GetAppSettings();
    this->settings                = ini->GetSection("Generic.OnlineAnalytics");

    if (!this->settings.Exists()) {
        return this->Exit(AppCUI::Dialogs::Result::Cancel);
    }

    std::string virusTotalApiKey = this->settings.GetValue("Config.VirusTotal.ApiKey").ToString();

    this->providers.push_back(Reference<Providers::IProvider>(new Providers::VirusTotalProvider(virusTotalApiKey)));
    this->provider = this->providers[0];

    for (Reference<Providers::IProvider> provider : this->providers) {
        ListViewItem item = this->providersList->AddItem(provider->GetName());
        item.SetData<Providers::IProvider>(provider);
    }

    this->providersList->GetItem(0).SetSelected(true);
    this->providerApiKeyLabel->SetText(std::format("Api key: {}", this->provider->GetApiKey()));

    this->didInit = true;
    return true;
}

AppCUI::Dialogs::Result OnlineAnalyticsInitialUI::Show()
{
    CHECK(this->didInit == true, AppCUI::Dialogs::Result::Cancel, "Did not call init on Initial UI");
    return Window::Show();
}

void OnlineAnalyticsInitialUI::OnButtonPressed(Reference<Controls::Button> button)
{
    switch (button->GetControlID()) {
    case CMD_BUTTON_EXIT:
        return this->OnExitButtonPressed();
    case CMD_BUTTON_OK:
        return this->OnOkButtonPressed();
    }
}

void OnlineAnalyticsInitialUI::OnListViewCurrentItemChanged(Reference<Controls::ListView> listView, Controls::ListViewItem item)
{
    this->provider = item.GetData<Providers::IProvider>();
    this->providerApiKeyLabel->SetText(std::format("Api key: {}", this->provider->GetApiKey()));
}

Reference<Providers::IProvider> OnlineAnalyticsInitialUI::GetProvider()
{
    return this->provider;
}

void OnlineAnalyticsInitialUI::OnExitButtonPressed()
{
    this->Exit(Dialogs::Result::Cancel);
}

void OnlineAnalyticsInitialUI::OnOkButtonPressed()
{
    if (this->object->GetData().GetSize() == 0) {
        Dialogs::MessageBox::ShowError("Error!", "Must open a file before running analytics");
        this->Exit(Dialogs::Result::Cancel);
        return;
    }

    this->Exit(Dialogs::Result::Ok);
}

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI