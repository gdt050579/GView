#include <format>

#include "providers/IProvider.hpp"
#include "providers/VirusTotal.hpp"
#include "ui/OnlineAnalyticsProvidersUI.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

constexpr int32 CMD_BUTTON_OK   = 1;
constexpr int32 CMD_BUTTON_EXIT = 2;

OnlineAnalyticsProvidersUI::OnlineAnalyticsProvidersUI(Reference<GView::Object> object)
    : Controls::Window("Online analytics: provider selection", "d:c,w:80,h:24", WindowFlags::None)
{
    this->object  = object;
    this->didInit = false;

    this->providersList = Factory::ListView::Create(this, "a:t,l:1,r:1,y:1,h:80%", { "n:&Provider,w:35%", "n:&Api key,w:65%" });
    this->providersList->Handlers()->OnCurrentItemChanged = this;

    Reference<Controls::Label> disclaimerLabel =
          Factory::Label::Create(this, "NOTE: A request to the given provider will be performed on your behalf.", "a:b,l:1,r:1,y:95%,h:2");

    Reference<Controls::Button> okButton  = Factory::Button::Create(this, "&Analyse", "a:b,x:25%,y:100%,w:12", CMD_BUTTON_OK);
    okButton->Handlers()->OnButtonPressed = this;
    okButton->SetFocus();

    Reference<Controls::Button> exitButton  = Factory::Button::Create(this, "&Close", "a:b,x:75%,y:100%,w:12", CMD_BUTTON_EXIT);
    exitButton->Handlers()->OnButtonPressed = this;
};

bool OnlineAnalyticsProvidersUI::Init()
{
    CHECK(this->didInit == false, NULL, "Initial UI was already inited");

    AppCUI::Utils::IniObject* ini      = Application::GetAppSettings();
    AppCUI::Utils::IniSection settings = ini->GetSection("Generic.OnlineAnalytics");

    if (!settings.Exists()) {
        return this->Exit(AppCUI::Dialogs::Result::Cancel);
    }

    this->providers.push_back(Reference<Providers::IProvider>(new Providers::VirusTotalProvider(settings.GetValue("Config.VirusTotal.ApiKey").ToString())));
    this->provider = this->providers[0];

    for (Reference<Providers::IProvider> provider : this->providers) {
        ListViewItem item = this->providersList->AddItem({ provider->GetName(), provider->GetApiKey() });
        item.SetData<Providers::IProvider>(provider);
    }

    this->providersList->GetItem(0).SetSelected(true);
    this->providersList->SetCurrentItem(this->providersList->GetItem(0));

    this->didInit = true;
    return true;
}

AppCUI::Dialogs::Result OnlineAnalyticsProvidersUI::Show()
{
    CHECK(this->didInit == true, AppCUI::Dialogs::Result::Cancel, "Did not call init on Initial UI");
    return Window::Show();
}

void OnlineAnalyticsProvidersUI::OnButtonPressed(Reference<Controls::Button> button)
{
    switch (button->GetControlID()) {
    case CMD_BUTTON_OK:
        return this->OnOkButtonPressed();
    case CMD_BUTTON_EXIT:
        return this->OnExitButtonPressed();
    }
}

void OnlineAnalyticsProvidersUI::OnListViewCurrentItemChanged(Reference<Controls::ListView> listView, Controls::ListViewItem item)
{
    this->provider = item.GetData<Providers::IProvider>();
}

Reference<Providers::IProvider> OnlineAnalyticsProvidersUI::GetProvider()
{
    return this->provider;
}

void OnlineAnalyticsProvidersUI::OnOkButtonPressed()
{
    if (this->object->GetData().GetSize() == 0) {
        Dialogs::MessageBox::ShowError("Error!", "Must open a file before running analytics");
        this->Exit(Dialogs::Result::Cancel);
        return;
    }

    this->Exit(Dialogs::Result::Ok);
}

void OnlineAnalyticsProvidersUI::OnExitButtonPressed()
{
    this->Exit(Dialogs::Result::Cancel);
}

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI