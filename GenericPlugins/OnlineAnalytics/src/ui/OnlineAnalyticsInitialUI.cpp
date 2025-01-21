#include "ui/OnlineAnalyticsInitialUI.hpp"
#include "stdio.h"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

constexpr int32 CMD_BUTTON_EXIT = 1;
constexpr int32 CMD_BUTTON_OK   = 2;

constexpr uint64 PROVIDER_VIRUSTOTAL = 1;

OnlineAnalyticsInitialUI::OnlineAnalyticsInitialUI(Reference<GView::Object> object)
    : Controls::Window("Online analytics", "d:c,w:60,h:30", WindowFlags::FixedPosition)
{
    this->object = object;

    this->providersList     = Factory::ListView::Create(this, "x:1,y:1,w:50%,h:80%", { "w:100%" }, Controls::ListViewFlags::HideColumns);
    ListViewItem VirusTotal = this->providersList->AddItem("VirusTotal");
    VirusTotal.SetData(PROVIDER_VIRUSTOTAL);
    VirusTotal.SetSelected(true);
    this->providersList->Handlers()->OnCurrentItemChanged = this;

    this->providerApiKey = Factory::Label::Create(this, "Api key:", "x:55%,y:2,h:1,w:30");

    this->disclaimer = Factory::Label::Create(this, "Note: A request will be performed on your behalf", "a:l,x:1,y:85%,w:100%");

    this->exit                              = Factory::Button::Create(this, "&Close", "a:b,x:75%,y:100%,w:16", CMD_BUTTON_EXIT);
    this->exit->Handlers()->OnButtonPressed = this;

    this->ok                              = Factory::Button::Create(this, "&Analyse", "a:b,x:25%,y:100%,w:16", CMD_BUTTON_OK);
    this->ok->Handlers()->OnButtonPressed = this;
    this->ok->SetFocus();
};

void OnlineAnalyticsInitialUI::OnButtonPressed(Reference<Controls::Button> button)
{
    switch (button->GetControlID()) {
    case CMD_BUTTON_EXIT:
        return this->OnExitButtonPressed(button);
    case CMD_BUTTON_OK:
        return this->OnOkButtonPressed(button);
    }
}

void OnlineAnalyticsInitialUI::OnListViewCurrentItemChanged(Reference<Controls::ListView> listView, Controls::ListViewItem item)
{
    switch (item.GetData(-1)) {
    case PROVIDER_VIRUSTOTAL:
        return this->OnVirusTotalSelected(listView, item);
    }
}

void OnlineAnalyticsInitialUI::OnExitButtonPressed(Reference<Controls::Button> button)
{
    this->Exit(Dialogs::Result::Cancel);
}

void OnlineAnalyticsInitialUI::OnOkButtonPressed(Reference<Controls::Button> button)
{
    if (this->object->GetData().GetSize() == 0) {
        Dialogs::MessageBox::ShowError("Error!", "Must open a file before running analytics");
        this->Exit(Dialogs::Result::Cancel);
        return;
    }

    this->Exit(Dialogs::Result::Ok);
}

void OnlineAnalyticsInitialUI::OnVirusTotalSelected(Reference<Controls::ListView> listView, Controls::ListViewItem item)
{
    LocalString<512> format;
    std::string text;

    item.GetText(0).ToString(text);

    this->providerApiKey->SetText(format.Format("Api-key: %s", text));
}

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI