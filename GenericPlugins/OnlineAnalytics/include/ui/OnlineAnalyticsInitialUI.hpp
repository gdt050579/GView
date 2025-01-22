#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

class OnlineAnalyticsInitialUI : public Controls::Window,
                                 public Controls::Handlers::OnButtonPressedInterface,
                                 public Controls::Handlers::OnListViewCurrentItemChangedInterface
{
  private:
    AppCUI::Utils::IniSection settings;
    bool didInit;
    std::vector<Reference<Providers::IProvider>> providers;
    Reference<Providers::IProvider> provider;

    Reference<GView::Object> object;
    Reference<Controls::ListView> providersList;
    Reference<Controls::Label> disclaimerLabel;
    Reference<Controls::Button> exitButton;
    Reference<Controls::Button> okButton;

  public:
    OnlineAnalyticsInitialUI(Reference<GView::Object> object);
    bool Init();

    AppCUI::Dialogs::Result Show();
    void OnButtonPressed(Reference<Controls::Button> button) override;
    void OnListViewCurrentItemChanged(Reference<Controls::ListView> listView, Controls::ListViewItem item) override;
    
    Reference<Providers::IProvider> GetProvider();

  private:
    void OnExitButtonPressed();
    void OnOkButtonPressed();
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI