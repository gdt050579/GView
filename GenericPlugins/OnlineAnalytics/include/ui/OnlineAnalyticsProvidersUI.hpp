#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

class OnlineAnalyticsProvidersUI : public Controls::Window,
                                   public Controls::Handlers::OnButtonPressedInterface,
                                   public Controls::Handlers::OnListViewCurrentItemChangedInterface
{
  private:
    bool didInit;
    Reference<GView::Object> object;
    std::vector<Reference<Providers::IProvider>> providers;
    Reference<Providers::IProvider> provider;

    Reference<Controls::ListView> providersList;

  public:
    OnlineAnalyticsProvidersUI(Reference<GView::Object> object);
    bool Init();

    AppCUI::Dialogs::Result Show();
    void OnButtonPressed(Reference<Controls::Button> button) override;
    void OnListViewCurrentItemChanged(Reference<Controls::ListView> listView, Controls::ListViewItem item) override;

    Reference<Providers::IProvider> GetProvider();

  private:
    void OnOkButtonPressed();
    void OnExitButtonPressed();
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI