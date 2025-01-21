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
    Reference<GView::Object> object;
    Reference<Controls::ListView> providersList;
    Reference<Controls::Label> providerApiKey;
    Reference<Controls::Label> disclaimer;
    Reference<Controls::Button> exit;
    Reference<Controls::Button> ok;

  public:
    OnlineAnalyticsInitialUI(Reference<GView::Object> object);

    void OnButtonPressed(Reference<Controls::Button> button) override;
    void OnListViewCurrentItemChanged(Reference<Controls::ListView> listView, Controls::ListViewItem item) override;

  private:
    void OnExitButtonPressed(Reference<Controls::Button> button);
    void OnOkButtonPressed(Reference<Controls::Button> button);
    void OnVirusTotalSelected(Reference<Controls::ListView> listView, Controls::ListViewItem item);
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI