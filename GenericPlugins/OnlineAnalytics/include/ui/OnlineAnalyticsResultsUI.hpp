#pragma once

#include "GView.hpp"

#include "utils/Report.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

class OnlineAnalyticsResultsUI : public Window, public Controls::Handlers::OnButtonPressedInterface
{
  private:
    bool didInit;
    Reference<Utils::Report> report;

  public:
    OnlineAnalyticsResultsUI(Reference<Utils::Report> report);
    bool Init();

    AppCUI::Dialogs::Result Show();

  private:
    void OnButtonPressed(Reference<Controls::Button> button) override;
    void OnVisitButtonPressed();
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI