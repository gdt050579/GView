#pragma once

#include "GView.hpp"

#include "utils/Report.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

class OnlineAnalyticsResultsUI : public Window
{
  private:
    bool didInit;
    Reference<GView::Object> object;
    Reference<Utils::Report> report;

    Reference<Controls::Tab> tabs;

  public:
    OnlineAnalyticsResultsUI(Reference<GView::Object> object, Reference<Utils::Report> report);
    bool Init();

    AppCUI::Dialogs::Result Show();
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI