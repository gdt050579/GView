#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

class OnlineAnalyticsResultsUI : public Window
{
  private:
    Reference<GView::Object> object;

  public:
    OnlineAnalyticsResultsUI(Reference<GView::Object> object);
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI