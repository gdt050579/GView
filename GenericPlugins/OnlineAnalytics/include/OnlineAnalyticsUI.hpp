#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics
{
using namespace AppCUI::Controls;

class OnlineAnalyticsUI : public Window
{
  private:
    Reference<GView::Object> object;

  public:
    OnlineAnalyticsUI(Reference<GView::Object> object);
};

}; // namespace GView::GenericPlugins::OnlineAnalytics