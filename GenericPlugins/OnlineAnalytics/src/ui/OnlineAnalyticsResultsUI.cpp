#include "ui/OnlineAnalyticsResultsUI.hpp"
#include "stdio.h"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

OnlineAnalyticsResultsUI::OnlineAnalyticsResultsUI(Reference<GView::Object> object) : Window("Online analytics", "d:c,w:30,h:30", WindowFlags::FixedPosition)
{
    this->object = object;
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI