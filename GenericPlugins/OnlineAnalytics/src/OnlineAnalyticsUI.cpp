#include "OnlineAnalyticsUI.hpp"
#include "stdio.h"

namespace GView::GenericPlugins::OnlineAnalytics
{
using namespace AppCUI::Controls;

OnlineAnalyticsUI::OnlineAnalyticsUI(Reference<GView::Object> object) : Window("Online analytics", "d:c,w:30,h:30", WindowFlags::FixedPosition)
{
    this->object = object;
};

}; // namespace GView::GenericPlugins::OnlineAnalytics