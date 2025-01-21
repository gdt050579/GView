#pragma once

#include "GView.hpp"

#include "utils/Report.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Providers
{
using namespace GView::Hashes;

class IProvider
{
  public:
    virtual Reference<Utils::Report> GetReport(unsigned char sha256[32]) = 0;
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::Providers