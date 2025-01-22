#pragma once

#include "GView.hpp"

#include "utils/Report.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Providers
{
using namespace GView::Hashes;

class IProvider
{
  public:
    virtual std::string GetName() = 0;
    virtual std::string GetApiKey() = 0;
    virtual Reference<Utils::Report> GetReport(Reference<std::array<uint8, 32>> sha256) = 0;
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::Providers