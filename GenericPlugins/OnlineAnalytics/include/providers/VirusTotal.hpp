#pragma once

#include "GView.hpp"

#include "utils/Report.hpp"
#include "utils/Http.hpp"
#include "providers/IProvider.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Providers
{

class VirusTotalProvider : public IProvider
{
  private:
    std::string apiKey;

  public:
    VirusTotalProvider(std::string apiKey);
    Reference<Utils::Report> GetReport(unsigned char sha256[32]);

  private:
    Reference<Utils::HTTPResponse> MakeRequest(unsigned char sha256[32]);
    Reference<Utils::Report> ProcessRequest(Reference<Utils::HTTPResponse> response);
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::Providers