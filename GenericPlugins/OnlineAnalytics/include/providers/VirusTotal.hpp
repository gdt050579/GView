#pragma once

#include <variant>
#include <curl/curl.h>
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
    std::string GetName();
    std::string GetApiKey();
    Reference<Utils::Report> GetReport(Reference<std::array<uint8, 32>> sha256);

  private:
    Reference<Utils::HTTPResponse> MakeRequest(Reference<std::array<uint8, 32>> sha256);
    Reference<Utils::HTTPResponse> MakeRequestInternal(
          CURL* curl, std::string& url, curl_slist* headers, std::string& data, long& status
    );
    Reference<Utils::Report> ProcessRequest(Reference<Utils::HTTPResponse> response);
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::Providers