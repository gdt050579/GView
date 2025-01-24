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
    VirusTotalProvider(AppCUI::Utils::IniSection& settings);
    std::string GetName();
    std::string GetApiKey();
    Reference<Utils::Report> GetReport(Reference<std::array<uint8, 32>> sha256);
    bool UploadFile(Reference<GView::Object>);

  private:
    Reference<std::string> MakeId(Reference<std::array<uint8, 32>> sha256);
    Reference<Utils::HTTPResponse> MakeReportRequest(Reference<std::string> id);
    Reference<Utils::HTTPResponse> MakeReportRequestInternal(CURL* curl, std::string& url, curl_slist* headers, std::string& data, long& status);
    Reference<Utils::Report> CreateReport(Reference<Utils::HTTPResponse> response, Reference<std::string> id);
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::Providers