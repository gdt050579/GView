#pragma once

#include <variant>
#include <curl/curl.h>
#include "GView.hpp"

#include "utils/Report.hpp"
#include "utils/Http.hpp"
#include "providers/IProvider.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Providers
{

class OpswatProvider : public IProvider
{
  private:
    std::string apiKey;

  public:
    OpswatProvider(AppCUI::Utils::IniSection& settings);
    std::string GetName();
    std::string GetApiKey();
    bool GetIsUploadSupported();
    Reference<Utils::Report> GetReport(Reference<std::array<uint8, 32>> sha256);
    bool UploadFile(Reference<GView::Object>);

  private:
    Reference<std::string> MakeId(Reference<std::array<uint8, 32>> sha256);
    Reference<Utils::HTTPResponse> MakeReportRequest(Reference<std::string> id);
    Reference<Utils::HTTPResponse> MakeReportRequestInternal(CURL* curl, std::string& url, curl_slist* headers, std::string& data, long& status);
    Reference<Utils::Report> CreateReport(Reference<Utils::HTTPResponse> response, Reference<std::string> id);

    Reference<Utils::HTTPResponse> MakeUploadRequest(Reference<Utils::HTTPUploadData> uploadData);
    Reference<Utils::HTTPResponse> MakeUploadRequestInternal(
          CURL* curl, std::string& url, curl_slist* headers, curl_mime* mime, curl_mimepart* part, Reference<Utils::HTTPUploadData> uploadData);
    Reference<Utils::HTTPResponse> MakeAnalysisRequest(Reference<std::string> id);
    Reference<Utils::HTTPResponse> MakeAnalysisRequestInternal(CURL* curl, std::string& url, curl_slist* headers);
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::Providers