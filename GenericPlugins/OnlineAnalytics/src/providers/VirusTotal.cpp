#include <stdexcept>
#include <format>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "providers/VirusTotal.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Providers
{

VirusTotalProvider::VirusTotalProvider(AppCUI::Utils::IniSection& settings)
{
    this->apiKey = settings.GetValue("Config.VirusTotal.ApiKey").ToString();
}

std::string VirusTotalProvider::GetName()
{
    return std::string("VirusTotal");
}

std::string VirusTotalProvider::GetApiKey()
{
    return this->apiKey;
}

Reference<Utils::Report> VirusTotalProvider::GetReport(Reference<std::array<uint8, 32>> sha256)
{
    Reference<std::string> id               = this->MakeId(sha256);
    Reference<Utils::HTTPResponse> response = this->MakeRequest(id);
    CHECK(response != NULL, NULL, "Could not retrieve cURL response");
    CHECK(response->status == 200, NULL, std::format("Request status was not 200: was {}", response->status).c_str());

    Reference<Utils::Report> result = this->CreateReport(response, id);
    CHECK(result != NULL, NULL, "Could not create report");

    return result;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    size_t realsize = size * nmemb;
    ((std::string*) userp)->append((char*) contents, realsize);
    return realsize;
}

Reference<std::string> VirusTotalProvider::MakeId(Reference<std::array<uint8, 32>> sha256)
{
    Reference<std::string> id(new std::string());

    for (long unsigned int i = 0; i < sha256->size(); i++) {
        id->append(std::format("{:02x}", sha256->at(i)));
    }

    return id;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeRequest(Reference<std::string> id)
{
    CURL* curl = curl_easy_init();
    CHECK(curl, NULL, "Could not initialise cURL");

    long status;
    std::string data;
    std::string url;

    struct curl_slist* headers = NULL;
    headers                    = curl_slist_append(headers, "Accept: application/json");
    headers                    = curl_slist_append(headers, std::format("x-apikey: {}", this->apiKey).c_str());

    url = std::format("https://www.virustotal.com/api/v3/files/{}", id->c_str());

    Reference<Utils::HTTPResponse> result = this->MakeRequestInternal(curl, url, headers, data, status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return result;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeRequestInternal(CURL* curl, std::string& url, curl_slist* headers, std::string& data, long& status)
{
    CHECK(curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) == CURLE_OK, NULL, "Could not set cURL url");
    CHECK(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) == CURLE_OK, NULL, "Could not set cURL headers");
    CHECK(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback) == CURLE_OK, NULL, "Could not set cURL write callback");
    CHECK(curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data) == CURLE_OK, NULL, "Could not set cURL read buffer");
    CHECK(curl_easy_perform(curl) == CURLE_OK, NULL, "Could not perform cURL request");
    CHECK(curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK, NULL, "Could not get cURL response status code");

    Reference<Utils::HTTPResponse> result(new Utils::HTTPResponse{ .url = url, .status = status, .data = data });
    return result;
}

Reference<Utils::Report> VirusTotalProvider::CreateReport(Reference<Utils::HTTPResponse> response, Reference<std::string> id)
{
    nlohmann::json data;
    try {
        data = nlohmann::json::parse(response->data)["data"]["attributes"];
    } catch (nlohmann::json::exception exception) {
        AppCUI::Log::Report(
              AppCUI::Log::Severity::Error,
              __FILE__,
              __FUNCTION__,
              "data = nlohmann::json::parse(readBuffer)[\"data\"][\"attributes\"];",
              __LINE__ - 2,
              "Could not parse the JSON response");
        return NULL;
    }

    std::vector<std::string> capabilities;
    std::vector<Utils::Analysis> analysis;
    std::vector<std::string> tags;

    for (auto it = data["last_analysis_results"].begin(); it != data["last_analysis_results"].end(); it++) {
        analysis.push_back(Utils::Analysis{
              .engine  = std::string((*it)["engine_name"].is_string() ? (*it)["engine_name"] : "Unknown"),
              .version = std::string((*it)["engine_version"].is_string() ? (*it)["engine_version"] : "Unknown"),
              .result  = (*it)["category"] == std::string("malicious") ? Utils::AnalysisResult::Malicious : Utils::AnalysisResult::Undetected,
        });
    }

    for (auto it = data["capabilities_tags"].begin(); it != data["capabilities_tags"].end(); it++) {
        capabilities.push_back(it.value());
    }

    for (auto it = data["tags"].begin(); it != data["tags"].end(); it++) {
        tags.push_back(it.value());
    }

    Reference<Utils::Report> result(new Utils::Report{ .md5          = data["md5"],
                                                       .sha1         = data["sha1"],
                                                       .sha256       = data["sha256"],
                                                       .fileName     = data["names"][0],
                                                       .fileSize     = data["size"],
                                                       .url          = std::format("https://www.virustotal.com/gui/file/{}", id.operator std::string&()),
                                                       .severity     = Utils::Severity::None,
                                                       .capabilities = capabilities,
                                                       .analysis     = analysis,
                                                       .tags         = tags });
    return result;
}

} // namespace GView::GenericPlugins::OnlineAnalytics::Providers