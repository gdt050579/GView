#include <stdexcept>
#include <format>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "providers/VirusTotal.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Providers
{

VirusTotalProvider::VirusTotalProvider(std::string apiKey)
{
    this->apiKey = apiKey;
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
    Reference<Utils::HTTPResponse> response = this->MakeRequest(sha256);
    CHECK(response != NULL, NULL, "Could not retrieve cURL response");
    CHECK(response->status == 200, NULL, std::format("Request status was not 200: was {}", response->status).c_str());

    Reference<Utils::Report> result = this->ProcessRequest(response);
    CHECK(result != NULL, NULL, "Could not process response");

    return result;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    size_t realsize = size * nmemb;
    ((std::string*) userp)->append((char*) contents, realsize);
    return realsize;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeRequest(Reference<std::array<uint8, 32>> sha256)
{
    CURL* curl = curl_easy_init();
    CHECK(curl, NULL, "Could not initialise cURL");

    long status;
    std::string id;
    std::string data;
    std::string url;

    struct curl_slist* headers = NULL;
    headers                    = curl_slist_append(headers, "Accept: application/json");
    headers                    = curl_slist_append(headers, std::format("x-apikey: {}", this->apiKey).c_str());

    for (long unsigned int i = 0; i < sha256->size(); i++) {
        id += std::format("{:02x}", sha256->at(i));
    }

    url = std::format("https://www.virustotal.com/api/v3/files/{}", id);

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

Reference<Utils::Report> VirusTotalProvider::ProcessRequest(Reference<Utils::HTTPResponse> response)
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
    std::vector<std::string> urls;
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

    urls.push_back(response->url);

    for (auto it = data["tags"].begin(); it != data["tags"].end(); it++) {
        tags.push_back(it.value());
    }

    Reference<Utils::Report> result(new Utils::Report{ .md5          = data["md5"],
                                                       .sha1         = data["sha1"],
                                                       .sha256       = data["sha256"],
                                                       .fileName     = data["names"][0],
                                                       .fileSize     = data["size"],
                                                       .severity     = Utils::Severity::None,
                                                       .capabilities = capabilities,
                                                       .analysis     = analysis,
                                                       .urls         = urls,
                                                       .tags         = tags

    });
    return result;
}

} // namespace GView::GenericPlugins::OnlineAnalytics::Providers