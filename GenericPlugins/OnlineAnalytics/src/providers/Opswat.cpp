#include <stdexcept>
#include <format>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "providers/Opswat.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Providers
{

OpswatProvider::OpswatProvider(AppCUI::Utils::IniSection& settings)
{
    if (!settings.HasValue("Config.Opswat.ApiKey")) {
        this->apiKey = std::string("-");
    } else {
        this->apiKey = settings.GetValue("Config.Opswat.ApiKey").ToString();
    }
}

std::string OpswatProvider::GetName()
{
    return std::string("OPSWAT MetaDefender Cloud");
}

std::string OpswatProvider::GetApiKey()
{
    return this->apiKey;
}

Reference<Utils::Report> OpswatProvider::GetReport(Reference<std::array<uint8, 32>> sha256)
{
    Reference<std::string> id               = this->MakeId(sha256);
    Reference<Utils::HTTPResponse> response = this->MakeRequest(id);
    CHECK(response != NULL, NULL, "Could not retrieve cURL response");
    CHECK(response->status == 200, NULL, std::format("Request status was not 200: was {}", response->status).c_str());

    Reference<Utils::Report> result = this->CreateReport(response, id);
    CHECK(result != NULL, NULL, "Could not create report");

    return result;
}
Reference<std::string> OpswatProvider::MakeId(Reference<std::array<uint8, 32>> sha256)
{
    Reference<std::string> id(new std::string());

    for (long unsigned int i = 0; i < sha256->size(); i++) {
        id->append(std::format("{:02x}", sha256->at(i)));
    }

    return id;
}

Reference<Utils::HTTPResponse> OpswatProvider::MakeRequest(Reference<std::string> id)
{
    CURL* curl = curl_easy_init();
    CHECK(curl, NULL, "Could not initialise cURL");

    long status;
    std::string data;
    std::string url;

    struct curl_slist* headers = NULL;
    headers                    = curl_slist_append(headers, "Accept: application/json");
    headers                    = curl_slist_append(headers, std::format("apikey: {}", this->apiKey).c_str());
    headers                    = curl_slist_append(headers, "extended: 1");

    url = std::format("https://api.metadefender.com/v5/threat-intel/file-analysis/{}", id->c_str());

    Reference<Utils::HTTPResponse> result = this->MakeRequestInternal(curl, url, headers, data, status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return result;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    size_t realsize = size * nmemb;
    ((std::string*) userp)->append((char*) contents, realsize);
    return realsize;
}

Reference<Utils::HTTPResponse> OpswatProvider::MakeRequestInternal(CURL* curl, std::string& url, curl_slist* headers, std::string& data, long& status)
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

Reference<Utils::Report> OpswatProvider::CreateReport(Reference<Utils::HTTPResponse> response, Reference<std::string> id)
{
    nlohmann::json data;
    try {
        data = nlohmann::json::parse(response->data);
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

    Utils::Severity severity;
    std::vector<std::string> capabilities;
    std::vector<Utils::Analysis> analysis;
    std::vector<std::string> tags;

    double detectRate    = 0;
    int totalAvs         = data["last_av_scan"]["total_avs"].get<int>();
    int totalDetectedAvs = data["last_av_scan"]["total_detected_avs"].get<int>();

    if (totalAvs > 0) {
        detectRate = totalDetectedAvs / totalAvs;
    }

    if (detectRate > 0.75) {
        severity = Utils::Severity::Critical;
    } else if (detectRate > 0.50) {
        severity = Utils::Severity::High;
    } else if (detectRate > 0.25) {
        severity = Utils::Severity::Medium;
    } else if (detectRate > 0) {
        severity = Utils::Severity::Low;
    } else {
        severity = Utils::Severity::None;
    }

    for (auto it = data["last_av_scan"]["scan_details"].begin(); it != data["last_av_scan"]["scan_details"].end(); it++) {
        analysis.push_back(Utils::Analysis{
              .engine  = std::string(it.key()),
              .version = std::string("Not specified"),
              .result  = (*it)["scan_result_i"] > 0 ? Utils::AnalysisResult::Malicious : Utils::AnalysisResult::Undetected,
        });
    }

    for (auto it = data["last_av_scan"]["malware_families"].begin(); it != data["last_av_scan"]["malware_families"].end(); it++) {
        capabilities.push_back(it.value());
    }

    for (auto it = data["last_av_scan"]["malware_types"].begin(); it != data["last_av_scan"]["malware_types"].end(); it++) {
        tags.push_back(it.value());
    }

    Reference<Utils::Report> result(new Utils::Report{ .md5          = data["md5"],
                                                       .sha1         = data["sha1"],
                                                       .sha256       = data["sha256"],
                                                       .fileName     = std::string("Unknown"),
                                                       .fileSize     = data["file_info"]["file_size"],
                                                       .url          = std::format("https://metadefender.com/results/hash/{}", id.operator std::string &()),
                                                       .severity     = severity,
                                                       .capabilities = capabilities,
                                                       .analysis     = analysis,
                                                       .tags         = tags });
    return result;
}

} // namespace GView::GenericPlugins::OnlineAnalytics::Providers