#include <stdexcept>
#include <format>
#include <string>
#include <locale>
#include <codecvt>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "providers/VirusTotal.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Providers
{

static size_t ReadCallback(char* buffer, size_t size, size_t nmemb, void* userp)
{
    Reference<Utils::HTTPUploadData> uploadData = *((Reference<Utils::HTTPUploadData>*) (userp));
    size_t maxToRead                            = size * nmemb;
    size_t remaining                            = uploadData->size - uploadData->position;

    if (maxToRead > remaining) {
        maxToRead = remaining;
    }

    std::memcpy(buffer, uploadData->data + uploadData->position, maxToRead);
    uploadData->position += maxToRead;

    return maxToRead;
}

static size_t WriteCallback(void* buffer, size_t size, size_t nmemb, void* userp)
{
    size_t realsize = size * nmemb;
    ((std::string*) userp)->append((char*) buffer, realsize);
    return realsize;
}

VirusTotalProvider::VirusTotalProvider(AppCUI::Utils::IniSection& settings)
{
    if (!settings.HasValue("Config.VirusTotal.ApiKey")) {
        this->apiKey = std::string("-");
    } else {
        this->apiKey = settings.GetValue("Config.VirusTotal.ApiKey").ToString();
    }
}

std::string VirusTotalProvider::GetName()
{
    return std::string("VirusTotal");
}

std::string VirusTotalProvider::GetApiKey()
{
    return this->apiKey;
}

bool VirusTotalProvider::GetIsUploadSupported()
{
    return true;
}

Reference<Utils::Report> VirusTotalProvider::GetReport(Reference<std::array<uint8, 32>> sha256)
{
    Reference<std::string> id               = this->MakeId(sha256);
    Reference<Utils::HTTPResponse> response = this->MakeReportRequest(id);
    CHECK(response != NULL, NULL, "Could not retrieve cURL response");
    CHECK(response->status == 200, NULL, std::format("Request status was not 200: was {}", response->status).c_str());

    Reference<Utils::Report> result = this->CreateReport(response, id);
    CHECK(result != NULL, NULL, "Could not create report");

    return result;
}

bool VirusTotalProvider::UploadFile(Reference<GView::Object> object)
{
    AppCUI::Utils::BufferView file = object->GetData().GetEntireFile();
    Reference<Utils::HTTPUploadData> uploadData =
          Reference(new Utils::HTTPUploadData{ .name = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>().to_bytes(
                                                     object->GetName().data(), object->GetName().data() + object->GetName().size()),
                                               .data     = file.GetData(),
                                               .size     = file.GetLength(),
                                               .position = 0 });

    ProgressStatus::Init("Waiting for upload to complete", 1);
    Reference<Utils::HTTPResponse> uploadResponse = this->MakeUploadRequest(uploadData);
    ProgressStatus::Update(1);

    CHECK(uploadResponse->status == 200, false, std::format("Request failed with status {}", uploadResponse->status).c_str());

    nlohmann::json data;
    try {
        data = nlohmann::json::parse(uploadResponse->data);
    } catch (nlohmann::json::exception exception) {
        AppCUI::Log::Report(
              AppCUI::Log::Severity::Error,
              __FILE__,
              __FUNCTION__,
              "data = nlohmann::json::parse(uploadResponse->data);",
              __LINE__ - 2,
              "Could not parse the JSON response");
        return false;
    }

    bool finished                                   = false;
    Reference<std::string> analysisId               = Reference(new std::string(data["data"]["id"].get<std::string>()));
    Reference<Utils::HTTPResponse> analysisResponse = NULL;

    ProgressStatus::Init("Waiting for analysis to complete", 1);

    while (!finished) {
        analysisResponse = this->MakeAnalysisRequest(analysisId);

        if (analysisResponse->status != 200) {
            return false;
        }

        try {
            data = nlohmann::json::parse(analysisResponse->data);
        } catch (nlohmann::json::exception exception) {
            AppCUI::Log::Report(
                  AppCUI::Log::Severity::Error,
                  __FILE__,
                  __FUNCTION__,
                  "data = nlohmann::json::parse(rawData);",
                  __LINE__ - 2,
                  "Could not parse the JSON response");
            return false;
        }

        finished = data["data"]["attributes"]["status"] != std::string("completed");
    }

    ProgressStatus::Update(1);

    return true;
}

Reference<std::string> VirusTotalProvider::MakeId(Reference<std::array<uint8, 32>> sha256)
{
    Reference<std::string> id(new std::string());

    for (long unsigned int i = 0; i < sha256->size(); i++) {
        id->append(std::format("{:02x}", sha256->at(i)));
    }

    return id;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeReportRequest(Reference<std::string> id)
{
    CURL* curl = curl_easy_init();
    CHECK(curl, NULL, "Could not initialise cURL");

    struct curl_slist* headers = NULL;
    std::string url            = std::string();

    url     = std::format("https://www.virustotal.com/api/v3/files/{}", id->c_str());
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, std::format("x-apikey: {}", this->apiKey).c_str());

    Reference<Utils::HTTPResponse> result = this->MakeReportRequestInternal(curl, url, headers);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return result;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeReportRequestInternal(CURL* curl, std::string& url, curl_slist* headers)
{
    long status      = -1;
    std::string data = std::string();

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

    Utils::Severity severity;
    std::vector<std::string> capabilities;
    std::vector<Utils::Analysis> analysis;
    std::vector<std::string> tags;

    if (data["last_analysis_stats"]["malicious"] > 4) {
        severity = Utils::Severity::Critical;
    } else if (data["last_analysis_stats"]["malicious"] > 2) {
        severity = Utils::Severity::High;
    } else if (data["last_analysis_stats"]["malicious"] > 0) {
        severity = Utils::Severity::Medium;
    } else if (data["last_analysis_stats"]["suspicious"] > 0) {
        severity = Utils::Severity::Low;
    } else {
        severity = Utils::Severity::None;
    }

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
                                                       .severity     = severity,
                                                       .capabilities = capabilities,
                                                       .analysis     = analysis,
                                                       .tags         = tags });
    return result;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeUploadRequest(Reference<Utils::HTTPUploadData> uploadData)
{
    CURL* curl = curl_easy_init();
    CHECK(curl, NULL, "Could not initialise cURL");

    ProgressStatus::Init("Uploading file to provider", uploadData->size);

    struct curl_slist* headers = NULL;
    std::string url            = std::string();
    curl_mime* mime            = NULL;
    curl_mimepart* part        = NULL;

    url     = std::string("https://www.virustotal.com/api/v3/files");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, std::format("x-apikey: {}", this->apiKey).c_str());
    mime    = curl_mime_init(curl);
    part    = curl_mime_addpart(mime);

    Reference<Utils::HTTPResponse> result = this->MakeUploadRequestInternal(curl, url, headers, mime, part, uploadData);

    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return result;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeUploadRequestInternal(
      CURL* curl, std::string& url, curl_slist* headers, curl_mime* mime, curl_mimepart* part, Reference<Utils::HTTPUploadData> uploadData)
{
    long status      = -1;
    std::string data = std::string();

    CHECK(curl_mime_name(part, "file") == CURLE_OK, NULL, "Could not set cURL file");
    CHECK(curl_mime_filename(part, uploadData->name.c_str()) == CURLE_OK, NULL, "Could not set cURL filename");
    CHECK(curl_mime_type(part, "application/octet-stream") == CURLE_OK, NULL, "Could not set cURL mime type");
    CHECK(curl_mime_data_cb(part, uploadData->size, ReadCallback, NULL, NULL, &uploadData) == CURLE_OK, NULL, "Could not set cURL read callback");

    CHECK(curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) == CURLE_OK, NULL, "Could not set cURL url");
    CHECK(curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime) == CURLE_OK, NULL, "Could not set cURL mime type for the POST request");
    CHECK(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) == CURLE_OK, NULL, "Could not set cURL headers");
    CHECK(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback) == CURLE_OK, NULL, "Could not set cURL write callback");
    CHECK(curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data) == CURLE_OK, NULL, "Could not set cURL read buffer");
    CHECK(curl_easy_perform(curl) == CURLE_OK, NULL, "Could not perform cURL request");
    CHECK(curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK, NULL, "Could not get cURL response status code");

    Reference<Utils::HTTPResponse> result(new Utils::HTTPResponse{ .url = url, .status = status, .data = data });
    return result;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeAnalysisRequest(Reference<std::string> id)
{
    CURL* curl = curl_easy_init();
    CHECK(curl, NULL, "Could not initialise cURL");

    struct curl_slist* headers = NULL;
    std::string url            = std::string();

    url     = std::format("https://www.virustotal.com/api/v3/analyses/{}", id.operator std::string&());
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, std::format("x-apikey: {}", this->apiKey).c_str());

    Reference<Utils::HTTPResponse> result = this->MakeAnalysisRequestInternal(curl, url, headers);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return result;
}

Reference<Utils::HTTPResponse> VirusTotalProvider::MakeAnalysisRequestInternal(CURL* curl, std::string& url, curl_slist* headers)
{
    long status      = -1;
    std::string data = std::string();

    CHECK(curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) == CURLE_OK, NULL, "Could not set cURL url");
    CHECK(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) == CURLE_OK, NULL, "Could not set cURL headers");
    CHECK(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback) == CURLE_OK, NULL, "Could not set cURL write callback");
    CHECK(curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data) == CURLE_OK, NULL, "Could not set cURL read buffer");
    CHECK(curl_easy_perform(curl) == CURLE_OK, NULL, "Could not perform cURL request");
    CHECK(curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK, NULL, "Could not get cURL response status code");

    Reference<Utils::HTTPResponse> result(new Utils::HTTPResponse{ .url = url, .status = status, .data = data });
    return result;
}

} // namespace GView::GenericPlugins::OnlineAnalytics::Providers