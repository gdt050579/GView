#include "VirusTotalService.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace GView::GenericPlugins::HashAnalyzer
{

const char* VirusTotalService::GetID() const
{
    return SERVICE_ID;
}

const char* VirusTotalService::GetName() const
{
    return SERVICE_NAME;
}

bool VirusTotalService::IsConfigured()
{
    // hasValidKey() automatically ensures keys are loaded (thread-safe)
    return getApiKeyManager().hasValidKey(API_KEY_ENV_NAME);
}

AnalysisResult VirusTotalService::AnalyzeHash(const std::string& hash, HashKind type)
{
    AnalysisResult result;
    result.serviceName = SERVICE_NAME;
    result.queryHash = hash;

    // Check if API key is configured (ensureLoaded is thread-safe)
    auto& keyManager = getApiKeyManager();
    keyManager.ensureLoaded();

    auto apiKeyOpt = keyManager.getKey(API_KEY_ENV_NAME);
    if (!apiKeyOpt.has_value() || apiKeyOpt->empty() || *apiKeyOpt == "your_api_key_here") {
        result.success = false;
        result.errorMessage = "VirusTotal API key not configured. Please set VIRUSTOTAL_API_KEY in .env file.";
        return result;
    }

    // Build the API request
    // VirusTotal API v3 accepts MD5, SHA1, or SHA256 for file lookups
    HttpRequest request;
    request.setUrl(std::string(API_BASE_URL) + hash)
           .setMethod("GET")
           .addHeader("Accept", "application/json")
           .addHeader("User-Agent", "GView-HashAnalyzer/1.0")
           .addHeader(API_KEY_HEADER, *apiKeyOpt);

    // Send the request
    HttpResponse response = sendHttpRequest(request);

    // Parse the response
    return parseResponse(response, hash);
}

AnalysisResult VirusTotalService::parseResponse(const HttpResponse& response, const std::string& hash)
{
    AnalysisResult result;
    result.serviceName = SERVICE_NAME;
    result.queryHash = hash;

    // Handle network/CURL errors
    if (!response.success) {
        result.success = false;
        result.found = false;
        result.errorMessage = response.error.empty() ? "Network error occurred" : response.error;
        return result;
    }

    // Handle HTTP error codes
    if (response.isNotFound()) {
        // 404 - File not in VirusTotal database
        result.success = true;
        result.found = false;
        result.errorMessage = "File not found in VirusTotal database";
        return result;
    }

    if (response.isRateLimited()) {
        // 429 - Rate limited
        result.success = false;
        result.found = false;
        result.errorMessage = "Rate limited. Please wait before making more requests. (VirusTotal free API: 4 requests/minute)";
        return result;
    }

    if (response.isAuthError()) {
        // 401/403 - Authentication error
        result.success = false;
        result.found = false;
        result.errorMessage = "Invalid API key. Please check your VIRUSTOTAL_API_KEY in .env file.";
        return result;
    }

    if (!response.isSuccess()) {
        // Other HTTP errors
        result.success = false;
        result.found = false;
        result.errorMessage = "HTTP error: " + std::to_string(response.statusCode);
        return result;
    }

    // Parse JSON response
    try {
        nlohmann::json jsonResponse = nlohmann::json::parse(response.body);

        result.success = true;
        result.found = true;

        // Navigate to data.attributes
        if (!jsonResponse.contains("data") || !jsonResponse["data"].contains("attributes")) {
            result.success = false;
            result.found = false;
            result.errorMessage = "Invalid response format from VirusTotal";
            return result;
        }

        const auto& attributes = jsonResponse["data"]["attributes"];

        // Parse last_analysis_stats for detection counts
        if (attributes.contains("last_analysis_stats")) {
            const auto& stats = attributes["last_analysis_stats"];
            
            uint32_t malicious = stats.value("malicious", 0);
            uint32_t suspicious = stats.value("suspicious", 0);
            uint32_t undetected = stats.value("undetected", 0);
            uint32_t harmless = stats.value("harmless", 0);
            uint32_t timeout = stats.value("timeout", 0);
            uint32_t confirmedTimeout = stats.value("confirmed-timeout", 0);
            uint32_t failure = stats.value("failure", 0);
            uint32_t typeunsupported = stats.value("type-unsupported", 0);

            result.detectionCount = malicious + suspicious;
            result.totalEngines = malicious + suspicious + undetected + harmless + 
                                  timeout + confirmedTimeout + failure + typeunsupported;
        }

        // Parse scan date
        if (attributes.contains("last_analysis_date")) {
            int64_t timestamp = attributes["last_analysis_date"].get<int64_t>();
            result.scanDate = formatTimestamp(timestamp);
        }

        // Parse file metadata
        result.fileSize = attributes.value("size", 0ULL);
        result.fileType = attributes.value("type_description", "Unknown");

        // Parse permalink from links
        if (jsonResponse["data"].contains("links") && jsonResponse["data"]["links"].contains("self")) {
            // Convert API URL to GUI URL
            std::string apiUrl = jsonResponse["data"]["links"]["self"].get<std::string>();
            // Replace /api/v3/files/ with /gui/file/
            size_t pos = apiUrl.find("/api/v3/files/");
            if (pos != std::string::npos) {
                result.permalink = apiUrl.substr(0, pos) + "/gui/file/" + hash;
            } else {
                result.permalink = "https://www.virustotal.com/gui/file/" + hash;
            }
        } else {
            result.permalink = "https://www.virustotal.com/gui/file/" + hash;
        }

        // Parse vendor results
        if (attributes.contains("last_analysis_results")) {
            parseVendorResults(attributes["last_analysis_results"], result);
        }

    } catch (const nlohmann::json::exception& e) {
        result.success = false;
        result.found = false;
        result.errorMessage = std::string("JSON parsing error: ") + e.what();
    }

    return result;
}

void VirusTotalService::parseVendorResults(const nlohmann::json& analysisResults, AnalysisResult& result)
{
    for (auto it = analysisResults.begin(); it != analysisResults.end(); ++it) {
        const std::string& vendorName = it.key();
        const auto& vendorData = it.value();

        std::string category = vendorData.value("category", "unknown");
        
        // Get the detection result (malware name) if present
        std::string detectionResult;
        if (vendorData.contains("result") && !vendorData["result"].is_null()) {
            detectionResult = vendorData["result"].get<std::string>();
        }

        // Format the result string based on category
        std::string displayValue;
        if (category == "malicious" || category == "suspicious") {
            displayValue = detectionResult.empty() ? category : detectionResult;
        } else if (category == "undetected") {
            displayValue = "Clean";
        } else if (category == "harmless") {
            displayValue = "Harmless";
        } else if (category == "timeout" || category == "confirmed-timeout") {
            displayValue = "Timeout";
        } else if (category == "failure") {
            displayValue = "Scan failed";
        } else if (category == "type-unsupported") {
            displayValue = "Type not supported";
        } else {
            displayValue = category;
        }

        result.vendorResults[vendorName] = displayValue;
    }
}

std::string VirusTotalService::formatTimestamp(int64_t timestamp)
{
    std::time_t time = static_cast<std::time_t>(timestamp);
    std::tm tmBuffer{};
    
    // Use thread-safe variants of gmtime
#ifdef _WIN32
    // Windows: gmtime_s has reversed parameter order and returns errno_t
    if (gmtime_s(&tmBuffer, &time) != 0) {
        return "Unknown";
    }
#else
    // POSIX: gmtime_r returns pointer to the buffer on success, nullptr on failure
    if (gmtime_r(&time, &tmBuffer) == nullptr) {
        return "Unknown";
    }
#endif

    std::ostringstream oss;
    oss << std::put_time(&tmBuffer, "%Y-%m-%d %H:%M:%S UTC");
    return oss.str();
}

} // namespace GView::GenericPlugins::HashAnalyzer

