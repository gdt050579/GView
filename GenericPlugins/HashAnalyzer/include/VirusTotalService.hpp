#pragma once

#include "ServiceInterface.hpp"
#include "HttpClient.hpp"
#include <nlohmann/json.hpp>

namespace GView::GenericPlugins::HashAnalyzer
{

/**
 * @brief VirusTotal service provider implementation.
 * 
 * Implements the IAnalysisService interface to query VirusTotal's
 * public API v3 for file hash lookups.
 * 
 * API Documentation: https://docs.virustotal.com/reference/file-info
 */
class VirusTotalService : public IAnalysisService
{
    static constexpr const char* SERVICE_ID = "virustotal";
    static constexpr const char* SERVICE_NAME = "VirusTotal";
    static constexpr const char* API_BASE_URL = "https://www.virustotal.com/api/v3/files/";
    static constexpr const char* API_KEY_ENV_NAME = "VIRUSTOTAL_API_KEY";
    static constexpr const char* API_KEY_HEADER = "x-apikey";

  public:
    /**
     * @brief Get the internal service identifier.
     * @return "virustotal"
     */
    const char* GetID() const override;

    /**
     * @brief Get the display name for the UI.
     * @return "VirusTotal"
     */
    const char* GetName() const override;

    /**
     * @brief Check if the service has a valid API key configured.
     * @return true if VIRUSTOTAL_API_KEY is set in .env file
     */
    bool IsConfigured() override;

    /**
     * @brief Query VirusTotal for analysis results of a file hash.
     * 
     * Makes a GET request to /api/v3/files/{hash} and parses the response.
     * Supports MD5, SHA1, and SHA256 hashes.
     * 
     * @param hash The file hash to query
     * @param type The type of hash (MD5, SHA1, or SHA256)
     * @return AnalysisResult containing detection info or error details
     */
    AnalysisResult AnalyzeHash(const std::string& hash, HashKind type) override;

  private:
    /**
     * @brief Parse the HTTP response into an AnalysisResult.
     * @param response The HTTP response from VirusTotal API
     * @param hash The queried hash (for inclusion in result)
     * @return Populated AnalysisResult
     */
    AnalysisResult parseResponse(const HttpResponse& response, const std::string& hash);

    /**
     * @brief Parse individual vendor results from the JSON response.
     * @param analysisResults The "last_analysis_results" JSON object
     * @param result The AnalysisResult to populate with vendor data
     */
    void parseVendorResults(const nlohmann::json& analysisResults, AnalysisResult& result);

    /**
     * @brief Convert Unix timestamp to human-readable date string.
     * @param timestamp Unix timestamp
     * @return Formatted date string (YYYY-MM-DD HH:MM:SS)
     */
    static std::string formatTimestamp(int64_t timestamp);
};

} // namespace GView::GenericPlugins::HashAnalyzer

