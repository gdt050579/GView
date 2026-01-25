#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace GView::GenericPlugins::HashAnalyzer
{

/**
 * Defines the type of hash used for the analysis query.
 */
enum class HashKind { MD5, SHA1, SHA256 };

/**
 * Structure that holds the analysis result retrieved from an online service (VirusTotal).
 */
struct AnalysisResult {
    std::string serviceName; // "VirusTotal"
    std::string queryHash;   // The hash that was queried

    bool found;   // True if the file was found in the service's database
    bool success; // True if the API call was successful (no network errors)

    uint32_t detectionCount; // Number of engines that detected the file as malicious
    uint32_t totalEngines;   // Total number of engines used for scanning

    std::string scanDate;     // Date of the last scan
    std::string permalink;    // Link to the full web report
    std::string errorMessage; // Error message (populated if success == false)

    // Detailed results per vendor (E.g., "Microsoft" -> "Trojan:Win32/Emotet")
    // Using std::map for easy display in a ListView (similar to Hashes.cpp)
    std::map<std::string, std::string> vendorResults;

    // Generic file metadata
    uint64_t fileSize;
    std::string fileType; // e.g., "Win32 DLL"

    AnalysisResult() : found(false), success(false), detectionCount(0), totalEngines(0), fileSize(0)
    {
    }
};

/**
 * Abstract Interface (Contract).
 * Any new service (VirusTotal, HybridAnalysis, etc.) must implement this class.
 */
class IAnalysisService
{
  public:
    virtual ~IAnalysisService() = default;

    // Returns the internal service ID (used in settings/config)
    // E.g., "virustotal"
    virtual const char* GetID() const = 0;

    // Returns the display name shown to the user
    // E.g., "VirusTotal Public API"
    virtual const char* GetName() const = 0;

    // Checks if the service has an API Key configured
    virtual bool IsConfigured() = 0;

    // This method is blocking (should be called from a worker thread in the UI).
    virtual AnalysisResult AnalyzeHash(const std::string& hash, HashKind type) = 0;
};

/**
 * Service Manager (Singleton).
 * Manages the list of available analysis services.
 */
class ServiceManager
{
    std::vector<std::unique_ptr<IAnalysisService>> services;

    ServiceManager() = default;

  public:
    // Singleton access
    static ServiceManager& Get()
    {
        static ServiceManager instance;
        return instance;
    }

    // Registers a new service (used during plugin initialization)
    void RegisterService(std::unique_ptr<IAnalysisService> service)
    {
        if (service) {
            services.push_back(std::move(service));
        }
    }

    // Returns the list of services (used to populate the UI Dropdown)
    const std::vector<std::unique_ptr<IAnalysisService>>& GetServices() const
    {
        return services;
    }

    // Retrieves a service by its ID (useful for saving user preference)
    IAnalysisService* GetServiceByID(const std::string& id)
    {
        for (const auto& svc : services) {
            if (svc->GetID() == id)
                return svc.get();
        }
        return nullptr;
    }
};

} // namespace GView::GenericPlugins::HashAnalyzer