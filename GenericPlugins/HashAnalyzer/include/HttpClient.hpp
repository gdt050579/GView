#pragma once

#include "GView.hpp"
#include <curl/curl.h>
#include <unordered_map>
#include <sstream>
#include <optional>
#include <string>
#include <fstream>
#include <filesystem>
#include <mutex>

namespace GView::GenericPlugins::HashAnalyzer
{

/**
 * @brief HTTP Response structure containing the result of an HTTP request.
 */
struct HttpResponse
{
    int statusCode = 0;                                    
    std::string body;                                      
    std::unordered_map<std::string, std::string> headers;  
    std::string error;                                      
    bool success = false;                                   

    /**
     * @brief Check if the response indicates a successful HTTP status (2xx)
     */
    bool isSuccess() const
    {
        return success && statusCode >= 200 && statusCode < 300;
    }

    /**
     * @brief Check if the response indicates the resource was not found (404)
     */
    bool isNotFound() const
    {
        return statusCode == 404;
    }

    /**
     * @brief Check if the response indicates rate limiting (429)
     */
    bool isRateLimited() const
    {
        return statusCode == 429;
    }

    /**
     * @brief Check if the response indicates an authentication error (401/403)
     */
    bool isAuthError() const
    {
        return statusCode == 401 || statusCode == 403;
    }
};

/**
 * @brief Configuration manager for API keys loaded from .env file
 * 
 * Thread-safe: Uses std::call_once to ensure keys are loaded exactly once
 * even when accessed from multiple threads concurrently.
 */
class ApiKeyManager
{
    std::unordered_map<std::string, std::string> keys;
    bool loaded = false;
    mutable std::once_flag loadOnceFlag;

    /**
     * @brief Internal implementation of file loading (called once by std::call_once)
     */
    void loadFromFileImpl(const std::string& envFilePath)
    {
        std::vector<std::string> searchPaths;
        
        if (!envFilePath.empty()) {
            searchPaths.push_back(envFilePath);
        } else {
            // Search common locations
            searchPaths.push_back(".env");
            searchPaths.push_back("GenericPlugins/HashAnalyzer/.env");
            
            // Try to find relative to executable
            #ifdef _WIN32
            char buffer[MAX_PATH];
            if (GetModuleFileNameA(nullptr, buffer, MAX_PATH)) {
                std::filesystem::path exePath(buffer);
                searchPaths.push_back((exePath.parent_path() / ".env").string());
                searchPaths.push_back((exePath.parent_path() / "GenericPlugins" / "HashAnalyzer" / ".env").string());
            }
            #endif
        }
        
        for (const auto& path : searchPaths) {
            std::ifstream file(path);
            if (file.is_open()) {
                std::string line;
                while (std::getline(file, line)) {
                    // Skip empty lines and comments
                    if (line.empty() || line[0] == '#') continue;
                    
                    // Parse KEY=VALUE format
                    size_t pos = line.find('=');
                    if (pos != std::string::npos) {
                        std::string key = line.substr(0, pos);
                        std::string value = line.substr(pos + 1);
                        
                        // Trim whitespace
                        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
                        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(0, 1);
                        
                        keys[key] = value;
                    }
                }
                loaded = true;
                return;
            }
        }
    }

  public:
    /**
     * @brief Ensure API keys are loaded from the .env file (thread-safe)
     * 
     * This method is idempotent and thread-safe. It will load keys exactly once,
     * even if called concurrently from multiple threads.
     * 
     * @param envFilePath Path to the .env file (default: searches common locations)
     */
    void ensureLoaded(const std::string& envFilePath = "")
    {
        std::call_once(loadOnceFlag, [this, envFilePath]() {
            loadFromFileImpl(envFilePath);
        });
    }

    /**
     * @brief Load API keys from a .env file (thread-safe, deprecated)
     * @deprecated Use ensureLoaded() instead for clearer semantics
     * @param envFilePath Path to the .env file (default: searches common locations)
     * @return true if file was loaded successfully
     */
    bool loadFromFile(const std::string& envFilePath = "")
    {
        ensureLoaded(envFilePath);
        return loaded;
    }

    /**
     * @brief Get an API key by name
     * @param keyName The name of the key (e.g., "VIRUSTOTAL_API_KEY")
     * @return The API key value, or empty optional if not found
     */
    std::optional<std::string> getKey(const std::string& keyName) const
    {
        auto it = keys.find(keyName);
        if (it != keys.end()) {
            return it->second;
        }
        return {};
    }

    /**
     * @brief Check if a key exists and is not the placeholder value
     * @note Automatically ensures keys are loaded before checking
     */
    bool hasValidKey(const std::string& keyName)
    {
        ensureLoaded();
        auto key = getKey(keyName);
        return key.has_value() && !key->empty() && *key != "your_api_key_here";
    }

    bool isLoaded() const { return loaded; }
};

// Global API key manager instance
inline ApiKeyManager& getApiKeyManager()
{
    static ApiKeyManager instance;
    return instance;
}

/**
 * @brief HTTP Request builder class with fluent interface.
 * 
 * Allows constructing HTTP requests with method chaining:
 * @code
 * HttpRequest request;
 * request.setUrl("https://api.example.com/endpoint")
 *        .setMethod("GET")
 *        .addHeader("Authorization", "Bearer token123");
 * @endcode
 */
class HttpRequest
{
    std::string url;
    std::string method = "GET";
    std::string params;
    std::string body;
    std::unordered_map<std::string, std::string> headersMap;

  public:
    HttpRequest& setUrl(const std::string& u)
    {
        url = u;
        return *this;
    }

    const std::string& getUrl() const
    {
        return url;
    }

    HttpRequest& setMethod(const std::string& m)
    {
        method = m;
        return *this;
    }

    const std::string& getMethod() const
    {
        return method;
    }

    HttpRequest& setParams(const std::string& p)
    {
        params = p;
        return *this;
    }

    bool hasParams() const
    {
        return !params.empty();
    }

    const std::string& getParams() const
    {
        return params;
    }

    HttpRequest& setBody(const std::string& b)
    {
        body = b;
        return *this;
    }

    const std::string& getBody() const
    {
        return body;
    }

    bool hasBody() const
    {
        return !body.empty();
    }

    HttpRequest& addHeader(const std::string& key, const std::string& value)
    {
        headersMap[key] = value;
        return *this;
    }

    HttpRequest& removeHeader(const std::string& key)
    {
        headersMap.erase(key);
        return *this;
    }

    std::optional<std::string> getHeader(const std::string& key) const
    {
        const auto it = headersMap.find(key);
        if (it != headersMap.end())
            return it->second;
        return {};
    }

    /**
     * @brief Set API key authentication header
     * @param apiKey The API key to use
     * @param headerName The header name (default: "x-apikey" for VirusTotal)
     */
    HttpRequest& setApiKey(const std::string& apiKey, const std::string& headerName = "x-apikey")
    {
        return addHeader(headerName, apiKey);
    }

    /**
     * @brief Load and set API key from the .env file
     * @param keyName The key name in .env file (e.g., "VIRUSTOTAL_API_KEY")
     * @param headerName The header name to use (default: "x-apikey")
     * @return true if key was loaded and set successfully
     */
    bool loadApiKeyFromEnv(const std::string& keyName, const std::string& headerName = "x-apikey")
    {
        auto& manager = getApiKeyManager();
        if (!manager.isLoaded()) {
            manager.loadFromFile();
        }
        
        auto key = manager.getKey(keyName);
        if (key.has_value() && !key->empty() && *key != "your_api_key_here") {
            setApiKey(*key, headerName);
            return true;
        }
        return false;
    }

    /**
     * @brief Set Bearer token authentication
     * @param token The bearer token
     */
    HttpRequest& setBearerToken(const std::string& token)
    {
        return addHeader("Authorization", "Bearer " + token);
    }

    /**
     * @brief Generate curl_slist from headers map
     * @return curl_slist pointer (caller must free with curl_slist_free_all)
     */
    struct curl_slist* generateCurlHeaders() const
    {
        struct curl_slist* list = nullptr;
        for (const auto& pair : headersMap) {
            std::ostringstream oss;
            oss << pair.first << ": " << pair.second;
            list = curl_slist_append(list, oss.str().c_str());
        }
        return list;
    }
};

/**
 * @brief Send an HTTP request and return the response.
 * 
 * This function handles all the libcurl setup and teardown, and returns
 * the response in a structured format suitable for API consumption.
 * 
 * @param request The HTTP request to send
 * @return HttpResponse containing status code, body, headers, and any error
 */
HttpResponse sendHttpRequest(const HttpRequest& request);

/**
 * @brief Initialize the HTTP client library.
 * 
 * Should be called once before making any HTTP requests.
 * Thread-safe to call multiple times (will only initialize once).
 * 
 * @return true if initialization succeeded, false otherwise
 */
bool initHttpClient();

/**
 * @brief Cleanup the HTTP client library.
 * 
 * Should be called when the plugin is unloaded.
 */
void cleanupHttpClient();

/**
 * @brief Test the HTTP client by making a request to httpbin.org
 * 
 * This function is used for verification purposes.
 * 
 * @return HttpResponse from the test request
 */
HttpResponse testHttpClient();

} // namespace GView::GenericPlugins::HashAnalyzer
