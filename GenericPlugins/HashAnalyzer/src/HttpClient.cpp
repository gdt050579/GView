#include "HttpClient.hpp"

#include <atomic>
#include <mutex>

namespace GView::GenericPlugins::HashAnalyzer
{

// Static initialization flag
static std::atomic<bool> g_curlInitialized{false};
static std::mutex g_initMutex;

// Callback function to write response body to string
static size_t writeToString(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    std::string* response = static_cast<std::string*>(userdata);
    const size_t totalSize = size * nmemb;
    response->append(static_cast<char*>(ptr), totalSize);
    return totalSize;
}

// Callback function to capture response headers
static size_t headerCallback(char* buffer, size_t size, size_t nitems, void* userdata)
{
    auto* headers = static_cast<std::unordered_map<std::string, std::string>*>(userdata);
    const size_t totalSize = size * nitems;
    
    std::string headerLine(buffer, totalSize);
    
    // Remove trailing \r\n
    while (!headerLine.empty() && (headerLine.back() == '\r' || headerLine.back() == '\n')) {
        headerLine.pop_back();
    }
    
    // Skip empty lines and HTTP status line
    if (headerLine.empty() || headerLine.substr(0, 4) == "HTTP") {
        return totalSize;
    }
    
    // Parse "Header-Name: value" format
    const size_t colonPos = headerLine.find(':');
    if (colonPos != std::string::npos) {
        std::string key = headerLine.substr(0, colonPos);
        std::string value = headerLine.substr(colonPos + 1);
        
        // Trim leading whitespace from value
        while (!value.empty() && value.front() == ' ') {
            value.erase(0, 1);
        }
        
        (*headers)[key] = value;
    }
    
    return totalSize;
}

bool initHttpClient()
{
    // Double-checked locking for thread-safe initialization
    if (g_curlInitialized.load()) {
        return true;
    }
    
    std::lock_guard<std::mutex> lock(g_initMutex);
    
    if (g_curlInitialized.load()) {
        return true;
    }
    
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return false;
    }
    
    g_curlInitialized.store(true);
    return true;
}

void cleanupHttpClient()
{
    if (g_curlInitialized.load()) {
        curl_global_cleanup();
        g_curlInitialized.store(false);
    }
}

HttpResponse sendHttpRequest(const HttpRequest& request)
{
    HttpResponse response;
    
    // Ensure libcurl is initialized
    if (!initHttpClient()) {
        response.error = "Failed to initialize HTTP client";
        response.success = false;
        return response;
    }
    
    // Initialize CURL handle
    CURL* curl = curl_easy_init();
    if (!curl) {
        response.error = "Failed to create CURL handle";
        response.success = false;
        return response;
    }
    
    // Build full URL with params
    std::string fullUrl = request.getUrl();
    if (request.hasParams()) {
        fullUrl += "?" + request.getParams();
    }
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
    
    // Follow redirects
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    // Set timeout (30 seconds)
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    
    // Set method
    const std::string& method = request.getMethod();
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (request.hasBody()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.getBody().size()));
        }
    } else if (method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        if (request.hasBody()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.getBody().size()));
        }
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else if (method == "PATCH") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        if (request.hasBody()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.getBody().size()));
        }
    }
    // GET is the default, no need to set explicitly
    
    // Set headers
    struct curl_slist* curlHeaders = request.generateCurlHeaders();
    if (curlHeaders) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curlHeaders);
    }
    
    // Set response callbacks
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    
    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    
    // Get HTTP status code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.statusCode);
    
    // Cleanup headers
    if (curlHeaders) {
        curl_slist_free_all(curlHeaders);
    }
    
    // Cleanup CURL handle
    curl_easy_cleanup(curl);
    
    // Check for errors
    if (res != CURLE_OK) {
        response.error = "CURL error: " + std::string(curl_easy_strerror(res));
        response.success = false;
        return response;
    }
    
    response.success = true;
    return response;
}

HttpResponse testHttpClient()
{
    // Test with httpbin.org - a public HTTP testing service
    HttpRequest request;
    request.setUrl("https://httpbin.org/get")
           .setMethod("GET")
           .addHeader("Accept", "application/json")
           .addHeader("User-Agent", "GView-HashAnalyzer/1.0");
    
    return sendHttpRequest(request);
}

} // namespace GView::GenericPlugins::HashAnalyzer
