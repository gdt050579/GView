#pragma once

#include "GView.hpp"
#include <curl/curl.h>
#include <unordered_map>
#include <sstream>

namespace GView::GenericPlugins::FileDownloader
{
class HttpRequest
{
    std::string url;
    std::string method;
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

    // Generate curl_slist from map
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
} // namespace GView::GenericPlugins::FileDownloader
