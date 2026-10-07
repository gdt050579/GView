#pragma once

// Minimal libcurl GET client for the auto-updater (worker threads only, never the UI thread).
// Security options mirror Security/Learning/LearningHttp.cpp: https only (also for redirects), TLS >= 1.2,
// peer + host verification, native CA store on Windows, size caps, timeouts and cooperative cancellation.

#include "GView.hpp"

#include <atomic>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace GView::Update
{
struct HttpGetRequest {
    std::string url;
    std::vector<std::string> headers; // "Name: value"
    uint64 maxBytes{ 1024 * 1024 };
    long connectTimeoutSeconds{ 10 };
    long totalTimeoutSeconds{ 30 }; // 0 = no total limit (large downloads rely on the low speed limit)
    long lowSpeedSeconds{ 30 };     // abort when slower than 1 KB/s for this long
    bool followRedirects{ false };
    std::string proxy;
    const std::atomic<bool>* cancel{ nullptr };
    // called on the worker thread with (received, expectedTotal or 0)
    std::function<void(uint64, uint64)> progress;
};

struct HttpGetResponse {
    bool transportOk{ false }; // an HTTP status line was received
    long status{ 0 };
    std::string body;          // memory downloads only
    std::string etag;
    bool tooLarge{ false };
    bool cancelled{ false };
    std::string error; // transport error description

    bool IsSuccess() const noexcept
    {
        return transportOk && status >= 200 && status < 300 && !tooLarge && !cancelled;
    }
    std::string Describe() const;
};

HttpGetResponse HttpGetToMemory(const HttpGetRequest& request);
// Streams the body into 'destination' (created/truncated). The file is removed on any failure.
HttpGetResponse HttpGetToFile(const HttpGetRequest& request, const std::filesystem::path& destination);

// "GView/<version> (<os>; <arch>)"
std::string UserAgent();
} // namespace GView::Update
