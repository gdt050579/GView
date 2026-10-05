#pragma once

// HTTPS transport for Learning and Evaluation Mode.
// IHttpTransport is the seam used by unit tests (FakeTransport) and by the real libcurl implementation.

#include "LearningProtocol.hpp"

#include <atomic>
#include <memory>
#include <mutex>

namespace GView::Security::Learning
{
struct HttpRequest {
    std::string path;      // e.g. "/GView/Connect" (appended to the server URL)
    SecureString body{ "{}" };
    size_t maxResponseBytes{ MAX_JSON_RESPONSE_BYTES };
    long totalTimeoutSeconds{ REQUEST_TIMEOUT_SECONDS };
    const std::atomic<bool>* cancel{ nullptr }; // when set to true the transfer is aborted (checked ~ every second)
};

struct HttpResponse {
    bool transportOk{ false }; // an HTTP status line was received
    long status{ 0 };
    SecureBytes body;
    HeaderMap headers;
    bool tooLarge{ false };    // response exceeded maxResponseBytes (transfer aborted)
    std::string transportError;

    inline bool IsSuccess() const noexcept
    {
        return transportOk && status >= 200 && status < 300 && !tooLarge;
    }
    // envelope for non-success responses (transport failures map to ErrorCode::Transport)
    ServerError ToError() const;
};

class IHttpTransport
{
  public:
    virtual ~IHttpTransport() = default;
    // Thread-safe: may be called concurrently from the worker and the telemetry flusher.
    virtual HttpResponse Post(const HttpRequest& request) = 0;
    // X-GView-Policy header value for subsequent requests ("" = do not send)
    virtual void SetPolicyId(std::string_view policyId) = 0;
};

struct TransportConfig {
    std::string serverUrl; // validated + normalised
    SecureString token;
    std::string caPem;
    bool allowPlainHttpLocalhost{ false };
    std::string clientVersion;
};

// Builds the request header list exactly as sent on the wire (exposed for unit tests).
std::vector<SecureString> BuildRequestHeaders(const SecureString& token, std::string_view clientVersion, std::string_view policyId);

std::unique_ptr<IHttpTransport> CreateCurlTransport(TransportConfig config);

namespace Detail
{
    // body accumulation used by the libcurl write callback; returns false (and sets tooLarge) when cap would be exceeded
    bool AppendBodyWithCap(HttpResponse& response, const uint8* data, size_t size, size_t cap);
} // namespace Detail
} // namespace GView::Security::Learning
