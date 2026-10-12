#pragma once

// HTTPS transport for Learning and Evaluation Mode.
// IHttpTransport is the seam used by unit tests (FakeTransport), by the libcurl implementation (desktop) and by the
// fetch() implementation of the web build (LearningHttpFetch.cpp, GVIEW_BROWSER_NETWORK).

#include "LearningProtocol.hpp"
#include "JobReplay.hpp"

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
    // WebAssembly: called from a job of a BackgroundWorker (the job is re-run when the response arrives, see
    // JobReplay.hpp), or outside a job (final telemetry flush), where the request is sent without waiting for it.
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

#ifdef BUILD_FOR_WASM
namespace JobReplay
{
    // a request that the running job waits for (see JobReplay.hpp)
    struct PendingRequest {
        std::string path;
        std::function<bool()> ready;            // the response (or the failure) is there
        std::function<HttpResponse()> collect;  // takes it (once)
        std::function<void()> abort;            // stops it: collect() then reports a transport error
        const std::atomic<bool>* cancel{ nullptr };
    };
    // Transport side, inside a job: the response this request got in a previous run of the job, if any. A replayed
    // response recorded for another path means the job is not deterministic: it is refused with a transport error.
    std::optional<HttpResponse> ReplayNext(std::string_view path);
    // Records the request the job now waits for and abandons the run (throws NetworkPending).
    [[noreturn]] void Wait(PendingRequest pending);
} // namespace JobReplay
#endif

// Builds the request header list exactly as sent on the wire (exposed for unit tests).
std::vector<SecureString> BuildRequestHeaders(const SecureString& token, std::string_view clientVersion, std::string_view policyId);

std::unique_ptr<IHttpTransport> CreateCurlTransport(TransportConfig config);
#ifdef GVIEW_BROWSER_NETWORK
// WebAssembly: requests go through fetch() of the page (LearningHttpFetch.cpp)
std::unique_ptr<IHttpTransport> CreateFetchTransport(TransportConfig config);
#endif

// The transport of this build: fetch() in the browser, libcurl otherwise (a stub that always fails without network).
std::unique_ptr<IHttpTransport> CreateDefaultTransport(TransportConfig config);

#ifdef GVIEW_BROWSER_NETWORK
constexpr bool BROWSER_TRANSPORT = true;
#else
constexpr bool BROWSER_TRANSPORT = false;
#endif
// Browser build: the page itself is served from a loopback host (localhost, 127.0.0.1, [::1]). False in other builds.
bool PageIsServedLocally() noexcept;

// Checks done before any request is sent. The browser owns TLS: it can not restrict trust to a private CA (caPem of the
// connection string) - such a connection is refused instead of silently trusting the certificate store of the system -
// and plain HTTP is only possible for local development (page served from the same machine).
// browserTransport: the requests go through fetch() of a web page; pageIsLocal: the page origin is a loopback host.
Utils::GStatus CheckTransportRequirements(const TransportConfig& config, bool browserTransport, bool pageIsLocal);

namespace Detail
{
    // body accumulation used by the libcurl write callback; returns false (and sets tooLarge) when cap would be exceeded
    bool AppendBodyWithCap(HttpResponse& response, const uint8* data, size_t size, size_t cap);
    // "/GView/..." made of [A-Za-z0-9/_-] only, without "//", at most 256 characters
    bool IsValidRequestPath(std::string_view path) noexcept;
} // namespace Detail
} // namespace GView::Security::Learning
