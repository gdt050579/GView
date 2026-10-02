#include "LearningHttp.hpp"

#include <curl/curl.h>
#include <mutex>

namespace GView::Security::Learning
{
namespace
{
    constexpr size_t MAX_HEADER_COUNT       = 64;
    constexpr size_t MAX_HEADER_LINE_LENGTH = 8 * 1024;

    std::once_flag g_curlInitFlag;
    bool g_curlInitOk = false;

    bool EnsureCurlGlobal() noexcept
    {
        std::call_once(g_curlInitFlag, []() { g_curlInitOk = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; });
        return g_curlInitOk;
    }

    bool IsValidRequestPath(std::string_view path) noexcept
    {
        if (!path.starts_with("/GView/") || path.size() > 256)
            return false;
        for (char c : path)
        {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '_' || c == '-'))
                return false;
        }
        return path.find("//") == std::string_view::npos;
    }

    struct TransferContext {
        HttpResponse* response;
        size_t cap;
        const std::atomic<bool>* cancel;
    };

    int ProgressCallback(void* userdata, curl_off_t, curl_off_t, curl_off_t, curl_off_t) noexcept
    {
        const auto* ctx = static_cast<const TransferContext*>(userdata);
        return (ctx->cancel != nullptr && ctx->cancel->load(std::memory_order_acquire)) ? 1 : 0;
    }

    size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) noexcept
    {
        auto* ctx = static_cast<TransferContext*>(userdata);
        // size is always 1 for curl write callbacks; guard against overflow anyway
        if (size != 0 && nmemb > SIZE_MAX / size)
            return 0;
        const size_t n = size * nmemb;
        // returning a short count aborts the transfer (CURLE_WRITE_ERROR)
        return Detail::AppendBodyWithCap(*ctx->response, reinterpret_cast<const uint8*>(ptr), n, ctx->cap) ? n : 0;
    }

    size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) noexcept
    {
        auto* ctx = static_cast<TransferContext*>(userdata);
        if (size != 0 && nitems > SIZE_MAX / size)
            return 0;
        const size_t n = size * nitems;
        if (n > MAX_HEADER_LINE_LENGTH)
            return n; // ignore absurd lines, do not abort
        std::string_view line(buffer, n);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.remove_suffix(1);
        try
        {
            if (line.starts_with("HTTP/"))
            {
                // a new response (e.g. after "100 Continue"): headers of the previous one are discarded
                ctx->response->headers.clear();
                return n;
            }
            const size_t colon = line.find(':');
            if (colon == std::string_view::npos || colon == 0 || ctx->response->headers.size() >= MAX_HEADER_COUNT)
                return n;
            std::string name(line.substr(0, colon));
            for (auto& c : name)
            {
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c - 'A' + 'a');
            }
            std::string_view value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                value.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                value.remove_suffix(1);
            if (name == "content-length")
            {
                // pre-size the body when the length is known and within the cap
                uint64 len = 0;
                bool ok    = !value.empty() && value.size() < 20;
                for (char c : value)
                {
                    if (c < '0' || c > '9')
                    {
                        ok = false;
                        break;
                    }
                    len = len * 10 + static_cast<uint64>(c - '0');
                }
                if (ok && len <= ctx->cap)
                    ctx->response->body.reserve(static_cast<size_t>(len));
            }
            ctx->response->headers.emplace_back(std::move(name), std::string(value));
        }
        catch (...)
        {
            return 0;
        }
        return n;
    }

    struct CurlHandle {
        CURL* curl{ nullptr };
        curl_slist* headers{ nullptr };
        ~CurlHandle()
        {
            if (headers)
                curl_slist_free_all(headers);
            if (curl)
                curl_easy_cleanup(curl);
        }
    };

    class CurlTransport : public IHttpTransport
    {
        TransportConfig cfg;
        std::mutex policyMutex;
        std::string policyId;

      public:
        explicit CurlTransport(TransportConfig c) : cfg(std::move(c))
        {
        }

        void SetPolicyId(std::string_view id) override
        {
            std::lock_guard<std::mutex> lk(policyMutex);
            policyId.assign(id);
        }

        HttpResponse Post(const HttpRequest& req) override
        {
            HttpResponse resp;
            if (!IsValidRequestPath(req.path))
            {
                resp.transportError = "invalid request path";
                return resp;
            }
            if (!EnsureCurlGlobal())
            {
                resp.transportError = "libcurl initialisation failed";
                return resp;
            }
            CurlHandle h;
            h.curl = curl_easy_init();
            if (!h.curl)
            {
                resp.transportError = "curl_easy_init failed";
                return resp;
            }
            std::string currentPolicy;
            {
                std::lock_guard<std::mutex> lk(policyMutex);
                currentPolicy = policyId;
            }
            for (const auto& hdr : BuildRequestHeaders(cfg.token, cfg.clientVersion, currentPolicy))
            {
                // libcurl keeps its own copy; ours is wiped by SecureString
                auto* next = curl_slist_append(h.headers, hdr.c_str());
                if (!next)
                {
                    resp.transportError = "out of memory";
                    return resp;
                }
                h.headers = next;
            }
            for (const char* fixed : { "Content-Type: application/json; charset=utf-8", "Accept: application/json, application/octet-stream", "Expect:" })
            {
                auto* next = curl_slist_append(h.headers, fixed);
                if (!next)
                {
                    resp.transportError = "out of memory";
                    return resp;
                }
                h.headers = next;
            }

            const std::string url = cfg.serverUrl + req.path;
            const bool plainHttp  = url.starts_with("http://");
            if (plainHttp && !cfg.allowPlainHttpLocalhost)
            {
                resp.transportError = "plain HTTP is not allowed";
                return resp;
            }
            char errorBuffer[CURL_ERROR_SIZE] = {};
            TransferContext ctx{ &resp, req.maxResponseBytes, req.cancel };

            CURL* c = h.curl;
            curl_easy_setopt(c, CURLOPT_ERRORBUFFER, errorBuffer);
            curl_easy_setopt(c, CURLOPT_URL, url.c_str());
            curl_easy_setopt(c, CURLOPT_POST, 1L);
            curl_easy_setopt(c, CURLOPT_POSTFIELDS, req.body.data());
            curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(req.body.size()));
            curl_easy_setopt(c, CURLOPT_HTTPHEADER, h.headers);
            // Never follow redirects: the access token header must only ever reach the configured server.
            curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
            curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, plainHttp ? "http" : "https");
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(c, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
            if (!cfg.caPem.empty())
            {
                curl_blob blob;
                blob.data  = const_cast<char*>(cfg.caPem.data());
                blob.len   = cfg.caPem.size();
                blob.flags = CURL_BLOB_COPY;
                curl_easy_setopt(c, CURLOPT_CAINFO_BLOB, &blob);
            }
            else
            {
#ifdef BUILD_FOR_WINDOWS
                // OpenSSL backend: trust the Windows certificate store (no CA bundle ships with GView)
                curl_easy_setopt(c, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
#endif
            }
            curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECONDS);
            curl_easy_setopt(c, CURLOPT_TIMEOUT, req.totalTimeoutSeconds);
            curl_easy_setopt(c, CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(req.maxResponseBytes));
            curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
            curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, HeaderCallback);
            curl_easy_setopt(c, CURLOPT_HEADERDATA, &ctx);
            if (req.cancel != nullptr)
            {
                curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, ProgressCallback);
                curl_easy_setopt(c, CURLOPT_XFERINFODATA, &ctx);
                curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
            }

            const CURLcode res = curl_easy_perform(c);
            long status        = 0;
            curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
            resp.status = status;
            if (res == CURLE_OK)
            {
                resp.transportOk = status > 0;
                if (!resp.transportOk)
                    resp.transportError = "no HTTP status received";
            }
            else if (res == CURLE_FILESIZE_EXCEEDED || (res == CURLE_WRITE_ERROR && resp.tooLarge))
            {
                resp.tooLarge       = true;
                resp.transportOk    = status > 0;
                resp.transportError = "response exceeds the allowed size";
                resp.body.clear();
            }
            else
            {
                resp.transportOk    = false;
                resp.transportError = errorBuffer[0] ? std::string(errorBuffer) : std::string(curl_easy_strerror(res));
                resp.body.clear();
            }
            return resp;
        }
    };
} // namespace

bool Detail::AppendBodyWithCap(HttpResponse& response, const uint8* data, size_t size, size_t cap)
{
    if (size > cap || response.body.size() > cap - size)
    {
        response.tooLarge = true;
        return false;
    }
    try
    {
        response.body.insert(response.body.end(), data, data + size);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

ServerError HttpResponse::ToError() const
{
    if (!transportOk)
    {
        ServerError e;
        e.code      = ErrorCode::Transport;
        e.details   = transportError;
        e.retryable = true;
        return e;
    }
    if (tooLarge)
    {
        ServerError e;
        e.code       = ErrorCode::Protocol;
        e.httpStatus = status;
        e.details    = "response exceeds the allowed size";
        return e;
    }
    return ParseErrorEnvelope(status, ToView(body), FindHeader(headers, "retry-after"));
}

std::vector<SecureString> BuildRequestHeaders(const SecureString& token, std::string_view clientVersion, std::string_view policyId)
{
    std::vector<SecureString> h;
    h.reserve(4);
    SecureString auth("XAppUserID: ");
    auth.append(token.data(), token.size());
    h.push_back(std::move(auth));
    SecureString client("X-GView-Client: ");
    client.append(clientVersion.data(), clientVersion.size());
    h.push_back(std::move(client));
    h.emplace_back("X-GView-Protocol: 2");
    if (!policyId.empty())
    {
        SecureString pol("X-GView-Policy: ");
        pol.append(policyId.data(), policyId.size());
        h.push_back(std::move(pol));
    }
    return h;
}

std::unique_ptr<IHttpTransport> CreateCurlTransport(TransportConfig config)
{
    return std::make_unique<CurlTransport>(std::move(config));
}
} // namespace GView::Security::Learning
