#include "HttpClient.hpp"
#include "UpdateCore.hpp"

#include <curl/curl.h>

#include <cstdio>
#include <fstream>
#include <mutex>

namespace GView::Update
{
namespace
{
    std::once_flag g_curlInitFlag;
    bool g_curlInitOk = false;

    bool EnsureCurlGlobal() noexcept
    {
        std::call_once(g_curlInitFlag, []() { g_curlInitOk = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; });
        return g_curlInitOk;
    }

    struct Sink {
        HttpGetResponse* response{ nullptr };
        std::ofstream* file{ nullptr };
        uint64 received{ 0 };
        uint64 cap{ 0 };
        bool writeFailed{ false };
        const HttpGetRequest* request{ nullptr };
    };

    size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) noexcept
    {
        auto* sink = static_cast<Sink*>(userdata);
        if (size != 0 && nmemb > SIZE_MAX / size)
            return 0;
        const size_t n = size * nmemb;
        if (n > sink->cap || sink->received > sink->cap - n) {
            sink->response->tooLarge = true;
            return 0; // aborts with CURLE_WRITE_ERROR
        }
        try {
            if (sink->file != nullptr) {
                sink->file->write(ptr, static_cast<std::streamsize>(n));
                if (!(*sink->file)) {
                    sink->writeFailed = true;
                    return 0;
                }
            } else {
                sink->response->body.append(ptr, n);
            }
        } catch (...) {
            sink->writeFailed = true;
            return 0;
        }
        sink->received += n;
        return n;
    }

    size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) noexcept
    {
        auto* sink = static_cast<Sink*>(userdata);
        if (size != 0 && nitems > SIZE_MAX / size)
            return 0;
        const size_t n = size * nitems;
        if (n > 8 * 1024)
            return n;
        std::string_view line(buffer, n);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.remove_suffix(1);
        if (line.starts_with("HTTP/")) {
            sink->response->etag.clear(); // a new response (redirect hop)
            return n;
        }
        constexpr std::string_view ETAG = "etag:";
        if (line.size() > ETAG.size()) {
            bool match = true;
            for (size_t i = 0; i < ETAG.size() && match; i++) {
                char c = line[i];
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c - 'A' + 'a');
                match = c == ETAG[i];
            }
            if (match) {
                auto value = line.substr(ETAG.size());
                while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                    value.remove_prefix(1);
                try {
                    sink->response->etag.assign(value);
                } catch (...) {
                    return 0;
                }
            }
        }
        return n;
    }

    int ProgressCallback(void* userdata, curl_off_t dltotal, curl_off_t dlnow, curl_off_t, curl_off_t) noexcept
    {
        auto* sink = static_cast<Sink*>(userdata);
        const auto* req = sink->request;
        if (req->cancel != nullptr && req->cancel->load(std::memory_order_acquire)) {
            sink->response->cancelled = true;
            return 1;
        }
        if (req->progress) {
            try {
                req->progress(dlnow > 0 ? static_cast<uint64>(dlnow) : 0, dltotal > 0 ? static_cast<uint64>(dltotal) : 0);
            } catch (...) {
            }
        }
        return 0;
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

    HttpGetResponse Perform(const HttpGetRequest& req, std::ofstream* file)
    {
        HttpGetResponse resp;
        if (!IsAllowedUrl(req.url)) {
            resp.error = "the URL is not allowed (https only)";
            return resp;
        }
        if (!EnsureCurlGlobal()) {
            resp.error = "libcurl initialisation failed";
            return resp;
        }
        CurlHandle h;
        h.curl = curl_easy_init();
        if (!h.curl) {
            resp.error = "curl_easy_init failed";
            return resp;
        }
        for (const auto& hdr : req.headers) {
            if (auto* next = curl_slist_append(h.headers, hdr.c_str()))
                h.headers = next;
            else {
                resp.error = "out of memory";
                return resp;
            }
        }
        const auto userAgent = "User-Agent: " + UserAgent();
        for (const char* fixed : { userAgent.c_str(), "Expect:" }) {
            if (auto* next = curl_slist_append(h.headers, fixed))
                h.headers = next;
            else {
                resp.error = "out of memory";
                return resp;
            }
        }

        Sink sink;
        sink.response = &resp;
        sink.file     = file;
        sink.cap      = req.maxBytes;
        sink.request  = &req;

        char errorBuffer[CURL_ERROR_SIZE] = {};
        CURL* c                           = h.curl;
        curl_easy_setopt(c, CURLOPT_ERRORBUFFER, errorBuffer);
        curl_easy_setopt(c, CURLOPT_URL, req.url.c_str());
        curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, h.headers);
#ifdef DISSASM_DEV
        const char* protocols = req.url.starts_with("http://") ? "http,https" : "https";
#else
        const char* protocols = "https";
#endif
        curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, protocols);
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, protocols);
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, req.followRedirects ? 1L : 0L);
        curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(c, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
#ifdef BUILD_FOR_WINDOWS
        // OpenSSL backend: trust the Windows certificate store (no CA bundle ships with GView)
        curl_easy_setopt(c, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
#endif
        if (!req.proxy.empty())
            curl_easy_setopt(c, CURLOPT_PROXY, req.proxy.c_str());
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, req.connectTimeoutSeconds);
        if (req.totalTimeoutSeconds > 0)
            curl_easy_setopt(c, CURLOPT_TIMEOUT, req.totalTimeoutSeconds);
        if (req.lowSpeedSeconds > 0) {
            curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1024L);
            curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, req.lowSpeedSeconds);
        }
        curl_easy_setopt(c, CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(req.maxBytes));
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(c, CURLOPT_HEADERDATA, &sink);
        curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, ProgressCallback);
        curl_easy_setopt(c, CURLOPT_XFERINFODATA, &sink);
        curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);

        const CURLcode res = curl_easy_perform(c);
        long status        = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
        resp.status = status;
        if (res == CURLE_OK) {
            resp.transportOk = status > 0;
            if (!resp.transportOk)
                resp.error = "no HTTP status received";
        } else if (res == CURLE_FILESIZE_EXCEEDED || resp.tooLarge) {
            resp.tooLarge    = true;
            resp.transportOk = status > 0;
            resp.error       = "the response is larger than allowed";
        } else if (res == CURLE_ABORTED_BY_CALLBACK || resp.cancelled) {
            resp.cancelled = true;
            resp.error     = "cancelled";
        } else if (sink.writeFailed) {
            resp.error = "unable to write the downloaded data to disk";
        } else {
            resp.error = errorBuffer[0] ? std::string(errorBuffer) : std::string(curl_easy_strerror(res));
        }
        if (!resp.IsSuccess())
            resp.body.clear();
        return resp;
    }
} // namespace

std::string HttpGetResponse::Describe() const
{
    if (cancelled)
        return "cancelled";
    if (!error.empty())
        return error;
    if (status == 403 || status == 429)
        return "the server refused the request (HTTP " + std::to_string(status) + ", rate limited?)";
    return "unexpected HTTP status " + std::to_string(status);
}

std::string UserAgent()
{
    const auto p = Platform::Current();
    std::string ua = "GView/" GVIEW_VERSION " (";
    ua += (p.os == PlatformOS::Windows) ? "Windows" : (p.os == PlatformOS::MacOS ? "macOS" : "Linux");
    ua += "; ";
    ua += (p.arch == Arch::X64) ? "x64" : (p.arch == Arch::Arm64 ? "arm64" : "unknown");
    ua += ")";
    return ua;
}

HttpGetResponse HttpGetToMemory(const HttpGetRequest& request)
{
    return Perform(request, nullptr);
}

HttpGetResponse HttpGetToFile(const HttpGetRequest& request, const std::filesystem::path& destination)
{
    HttpGetResponse resp;
    {
        std::ofstream out(destination, std::ios::binary | std::ios::trunc);
        if (!out) {
            resp.error = "unable to create the download file";
            return resp;
        }
        resp = Perform(request, &out);
        out.flush();
        if (!out && resp.IsSuccess()) {
            resp.transportOk = false;
            resp.error       = "unable to write the downloaded data to disk";
        }
    }
    if (!resp.IsSuccess()) {
        std::error_code ec;
        std::filesystem::remove(destination, ec);
    }
    return resp;
}
} // namespace GView::Update
