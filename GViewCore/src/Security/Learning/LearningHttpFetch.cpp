// IHttpTransport of the web build (GVIEW_BROWSER_NETWORK): the requests go through fetch() of the page.
//
// A web page has no sockets, so libcurl can not run; fetch() is the only HTTP client, and the browser owns TLS. The
// security properties of the desktop transport (LearningHttp.cpp) map as follows:
//   VERIFYPEER / VERIFYHOST / TLS >= 1.2  -> enforced by the browser (it never lets a page skip certificate checks)
//   PROTOCOLS_STR "https"                 -> CheckTransportRequirements (http:// only for local development)
//   FOLLOWLOCATION = 0                    -> redirect: "error" (the token header never leaves the configured server)
//   CAINFO_BLOB (caPem)                   -> impossible in a page: the connection is refused (fail closed)
//   MAXFILESIZE / write callback cap      -> Content-Length check + byte counting stream reader (aborts past the cap)
//   TIMEOUT / progress cancel             -> AbortController (timer) / gview_js_fetch_abort when the cancel flag is set
// Cookies and ambient credentials are never sent (credentials: "omit"), the referrer is not sent, nothing is cached.
// The server must answer the CORS preflight (docs/source/learning_mode_protocol.rst, "Browser clients").
//
// Waiting: nothing ever waits. Inside a job of a BackgroundWorker, Post() returns the response recorded by a previous run
// of the job, or starts the request and abandons the run (JobReplay::Wait): the job is run again once the response is
// there (BackgroundWorkerWasm.cpp, JobReplay.hpp). Outside a job (the final telemetry flush of End session) the
// request is sent without waiting for its answer (keepalive: it survives the page being closed).
//
// ABI with the JavaScript side (numbers only; JavaScript writes only into buffers allocated by C++ for that purpose):
//   id = gview_js_fetch_begin(url, headers, headersLen, body, bodyLen, maxBytes, timeoutMs, keepalive) 0 = not started
//   gview_js_fetch_state(id)          0 = pending, 1 = response received, 2 = failed (network / CORS / TLS / abort)
//   gview_js_fetch_status / _too_large / _headers_size / _headers_copy / _body_size / _body_copy / _error_copy
//   gview_js_fetch_abort(id), gview_js_fetch_release(id) (wipes and forgets the request)
//   gview_js_fetch_detach(id)         the request goes on; it is forgotten once it settles (nobody reads its answer)

#include "LearningHttp.hpp"

#include <emscripten/emscripten.h>

#include <algorithm>
#include <limits>

EM_JS_DEPS(gview_learning_fetch, "$UTF8ToString,$stringToUTF8,$lengthBytesUTF8");

// Starts the request. The headers are "Name: value" lines separated by "\n". Returns the request id (> 0) or 0.
EM_JS(int32_t, gview_js_fetch_begin, (const char* url, const char* headers, uint32_t headersLen, const uint8_t* body, uint32_t bodyLen,
                                      uint32_t maxBytes, uint32_t timeoutMs, int32_t keepalive), {
    try {
        const st = Module["gviewNet"] || (Module["gviewNet"] = { next: 1, reqs: new Map() });
        const id = st.next;
        st.next = (st.next >= 0x7FFFFF00) ? 1 : st.next + 1;
        const ctl = new AbortController();
        const r = { state: 0, status: 0, headers: null, chunks: [], size: 0, tooLarge: false, error: "", ctl: ctl, timer: 0, detached: false };
        const hdrs = new Headers();
        const lines = UTF8ToString(headers, headersLen).split("\n");
        for (const line of lines) {
            const colon = line.indexOf(":");
            if (colon > 0) hdrs.append(line.slice(0, colon).trim(), line.slice(colon + 1).trim());
        }
        const payload = HEAPU8.slice(body, body + bodyLen); // copied: the wasm memory may grow (and move) meanwhile
        const target = UTF8ToString(url);
        st.reqs.set(id, r);
        const settle = () => {
            if (r.timer) { clearTimeout(r.timer); r.timer = 0; }
            if (r.detached) {
                for (const c of r.chunks) c.fill(0);
                st.reqs.delete(id);
                return;
            }
            const host = Module["appcui"];
            if (host && host.wake) host.wake(); // an idle AppCUI loop runs the next frame now (the job goes on)
        };
        r.settle = settle;
        r.timer = setTimeout(() => { if (r.state === 0) { r.error = "timeout"; ctl.abort(); } }, timeoutMs);
        (async () => {
            try {
                const resp = await fetch(target, {
                    method: "POST", mode: "cors", credentials: "omit", redirect: "error", cache: "no-store",
                    referrerPolicy: "no-referrer", headers: hdrs, body: payload, signal: ctl.signal,
                    keepalive: keepalive !== 0 && bodyLen <= 60000 }); // browsers cap keepalive bodies at 64 KiB
                if (r.state !== 0) return;
                r.status = resp.status;
                r.headers = resp.headers;
                const declared = resp.headers.get("content-length");
                if (declared !== null && declared.length > 0 && declared.length < 16 && !isNaN(Number(declared)) && Number(declared) > maxBytes) {
                    r.tooLarge = true;
                } else if (resp.body) {
                    const reader = resp.body.getReader();
                    for (;;) {
                        const part = await reader.read();
                        if (part.done) break;
                        if (r.state !== 0) { reader.cancel().catch(() => {}); return; }
                        r.size += part.value.length;
                        if (r.size > maxBytes) { r.tooLarge = true; reader.cancel().catch(() => {}); break; }
                        r.chunks.push(part.value);
                    }
                }
                if (r.tooLarge) {
                    for (const c of r.chunks) c.fill(0);
                    r.chunks = []; r.size = 0;
                    ctl.abort();
                }
                if (r.state === 0) r.state = 1;
            } catch (e) {
                if (r.state === 0) {
                    r.state = 2;
                    if (!r.error) r.error = (e && e.name === "AbortError") ? "aborted"
                                            : "network, TLS, CORS or redirect failure (details in the console of the browser)";
                }
            } finally {
                settle();
            }
        })();
        return id;
    } catch (e) {
        return 0;
    }
});

EM_JS(int32_t, gview_js_fetch_state, (int32_t id), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    return r ? r.state : 2;
});

EM_JS(int32_t, gview_js_fetch_status, (int32_t id), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    return r ? r.status : 0;
});

EM_JS(int32_t, gview_js_fetch_too_large, (int32_t id), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    return (r && r.tooLarge) ? 1 : 0;
});

// "name: value" lines (names in lower case, only the headers the server exposes through CORS); size in UTF-8 bytes
EM_JS(int32_t, gview_js_fetch_headers_size, (int32_t id), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    if (!r || !r.headers) return 0;
    let text = "";
    r.headers.forEach((value, name) => { text += name.toLowerCase() + ": " + value + "\n"; });
    r.headerText = text;
    return lengthBytesUTF8(text);
});

EM_JS(int32_t, gview_js_fetch_headers_copy, (int32_t id, char* buffer, uint32_t capacity), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    if (!r || typeof r.headerText !== "string") return -1;
    return stringToUTF8(r.headerText, buffer, capacity);
});

EM_JS(int32_t, gview_js_fetch_body_size, (int32_t id), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    return r ? r.size : 0;
});

// copies the body into [buffer, buffer + capacity) and wipes the JavaScript copy; returns the bytes copied, -1 = failed
EM_JS(int32_t, gview_js_fetch_body_copy, (int32_t id, uint8_t* buffer, uint32_t capacity), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    if (!r || r.size > capacity) return -1;
    let offset = 0;
    for (const c of r.chunks) {
        HEAPU8.set(c, buffer + offset);
        offset += c.length;
        c.fill(0);
    }
    r.chunks = [];
    return offset;
});

EM_JS(int32_t, gview_js_fetch_error_copy, (int32_t id, char* buffer, uint32_t capacity), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    return stringToUTF8(r ? r.error : "unknown request", buffer, capacity);
});

// aborts a pending request: its state becomes "failed" immediately (the caller does not wait for the promise)
EM_JS(void, gview_js_fetch_abort, (int32_t id), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    if (!r || r.state !== 0) return;
    r.state = 2;
    r.error = "aborted";
    try { r.ctl.abort(); } catch (e) {}
    if (r.settle) r.settle();
});

EM_JS(void, gview_js_fetch_release, (int32_t id), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    if (!r) return;
    if (r.state === 0) { try { r.ctl.abort(); } catch (e) {} }
    for (const c of r.chunks) c.fill(0);
    r.chunks = [];
    r.headers = null;
    r.headerText = null;
    st.reqs.delete(id);
});

// nobody waits for this request any more: it goes on, and is forgotten once it settles
EM_JS(void, gview_js_fetch_detach, (int32_t id), {
    const st = Module["gviewNet"];
    const r = st ? st.reqs.get(id) : undefined;
    if (!r) return;
    if (r.state !== 0) {
        for (const c of r.chunks) c.fill(0);
        st.reqs.delete(id);
        return;
    }
    r.detached = true;
});

EM_JS(int32_t, gview_js_page_is_local, (), {
    try {
        const h = String((globalThis.location && globalThis.location.hostname) || "").toLowerCase();
        return (h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h === "::1" || h.endsWith(".localhost")) ? 1 : 0;
    } catch (e) {
        return 0;
    }
});

namespace GView::Security::Learning
{
namespace
{
    constexpr int32_t FETCH_PENDING          = 0;
    constexpr int32_t FETCH_RESPONSE         = 1;
    constexpr size_t MAX_HEADER_COUNT        = 64;
    constexpr size_t MAX_HEADER_LINE_LENGTH  = 8 * 1024;
    constexpr size_t MAX_HEADERS_TEXT_LENGTH = MAX_HEADER_COUNT * MAX_HEADER_LINE_LENGTH;

    void ParseHeaders(std::string_view text, HeaderMap& out)
    {
        while (!text.empty() && out.size() < MAX_HEADER_COUNT)
        {
            const auto eol        = text.find('\n');
            std::string_view line = text.substr(0, eol);
            text                  = eol == std::string_view::npos ? std::string_view() : text.substr(eol + 1);
            if (line.size() > MAX_HEADER_LINE_LENGTH)
                continue;
            const auto colon = line.find(':');
            if (colon == std::string_view::npos || colon == 0)
                continue;
            std::string name(line.substr(0, colon));
            for (auto& c : name)
            {
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c - 'A' + 'a');
            }
            std::string_view value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                value.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r'))
                value.remove_suffix(1);
            out.emplace_back(std::move(name), std::string(value));
        }
    }

    std::string ErrorOf(int32_t id)
    {
        char buffer[512] = {};
        if (gview_js_fetch_error_copy(id, buffer, sizeof(buffer)) <= 0)
            return "network request failed";
        return buffer;
    }

    void CollectResponse(int32_t id, size_t cap, HttpResponse& resp)
    {
        if (gview_js_fetch_state(id) != FETCH_RESPONSE)
        {
            resp.transportOk    = false;
            resp.transportError = ErrorOf(id);
            return;
        }
        resp.status      = gview_js_fetch_status(id);
        resp.transportOk = resp.status > 0;
        if (!resp.transportOk)
        {
            resp.transportError = "no HTTP status received";
            return;
        }
        const int32_t headersSize = gview_js_fetch_headers_size(id);
        if (headersSize > 0 && static_cast<size_t>(headersSize) <= MAX_HEADERS_TEXT_LENGTH)
        {
            std::string text(static_cast<size_t>(headersSize) + 1, '\0'); // + the 0 written by stringToUTF8
            const int32_t copied = gview_js_fetch_headers_copy(id, text.data(), static_cast<uint32_t>(text.size()));
            if (copied > 0)
                ParseHeaders(std::string_view(text.data(), static_cast<size_t>(copied)), resp.headers);
        }
        if (gview_js_fetch_too_large(id) != 0)
        {
            resp.tooLarge       = true;
            resp.transportError = "response exceeds the allowed size";
            return;
        }
        const int32_t size = gview_js_fetch_body_size(id);
        if (size <= 0)
            return;
        if (static_cast<size_t>(size) > cap)
        {
            resp.tooLarge       = true;
            resp.transportError = "response exceeds the allowed size";
            return;
        }
        try
        {
            resp.body.resize(static_cast<size_t>(size));
        }
        catch (...)
        {
            resp.transportOk    = false;
            resp.transportError = "out of memory";
            return;
        }
        const int32_t copied = gview_js_fetch_body_copy(id, resp.body.data(), static_cast<uint32_t>(resp.body.size()));
        if (copied != size)
        {
            resp.body.clear();
            resp.transportOk    = false;
            resp.transportError = "the response body could not be read";
        }
    }

    class FetchTransport : public IHttpTransport
    {
        TransportConfig cfg;
        std::string policyId; // the UI and the jobs run on the same thread, never concurrently

      public:
        explicit FetchTransport(TransportConfig c) : cfg(std::move(c))
        {
        }

        void SetPolicyId(std::string_view id) override
        {
            policyId.assign(id);
        }

        HttpResponse Post(const HttpRequest& req) override
        {
            HttpResponse resp;
            if (!Detail::IsValidRequestPath(req.path))
            {
                resp.transportError = "invalid request path";
                return resp;
            }
            // fail closed here too, not only when the session connects
            if (auto st = CheckTransportRequirements(cfg, true, PageIsServedLocally()); !st.ok)
            {
                resp.transportError = st.message;
                return resp;
            }
            SecureString headers;
            for (const auto& h : BuildRequestHeaders(cfg.token, cfg.clientVersion, policyId))
            {
                headers.append(h.data(), h.size());
                headers.push_back('\n');
            }
            // no "Expect:" (a forbidden header name for fetch; the browser decides)
            headers.append("Content-Type: application/json; charset=utf-8\nAccept: application/json, application/octet-stream\n");

            const bool inJob = JobReplay::Active();
            if (inJob)
            {
                // a previous run of this job already got the answer
                if (auto replayed = JobReplay::ReplayNext(req.path); replayed.has_value())
                    return std::move(*replayed);
            }
            if (req.cancel != nullptr && req.cancel->load(std::memory_order_acquire))
            {
                resp.transportError = "aborted";
                return resp;
            }

            const std::string url = cfg.serverUrl + req.path;
            const size_t cap      = std::min<size_t>(req.maxResponseBytes, static_cast<size_t>(std::numeric_limits<int32_t>::max()));
            const long timeoutSec = std::clamp<long>(req.totalTimeoutSeconds, 1, 3600);
            const int32_t id      = gview_js_fetch_begin(
                  url.c_str(),
                  headers.data(),
                  static_cast<uint32_t>(headers.size()),
                  reinterpret_cast<const uint8_t*>(req.body.data()),
                  static_cast<uint32_t>(req.body.size()),
                  static_cast<uint32_t>(cap),
                  static_cast<uint32_t>(timeoutSec * 1000),
                  inJob ? 0 : 1);
            if (id <= 0)
            {
                resp.transportError = "the browser refused to start the request";
                return resp;
            }
            if (!inJob)
            {
                // nobody can wait here (UI context, e.g. the final telemetry flush): the request goes on by itself
                gview_js_fetch_detach(id);
                resp.transportError = "sent without waiting for the answer";
                return resp;
            }
            JobReplay::PendingRequest pending;
            pending.path    = req.path;
            pending.cancel  = req.cancel;
            pending.ready   = [id]() { return gview_js_fetch_state(id) != FETCH_PENDING; };
            pending.abort   = [id]() { gview_js_fetch_abort(id); };
            pending.collect = [id, cap]() {
                HttpResponse r;
                CollectResponse(id, cap, r);
                gview_js_fetch_release(id);
                return r;
            };
            JobReplay::Wait(std::move(pending)); // abandons this run of the job; it is run again with the answer
        }
    };
} // namespace

bool PageIsServedLocally() noexcept
{
    return gview_js_page_is_local() == 1;
}

std::unique_ptr<IHttpTransport> CreateFetchTransport(TransportConfig config)
{
    return std::make_unique<FetchTransport>(std::move(config));
}
} // namespace GView::Security::Learning
