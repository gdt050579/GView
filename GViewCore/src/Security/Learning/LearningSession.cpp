#include "LearningSession.hpp"

#include <chrono>

namespace GView::Security::Learning
{
using RestrictedMode::Feature;
using RestrictedMode::Policy;
using RestrictedMode::StorageMode;

namespace
{
    constexpr uint64 TICK_INTERVAL_MS                  = 200;
    [[maybe_unused]] constexpr uint64 FOCUS_VALIDITY_MS = 1000;
    constexpr uint64 MAX_ACCOUNT_STEP_MS = 2000; // the UI loop may stall (modal dialogs); never credit more per tick
    constexpr long FINAL_FLUSH_TIMEOUT_S   = 2;
    constexpr uint64 FINAL_NOTES_TIMEOUT_MS = 5000; // all final note saves together (session end / exit)

    std::string_view ModeName(DeliveryMode m) noexcept
    {
        return m == DeliveryMode::Memory ? "memory" : "file";
    }
    std::string_view ModeName(StorageMode m) noexcept
    {
        return m == StorageMode::Memory ? "memory" : "file";
    }

    std::string RejectCodeOf(const std::string& message)
    {
        const auto pos = message.find(':');
        if (pos == std::string::npos || pos > 32)
            return "POLICY_REJECTED";
        return message.substr(0, pos);
    }

    uint64 DefaultMonoMs()
    {
        return static_cast<uint64>(
              std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    }
} // namespace

std::string_view SessionStateName(SessionState s) noexcept
{
    switch (s)
    {
    case SessionState::Disconnected:
        return "Disconnected";
    case SessionState::Connecting:
        return "Connecting";
    case SessionState::Active:
        return "Active";
    case SessionState::Legacy:
        return "Legacy (unrestricted)";
    case SessionState::Expired:
        return "Expired";
    case SessionState::Error:
        return "Error";
    }
    return "Unknown";
}

// ============================================================================ SubmissionTracker
std::string SubmissionTracker::IdFor(std::string_view problem, const SecureString& flag, const SecureString& explanation)
{
    SecureBytes material;
    material.reserve(problem.size() + flag.size() + explanation.size() + 2);
    material.insert(material.end(), problem.begin(), problem.end());
    material.push_back(0);
    material.insert(material.end(), flag.begin(), flag.end());
    material.push_back(0);
    material.insert(material.end(), explanation.begin(), explanation.end());
    std::array<uint8, 32> fp{};
    uint8 hash[32];
    if (!Crypto::Internal::ComputeSHA256(ToView(material), hash).ok)
        return {};
    std::copy(std::begin(hash), std::end(hash), fp.begin());

    auto& e = entries[std::string(problem)];
    if (!e.id.empty() && e.fingerprint == fp)
        return e.id; // same answer => transport retry => same idempotency key
    auto id = NewUuid4();
    if (!id.has_value())
        return {};
    e.fingerprint = fp;
    e.id          = *id;
    return e.id;
}

void SubmissionTracker::Consume(std::string_view problem)
{
    entries.erase(std::string(problem));
}

// ============================================================================ static network operations
ConnectResult LearningSession::PerformConnect(IHttpTransport& t, const ConnectionInfo& ci, uint64 now, const std::atomic<bool>* cancel)
{
    ConnectResult r;
    HttpRequest req;
    req.path             = "/GView/Connect";
    req.maxResponseBytes = MAX_CONNECT_RESPONSE_BYTES;
    req.cancel           = cancel;
    auto resp            = t.Post(req);
    if (resp.transportOk && (resp.status == 404 || resp.status == 405))
    {
        // pre-v2 server: only the legacy endpoint exists
        req.path = "/GView/";
        resp     = t.Post(req);
    }
    if (!resp.IsSuccess())
    {
        r.error  = resp.ToError();
        r.status = Utils::GStatus::Error(DescribeError(r.error));
        return r;
    }
    auto st = ParseConnectResponse(ToView(resp.body), r.response);
    if (!st.ok)
    {
        r.error.code = ErrorCode::Protocol;
        r.status     = Utils::GStatus::Error("Invalid connect response: " + st.message);
        return r;
    }
    if (r.response.legacy)
    {
        r.status = Utils::GStatus::Ok();
        return r;
    }
    if (ci.publicKey.size() != 32)
    {
        r.rejectCode = "POLICY_KEY_MISSING";
        r.status     = Utils::GStatus::Error(
              "POLICY_KEY_MISSING: the server sent a restricted policy but no policy public key is configured (connection string v2 or "
              "[GView] PolicyPublicKey). The policy cannot be verified and is refused.");
        return r;
    }
    Policy p;
    st = RestrictedMode::VerifyAndParsePolicy(
          BufferView(r.response.policyBytes.data(), r.response.policyBytes.size()),
          BufferView(r.response.signature.data(), r.response.signature.size()),
          BufferView(ci.publicKey.data(), ci.publicKey.size()),
          SubjectForToken(ci.token),
          ci.serverUrl,
          now,
          p);
    if (!st.ok)
    {
        r.rejectCode = RejectCodeOf(st.message);
        r.status     = st;
        return r;
    }
    r.policy = std::move(p);
    r.status = Utils::GStatus::Ok();
    return r;
}

CatalogueResult LearningSession::PerformFetchCatalogue(IHttpTransport& t, const std::atomic<bool>* cancel)
{
    CatalogueResult r;
    HttpRequest req;
    req.path             = "/GView/GetWeeks";
    req.maxResponseBytes = MAX_JSON_RESPONSE_BYTES;
    req.cancel           = cancel;
    auto resp            = t.Post(req);
    bool legacy          = false;
    if (resp.transportOk && (resp.status == 404 || resp.status == 405))
    {
        req.path = "/GView/GetProblems";
        resp     = t.Post(req);
        legacy   = true;
    }
    if (!resp.IsSuccess())
    {
        r.error  = resp.ToError();
        r.status = Utils::GStatus::Error(DescribeError(r.error));
        return r;
    }
    r.status = legacy ? ParseLegacyProblems(ToView(resp.body), r.catalogue) : ParseWeeks(ToView(resp.body), r.catalogue);
    if (!r.status.ok)
        r.error.code = ErrorCode::Protocol;
    return r;
}

DownloadResult LearningSession::PerformDownload(
      IHttpTransport& t, const CatalogueItem& item, const std::optional<Policy>& pol, const SecureString& token, const std::atomic<bool>* cancel)
{
    DownloadResult r;
    r.item = item;
    if (!IsValidItemName(item.name) || item.kind == ItemKind::ResourceLink)
    {
        r.error.code = ErrorCode::BadRequest;
        r.status     = Utils::GStatus::Error("this item cannot be downloaded");
        return r;
    }
    HttpRequest req;
    req.path                = (item.IsProblem() ? "/GView/GetProblems/" : "/GView/GetResource/") + item.name;
    req.maxResponseBytes    = MAX_BINARY_RESPONSE_BYTES;
    req.totalTimeoutSeconds = DOWNLOAD_TIMEOUT_SECONDS;
    req.cancel              = cancel;
    auto resp               = t.Post(req);
    if (!resp.IsSuccess())
    {
        r.error  = resp.ToError();
        r.status = Utils::GStatus::Error(DescribeError(r.error));
        return r;
    }
    DeliveryContext ctx;
    ctx.policy = pol.has_value() ? &pol.value() : nullptr;
    ctx.token  = &token;
    r.status   = ProcessDownloadResponse(resp, item, ctx, r.content);
    if (!r.status.ok)
        r.error.code = ErrorCode::Protocol;
    return r;
}

SubmitOutcome LearningSession::PerformSubmit(IHttpTransport& t, const SubmitRequest& sr, const std::atomic<bool>* cancel)
{
    SubmitOutcome o;
    HttpRequest req;
    req.path             = "/GView/SubmitFlag";
    req.body             = BuildSubmitBody(sr);
    req.maxResponseBytes = 64 * 1024;
    req.cancel           = cancel;
    auto resp            = t.Post(req);
    if (!resp.transportOk)
    {
        o.error      = resp.ToError();
        o.status     = Utils::GStatus::Error(DescribeError(o.error));
        o.definitive = false;
        return o;
    }
    o.status = ParseSubmitResponse(resp.status, ToView(resp.body), o.result, o.error);
    if (o.status.ok)
        o.definitive = true;
    else
        o.definitive = resp.status >= 400 && resp.status < 500 && resp.status != 429 && resp.status != 408;
    return o;
}

// ---------------------------------------------------------------------------- course notes (spec §10.11)
namespace
{
    NoteOpOutcome PostNoteOperation(
          IHttpTransport& t, std::string path, SecureString body, bool teacher, bool expectsResult, const std::atomic<bool>* cancel, long timeoutSeconds)
    {
        NoteOpOutcome o;
        HttpRequest req;
        req.path                = std::move(path);
        req.body                = std::move(body);
        req.maxResponseBytes    = MAX_NOTE_REPLY_BYTES;
        req.totalTimeoutSeconds = timeoutSeconds;
        req.cancel              = cancel;
        if (req.body.size() > MAX_NOTE_REQUEST_BYTES)
        {
            o.error.code    = ErrorCode::PayloadTooLarge;
            o.error.details = "the note exceeds the 256 KiB request limit";
            o.status        = Utils::GStatus::Error(DescribeError(o.error));
            return o;
        }
        auto resp = t.Post(req);
        if (!resp.IsSuccess())
        {
            o.error  = NoteErrorFromResponse(resp);
            o.status = Utils::GStatus::Error(DescribeError(o.error));
            return o;
        }
        if (!expectsResult)
        {
            o.status = Utils::GStatus::Ok();
            return o;
        }
        o.status = ParseSaveNoteResponse(ToView(resp.body), teacher, o.result);
        if (!o.status.ok)
        {
            // a 2xx that does not follow the contract: the save may have been applied => resend the same request
            o.error.code       = ErrorCode::Protocol;
            o.error.httpStatus = resp.status;
            o.error.details    = o.status.message;
        }
        return o;
    }
} // namespace

NotesFetchResult LearningSession::PerformGetNotes(IHttpTransport& t, const std::atomic<bool>* cancel)
{
    NotesFetchResult r;
    HttpRequest req;
    req.path             = "/GView/GetNotes";
    req.maxResponseBytes = MAX_NOTES_RESPONSE_BYTES;
    req.cancel           = cancel;
    auto resp            = t.Post(req);
    if (!resp.IsSuccess())
    {
        r.error  = NoteErrorFromResponse(resp);
        r.status = Utils::GStatus::Error(DescribeError(r.error));
        return r;
    }
    r.status = ParseNotesResponse(ToView(resp.body), r.snapshot);
    if (!r.status.ok)
    {
        r.error.code       = ErrorCode::Protocol;
        r.error.httpStatus = resp.status;
    }
    return r;
}

NoteOpOutcome LearningSession::PerformSaveNote(IHttpTransport& t, const SaveNoteRequest& sr, const std::atomic<bool>* cancel, long timeoutSeconds)
{
    if (!IsValidNoteId(sr.id) || !IsValidNoteScope(sr.scope))
    {
        NoteOpOutcome o;
        o.error.code = ErrorCode::BadRequest;
        o.status     = Utils::GStatus::Error("invalid note id or scope");
        return o;
    }
    return PostNoteOperation(t, "/GView/SaveNote", BuildSaveNoteBody(sr), false, true, cancel, timeoutSeconds);
}

NoteOpOutcome LearningSession::PerformDeleteNote(IHttpTransport& t, std::string_view id, const std::atomic<bool>* cancel, long timeoutSeconds)
{
    if (!IsValidNoteId(id))
    {
        NoteOpOutcome o;
        o.error.code = ErrorCode::BadRequest;
        o.status     = Utils::GStatus::Error("invalid note id");
        return o;
    }
    return PostNoteOperation(t, "/GView/DeleteNote", BuildDeleteNoteBody(id), false, false, cancel, timeoutSeconds);
}

NoteOpOutcome LearningSession::PerformSaveTeacherNote(IHttpTransport& t, const SaveTeacherNoteRequest& sr, const std::atomic<bool>* cancel)
{
    if ((sr.scope.has_value() && !IsValidNoteScope(*sr.scope)) || (sr.id.has_value() && (*sr.id < 1 || !sr.revision.has_value())))
    {
        NoteOpOutcome o;
        o.error.code = ErrorCode::BadRequest;
        o.status     = Utils::GStatus::Error("invalid course note request (an update needs its id and revision)");
        return o;
    }
    return PostNoteOperation(t, "/GView/SaveTeacherNote", BuildSaveTeacherNoteBody(sr), true, true, cancel, REQUEST_TIMEOUT_SECONDS);
}

NoteOpOutcome LearningSession::PerformDeleteTeacherNote(IHttpTransport& t, int64 id, const std::atomic<bool>* cancel)
{
    if (id < 1)
    {
        NoteOpOutcome o;
        o.error.code = ErrorCode::BadRequest;
        o.status     = Utils::GStatus::Error("invalid course note id");
        return o;
    }
    return PostNoteOperation(t, "/GView/DeleteTeacherNote", BuildDeleteTeacherNoteBody(id), true, false, cancel, REQUEST_TIMEOUT_SECONDS);
}

// ---------------------------------------------------------------------------- course work and solutions (spec §10.12)
namespace
{
    template <typename Outcome>
    Outcome RefusedLocally(std::string message)
    {
        Outcome o;
        o.error.code    = ErrorCode::BadRequest;
        o.error.details = message;
        o.status        = Utils::GStatus::Error(std::move(message));
        return o;
    }

    // one Post; a non-2xx answer fills `error` (409 => Conflict, 413 => PayloadTooLarge) and returns nullopt
    template <typename Outcome>
    std::optional<HttpResponse> PostWork(IHttpTransport& t, const char* path, SecureString body, size_t maxResponse, const std::atomic<bool>* cancel, Outcome& o, WorkServerError* fullError = nullptr)
    {
        HttpRequest req;
        req.path             = path;
        req.body             = std::move(body);
        req.maxResponseBytes = maxResponse;
        req.cancel           = cancel;
        if (req.body.size() > MAX_WORK_REQUEST_BYTES)
        {
            o.error.code    = ErrorCode::PayloadTooLarge;
            o.error.details = "the request exceeds the client limit";
            o.status        = Utils::GStatus::Error(DescribeError(o.error));
            return std::nullopt;
        }
        auto resp = t.Post(req);
        if (!resp.IsSuccess())
        {
            WorkServerError e = WorkErrorFromResponse(resp);
            o.error           = e;
            o.status          = Utils::GStatus::Error(DescribeError(o.error));
            if (fullError != nullptr)
                *fullError = std::move(e);
            return std::nullopt;
        }
        return resp;
    }

    template <typename Outcome>
    void MarkMalformed(Outcome& o, const HttpResponse& resp)
    {
        // a 2xx that does not follow the contract
        o.error.code       = ErrorCode::Protocol;
        o.error.httpStatus = resp.status;
        o.error.details    = o.status.message;
    }
} // namespace

WorkResult LearningSession::PerformGetWork(IHttpTransport& t, std::string_view problem, const std::atomic<bool>* cancel)
{
    if (!IsValidItemName(problem))
        return RefusedLocally<WorkResult>("invalid problem name");
    WorkResult r;
    auto resp = PostWork(t, "/GView/GetWork", BuildGetWorkBody(problem), MAX_WORK_RESPONSE_BYTES, cancel, r);
    if (!resp.has_value())
        return r;
    r.status = ParseWorkResponse(ToView(resp->body), r.response);
    if (!r.status.ok)
        MarkMalformed(r, *resp);
    return r;
}

SaveWorkOutcome LearningSession::PerformSaveWork(IHttpTransport& t, const SaveWorkRequest& sr, const std::atomic<bool>* cancel)
{
    if (!IsValidItemName(sr.problem) || (sr.revision.has_value() && *sr.revision < 1))
        return RefusedLocally<SaveWorkOutcome>("invalid problem name or revision");
    SaveWorkRequest canonical{ sr.problem, {}, sr.hasReplay, sr.hasReplay ? sr.replaySteps : 0, sr.revision };
    if (auto st = ValidateWorkDocumentText(sr.document, MAX_WORK_DOCUMENT_BYTES, canonical.document); !st.ok)
        return RefusedLocally<SaveWorkOutcome>(st.message);
    SaveWorkOutcome o;
    auto resp = PostWork(t, "/GView/SaveWork", BuildSaveWorkBody(canonical), MAX_WORK_REPLY_BYTES, cancel, o);
    if (!resp.has_value())
    {
        o.conflict = o.error.code == ErrorCode::Conflict;
        return o;
    }
    o.status = ParseSaveWorkResponse(ToView(resp->body), o.result);
    if (!o.status.ok)
        MarkMalformed(o, *resp);
    return o;
}

SolutionResult LearningSession::PerformGetSolution(IHttpTransport& t, std::string_view problem, std::optional<int64> id, const std::atomic<bool>* cancel)
{
    if (!IsValidItemName(problem) || (id.has_value() && *id < 1))
        return RefusedLocally<SolutionResult>("invalid problem name or solution id");
    SolutionResult r;
    auto resp = PostWork(t, "/GView/GetSolution", BuildGetSolutionBody(problem, id), MAX_WORK_RESPONSE_BYTES, cancel, r);
    if (!resp.has_value())
        return r;
    r.status = ParseSolutionResponse(ToView(resp->body), r.solution);
    if (!r.status.ok)
        MarkMalformed(r, *resp);
    return r;
}

PublishOutcome LearningSession::PerformPublishSolution(IHttpTransport& t, const PublishSolutionRequest& pr, const std::atomic<bool>* cancel)
{
    if (!IsValidItemName(pr.problem) || (pr.id.has_value() && (*pr.id < 1 || !pr.revision.has_value() || *pr.revision < 1)))
        return RefusedLocally<PublishOutcome>("invalid solution request (an update needs its id and revision)");
    PublishSolutionRequest canonical = pr;
    canonical.document.clear();
    if (!canonical.hasReplay)
        canonical.replaySteps = 0;
    if (auto st = ValidateWorkDocumentText(pr.document, MAX_WORK_DOCUMENT_BYTES, canonical.document); !st.ok)
        return RefusedLocally<PublishOutcome>(st.message);
    PublishOutcome o;
    WorkServerError full;
    auto resp = PostWork(t, "/GView/PublishSolution", BuildPublishSolutionBody(canonical), MAX_WORK_REPLY_BYTES, cancel, o, &full);
    if (!resp.has_value())
    {
        o.conflict = o.error.code == ErrorCode::Conflict;
        if (o.conflict)
        {
            o.existingId       = full.existingId;
            o.existingRevision = full.existingRevision;
        }
        return o;
    }
    o.status = ParsePublishSolutionResponse(ToView(resp->body), o.result);
    if (!o.status.ok)
        MarkMalformed(o, *resp);
    return o;
}

DeleteSolutionOutcome LearningSession::PerformDeleteSolution(IHttpTransport& t, int64 id, const std::atomic<bool>* cancel)
{
    if (id < 1)
        return RefusedLocally<DeleteSolutionOutcome>("invalid solution id");
    DeleteSolutionOutcome o;
    if (PostWork(t, "/GView/DeleteSolution", BuildDeleteSolutionBody(id), MAX_WORK_REPLY_BYTES, cancel, o).has_value())
        o.status = Utils::GStatus::Ok();
    return o;
}

// ============================================================================ lifecycle
LearningSession::LearningSession() : LearningSession(Dependencies{})
{
}

LearningSession::LearningSession(Dependencies d) : deps(std::move(d)), telemetry([this]() { return Now(); })
{
    if (!deps.transportFactory)
    {
        deps.transportFactory = [](const ConnectionInfo& ci, const LearningSettings& s) -> std::shared_ptr<IHttpTransport> {
            TransportConfig cfg;
            cfg.serverUrl               = ci.serverUrl;
            cfg.token                   = ci.token;
            cfg.caPem                   = ci.caPem;
            cfg.allowPlainHttpLocalhost = s.allowPlainHttpLocalhost;
            cfg.clientVersion           = ClientVersion();
            return std::shared_ptr<IHttpTransport>(CreateDefaultTransport(std::move(cfg)));
        };
    }
    if (!deps.activate)
        deps.activate = [](const Policy& p, RestrictedMode::Internal::ActivationReport& r) { return RestrictedMode::Internal::Activate(p, r); };
    if (!deps.deactivate)
        deps.deactivate = []() { RestrictedMode::Internal::Deactivate(); };
    if (!deps.clock)
        deps.clock = []() { return NowUnix(); };
    if (!deps.monoClock)
        deps.monoClock = []() { return DefaultMonoMs(); };
}

LearningSession::~LearningSession()
{
    Shutdown();
}

uint64 LearningSession::Now() const
{
    return deps.clock();
}

uint64 LearningSession::NowMs() const
{
    return deps.monoClock();
}

void LearningSession::RunJob(BackgroundWorker::Job job, bool countsAsBusy)
{
    if (countsAsBusy)
        pendingJobs++;
    BackgroundWorker::Job wrapped = [this, countsAsBusy, job = std::move(job)]() -> BackgroundWorker::Completion {
        // the completion must always be produced: it is the only place pendingJobs is released, so a throwing job
        // (e.g. bad_alloc) must not leave the session permanently busy
        BackgroundWorker::Completion c;
        try
        {
            c = job();
        }
#ifdef BUILD_FOR_WASM
        catch (const JobReplay::NetworkPending&)
        {
            throw; // the job waits for a response and will be run again (JobReplay.hpp)
        }
#endif
        catch (...)
        {
            c = nullptr;
        }
        return [this, countsAsBusy, c = std::move(c)]() {
            if (countsAsBusy && pendingJobs > 0)
                pendingJobs--;
            if (c)
                c();
        };
    };
#ifdef BUILD_FOR_WASM
    // the page always delivers frames: jobs run on the cooperative worker (the UI keeps running while they wait)
    const bool runInline = deps.synchronous;
#else
    const bool runInline = deps.synchronous || !frameUpdatesSeen.load(std::memory_order_acquire);
#endif
    if (runInline)
    {
        // no frame updates on this frontend (or tests): run inline, bounded by the network timeouts
        auto c = wrapped();
        if (c)
            c();
        return;
    }
    worker.Start();
    if (!worker.Post(wrapped))
    {
        auto c = wrapped();
        if (c)
            c();
    }
}

void LearningSession::StopJobs() noexcept
{
    // abort the running transfer (libcurl checks the flag ~ every second) instead of waiting for its timeout
    cancelJobs.store(true, std::memory_order_release);
    worker.Stop();
    cancelJobs.store(false, std::memory_order_release);
}

void LearningSession::SetState(SessionState s, std::string message)
{
    state         = s;
    statusMessage = std::move(message);
}

BatchMeta LearningSession::MakeBatchMeta() const
{
    BatchMeta m;
    m.sessionId     = sessionId;
    m.policyId      = policy.has_value() ? policy->id : std::string();
    m.policyDigest  = policy.has_value() ? policy->digest : std::string();
    m.clientVersion = ClientVersion();
    m.platform      = std::string(CurrentPlatform());
    m.sentAt        = Now();
    return m;
}

void LearningSession::ConfigureTelemetry()
{
    if (policy.has_value() && policy->telemetry.enabled && transport)
    {
        telemetry.Configure(policy->telemetry);
        if (!deps.telemetryThread)
            return;
        // the flusher thread must never read UI-thread state: give it an immutable snapshot
        const BatchMeta snapshot = MakeBatchMeta();
        auto clock               = deps.clock;
        flusher.Start(
              transport,
              &telemetry,
              [snapshot, clock]() {
                  BatchMeta m = snapshot;
                  m.sentAt    = clock();
                  return m;
              },
              [this]() { serverReportedExpiry.store(true, std::memory_order_release); },
              policy->telemetry.flushIntervalSeconds);
    }
    else
    {
        flusher.Stop();
        telemetry.Disable();
    }
}

void LearningSession::RecordSessionEnd(std::string_view reason)
{
    if (!sessionStartRecorded)
        return;
    telemetry.Record(EventType::SessionEnd, "", { FieldValue{ Field::Reason, std::string(reason) } });
    sessionStartRecorded = false;
}

void LearningSession::ExpireLocally(std::string_view reason)
{
    if (state == SessionState::Expired)
        return;
    // Restrictions stay applied (fail closed): already-open windows keep their protection; downloads and submissions
    // are refused until a newer policy validates.
    SetState(SessionState::Expired, "The course policy has expired. Downloads and submissions are disabled; reconnect to continue.");
    RecordSessionEnd(reason);
    // one final best-effort flush on the worker, then stop flushing (spec §2.3)
    flusher.Stop();
    if (telemetry.IsEnabled() && transport)
    {
        auto t        = transport;
        auto meta     = MakeBatchMeta();
        auto* coll    = &telemetry;
        RunJob([t, meta, coll]() -> BackgroundWorker::Completion {
            TelemetryFlusher::FlushOnce(*t, *coll, meta, FINAL_FLUSH_TIMEOUT_S, nullptr);
            return nullptr;
        });
    }
}

Utils::GStatus LearningSession::Connect(std::string_view connectionString, const LearningSettings& s, StatusCallback done)
{
    if (state == SessionState::Connecting)
        return Utils::GStatus::Error("a connection attempt is already in progress");
    ConnectionInfo ci;
    auto st = ParseConnectionString(connectionString, s.allowPlainHttpLocalhost, ci);
    if (!st.ok)
        return Utils::GStatus::Error("Invalid connection string: " + st.message);
    if (ci.publicKey.empty() && s.fallbackPublicKey.size() == 32)
        ci.publicKey = s.fallbackPublicKey;
    {
        // what the transport of this build can honour (the browser can not pin a private CA): refuse before connecting
        TransportConfig probe;
        probe.serverUrl               = ci.serverUrl;
        probe.caPem                   = ci.caPem;
        probe.allowPlainHttpLocalhost = s.allowPlainHttpLocalhost;
        if (auto req = CheckTransportRequirements(probe, BROWSER_TRANSPORT, PageIsServedLocally()); !req.ok)
            return req;
    }
    if (HasSession() && !bindings.empty() && !UsesConnection(ci))
        return Utils::GStatus::Error("Close all learning task windows before connecting with a different account or server.");

    std::shared_ptr<IHttpTransport> newTransport = deps.transportFactory(ci, s);
    if (!newTransport)
        return Utils::GStatus::Error("cannot create the network transport");
    if (policy.has_value())
        newTransport->SetPolicyId(policy->id);
    settings              = s;
    const auto previous   = state;
    const uint64 gen      = ++generation;
    SetState(SessionState::Connecting, "Connecting to " + ci.serverUrl + " ...");
    auto sharedInfo = std::make_shared<ConnectionInfo>(std::move(ci));
    const uint64 now = Now();
    RunJob([this, gen, previous, sharedInfo, newTransport, now, done]() -> BackgroundWorker::Completion {
        auto result = std::make_shared<ConnectResult>(PerformConnect(*newTransport, *sharedInfo, now, &cancelJobs));
        return [this, gen, previous, sharedInfo, newTransport, result, done]() {
            if (gen != generation)
                return; // superseded
            if (state == SessionState::Connecting)
                state = previous; // ApplyConnectResult decides the final state
            auto st = ApplyConnectResult(std::move(*sharedInfo), newTransport, std::move(*result));
            if (done)
                done(st);
            // spec §10.11: GetNotes after Connect, skipped when policy.notes.enabled is false (or absent)
            if (st.ok && CanUseNotes())
                RefreshNotes();
        };
    });
    return Utils::GStatus::Ok();
}

bool LearningSession::UsesConnection(const ConnectionInfo& ci) const noexcept
{
    return HasSession() && ci.serverUrl == info.serverUrl && ci.token.size() == info.token.size() &&
           Crypto::Internal::ConstantTimeEquals(ci.token.data(), info.token.data(), ci.token.size());
}

Utils::GStatus LearningSession::ApplyConnectResult(ConnectionInfo&& newInfo, std::shared_ptr<IHttpTransport> newTransport, ConnectResult&& result)
{
    if (state == SessionState::Connecting)
        state = policy.has_value() ? SessionState::Active : SessionState::Disconnected;

    if (!result.status.ok)
    {
        if (!result.rejectCode.empty())
            telemetry.Record(EventType::PolicyRejected, "", { FieldValue{ Field::Reason, result.rejectCode } }); // no-op without consent
        if (result.error.code == ErrorCode::PolicyExpired && policy.has_value())
        {
            ExpireLocally("policy_expired");
            return result.status;
        }
        if (policy.has_value())
        {
            // reconnect failed: the current (still valid) policy stays in force
            statusMessage = "Reconnect failed, the current policy stays in force: " + result.status.message;
        }
        else
        {
            const bool wasLegacy = state == SessionState::Legacy;
            SetState(wasLegacy ? SessionState::Legacy : SessionState::Error, result.status.message);
        }
        return result.status;
    }

    if (result.response.legacy)
    {
        if (policy.has_value())
        {
            // never downgrade from a verified policy to an unrestricted session
            statusMessage = "The server did not provide a policy; the current policy stays in force.";
            return Utils::GStatus::Error(statusMessage);
        }
        ResetNotes(); // a legacy server has no notes; never keep notes of another account in memory
        ResetWork();
        info        = std::move(newInfo);
        transport   = std::move(newTransport);
        lastConnect = std::move(result.response);
        if (sessionId.empty())
            sessionId = NewUuid4().value_or("");
        catalogueLoaded = false;
        SetState(
              SessionState::Legacy,
              "Server does not provide a policy (legacy). Learning mode restrictions are NOT active; catalogue and submissions only.");
        return Utils::GStatus::Ok();
    }

    RestrictedMode::Internal::ActivationReport report;
    auto st = deps.activate(*result.policy, report);
    if (!st.ok)
    {
        if (!policy.has_value())
            SetState(SessionState::Error, "The policy could not be applied: " + st.message);
        else
            statusMessage = "The new policy could not be applied, the current one stays in force: " + st.message;
        return st;
    }
    restrictionsActive = true;
    {
        // notes belong to one account on one server: unsaved text is never sent to another one
        const bool sameAccount = info.serverUrl == newInfo.serverUrl && info.token.size() == newInfo.token.size() &&
                                 Crypto::Internal::ConstantTimeEquals(info.token.data(), newInfo.token.data(), info.token.size());
        if (!sameAccount)
        {
            FinalNoteSaves(); // to the account (and server) the text belongs to, bounded
            ResetNotes();
            ResetWork(); // revisions and capabilities belong to the previous account
        }
        // the policy reflects the notes switch at connect time; a new connect tries again (spec §2.2)
        notesDisabledByServer = false;
        notesLoaded           = false;
        notesError.clear();
        if (result.policy->notes.present)
            notes.SetMaxChars(result.policy->notes.maxChars);
        // course work (spec §10.12): the same "try again at every connect"; the capability announced at connect is
        // replaced by every GetWork answer
        workDisabledByServer = false;
        workServerMaxBytes   = 0;
        if (result.response.canPublishSolutions.has_value())
            canPublishSolutions = *result.response.canPublishSolutions;
        if (result.response.audiences.has_value())
            audiences = *result.response.audiences;
    }
    const bool newPolicyId = !policy.has_value() || policy->id != result.policy->id;
    policy                 = std::move(result.policy);
    activation             = std::move(report);
    info                   = std::move(newInfo);
    transport              = std::move(newTransport);
    transport->SetPolicyId(policy->id);
    lastConnect = std::move(result.response);
    if (sessionId.empty())
        sessionId = NewUuid4().value_or("");
    screenRequirementUnmet = policy->requireScreenProtect && !activation.screenProtectApplied;
    catalogueLoaded        = false;

    ConfigureTelemetry();
    if (!sessionStartRecorded)
    {
        sessionStartRecorded = telemetry.Record(EventType::SessionStart, "");
    }
    if (newPolicyId)
        telemetry.Record(EventType::PolicyApplied, "", { FieldValue{ Field::Mode, std::string(ModeName(policy->storageMode)) } });
    if (activation.screenProtectRequested && !activation.screenProtectApplied)
        telemetry.Record(EventType::ScreenProtectFailed, "", { FieldValue{ Field::Reason, std::string("unsupported_platform") } });
    flusher.RequestFlush();

    if (screenRequirementUnmet)
    {
        SetState(
              SessionState::Error,
              "This course requires screen-capture protection, which is not available here (" + activation.platformNote +
                    "). Tasks cannot be opened. Use the Windows SDL frontend or contact your teacher.");
        return Utils::GStatus::Error(statusMessage);
    }
    SetState(SessionState::Active, std::string(ACTIVE_STATUS_MESSAGE));
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::RefreshCatalogue(StatusCallback done)
{
    if (!transport || state == SessionState::Disconnected || state == SessionState::Connecting)
        return Utils::GStatus::Error("not connected");
    if (state == SessionState::Expired)
        return Utils::GStatus::Error("the course policy has expired; reconnect first");
    auto t           = transport;
    const uint64 gen = generation;
    RunJob([this, t, gen, done]() -> BackgroundWorker::Completion {
        auto result = std::make_shared<CatalogueResult>(PerformFetchCatalogue(*t, &cancelJobs));
        return [this, gen, result, done]() {
            if (gen != generation)
                return;
            if (result->status.ok)
            {
                catalogue       = std::move(result->catalogue);
                catalogueLoaded = true;
            }
            else if (result->error.code == ErrorCode::PolicyExpired)
                ExpireLocally("policy_expired");
            if (done)
                done(result->status);
        };
    });
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::Download(const CatalogueItem& item, DownloadCallback done)
{
    if (!CanOpenItems())
        return Utils::GStatus::Error(state == SessionState::Expired ? "the course policy has expired" : "items cannot be opened in the current state");
    if (!IsValidItemName(item.name))
        return Utils::GStatus::Error("invalid item name");
    auto t           = transport;
    auto pol         = policy;
    auto token       = std::make_shared<SecureString>(info.token);
    const uint64 gen = generation;
    RunJob([this, t, pol, token, item, gen, done]() -> BackgroundWorker::Completion {
        auto result = std::make_shared<DownloadResult>(PerformDownload(*t, item, pol, *token, &cancelJobs));
        return [this, gen, result, done]() {
            if (gen != generation)
                return;
            if (!result->status.ok && result->error.code == ErrorCode::PolicyExpired)
                ExpireLocally("policy_expired");
            if (done)
                done(*result);
        };
    });
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::Submit(std::string_view problem, SecureString flag, SecureString explanation, SubmitCallback done)
{
    if (!CanSubmit())
        return Utils::GStatus::Error(state == SessionState::Expired ? "the course policy has expired" : "submissions are not allowed");
    if (!IsValidItemName(problem))
        return Utils::GStatus::Error("invalid problem");
    // trim surrounding whitespace of the flag (the server strips as well)
    while (!flag.empty() && (flag.back() == ' ' || flag.back() == '\t' || flag.back() == '\r' || flag.back() == '\n'))
        flag.pop_back();
    size_t lead = 0;
    while (lead < flag.size() && (flag[lead] == ' ' || flag[lead] == '\t'))
        lead++;
    flag.erase(0, lead);
    if (flag.empty())
        return Utils::GStatus::Error("the flag cannot be empty");
    if (flag.size() > MAX_FLAG_LENGTH)
        return Utils::GStatus::Error("the flag is too long (max 512 characters)");
    bool requireExplanation = false;
    uint32 maxChars         = 100000;
    if (policy.has_value())
    {
        requireExplanation = policy->submission.requireExplanation;
        maxChars           = policy->submission.explanationMaxChars;
    }
    if (const auto* item = catalogue.Find(problem, true); item != nullptr && item->requireExplanation)
        requireExplanation = true;
    if (requireExplanation && explanation.find_first_not_of(" \t\r\n") == SecureString::npos)
        return Utils::GStatus::Error("an explanation is required for this problem");
    if (explanation.size() > maxChars)
        return Utils::GStatus::Error("the explanation exceeds " + std::to_string(maxChars) + " characters");

    SubmitRequest req;
    req.problem            = std::string(problem);
    req.clientSubmissionId = submissions.IdFor(problem, flag, explanation);
    if (req.clientSubmissionId.empty())
        return Utils::GStatus::Error("cannot generate a submission id");
    req.flag          = std::move(flag);
    req.explanation   = std::move(explanation);
    req.policyId      = policy.has_value() ? policy->id : std::string();
    req.policyDigest  = policy.has_value() ? policy->digest : std::string();
    req.clientVersion = ClientVersion();
    req.clientTime    = Now();

    telemetry.Record(EventType::Submit, req.problem, { FieldValue{ Field::ClientSubmissionId, req.clientSubmissionId } });
    flusher.RequestFlush();

    auto t           = transport;
    auto shared      = std::make_shared<SubmitRequest>(std::move(req));
    const uint64 gen = generation;
    RunJob([this, t, shared, gen, done]() -> BackgroundWorker::Completion {
        auto outcome = std::make_shared<SubmitOutcome>(PerformSubmit(*t, *shared, &cancelJobs));
        return [this, gen, shared, outcome, done]() {
            if (gen != generation)
                return;
            if (outcome->definitive)
                submissions.Consume(shared->problem);
            if (outcome->status.ok && (outcome->result.correct || outcome->result.alreadySolved))
            {
                for (auto& w : catalogue.weeks)
                {
                    for (auto& p : w.problems)
                    {
                        if (p.name == shared->problem)
                        {
                            p.hasMe     = true;
                            p.me.solved = true;
                            if (outcome->result.attempts > 0)
                                p.me.attempts = outcome->result.attempts;
                        }
                    }
                }
            }
            else if (outcome->status.ok && outcome->result.attempts > 0)
            {
                for (auto& w : catalogue.weeks)
                    for (auto& p : w.problems)
                        if (p.name == shared->problem)
                        {
                            p.hasMe       = true;
                            p.me.attempts = outcome->result.attempts;
                        }
            }
            if (outcome->status.ok && outcome->result.hasTotalScore)
                lastConnect.score = outcome->result.totalScore;
            if (!outcome->status.ok && outcome->error.code == ErrorCode::PolicyExpired)
                ExpireLocally("policy_expired");
            if (done)
                done(*outcome);
        };
    });
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::EndSession(std::string_view reason)
{
    if (!bindings.empty())
        return Utils::GStatus::Error(
              "Close the " + std::to_string(bindings.size()) + " open learning window(s) first: their content would lose its protection.");
    generation++;
    RecordSessionEnd(reason);
    flusher.StopAndFlush(FINAL_FLUSH_TIMEOUT_S);
    StopJobs();
    FinalNoteSaves(); // unsaved note text is sent (bounded) before the transport goes away
    ResetNotes();
    ResetWork();
    telemetry.Disable();
    if (restrictionsActive)
        deps.deactivate();
    restrictionsActive = false;
    info               = ConnectionInfo{};
    transport.reset();
    policy.reset();
    activation             = {};
    screenRequirementUnmet = false;
    lastConnect            = {};
    catalogue              = {};
    catalogueLoaded        = false;
    sessionId.clear();
    submissions.Clear();
    pendingBinding.reset();
    pendingJobs = 0;
    SetState(SessionState::Disconnected, "Session ended.");
    return Utils::GStatus::Ok();
}

void LearningSession::Shutdown() noexcept
{
    try
    {
        generation++;
        StopJobs();
        FinalNoteSaves();
        ResetNotes();
        ResetWork();
        RecordSessionEnd("exit");
        flusher.StopAndFlush(FINAL_FLUSH_TIMEOUT_S);
        telemetry.Disable();
        if (restrictionsActive)
            deps.deactivate();
        restrictionsActive = false;
        info               = ConnectionInfo{};
        transport.reset();
        policy.reset();
        bindings.clear();
        pendingBinding.reset();
        state = SessionState::Disconnected;
    }
    catch (...)
    {
    }
}

void LearningSession::Tick(bool drainCompletions)
{
    if (drainCompletions)
        worker.DrainCompletions();
    const uint64 nowMs = NowMs();
    if (lastTickMs != 0 && nowMs >= lastTickMs && nowMs - lastTickMs < TICK_INTERVAL_MS)
        return;
    if (serverReportedExpiry.exchange(false, std::memory_order_acq_rel))
        ExpireLocally("policy_expired");
#ifdef BUILD_FOR_WASM
    flusher.Poll(nowMs); // no flusher thread in a web page
#endif
    if (policy.has_value() && (state == SessionState::Active || state == SessionState::Error) &&
        Now() > policy->endsAt + RestrictedMode::POLICY_CLOCK_SKEW_SECONDS)
        ExpireLocally("policy_ended");
    PumpNotes(false); // debounced autosave and retries, also while the Notes window is closed
    AccountTime(nowMs);
    lastTickMs = nowMs;
}

void LearningSession::AccountTime(uint64 nowMs)
{
    if (!policy.has_value() || !telemetry.IsEnabled())
        return;
    const uint64 thresholdMs = static_cast<uint64>(policy->telemetry.idleThresholdSeconds) * 1000;
    const uint64 lastAct     = lastActivityMs.load(std::memory_order_acquire);
    if (!idle && lastAct != 0 && nowMs > lastAct && nowMs - lastAct >= thresholdMs)
    {
        idle        = true;
        idleSinceMs = lastAct;
    }
    if (idle || lastTickMs == 0 || nowMs <= lastTickMs || focusedObject == nullptr)
        return;
    const auto* binding = FindBinding(focusedObject);
    if (binding == nullptr)
        return;
    const uint64 step = std::min<uint64>(nowMs - lastTickMs, MAX_ACCOUNT_STEP_MS);
    activeCarryMs += step;
    if (focusedViewer == "Dissasm")
        dissasmCarryMs += step;
    if (activeCarryMs >= 1000)
    {
        telemetry.AddSeconds(binding->item, "active_seconds", activeCarryMs / 1000);
        activeCarryMs %= 1000;
    }
    if (dissasmCarryMs >= 1000)
    {
        telemetry.AddSeconds(binding->item, "dissasm_seconds", dissasmCarryMs / 1000);
        dissasmCarryMs %= 1000;
    }
}

// ============================================================================ queries
bool LearningSession::CanOpenItems() const noexcept
{
    return (state == SessionState::Active && !screenRequirementUnmet && policy.has_value()) || state == SessionState::Legacy;
}

bool LearningSession::CanSubmit() const noexcept
{
    if (state == SessionState::Legacy)
        return true;
    return state == SessionState::Active && policy.has_value() && policy->submission.allowInTool;
}

LearningSession::Status LearningSession::GetStatus() const
{
    Status s;
    s.state       = state;
    s.message     = statusMessage;
    s.displayName = lastConnect.displayName;
    s.score       = lastConnect.score;
    s.label       = info.label;
    s.serverUrl   = info.serverUrl;
    s.busy        = pendingJobs > 0;
    if (policy.has_value())
    {
        s.hasPolicy              = true;
        s.purpose                = policy->purpose;
        s.policyId               = policy->id;
        s.endsAt                 = policy->endsAt;
        s.storageMode            = policy->storageMode;
        s.disabledFeatures       = policy->disabledFeatures;
        s.telemetryEnabled       = policy->telemetry.enabled;
        s.screenProtectRequested = activation.screenProtectRequested;
        s.screenProtectApplied   = activation.screenProtectApplied;
        s.screenRequirementUnmet = screenRequirementUnmet;
        s.screenNote             = activation.platformNote;
        s.requireExplanation     = policy->submission.requireExplanation;
        s.explanationMaxChars    = policy->submission.explanationMaxChars;
        s.notesMaxChars          = notes.MaxChars();
        s.workMaxBytes           = static_cast<uint32>(WorkMaxBytes());
    }
    else
    {
        s.explanationMaxChars = 100000;
    }
    s.notes               = GetNotesAvailability();
    s.work                = GetWorkAvailability();
    s.canPublishSolutions = CanPublishSolutions();
    s.audiences           = audiences;
    s.submissionAllowed = CanSubmit();
    return s;
}

// ============================================================================ bindings / hooks
void LearningSession::SetPendingBinding(ItemBinding binding)
{
    pendingBinding = std::move(binding);
}

void LearningSession::ClearPendingBinding() noexcept
{
    pendingBinding.reset();
}

bool LearningSession::SetPendingWorkDocument(std::string json, WorkspaceRole role)
{
    if (!pendingBinding.has_value() || role == WorkspaceRole::Normal)
        return false;
    pendingBinding->role        = role;
    pendingBinding->pendingWork = std::move(json);
    return true;
}

std::optional<std::string> LearningSession::TakePendingWork(const void* obj, WorkspaceRole& role)
{
    auto it = bindings.find(obj);
    if (it == bindings.end()) {
        role = WorkspaceRole::Normal;
        return std::nullopt;
    }
    role = it->second.role;
    std::optional<std::string> work;
    work.swap(it->second.pendingWork);
    return work;
}

void LearningSession::OnObjectCreated(const void* obj, bool inMemory)
{
    if (obj == nullptr)
        return;
    if (pendingBinding.has_value()) {
        bindings[obj] = std::move(*pendingBinding);
        pendingBinding.reset();
        return;
    }
    if (!inMemory)
        return;
    // GView does not track which window an in-memory object was extracted from, so while any memory-only content is open
    // every new in-memory object is assumed to derive from it (fail closed: it may not be written to disk either)
    bool memoryContentOpen = !memoryDerived.empty();
    for (auto it = bindings.begin(); it != bindings.end() && !memoryContentOpen; ++it)
        memoryContentOpen = it->second.mode == DeliveryMode::Memory;
    if (memoryContentOpen)
        memoryDerived.insert(obj);
}

void LearningSession::OnObjectClosed(const void* obj)
{
    memoryDerived.erase(obj);
    auto it = bindings.find(obj);
    if (it == bindings.end())
        return;
    if (it->second.problem && it->second.role == WorkspaceRole::Student) // a teacher solution window is not the task
        telemetry.Record(EventType::TaskClose, it->second.item);
    if (focusedObject == obj)
        focusedObject = nullptr;
    bindings.erase(it);
    flusher.RequestFlush();
}

const ItemBinding* LearningSession::FindBinding(const void* obj) const noexcept
{
    auto it = bindings.find(obj);
    return it == bindings.end() ? nullptr : &it->second;
}

void LearningSession::OnFrame(const void* obj, std::string_view viewerKind, bool focused)
{
    NotifyFrameUpdatesAvailable();
    Tick(false); // never run completions while AppCUI iterates the desktop's windows
    auto it = bindings.find(obj);
    if (it == bindings.end())
    {
        if (focused)
            focusedObject = nullptr;
        return;
    }
    const std::string_view viewer = NormalizeViewerName(viewerKind);
    if (it->second.lastViewer != viewer && it->second.role == WorkspaceRole::Student)
    {
        it->second.lastViewer = std::string(viewer);
        telemetry.Record(EventType::ViewerOpen, it->second.item, { FieldValue{ Field::Viewer, std::string(viewer) } });
    }
    if (focused)
    {
        focusedObject   = obj;
        focusedViewer   = std::string(viewer);
        lastFocusedItem = it->second.item;
    }
}

void LearningSession::NoteActivity() noexcept
{
    try
    {
        const uint64 now = NowMs();
        lastActivityMs.store(now, std::memory_order_release);
        if (idle)
        {
            idle               = false;
            const uint64 secs  = now > idleSinceMs ? (now - idleSinceMs) / 1000 : 0;
            if (secs > 0)
                telemetry.Record(EventType::Idle, lastFocusedItem, { FieldValue{ Field::Seconds, static_cast<int64>(secs) } });
            lastTickMs = now; // do not credit the idle period as active time
        }
    }
    catch (...)
    {
    }
}

bool LearningSession::Record(const void* obj, EventType type, std::vector<FieldValue> fields)
{
    const auto* b = FindBinding(obj);
    if (b == nullptr)
        return false; // telemetry is only collected for windows opened from the course catalogue
    if (b->role != WorkspaceRole::Student)
        return false; // a teacher solution / replay window: what happens there is not the student's work on the task
    return telemetry.Record(type, b->item, std::move(fields));
}

void LearningSession::RecordFeatureBlocked(Feature feature)
{
    const auto* b = focusedObject != nullptr ? FindBinding(focusedObject) : nullptr;
    if (b != nullptr && b->role != WorkspaceRole::Student)
        b = nullptr; // still recorded, without the item
    telemetry.Record(
          EventType::FeatureBlocked,
          b != nullptr ? std::string_view(b->item) : std::string_view(),
          { FieldValue{ Field::Feature, std::string(RestrictedMode::FeatureToString(feature)) } });
}

void LearningSession::RecordClientError(std::string_view constantMessage, bool fatal)
{
    telemetry.Record(EventType::ClientError, "", { FieldValue{ Field::Message, std::string(constantMessage) }, FieldValue{ Field::Fatal, fatal } });
}

void LearningSession::RecordItemOpened(const CatalogueItem& item, DeliveryMode mode, uint32 version, WorkspaceRole role)
{
    if (role == WorkspaceRole::Solution || role == WorkspaceRole::Replay)
        return;
    telemetry.Record(
          item.IsProblem() ? EventType::TaskOpen : EventType::ResourceOpen,
          item.name,
          { FieldValue{ Field::ItemVersion, static_cast<int64>(version) }, FieldValue{ Field::Mode, std::string(ModeName(mode)) } });
}

// ============================================================================ course notes (spec §10.11)
NotesAvailability LearningSession::GetNotesAvailability() const noexcept
{
    if (!policy.has_value() || !policy->notes.present)
        return NotesAvailability::Absent;
    if (!policy->notes.enabled)
        return NotesAvailability::DisabledByPolicy;
    if (notesDisabledByServer)
        return NotesAvailability::DisabledByServer;
    if (state != SessionState::Active || !transport)
        return NotesAvailability::Unavailable;
    return NotesAvailability::Available;
}

std::vector<std::string> LearningSession::TakeNotesNotices()
{
    auto r = std::move(notesNotices);
    notesNotices.clear();
    for (auto& n : notes.TakeNotices())
        r.push_back(std::move(n));
    return r;
}

void LearningSession::HandleNoteFailure(NoteFailure failure, bool teacherEndpoint)
{
    switch (failure)
    {
    case NoteFailure::Disabled:
        if (teacherEndpoint)
        {
            // 403 on a teacher endpoint: this token is not course staff (staff tokens are never gated)
            if (canEditTeacherNotes)
            {
                canEditTeacherNotes = false;
                teacherNotesVersion++;
            }
            notesNotices.push_back("Only course staff can edit course notes.");
        }
        else if (!notesDisabledByServer)
        {
            notesDisabledByServer = true; // hides the Notes UI until the next connect
            teacherNotesVersion++;
            notesNotices.push_back("Course notes are disabled by your teacher.");
        }
        break;
    case NoteFailure::Expired:
        ExpireLocally("policy_expired");
        break;
    case NoteFailure::Conflict:
    case NoteFailure::NotFound:
        RefreshNotes();
        break;
    default:
        break;
    }
}

Utils::GStatus LearningSession::RefreshNotes()
{
    if (!CanUseNotes())
    {
        switch (GetNotesAvailability())
        {
        case NotesAvailability::DisabledByPolicy:
        case NotesAvailability::DisabledByServer:
            return Utils::GStatus::Error("Course notes are disabled by your teacher.");
        case NotesAvailability::Absent:
            return Utils::GStatus::Error("This course server does not provide course notes.");
        default:
            return Utils::GStatus::Error("Course notes are not available in the current session state.");
        }
    }
    if (notesFetchInFlight)
    {
        notesFetchQueued = true;
        return Utils::GStatus::Ok();
    }
    notesFetchInFlight = true;
    notesFetchQueued   = false;
    notes.OnRefetchStarted();
    auto t            = transport;
    const uint64 epoch = notesEpoch;
    RunJob(
          [this, t, epoch]() -> BackgroundWorker::Completion {
              auto result = std::make_shared<NotesFetchResult>();
              try
              {
                  *result = PerformGetNotes(*t, &cancelJobs);
              }
#ifdef BUILD_FOR_WASM
              catch (const JobReplay::NetworkPending&)
              {
                  throw;
              }
#endif
              catch (...)
              {
                  result->error.code = ErrorCode::Transport;
                  result->status     = Utils::GStatus::Error("GetNotes failed");
              }
              return [this, epoch, result]() {
                  if (epoch != notesEpoch)
                      return;
                  notesFetchInFlight = false;
                  if (result->status.ok)
                  {
                      notes.ApplySnapshot(result->snapshot, NowMs());
                      teacherNotes        = std::move(result->snapshot.teacher);
                      canEditTeacherNotes = result->snapshot.canEditTeacherNotes;
                      notesLoaded         = true;
                      notesRefetchWanted  = false;
                      notesFetchRetries   = 0;
                      notesError.clear();
                      teacherNotesVersion++;
                  }
                  else
                  {
                      const auto failure = ClassifyNoteError(result->error);
                      notesError         = result->status.message;
                      teacherNotesVersion++;
                      if (failure == NoteFailure::Retry)
                      {
                          notesRefetchWanted = true;
                          notesFetchRetries++;
                          const uint64 delay = result->error.retryAfterSeconds > 0
                                                     ? static_cast<uint64>(result->error.retryAfterSeconds) * 1000
                                                     : std::min<uint64>(2000ull << std::min<uint32>(notesFetchRetries - 1, 5), NOTES_RETRY_MAX_MS);
                          notesRefetchAtMs = NowMs() + delay;
                      }
                      else
                      {
                          // not retried automatically (401, 400, ...): the window's Refresh or the next open tries again
                          notesRefetchWanted = false;
                          notesFetchRetries  = 0;
                          HandleNoteFailure(failure == NoteFailure::NotFound || failure == NoteFailure::Conflict ? NoteFailure::Refused : failure, false);
                      }
                  }
                  if (notesFetchQueued && CanUseNotes())
                      RefreshNotes();
              };
          },
          false);
    return Utils::GStatus::Ok();
}

void LearningSession::StartNoteAction(NotesSync::Action action)
{
    auto t             = transport;
    const uint64 epoch = notesEpoch;
    auto shared        = std::make_shared<NotesSync::Action>(std::move(action));
    RunJob(
          [this, t, epoch, shared]() -> BackgroundWorker::Completion {
              auto outcome = std::make_shared<NoteOpOutcome>();
              try
              {
                  *outcome = shared->kind == NotesSync::Action::Kind::Save ? PerformSaveNote(*t, shared->request, &cancelJobs)
                                                                           : PerformDeleteNote(*t, shared->id, &cancelJobs);
              }
#ifdef BUILD_FOR_WASM
              catch (const JobReplay::NetworkPending&)
              {
                  throw;
              }
#endif
              catch (...)
              {
                  outcome->error.code = ErrorCode::Transport; // never leave the note "in flight"
                  outcome->status     = Utils::GStatus::Error("note request failed");
              }
              return [this, epoch, shared, outcome]() {
                  if (epoch != notesEpoch)
                      return;
                  const auto failure = shared->kind == NotesSync::Action::Kind::Save ? notes.OnSaveResult(*shared, *outcome, NowMs())
                                                                                     : notes.OnDeleteResult(*shared, *outcome, NowMs());
                  HandleNoteFailure(failure, false);
              };
          },
          false);
}

void LearningSession::PumpNotes(bool flushAll)
{
    if (!CanUseNotes())
        return;
    const uint64 nowMs = NowMs();
    if (!notesFetchInFlight && (notes.RefetchNeeded() || (notesRefetchWanted && nowMs >= notesRefetchAtMs)))
        RefreshNotes();
    for (auto& action : notes.NextActions(nowMs, flushAll))
        StartNoteAction(std::move(action));
}

Utils::GStatus LearningSession::SaveTeacherNote(SaveTeacherNoteRequest req, NoteOpCallback done)
{
    if (!CanEditTeacherNotes())
        return Utils::GStatus::Error("Only course staff can edit course notes.");
    req.title = NormalizeNoteTitle(req.title);
    req.body  = NormalizeNoteBody(req.body);
    if (Utf8Length(req.body) > notes.MaxChars())
        return Utils::GStatus::Error("The note is longer than " + std::to_string(notes.MaxChars()) + " characters.");
    auto t             = transport;
    const uint64 epoch = notesEpoch;
    auto shared        = std::make_shared<SaveTeacherNoteRequest>(std::move(req));
    RunJob([this, t, epoch, shared, done]() -> BackgroundWorker::Completion {
        auto outcome = std::make_shared<NoteOpOutcome>();
        try
        {
            *outcome = PerformSaveTeacherNote(*t, *shared, &cancelJobs);
        }
#ifdef BUILD_FOR_WASM
        catch (const JobReplay::NetworkPending&)
        {
            throw;
        }
#endif
        catch (...)
        {
            outcome->error.code = ErrorCode::Transport; // the editor always gets an answer
            outcome->status     = Utils::GStatus::Error("course note request failed");
        }
        return [this, epoch, outcome, done]() {
            if (epoch != notesEpoch)
                return;
            if (outcome->status.ok)
                RefreshNotes(); // the list shows the new revision / order
            else
                HandleNoteFailure(ClassifyNoteError(outcome->error), true);
            if (done)
                done(*outcome);
        };
    });
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::DeleteTeacherNote(int64 id, NoteOpCallback done)
{
    if (!CanEditTeacherNotes())
        return Utils::GStatus::Error("Only course staff can edit course notes.");
    auto t             = transport;
    const uint64 epoch = notesEpoch;
    RunJob([this, t, epoch, id, done]() -> BackgroundWorker::Completion {
        auto outcome = std::make_shared<NoteOpOutcome>();
        try
        {
            *outcome = PerformDeleteTeacherNote(*t, id, &cancelJobs);
        }
#ifdef BUILD_FOR_WASM
        catch (const JobReplay::NetworkPending&)
        {
            throw;
        }
#endif
        catch (...)
        {
            outcome->error.code = ErrorCode::Transport;
            outcome->status     = Utils::GStatus::Error("course note request failed");
        }
        return [this, epoch, outcome, done]() {
            if (epoch != notesEpoch)
                return;
            const auto failure = ClassifyNoteError(outcome->error);
            if (outcome->status.ok || failure == NoteFailure::NotFound)
                RefreshNotes();
            else
                HandleNoteFailure(failure, true);
            if (done)
                done(*outcome);
        };
    });
    return Utils::GStatus::Ok();
}

void LearningSession::RecordNoteAdd(const void* obj)
{
    Record(obj, EventType::NoteAdd); // a bare count: never the note text (spec §5 privacy)
}

void LearningSession::FinalNoteSaves() noexcept
{
    try
    {
        // End session / exit: StopJobs() dropped the queued requests and the completion of the running one. Account
        // switch: a request may still run on the worker; resending it is harmless (creates and updates are idempotent).
        notes.AbortAllInFlight();
        // conflicts not resolved yet / notes the server refused: one last chance, nothing typed is dropped unsent
        notes.PrepareFinalFlush();
        if (!transport || !policy.has_value() || !policy->notes.present || !policy->notes.enabled || notesDisabledByServer)
            return;
        if (state != SessionState::Active)
            return; // an expired policy is refused by the server (403 POLICY_EXPIRED)
#ifdef BUILD_FOR_WASM
        constexpr int ROUNDS = 1; // outside a job the page sends the request without waiting for its answer
#else
        constexpr int ROUNDS = 3; // an unanswered request first, then the newer text with the revision it returned
#endif
        const uint64 deadline = NowMs() + FINAL_NOTES_TIMEOUT_MS;
        for (int round = 0; round < ROUNDS; round++)
        {
            auto actions = notes.NextActions(NowMs(), true);
            if (actions.empty())
                break;
            for (auto& a : actions)
            {
                if (NowMs() >= deadline)
                {
                    notes.AbortAllInFlight();
                    return;
                }
                if (a.kind == NotesSync::Action::Kind::Save)
                    notes.OnSaveResult(a, PerformSaveNote(*transport, a.request, nullptr, FINAL_FLUSH_TIMEOUT_S), NowMs());
                else
                    notes.OnDeleteResult(a, PerformDeleteNote(*transport, a.id, nullptr, FINAL_FLUSH_TIMEOUT_S), NowMs());
            }
        }
    }
    catch (...)
    {
    }
}

void LearningSession::ResetNotes() noexcept
{
    notesEpoch++; // completions of requests still running belong to the old notes
    notes.Clear();
    for (auto& n : teacherNotes)
    {
        WipeString(n.title);
        WipeString(n.body);
    }
    teacherNotes.clear();
    canEditTeacherNotes   = false;
    notesLoaded           = false;
    notesDisabledByServer = false;
    notesFetchInFlight    = false;
    notesFetchQueued      = false;
    notesRefetchWanted    = false;
    notesRefetchAtMs      = 0;
    notesFetchRetries     = 0;
    notesError.clear();
    notesNotices.clear();
    teacherNotesVersion++;
}

// ============================================================================ course work and solutions (spec §10.12)
namespace
{
    // the UI (a progress dialog) always gets an answer, also when a job throws
    template <typename Result, typename Fn>
    std::shared_ptr<Result> RunWorkRequest(Fn&& fn)
    {
        auto result = std::make_shared<Result>();
        try
        {
            *result = fn();
        }
#ifdef BUILD_FOR_WASM
        catch (const JobReplay::NetworkPending&)
        {
            throw; // the job waits for a response and will be run again (JobReplay.hpp)
        }
#endif
        catch (...)
        {
            result->error.code = ErrorCode::Transport;
            result->status     = Utils::GStatus::Error("the course work request failed");
        }
        return result;
    }
} // namespace

void LearningSession::ResetWork() noexcept
{
    workRevisions.clear();
    canPublishSolutions  = false;
    audiences.clear();
    workDisabledByServer = false;
    workServerMaxBytes   = 0;
}

WorkAvailability LearningSession::GetWorkAvailability() const noexcept
{
    if (!policy.has_value() || !policy->work.present)
        return WorkAvailability::Absent;
    if (!canPublishSolutions) // course staff are never gated by the switch (as on the server)
    {
        if (!policy->work.enabled)
            return WorkAvailability::DisabledByPolicy;
        if (workDisabledByServer)
            return WorkAvailability::DisabledByServer;
    }
    if (state != SessionState::Active || !transport)
        return WorkAvailability::Unavailable;
    return WorkAvailability::Available;
}

Utils::GStatus LearningSession::CheckWorkUsable(bool staffOnly) const
{
    if (staffOnly && !canPublishSolutions)
        return Utils::GStatus::Error("Only course staff can publish or delete solutions.");
    switch (GetWorkAvailability())
    {
    case WorkAvailability::Available:
        return Utils::GStatus::Ok();
    case WorkAvailability::Absent:
        return Utils::GStatus::Error("This course server does not store course work.");
    case WorkAvailability::DisabledByPolicy:
    case WorkAvailability::DisabledByServer:
        return Utils::GStatus::Error("Saving course work is disabled by your teacher.");
    default:
        return Utils::GStatus::Error(
              state == SessionState::Expired ? "The course policy has expired; reconnect first." : "Course work is not available in the current session state.");
    }
}

std::vector<NoteAudience> LearningSession::SolutionAudiences() const
{
    return audiences.empty() ? std::vector<NoteAudience>{ NoteAudience::All } : audiences;
}

size_t LearningSession::WorkMaxBytes() const noexcept
{
    size_t m = MAX_WORK_DOCUMENT_BYTES;
    if (policy.has_value() && policy->work.present)
        m = std::min<size_t>(m, policy->work.maxBytes);
    if (workServerMaxBytes > 0)
        m = std::min<size_t>(m, workServerMaxBytes);
    return m;
}

std::optional<int64> LearningSession::WorkRevision(std::string_view problem) const
{
    auto it = workRevisions.find(std::string(problem));
    if (it == workRevisions.end())
        return std::nullopt;
    return it->second;
}

void LearningSession::HandleWorkFailure(const ServerError& error, WorkEndpoint endpoint)
{
    if (error.code == ErrorCode::PolicyExpired)
    {
        ExpireLocally("policy_expired");
        return;
    }
    if (error.code != ErrorCode::Forbidden)
        return;
    if (endpoint == WorkEndpoint::Staff)
        canPublishSolutions = false; // this token is not (any more) course staff
    else if (endpoint == WorkEndpoint::OwnWork && !canPublishSolutions)
        workDisabledByServer = true; // hides the Save / Resume UI until the next connect
}

Utils::GStatus LearningSession::GetWork(std::string_view problem, WorkCallback done)
{
    if (auto st = CheckWorkUsable(false); !st.ok)
        return st;
    if (!IsValidItemName(problem))
        return Utils::GStatus::Error("invalid problem");
    auto t           = transport;
    const uint64 gen = generation;
    auto name        = std::make_shared<std::string>(problem);
    RunJob([this, t, gen, name, done]() -> BackgroundWorker::Completion {
        auto result = RunWorkRequest<WorkResult>([&]() { return PerformGetWork(*t, *name, &cancelJobs); });
        return [this, gen, name, result, done]() {
            if (gen != generation)
                return;
            if (result->status.ok)
            {
                const auto& r = result->response;
                if (r.hasWork)
                    workRevisions[*name] = r.revision;
                else
                    workRevisions.erase(*name); // nothing saved (or deleted on the website): the next save creates
                canPublishSolutions  = r.canPublishSolutions;
                audiences            = r.audiences;
                workServerMaxBytes   = r.maxBytes;
                workDisabledByServer = false;
            }
            else
                HandleWorkFailure(result->error, WorkEndpoint::OwnWork);
            if (done)
                done(*result);
        };
    });
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::SaveWork(std::string_view problem, std::string document, bool hasReplay, uint32 replaySteps, SaveWorkCallback done)
{
    if (auto st = CheckWorkUsable(false); !st.ok)
        return st;
    if (!IsValidItemName(problem))
        return Utils::GStatus::Error("invalid problem");
    auto req     = std::make_shared<SaveWorkRequest>();
    req->problem = std::string(problem);
    auto st      = ValidateWorkDocumentText(document, WorkMaxBytes(), req->document);
    WipeString(document);
    if (!st.ok)
        return Utils::GStatus::Error("The work cannot be saved: " + st.message);
    req->hasReplay   = hasReplay;
    req->replaySteps = hasReplay ? replaySteps : 0;
    req->revision    = WorkRevision(problem);
    auto t           = transport;
    const uint64 gen = generation;
    RunJob([this, t, gen, req, done]() -> BackgroundWorker::Completion {
        auto outcome = RunWorkRequest<SaveWorkOutcome>([&]() { return PerformSaveWork(*t, *req, &cancelJobs); });
        return [this, gen, req, outcome, done]() {
            WipeString(req->document);
            if (gen != generation)
                return;
            if (outcome->status.ok)
            {
                workRevisions[req->problem] = outcome->result.revision;
                for (auto& w : catalogue.weeks)
                {
                    for (auto& p : w.problems)
                    {
                        if (p.name == req->problem)
                        {
                            p.hasMe           = true;
                            p.me.workRevision = outcome->result.revision;
                            p.me.workSavedAt  = outcome->result.updatedAt != 0 ? outcome->result.updatedAt : Now();
                        }
                    }
                }
            }
            else if (!outcome->conflict) // a conflict keeps the cached revision: GetWork, then save again to overwrite
            {
                if (outcome->error.code == ErrorCode::NotFound)
                    workRevisions.erase(req->problem); // the work was deleted on the website: the next save creates
                HandleWorkFailure(outcome->error, WorkEndpoint::OwnWork);
            }
            if (done)
                done(*outcome);
        };
    });
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::GetSolution(std::string_view problem, std::optional<int64> id, SolutionCallback done)
{
    if (auto st = CheckWorkUsable(false); !st.ok)
        return st;
    if (!IsValidItemName(problem) || (id.has_value() && *id < 1))
        return Utils::GStatus::Error("invalid problem or solution id");
    auto t           = transport;
    const uint64 gen = generation;
    auto name        = std::make_shared<std::string>(problem);
    RunJob([this, t, gen, name, id, done]() -> BackgroundWorker::Completion {
        auto result = RunWorkRequest<SolutionResult>([&]() { return PerformGetSolution(*t, *name, id, &cancelJobs); });
        return [this, gen, result, done]() {
            if (gen != generation)
                return;
            if (!result->status.ok)
                HandleWorkFailure(result->error, WorkEndpoint::Solution);
            if (done)
                done(*result);
        };
    });
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::PublishSolution(PublishSolutionRequest req, PublishCallback done)
{
    if (auto st = CheckWorkUsable(true); !st.ok)
        return st;
    if (!IsValidItemName(req.problem))
        return Utils::GStatus::Error("invalid problem");
    if (req.id.has_value() && (*req.id < 1 || !req.revision.has_value() || *req.revision < 1))
        return Utils::GStatus::Error("replacing a solution needs its id and revision");
    if (const auto known = SolutionAudiences(); std::find(known.begin(), known.end(), req.audience) == known.end())
        return Utils::GStatus::Error("The course server does not accept solutions for the audience " + std::string(NoteAudienceName(req.audience)) + ".");
    auto shared = std::make_shared<PublishSolutionRequest>(std::move(req));
    std::string canonical;
    auto st = ValidateWorkDocumentText(shared->document, WorkMaxBytes(), canonical);
    WipeString(shared->document);
    if (!st.ok)
        return Utils::GStatus::Error("The solution cannot be published: " + st.message);
    shared->document = std::move(canonical);
    if (!shared->hasReplay)
        shared->replaySteps = 0;
    auto t           = transport;
    const uint64 gen = generation;
    RunJob([this, t, gen, shared, done]() -> BackgroundWorker::Completion {
        auto outcome = RunWorkRequest<PublishOutcome>([&]() { return PerformPublishSolution(*t, *shared, &cancelJobs); });
        return [this, gen, shared, outcome, done]() {
            WipeString(shared->document);
            if (gen != generation)
                return;
            if (!outcome->status.ok && !outcome->conflict)
                HandleWorkFailure(outcome->error, WorkEndpoint::Staff);
            if (done)
                done(*outcome);
        };
    });
    return Utils::GStatus::Ok();
}

Utils::GStatus LearningSession::DeleteSolution(int64 id, DeleteSolutionCallback done)
{
    if (auto st = CheckWorkUsable(true); !st.ok)
        return st;
    if (id < 1)
        return Utils::GStatus::Error("invalid solution id");
    auto t           = transport;
    const uint64 gen = generation;
    RunJob([this, t, gen, id, done]() -> BackgroundWorker::Completion {
        auto outcome = RunWorkRequest<DeleteSolutionOutcome>([&]() { return PerformDeleteSolution(*t, id, &cancelJobs); });
        return [this, gen, outcome, done]() {
            if (gen != generation)
                return;
            if (!outcome->status.ok)
                HandleWorkFailure(outcome->error, WorkEndpoint::Staff);
            if (done)
                done(*outcome);
        };
    });
    return Utils::GStatus::Ok();
}

LearningSession& GetSession()
{
    // intentionally never destroyed: threads are stopped by Shutdown() before process exit, and static destruction
    // order relative to OpenSSL/libcurl is undefined
    static LearningSession* session = new LearningSession();
    return *session;
}
} // namespace GView::Security::Learning
