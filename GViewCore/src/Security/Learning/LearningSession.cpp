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
    constexpr long FINAL_FLUSH_TIMEOUT_S = 2;

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
            return std::shared_ptr<IHttpTransport>(CreateCurlTransport(std::move(cfg)));
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

void LearningSession::RunJob(BackgroundWorker::Job job)
{
    pendingJobs++;
    BackgroundWorker::Job wrapped = [this, job = std::move(job)]() -> BackgroundWorker::Completion {
        // the completion must always be produced: it is the only place pendingJobs is released, so a throwing job
        // (e.g. bad_alloc) must not leave the session permanently busy
        BackgroundWorker::Completion c;
        try
        {
            c = job();
        }
        catch (...)
        {
            c = nullptr;
        }
        return [this, c = std::move(c)]() {
            if (pendingJobs > 0)
                pendingJobs--;
            if (c)
                c();
        };
    };
    if (deps.synchronous || !frameUpdatesSeen.load(std::memory_order_acquire))
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
    if (HasSession() && !bindings.empty() &&
        (ci.serverUrl != info.serverUrl || ci.token.size() != info.token.size() ||
         !Crypto::Internal::ConstantTimeEquals(ci.token.data(), info.token.data(), ci.token.size())))
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
        };
    });
    return Utils::GStatus::Ok();
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
    SetState(SessionState::Active, "Connected. Course policy verified and applied.");
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
    if (policy.has_value() && (state == SessionState::Active || state == SessionState::Error) &&
        Now() > policy->endsAt + RestrictedMode::POLICY_CLOCK_SKEW_SECONDS)
        ExpireLocally("policy_ended");
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
    }
    else
    {
        s.explanationMaxChars = 100000;
    }
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

void LearningSession::OnObjectCreated(const void* obj)
{
    if (!pendingBinding.has_value() || obj == nullptr)
        return;
    bindings[obj] = std::move(*pendingBinding);
    pendingBinding.reset();
}

void LearningSession::OnObjectClosed(const void* obj)
{
    auto it = bindings.find(obj);
    if (it == bindings.end())
        return;
    if (it->second.problem)
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
    if (it->second.lastViewer != viewer)
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
    return telemetry.Record(type, b->item, std::move(fields));
}

void LearningSession::RecordFeatureBlocked(Feature feature)
{
    const auto* b = focusedObject != nullptr ? FindBinding(focusedObject) : nullptr;
    telemetry.Record(
          EventType::FeatureBlocked,
          b != nullptr ? std::string_view(b->item) : std::string_view(),
          { FieldValue{ Field::Feature, std::string(RestrictedMode::FeatureToString(feature)) } });
}

void LearningSession::RecordClientError(std::string_view constantMessage, bool fatal)
{
    telemetry.Record(EventType::ClientError, "", { FieldValue{ Field::Message, std::string(constantMessage) }, FieldValue{ Field::Fatal, fatal } });
}

void LearningSession::RecordItemOpened(const CatalogueItem& item, DeliveryMode mode, uint32 version)
{
    telemetry.Record(
          item.IsProblem() ? EventType::TaskOpen : EventType::ResourceOpen,
          item.name,
          { FieldValue{ Field::ItemVersion, static_cast<int64>(version) }, FieldValue{ Field::Mode, std::string(ModeName(mode)) } });
}

LearningSession& GetSession()
{
    // intentionally never destroyed: threads are stopped by Shutdown() before process exit, and static destruction
    // order relative to OpenSSL/libcurl is undefined
    static LearningSession* session = new LearningSession();
    return *session;
}
} // namespace GView::Security::Learning
