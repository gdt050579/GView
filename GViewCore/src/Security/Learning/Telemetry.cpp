#include "Telemetry.hpp"

#include <nlohmann/json.hpp>

namespace GView::Security::Learning
{
using json = nlohmann::json;

namespace
{
    constexpr uint32 F(Field f) noexcept
    {
        return 1u << static_cast<uint32>(f);
    }

    struct EventSpec {
        std::string_view name;
        bool item;      // may carry an "item"
        uint32 fields;  // whitelist bitmask
        std::string_view counter; // scalar counter incremented by this event ("" = none)
    };

    // The single source of truth for the telemetry contract (mirrored by the server whitelist).
    constexpr EventSpec EVENT_SPECS[] = {
        /* SessionStart        */ { "session_start", false, 0, "" },
        /* SessionEnd          */ { "session_end", false, F(Field::Reason), "" },
        /* PolicyApplied       */ { "policy_applied", false, F(Field::Mode), "" },
        /* PolicyRejected      */ { "policy_rejected", false, F(Field::Reason), "" },
        /* TaskOpen            */ { "task_open", true, F(Field::ItemVersion) | F(Field::Mode), "" },
        /* TaskClose           */ { "task_close", true, 0, "" },
        /* ResourceOpen        */ { "resource_open", true, F(Field::ItemVersion) | F(Field::Mode), "" },
        /* ViewerOpen          */ { "viewer_open", true, F(Field::Viewer), "" },
        /* JumpFollow          */ { "jump_follow", true, F(Field::From) | F(Field::To) | F(Field::Kind), "jump_follow" },
        /* JumpBack            */ { "jump_back", true, 0, "jump_back" },
        /* JumpForward         */ { "jump_forward", true, 0, "jump_forward" },
        /* GotoEntrypoint      */ { "goto_entrypoint", true, 0, "goto_entrypoint" },
        /* GotoDialog          */ { "goto_dialog", true, 0, "goto_dialog" },
        /* CommentAdd          */ { "comment_add", true, 0, "comment_add" },
        /* CommentEdit         */ { "comment_edit", true, 0, "comment_edit" },
        /* CommentRemove       */ { "comment_remove", true, 0, "comment_remove" },
        /* LabelRename         */ { "label_rename", true, 0, "label_rename" },
        /* NoteAdd             */ { "note_add", true, 0, "note_add" },
        /* Idle                */ { "idle", true, F(Field::Seconds), "" },
        /* FeatureBlocked      */ { "feature_blocked", true, F(Field::Feature), "" },
        /* Submit              */ { "submit", true, F(Field::ClientSubmissionId), "" },
        /* ClientError         */ { "client_error", false, F(Field::Message) | F(Field::Fatal), "" },
        /* ScreenProtectFailed */ { "screen_protect_failed", false, F(Field::Reason), "" },
    };
    static_assert(std::size(EVENT_SPECS) == static_cast<size_t>(EventType::Count), "EVENT_SPECS must cover every EventType");

    constexpr std::string_view FIELD_NAMES[] = { "itemVersion", "mode", "viewer", "from", "to", "kind", "seconds", "feature",
                                                 "clientSubmissionId", "message", "fatal", "reason" };
    static_assert(std::size(FIELD_NAMES) == static_cast<size_t>(Field::Count), "FIELD_NAMES must cover every Field");

    constexpr std::string_view SCALAR_COUNTERS[] = { "jump_follow",    "jump_back",      "jump_forward", "goto_entrypoint", "goto_dialog",
                                                     "comment_add",    "comment_edit",   "comment_remove", "label_rename",  "note_add",
                                                     "idle_seconds",   "active_seconds", "dissasm_seconds" };

    constexpr size_t MAX_STRING_FIELD = 256;

    const EventSpec& Spec(EventType t) noexcept
    {
        return EVENT_SPECS[static_cast<size_t>(t)];
    }

    json EventToJson(const TelemetryEvent& e)
    {
        json j    = json::object();
        j["seq"]  = e.seq;
        j["t"]    = e.t;
        j["type"] = std::string(EventTypeName(e.type));
        if (!e.item.empty())
            j["item"] = e.item;
        for (const auto& f : e.fields)
        {
            const std::string key(FieldName(f.key));
            std::visit(
                  [&](const auto& v) {
                      using V = std::decay_t<decltype(v)>;
                      if constexpr (std::is_same_v<V, std::string>)
                          j[key] = v;
                      else
                          j[key] = v;
                  },
                  f.value);
        }
        return j;
    }
} // namespace

std::string_view EventTypeName(EventType t) noexcept
{
    if (t >= EventType::Count)
        return "unknown";
    return Spec(t).name;
}

std::string_view FieldName(Field f) noexcept
{
    if (f >= Field::Count)
        return "unknown";
    return FIELD_NAMES[static_cast<size_t>(f)];
}

bool IsFieldAllowed(EventType t, Field f) noexcept
{
    if (t >= EventType::Count || f >= Field::Count)
        return false;
    return (Spec(t).fields & F(f)) != 0;
}

bool IsItemAllowed(EventType t) noexcept
{
    return t < EventType::Count && Spec(t).item;
}

std::string_view NormalizeViewerName(std::string_view viewerKind) noexcept
{
    static constexpr std::string_view KNOWN[] = { "Buffer", "Text", "Lexical", "Image", "Grid", "Dissasm", "Container" };
    for (auto k : KNOWN)
    {
        if (k == viewerKind)
            return k;
    }
    return "Other";
}

std::string_view CurrentPlatform() noexcept
{
#if defined(BUILD_FOR_WINDOWS)
#    if defined(_M_ARM64) || defined(__aarch64__)
    return "windows-arm64";
#    else
    return "windows-x64";
#    endif
#elif defined(BUILD_FOR_OSX)
#    if defined(__aarch64__) || defined(__arm64__)
    return "macos-arm64";
#    else
    return "macos-x64";
#    endif
#else
#    if defined(__aarch64__)
    return "linux-arm64";
#    else
    return "linux-x64";
#    endif
#endif
}

FlushOutcome ClassifyTelemetryResponse(const HttpResponse& response) noexcept
{
    if (!response.transportOk)
        return FlushOutcome::Retry;
    if (response.status >= 200 && response.status < 300 && !response.tooLarge)
        return FlushOutcome::Accepted;
    if (response.status == 429 || response.status >= 500)
        return FlushOutcome::Retry;
    // any other 4xx: the batch will never be accepted; do not retry forever (spec §5)
    return FlushOutcome::Dropped;
}

// ============================================================================ collector
TelemetryCollector::TelemetryCollector(Clock clk) : clock(std::move(clk))
{
    if (!clock)
        clock = []() { return NowUnix(); };
}

void TelemetryCollector::Configure(const RestrictedMode::TelemetrySettings& settings)
{
    std::lock_guard<std::mutex> lk(mtx);
    enabled        = settings.enabled;
    eventLevel     = settings.eventLevel;
    maxBatchEvents = std::max<uint32>(1, settings.maxBatchEvents);
    if (!enabled)
    {
        pending.clear();
        inFlight.clear();
        counters.clear();
        countersDirty = false;
    }
}

void TelemetryCollector::Disable()
{
    std::lock_guard<std::mutex> lk(mtx);
    enabled = false;
    pending.clear();
    inFlight.clear();
    counters.clear();
    countersDirty = false;
}

bool TelemetryCollector::IsEnabled() const
{
    std::lock_guard<std::mutex> lk(mtx);
    return enabled;
}

size_t TelemetryCollector::CapacityLocked() const noexcept
{
    return static_cast<size_t>(maxBatchEvents) * 4;
}

TelemetryCollector::ItemCounters& TelemetryCollector::CountersFor(const std::string& item)
{
    auto it = counters.find(item);
    if (it != counters.end())
        return it->second;
    ItemCounters c;
    for (auto name : SCALAR_COUNTERS)
        c.scalars.emplace(std::string(name), 0);
    c.keyed.emplace("viewer_open", std::map<std::string, uint64>{});
    c.keyed.emplace("feature_blocked", std::map<std::string, uint64>{});
    return counters.emplace(item, std::move(c)).first->second;
}

void TelemetryCollector::UpdateCountersLocked(EventType type, const std::string& item, const std::vector<FieldValue>& fields)
{
    if (item.empty())
        return;
    auto& c = CountersFor(item);
    if (auto counter = Spec(type).counter; !counter.empty())
    {
        c.scalars[std::string(counter)]++;
        countersDirty = true;
    }
    auto keyedField = [&](Field f) -> const std::string* {
        for (const auto& fv : fields)
        {
            if (fv.key == f)
                return std::get_if<std::string>(&fv.value);
        }
        return nullptr;
    };
    if (type == EventType::ViewerOpen)
    {
        if (const auto* v = keyedField(Field::Viewer))
        {
            c.keyed["viewer_open"][*v]++;
            countersDirty = true;
        }
    }
    else if (type == EventType::FeatureBlocked)
    {
        if (const auto* v = keyedField(Field::Feature))
        {
            c.keyed["feature_blocked"][*v]++;
            countersDirty = true;
        }
    }
    else if (type == EventType::Idle)
    {
        for (const auto& fv : fields)
        {
            if (fv.key == Field::Seconds)
            {
                if (const auto* s = std::get_if<int64>(&fv.value); s && *s > 0)
                {
                    c.scalars["idle_seconds"] += static_cast<uint64>(*s);
                    countersDirty = true;
                }
            }
        }
    }
}

bool TelemetryCollector::Record(EventType type, std::string_view item, std::initializer_list<FieldValue> fields)
{
    return Record(type, item, std::vector<FieldValue>(fields));
}

bool TelemetryCollector::Record(EventType type, std::string_view item, std::vector<FieldValue> fields)
{
    std::lock_guard<std::mutex> lk(mtx);
    if (!enabled || type >= EventType::Count)
        return false;
    // privacy whitelist: refuse the whole event if any field is not allowed for this type
    if (!item.empty() && !Spec(type).item)
    {
        whitelistViolations++;
        return false;
    }
    for (auto& f : fields)
    {
        if (!IsFieldAllowed(type, f.key))
        {
            whitelistViolations++;
            return false;
        }
        if (auto* s = std::get_if<std::string>(&f.value); s && s->size() > MAX_STRING_FIELD)
            s->resize(MAX_STRING_FIELD);
    }
    TelemetryEvent e;
    e.seq    = nextSeq++;
    e.t      = clock();
    e.type   = type;
    e.item   = std::string(item.substr(0, MAX_ITEM_NAME_LENGTH));
    e.fields = std::move(fields);
    UpdateCountersLocked(type, e.item, e.fields);
    if (!eventLevel)
        return true; // counters only
    // bounded queue: drop the oldest pending events beyond maxBatchEvents x 4
    while (!pending.empty() && pending.size() + inFlight.size() >= CapacityLocked())
    {
        pending.pop_front();
        droppedEvents++;
    }
    if (pending.size() + inFlight.size() >= CapacityLocked())
    {
        droppedEvents++;
        return true; // everything is in flight; this event is lost but counted
    }
    pending.push_back(std::move(e));
    return true;
}

void TelemetryCollector::AddSeconds(std::string_view item, std::string_view counterName, uint64 seconds)
{
    if (seconds == 0 || item.empty())
        return;
    if (counterName != "idle_seconds" && counterName != "active_seconds" && counterName != "dissasm_seconds")
        return;
    std::lock_guard<std::mutex> lk(mtx);
    if (!enabled)
        return;
    auto& c = CountersFor(std::string(item.substr(0, MAX_ITEM_NAME_LENGTH)));
    c.scalars[std::string(counterName)] += seconds;
    countersDirty = true;
}

std::optional<std::string> TelemetryCollector::BeginBatch(const BatchMeta& meta, size_t maxBodyBytes)
{
    std::lock_guard<std::mutex> lk(mtx);
    if (!enabled || !inFlight.empty() || countersInFlight)
        return std::nullopt;
    if (pending.empty() && !countersDirty)
        return std::nullopt;

    json body               = json::object();
    body["sessionId"]       = meta.sessionId;
    body["policyId"]        = meta.policyId;
    body["policyDigest"]    = meta.policyDigest;
    body["clientVersion"]   = meta.clientVersion;
    body["platform"]        = meta.platform;
    body["sentAt"]          = meta.sentAt;
    json counterJson        = json::object();
    for (const auto& [item, c] : counters)
    {
        json ic = json::object();
        for (const auto& [k, v] : c.scalars)
            ic[k] = v;
        for (const auto& [k, m] : c.keyed)
        {
            json km = json::object();
            for (const auto& [kk, vv] : m)
                km[kk] = vv;
            ic[k] = std::move(km);
        }
        counterJson[item] = std::move(ic);
    }
    body["counters"] = std::move(counterJson);
    size_t budget    = body.dump().size();

    json events = json::array();
    while (!pending.empty() && inFlight.size() < maxBatchEvents)
    {
        json ej              = EventToJson(pending.front());
        const size_t evtSize = ej.dump().size() + 1;
        if (!inFlight.empty() && budget + evtSize > maxBodyBytes)
            break;
        budget += evtSize;
        events.push_back(std::move(ej));
        inFlight.push_back(std::move(pending.front()));
        pending.pop_front();
    }
    body["events"]   = std::move(events);
    countersInFlight = true;
    countersDirty    = false;
    return body.dump();
}

void TelemetryCollector::OnFlushResult(FlushOutcome outcome)
{
    std::lock_guard<std::mutex> lk(mtx);
    if (outcome == FlushOutcome::Retry)
    {
        // keep ordering: in-flight events go back to the front of the queue
        for (auto it = inFlight.rbegin(); it != inFlight.rend(); ++it)
            pending.push_front(std::move(*it));
        if (countersInFlight)
            countersDirty = true;
        while (pending.size() > CapacityLocked())
        {
            pending.pop_front();
            droppedEvents++;
        }
    }
    else if (outcome == FlushOutcome::Dropped)
    {
        droppedEvents += inFlight.size();
    }
    inFlight.clear();
    countersInFlight = false;
}

size_t TelemetryCollector::PendingCount() const
{
    std::lock_guard<std::mutex> lk(mtx);
    return pending.size();
}

size_t TelemetryCollector::InFlightCount() const
{
    std::lock_guard<std::mutex> lk(mtx);
    return inFlight.size();
}

uint64 TelemetryCollector::DroppedCount() const
{
    std::lock_guard<std::mutex> lk(mtx);
    return droppedEvents;
}

uint32 TelemetryCollector::WhitelistViolations() const
{
    std::lock_guard<std::mutex> lk(mtx);
    return whitelistViolations;
}

uint64 TelemetryCollector::LastSeq() const
{
    std::lock_guard<std::mutex> lk(mtx);
    return nextSeq - 1;
}

std::string TelemetryCollector::CountersJson() const
{
    std::lock_guard<std::mutex> lk(mtx);
    json out = json::object();
    for (const auto& [item, c] : counters)
    {
        json ic = json::object();
        for (const auto& [k, v] : c.scalars)
            ic[k] = v;
        for (const auto& [k, m] : c.keyed)
        {
            json km = json::object();
            for (const auto& [kk, vv] : m)
                km[kk] = vv;
            ic[k] = std::move(km);
        }
        out[item] = std::move(ic);
    }
    return out.dump();
}

// ============================================================================ flusher
TelemetryFlusher::~TelemetryFlusher()
{
    Stop();
}

std::optional<FlushOutcome> TelemetryFlusher::FlushOnce(
      IHttpTransport& transport, TelemetryCollector& collector, const BatchMeta& meta, long timeoutSeconds, const std::atomic<bool>* cancel,
      bool* policyExpired)
{
    auto body = collector.BeginBatch(meta);
    if (!body.has_value())
        return std::nullopt;
    HttpRequest req;
    req.path                = "/GView/Telemetry";
    req.body.assign(body->data(), body->size());
    req.maxResponseBytes    = 64 * 1024;
    req.totalTimeoutSeconds = timeoutSeconds;
    req.cancel              = cancel;
    auto resp               = transport.Post(req);
    const auto outcome      = ClassifyTelemetryResponse(resp);
    if (policyExpired != nullptr && resp.transportOk && resp.status == 403)
        *policyExpired = resp.ToError().code == ErrorCode::PolicyExpired;
    collector.OnFlushResult(outcome);
    return outcome;
}

void TelemetryFlusher::Start(std::shared_ptr<IHttpTransport> t, TelemetryCollector* c, MetaProvider meta, ExpiredSignal expired, uint32 interval)
{
    Stop();
    transport       = std::move(t);
    collector       = c;
    metaProvider    = std::move(meta);
    onPolicyExpired = std::move(expired);
    intervalSeconds = std::max<uint32>(5, interval);
    {
        std::lock_guard<std::mutex> lk(mtx);
        stopRequested  = false;
        flushRequested = false;
    }
    cancel.store(false);
    worker = std::thread([this]() { Run(); });
}

void TelemetryFlusher::Run()
{
    while (true)
    {
        {
            std::unique_lock<std::mutex> lk(mtx);
            cv.wait_for(lk, std::chrono::seconds(intervalSeconds), [this]() { return stopRequested || flushRequested; });
            if (stopRequested)
                return;
            flushRequested = false;
        }
        try
        {
            std::lock_guard<std::mutex> fl(flushMutex);
            bool expired = false;
            // drain: keep sending while full batches are accepted
            for (int round = 0; round < 8; round++)
            {
                auto outcome = FlushOnce(*transport, *collector, metaProvider(), 15, &cancel, &expired);
                if (!outcome.has_value() || *outcome != FlushOutcome::Accepted || collector->PendingCount() == 0)
                    break;
            }
            if (expired && onPolicyExpired)
                onPolicyExpired();
        }
        catch (...)
        {
            // never let telemetry take the process down
        }
    }
}

void TelemetryFlusher::RequestFlush()
{
    if (!worker.joinable())
        return;
    {
        std::lock_guard<std::mutex> lk(mtx);
        flushRequested = true;
    }
    cv.notify_one();
}

void TelemetryFlusher::Stop()
{
    if (!worker.joinable())
        return;
    {
        std::lock_guard<std::mutex> lk(mtx);
        stopRequested = true;
    }
    cancel.store(true);
    cv.notify_one();
    worker.join();
    cancel.store(false);
}

void TelemetryFlusher::StopAndFlush(long timeoutSeconds)
{
    const bool hadWorker = worker.joinable();
    Stop();
    if (!hadWorker || !transport || collector == nullptr)
        return;
    try
    {
        std::lock_guard<std::mutex> fl(flushMutex);
        FlushOnce(*transport, *collector, metaProvider(), std::max<long>(1, timeoutSeconds), nullptr);
    }
    catch (...)
    {
    }
}
} // namespace GView::Security::Learning
