#pragma once

// Learning-mode telemetry (spec §5).
//
// Privacy by construction:
//  - the event type set is closed (EventType) and every event type has a fixed whitelist of fields (Field);
//    Record() refuses (and counts) any attempt to attach a field outside that whitelist;
//  - field values are numbers, booleans, or short strings produced by GView itself (addresses, mnemonics, viewer
//    names, feature names, error codes) - never comment text, label names, notes, clipboard content or paths.
//  - when the policy disables telemetry (or there is no policy) Record() is a no-op and no thread is started.

#include "LearningHttp.hpp"

#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <thread>
#include <variant>

namespace GView::Security::Learning
{
enum class EventType : uint8 {
    SessionStart,
    SessionEnd,
    PolicyApplied,
    PolicyRejected,
    TaskOpen,
    TaskClose,
    ResourceOpen,
    ViewerOpen,
    JumpFollow,
    JumpBack,
    JumpForward,
    GotoEntrypoint,
    GotoDialog,
    CommentAdd,
    CommentEdit,
    CommentRemove,
    LabelRename,
    NoteAdd,
    Idle,
    FeatureBlocked,
    Submit,
    ClientError,
    ScreenProtectFailed,
    Count
};

enum class Field : uint8 { ItemVersion, Mode, Viewer, From, To, Kind, Seconds, Feature, ClientSubmissionId, Message, Fatal, Reason, Count };

std::string_view EventTypeName(EventType t) noexcept;
std::string_view FieldName(Field f) noexcept;
bool IsFieldAllowed(EventType t, Field f) noexcept;
bool IsItemAllowed(EventType t) noexcept;

// closed set of viewer names used in viewer_open / counters
std::string_view NormalizeViewerName(std::string_view viewerKind) noexcept;

struct FieldValue {
    Field key;
    std::variant<int64, bool, std::string> value;
};

struct TelemetryEvent {
    uint64 seq{ 0 };
    uint64 t{ 0 };
    EventType type{ EventType::SessionStart };
    std::string item;
    std::vector<FieldValue> fields;
};

struct BatchMeta {
    std::string sessionId;
    std::string policyId;
    std::string policyDigest;
    std::string clientVersion;
    std::string platform;
    uint64 sentAt{ 0 };
};

enum class FlushOutcome : uint8 { Accepted, Dropped, Retry };
FlushOutcome ClassifyTelemetryResponse(const HttpResponse& response) noexcept;
std::string_view CurrentPlatform() noexcept;

class TelemetryCollector
{
  public:
    using Clock = std::function<uint64()>;

  private:
    mutable std::mutex mtx;
    Clock clock;
    bool enabled{ false };
    bool eventLevel{ true };
    uint32 maxBatchEvents{ 500 };
    uint64 nextSeq{ 1 };
    std::deque<TelemetryEvent> pending;
    std::vector<TelemetryEvent> inFlight;
    bool countersDirty{ false };
    bool countersInFlight{ false };
    uint64 droppedEvents{ 0 };
    uint32 whitelistViolations{ 0 };

    struct ItemCounters {
        std::map<std::string, uint64> scalars;
        std::map<std::string, std::map<std::string, uint64>> keyed;
    };
    std::map<std::string, ItemCounters> counters;

    void UpdateCountersLocked(EventType type, const std::string& item, const std::vector<FieldValue>& fields);
    ItemCounters& CountersFor(const std::string& item);
    size_t CapacityLocked() const noexcept;

  public:
    explicit TelemetryCollector(Clock clk = {});

    void Configure(const RestrictedMode::TelemetrySettings& settings);
    void Disable();
    bool IsEnabled() const;

    // Returns false when telemetry is disabled or a field violates the whitelist (the event is then not recorded).
    bool Record(EventType type, std::string_view item, std::initializer_list<FieldValue> fields = {});
    bool Record(EventType type, std::string_view item, std::vector<FieldValue> fields);
    // time accounting: name must be one of idle_seconds, active_seconds, dissasm_seconds
    void AddSeconds(std::string_view item, std::string_view counterName, uint64 seconds);

    // Moves up to maxBatchEvents pending events into the in-flight set and serialises the batch. Returns an empty
    // optional when there is nothing to send. Exactly one batch can be in flight; call OnFlushResult afterwards.
    std::optional<std::string> BeginBatch(const BatchMeta& meta, size_t maxBodyBytes = 900 * 1024);
    void OnFlushResult(FlushOutcome outcome);

    size_t PendingCount() const;
    size_t InFlightCount() const;
    uint64 DroppedCount() const;
    uint32 WhitelistViolations() const;
    uint64 LastSeq() const;
    std::string CountersJson() const; // for tests / diagnostics
};

// Background flusher: posts batches to /GView/Telemetry every flushIntervalSeconds or on demand.
class TelemetryFlusher
{
  public:
    using MetaProvider  = std::function<BatchMeta()>;
    using ExpiredSignal = std::function<void()>;

  private:
    std::shared_ptr<IHttpTransport> transport;
    TelemetryCollector* collector{ nullptr };
    MetaProvider metaProvider;
    ExpiredSignal onPolicyExpired;
    uint32 intervalSeconds{ 60 };

    std::thread worker;
    std::mutex mtx;
    std::condition_variable cv;
    bool stopRequested{ false };
    bool flushRequested{ false };
    std::atomic<bool> cancel{ false };
    std::mutex flushMutex; // serialises FlushOnce between the worker and FlushSync

    void Run();

  public:
    TelemetryFlusher() = default;
    ~TelemetryFlusher();
    TelemetryFlusher(const TelemetryFlusher&)            = delete;
    TelemetryFlusher& operator=(const TelemetryFlusher&) = delete;

    void Start(std::shared_ptr<IHttpTransport> t, TelemetryCollector* c, MetaProvider meta, ExpiredSignal expired, uint32 interval);
    void RequestFlush();
    // Stops the thread (aborting any in-flight request) and performs one synchronous flush bounded by timeoutSeconds.
    void StopAndFlush(long timeoutSeconds);
    void Stop();
    bool IsRunning() const noexcept
    {
        return worker.joinable();
    }
    // One flush attempt (used by the thread and by tests). Returns the outcome, or nullopt if nothing was sent.
    static std::optional<FlushOutcome> FlushOnce(
          IHttpTransport& transport, TelemetryCollector& collector, const BatchMeta& meta, long timeoutSeconds, const std::atomic<bool>* cancel,
          bool* policyExpired = nullptr);
};
} // namespace GView::Security::Learning
