#pragma once

// Learning and Evaluation Mode client session (plans/PLAN_GVIEW_CLIENT.md §3).
//
//   Disconnected --Connect--> Connecting --verified policy--> Active --endsAt / POLICY_EXPIRED--> Expired
//                                  |  \--legacy server-------> Legacy (catalogue only, unrestricted)
//                                  \--------any failure-----> Error (no task can be opened)
//   Active --requireScreenProtect unmet--> Error (restrictions stay applied, tasks cannot be opened)
//   Active/Expired/Error --Reconnect--> Connecting (the current policy stays in force until a newer one validates)
//
// Threading: every public non-static method is UI-thread only, except the ones documented otherwise. Network work
// runs in Perform* (static, pure) on the BackgroundWorker; completions are applied on the UI thread.

#include "BackgroundWorker.hpp"
#include "ContentDelivery.hpp"
#include "Telemetry.hpp"

#include <array>
#include <map>

namespace GView::Security::Learning
{
enum class SessionState : uint8 { Disconnected, Connecting, Active, Legacy, Expired, Error };
std::string_view SessionStateName(SessionState s) noexcept;

struct LearningSettings {
    bool allowPlainHttpLocalhost{ false };
    std::vector<uint8> fallbackPublicKey; // [GView] PolicyPublicKey
    std::string downloadFolder;           // [GView] LearningDownloadFolder
};

struct ConnectResult {
    Utils::GStatus status;
    std::string rejectCode; // POLICY_* when the policy was rejected by validation
    ServerError error;      // server / transport error
    ConnectResponse response;
    std::optional<RestrictedMode::Policy> policy;
};

struct CatalogueResult {
    Utils::GStatus status;
    ServerError error;
    Catalogue catalogue;
};

struct DownloadResult {
    Utils::GStatus status;
    ServerError error;
    CatalogueItem item;
    DeliveredContent content;
};

struct SubmitOutcome {
    Utils::GStatus status;
    ServerError error;
    SubmitResult result;
    bool definitive{ false }; // the server graded (or refused) the answer: the idempotency key is consumed
};

struct ItemBinding {
    std::string item;
    bool problem{ false };
    DeliveryMode mode{ DeliveryMode::File };
    uint32 version{ 0 };
    std::string lastViewer;
};

// Idempotency keys (spec §4): one UUIDv4 per *new* answer, reused for transport retries of the same answer.
class SubmissionTracker
{
    struct Entry {
        std::array<uint8, 32> fingerprint{};
        std::string id;
    };
    std::map<std::string, Entry> entries;

  public:
    // returns the id to use for (problem, flag, explanation); empty on RNG failure
    std::string IdFor(std::string_view problem, const SecureString& flag, const SecureString& explanation);
    // the server produced a verdict: the next submission for this problem is a new attempt
    void Consume(std::string_view problem);
    void Clear() noexcept
    {
        entries.clear();
    }
};

class LearningSession
{
  public:
    using TransportFactory = std::function<std::shared_ptr<IHttpTransport>(const ConnectionInfo&, const LearningSettings&)>;
    using Activator        = std::function<Utils::GStatus(const RestrictedMode::Policy&, RestrictedMode::Internal::ActivationReport&)>;
    using Deactivator      = std::function<void()>;
    using Clock            = std::function<uint64()>;       // unix seconds
    using MonoClock        = std::function<uint64()>;       // monotonic milliseconds
    using StatusCallback   = std::function<void(const Utils::GStatus&)>;
    using DownloadCallback = std::function<void(DownloadResult&)>;
    using SubmitCallback   = std::function<void(const SubmitOutcome&)>;

    struct Dependencies {
        TransportFactory transportFactory;
        Activator activate;
        Deactivator deactivate;
        Clock clock;
        MonoClock monoClock;
        bool synchronous{ false };    // run jobs inline (tests, frontends without frame updates)
        bool telemetryThread{ true }; // start the background flusher (tests drive flushes explicitly)
    };

    struct Status {
        SessionState state{ SessionState::Disconnected };
        std::string message;
        std::string displayName;
        int64 score{ 0 };
        std::string label;
        std::string serverUrl;
        std::string purpose;
        std::string policyId;
        uint64 endsAt{ 0 };
        bool hasPolicy{ false };
        RestrictedMode::StorageMode storageMode{ RestrictedMode::StorageMode::File };
        std::vector<RestrictedMode::Feature> disabledFeatures;
        bool telemetryEnabled{ false };
        bool screenProtectRequested{ false };
        bool screenProtectApplied{ false };
        bool screenRequirementUnmet{ false };
        std::string screenNote;
        bool submissionAllowed{ false };
        bool requireExplanation{ false };
        uint32 explanationMaxChars{ 0 };
        bool busy{ false };
    };

  private:
    Dependencies deps;
    BackgroundWorker worker;
    std::atomic<bool> frameUpdatesSeen{ false };
    std::atomic<bool> cancelJobs{ false }; // aborts the running network job (session end / exit)
    uint64 generation{ 0 };

    SessionState state{ SessionState::Disconnected };
    std::string statusMessage;
    ConnectionInfo info;
    LearningSettings settings;
    std::shared_ptr<IHttpTransport> transport;
    std::optional<RestrictedMode::Policy> policy;
    RestrictedMode::Internal::ActivationReport activation;
    bool screenRequirementUnmet{ false };
    ConnectResponse lastConnect;
    Catalogue catalogue;
    bool catalogueLoaded{ false };
    std::string sessionId;
    bool sessionStartRecorded{ false };
    bool restrictionsActive{ false };
    uint32 pendingJobs{ 0 };

    TelemetryCollector telemetry;
    TelemetryFlusher flusher;
    std::atomic<bool> serverReportedExpiry{ false };

    std::map<const void*, ItemBinding> bindings;
    std::optional<ItemBinding> pendingBinding;
    SubmissionTracker submissions;

    // activity / time accounting (monotonic ms)
    std::atomic<uint64> lastActivityMs{ 0 };
    bool idle{ false };
    uint64 idleSinceMs{ 0 };
    uint64 lastTickMs{ 0 };
    uint64 activeCarryMs{ 0 };
    uint64 dissasmCarryMs{ 0 };
    const void* focusedObject{ nullptr };
    std::string focusedViewer;
    std::string lastFocusedItem;

    void RunJob(BackgroundWorker::Job job);
    void StopJobs() noexcept;
    void SetState(SessionState s, std::string message);
    void ConfigureTelemetry();
    void RecordSessionEnd(std::string_view reason);
    void ExpireLocally(std::string_view reason);
    void AccountTime(uint64 nowMs);
    BatchMeta MakeBatchMeta() const;
    uint64 Now() const;
    uint64 NowMs() const;

  public:
    // two constructors instead of `Dependencies d = {}`: a default argument that value-initializes a nested class with
    // default member initializers is ill-formed inside the enclosing class (GCC/Clang reject it, MSVC accepts it)
    LearningSession();
    explicit LearningSession(Dependencies d);
    ~LearningSession();
    LearningSession(const LearningSession&)            = delete;
    LearningSession& operator=(const LearningSession&) = delete;

    // ---------------- pure network operations (any thread) ----------------
    // cancel (optional): when it becomes true the transfer is aborted (see HttpRequest::cancel)
    static ConnectResult PerformConnect(IHttpTransport& t, const ConnectionInfo& info, uint64 now, const std::atomic<bool>* cancel = nullptr);
    static CatalogueResult PerformFetchCatalogue(IHttpTransport& t, const std::atomic<bool>* cancel = nullptr);
    static DownloadResult PerformDownload(
          IHttpTransport& t,
          const CatalogueItem& item,
          const std::optional<RestrictedMode::Policy>& policy,
          const SecureString& token,
          const std::atomic<bool>* cancel = nullptr);
    static SubmitOutcome PerformSubmit(IHttpTransport& t, const SubmitRequest& req, const std::atomic<bool>* cancel = nullptr);

    // ---------------- UI thread state machine ----------------
    // Parses the connection string and starts the connect job. done() runs on the UI thread.
    Utils::GStatus Connect(std::string_view connectionString, const LearningSettings& s, StatusCallback done);
    // Applies a finished connect (normally called by Connect's completion; public for tests).
    Utils::GStatus ApplyConnectResult(ConnectionInfo&& newInfo, std::shared_ptr<IHttpTransport> newTransport, ConnectResult&& result);
    Utils::GStatus RefreshCatalogue(StatusCallback done);
    Utils::GStatus Download(const CatalogueItem& item, DownloadCallback done);
    Utils::GStatus Submit(std::string_view problem, SecureString flag, SecureString explanation, SubmitCallback done);
    // Ends the session: refuses while learning windows are open (their content would lose its protection).
    Utils::GStatus EndSession(std::string_view reason);
    void Shutdown() noexcept; // application exit: session_end, bounded flush, deactivate, wipe secrets

    // per-frame pump (UI thread); safe to call many times per frame. drainCompletions must be false when called while
    // AppCUI iterates the desktop children (FileWindow::OnFrameUpdate): a completion may open a new window.
    void Tick(bool drainCompletions = true);
    void NotifyFrameUpdatesAvailable() noexcept
    {
        frameUpdatesSeen.store(true, std::memory_order_release);
    }
    size_t DrainCompletions()
    {
        return worker.DrainCompletions();
    }

    // ---------------- queries ----------------
    Status GetStatus() const;
    SessionState GetState() const noexcept
    {
        return state;
    }
    bool HasSession() const noexcept
    {
        return state != SessionState::Disconnected;
    }
    bool CanOpenItems() const noexcept;
    bool CanSubmit() const noexcept;
    const Catalogue& GetCatalogue() const noexcept
    {
        return catalogue;
    }
    bool IsCatalogueLoaded() const noexcept
    {
        return catalogueLoaded;
    }
    const std::optional<RestrictedMode::Policy>& GetPolicy() const noexcept
    {
        return policy;
    }
    const std::string& GetSessionId() const noexcept
    {
        return sessionId;
    }
    const LearningSettings& GetSettings() const noexcept
    {
        return settings;
    }
    TelemetryCollector& Telemetry() noexcept
    {
        return telemetry;
    }

    // ---------------- window bindings / hooks (UI thread) ----------------
    void SetPendingBinding(ItemBinding binding);
    void ClearPendingBinding() noexcept;
    void OnObjectCreated(const void* obj);
    void OnObjectClosed(const void* obj);
    const ItemBinding* FindBinding(const void* obj) const noexcept;
    size_t OpenLearningWindows() const noexcept
    {
        return bindings.size();
    }
    void OnFrame(const void* obj, std::string_view viewerKind, bool focused);
    void NoteActivity() noexcept; // any thread
    bool Record(const void* obj, EventType type, std::vector<FieldValue> fields = {});
    void RecordFeatureBlocked(RestrictedMode::Feature feature);
    void RecordClientError(std::string_view constantMessage, bool fatal);
    void RecordItemOpened(const CatalogueItem& item, DeliveryMode mode, uint32 version);
};

// process-wide session used by the UI and the hooks
LearningSession& GetSession();
} // namespace GView::Security::Learning
