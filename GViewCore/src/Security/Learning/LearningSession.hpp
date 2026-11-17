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
// WebAssembly: the BackgroundWorker runs its jobs on the UI thread and re-runs them when their responses arrive
// (JobReplay.hpp); the telemetry flusher is driven by Tick() - same code paths, no thread.

#include "BackgroundWorker.hpp"
#include "ContentDelivery.hpp"
#include "LearningNotes.hpp"
#include "LearningWork.hpp"
#include "Telemetry.hpp"

#include <array>
#include <map>
#include <set>

namespace GView::Security::Learning
{
enum class SessionState : uint8 { Disconnected, Connecting, Active, Legacy, Expired, Error };
std::string_view SessionStateName(SessionState s) noexcept;

// status message of a normal Active session (the UI does not repeat it: the state already says so)
constexpr std::string_view ACTIVE_STATUS_MESSAGE = "Connected. Course policy verified and applied.";

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

// Course notes (spec §10.11) as seen by the UI
enum class NotesAvailability : uint8 {
    Absent,           // no policy, or a policy without a "notes" object (server without notes): no Notes UI
    DisabledByPolicy, // policy.notes.enabled = false at connect: "disabled by your teacher", GetNotes is not called
    DisabledByServer, // a note endpoint answered 403 FORBIDDEN (notes turned off after connect): same message
    Unavailable,      // the session is not Active (connecting, expired, error)
    Available,
};

// Course work documents and teacher solutions (spec §10.12) as seen by the UI. Course staff (canPublishSolutions) are
// never gated by the switch: they get Available whenever the server has the feature and the session is Active.
enum class WorkAvailability : uint8 {
    Absent,           // no policy, or a policy without a "work" object (server without it): no Save / Resume / Compare UI
    DisabledByPolicy, // policy.work.enabled = false at connect: "disabled by your teacher"
    DisabledByServer, // GetWork / SaveWork answered 403 FORBIDDEN (turned off after connect): same message
    Unavailable,      // the session is not Active (connecting, expired, error)
    Available,
};

struct ItemBinding {
    std::string item;
    bool problem{ false };
    DeliveryMode mode{ DeliveryMode::File };
    uint32 version{ 0 };
    std::string lastViewer;
    // what the window shows (Hooks::GetWorkspaceRole); Normal is never stored (it means: no binding)
    WorkspaceRole role{ WorkspaceRole::Student };
    // a work document (JSON) the window applies once it is shown (Hooks::TakePendingWorkDocument: taken once)
    std::optional<std::string> pendingWork;
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
    using NoteOpCallback   = std::function<void(const NoteOpOutcome&)>;
    using WorkCallback           = std::function<void(WorkResult&)>;
    using SaveWorkCallback       = std::function<void(const SaveWorkOutcome&)>;
    using SolutionCallback       = std::function<void(SolutionResult&)>;
    using PublishCallback        = std::function<void(const PublishOutcome&)>;
    using DeleteSolutionCallback = std::function<void(const DeleteSolutionOutcome&)>;

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
        NotesAvailability notes{ NotesAvailability::Absent };
        uint32 notesMaxChars{ 0 };
        WorkAvailability work{ WorkAvailability::Absent };
        uint32 workMaxBytes{ 0 }; // largest work document this client sends (policy / GetWork / client cap); 0 without a policy
        bool canPublishSolutions{ false };
        std::vector<NoteAudience> audiences; // the audiences a solution may be published to (All first); empty = unknown
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
    // in-memory objects created while memory-only content was open (e.g. an entry extracted from a memory-only archive):
    // they may hold derived content, so they are treated as memory-only until their window closes
    std::set<const void*> memoryDerived;
    SubmissionTracker submissions;

    // course notes (memory only; see LearningNotes.hpp)
    NotesSync notes;
    std::vector<TeacherNote> teacherNotes;
    bool canEditTeacherNotes{ false };
    bool notesLoaded{ false };           // a GetNotes answer was applied since connect
    bool notesDisabledByServer{ false }; // 403 FORBIDDEN from a student note endpoint
    bool notesFetchInFlight{ false };
    bool notesFetchQueued{ false };
    bool notesRefetchWanted{ false };    // the last GetNotes failed with a retryable error
    uint64 notesRefetchAtMs{ 0 };
    uint32 notesFetchRetries{ 0 };
    uint64 notesEpoch{ 0 };              // completions of note requests from before EndSession are dropped
    uint64 teacherNotesVersion{ 0 };
    std::string notesError;              // last GetNotes failure, shown by the Notes window
    std::vector<std::string> notesNotices;

    // course work and solutions (spec §10.12; the documents themselves are never kept here)
    std::map<std::string, int64> workRevisions; // problem => last revision of the own work seen (GetWork / SaveWork)
    bool canPublishSolutions{ false };          // Connect user.canPublishSolutions, then GetWork (authoritative)
    std::vector<NoteAudience> audiences;        // Connect user.audiences, then GetWork
    bool workDisabledByServer{ false };         // 403 FORBIDDEN from GetWork / SaveWork for a student
    uint32 workServerMaxBytes{ 0 };             // "maxBytes" of the last GetWork (0 = not known yet)

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

    // countsAsBusy=false: background work (note autosave) that must not disable the window's buttons
    void RunJob(BackgroundWorker::Job job, bool countsAsBusy = true);
    void StopJobs() noexcept;
    void StartNoteAction(NotesSync::Action action);
    void HandleNoteFailure(NoteFailure failure, bool teacherEndpoint);
    void FinalNoteSaves() noexcept;
    void ResetNotes() noexcept;
    void ResetWork() noexcept;
    enum class WorkEndpoint : uint8 { OwnWork, Solution, Staff };
    // PolicyExpired => ExpireLocally; 403 => workDisabledByServer (own work, students) / not course staff (staff endpoints)
    void HandleWorkFailure(const ServerError& error, WorkEndpoint endpoint);
    // the precondition of every work / solution request; refusals carry the message for the user
    Utils::GStatus CheckWorkUsable(bool staffOnly) const;
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
    // course notes (spec §10.11)
    static NotesFetchResult PerformGetNotes(IHttpTransport& t, const std::atomic<bool>* cancel = nullptr);
    static NoteOpOutcome PerformSaveNote(
          IHttpTransport& t, const SaveNoteRequest& req, const std::atomic<bool>* cancel = nullptr, long timeoutSeconds = REQUEST_TIMEOUT_SECONDS);
    static NoteOpOutcome PerformDeleteNote(
          IHttpTransport& t, std::string_view id, const std::atomic<bool>* cancel = nullptr, long timeoutSeconds = REQUEST_TIMEOUT_SECONDS);
    static NoteOpOutcome PerformSaveTeacherNote(IHttpTransport& t, const SaveTeacherNoteRequest& req, const std::atomic<bool>* cancel = nullptr);
    static NoteOpOutcome PerformDeleteTeacherNote(IHttpTransport& t, int64 id, const std::atomic<bool>* cancel = nullptr);
    // course work and solutions (spec §10.12): one Post each, constant path (deterministic for the WebAssembly job
    // replay); the documents are validated (ValidateWorkDocumentText) and embedded canonical, nothing is sent otherwise
    static WorkResult PerformGetWork(IHttpTransport& t, std::string_view problem, const std::atomic<bool>* cancel = nullptr);
    static SaveWorkOutcome PerformSaveWork(IHttpTransport& t, const SaveWorkRequest& req, const std::atomic<bool>* cancel = nullptr);
    static SolutionResult PerformGetSolution(
          IHttpTransport& t, std::string_view problem, std::optional<int64> id, const std::atomic<bool>* cancel = nullptr);
    static PublishOutcome PerformPublishSolution(IHttpTransport& t, const PublishSolutionRequest& req, const std::atomic<bool>* cancel = nullptr);
    static DeleteSolutionOutcome PerformDeleteSolution(IHttpTransport& t, int64 id, const std::atomic<bool>* cancel = nullptr);

    // ---------------- UI thread state machine ----------------
    // Parses the connection string and starts the connect job. done() runs on the UI thread.
    Utils::GStatus Connect(std::string_view connectionString, const LearningSettings& s, StatusCallback done);
    // Applies a finished connect (normally called by Connect's completion; public for tests).
    Utils::GStatus ApplyConnectResult(ConnectionInfo&& newInfo, std::shared_ptr<IHttpTransport> newTransport, ConnectResult&& result);
    Utils::GStatus RefreshCatalogue(StatusCallback done);
    Utils::GStatus Download(const CatalogueItem& item, DownloadCallback done);
    Utils::GStatus Submit(std::string_view problem, SecureString flag, SecureString explanation, SubmitCallback done);

    // ---------------- course notes (UI thread) ----------------
    NotesAvailability GetNotesAvailability() const noexcept;
    bool CanUseNotes() const noexcept
    {
        return GetNotesAvailability() == NotesAvailability::Available;
    }
    // GetNotes; a call while one is running queues one more. Results are applied to Notes()/TeacherNotes().
    Utils::GStatus RefreshNotes();
    NotesSync& Notes() noexcept
    {
        return notes;
    }
    const NotesSync& Notes() const noexcept
    {
        return notes;
    }
    const std::vector<TeacherNote>& TeacherNotes() const noexcept
    {
        return teacherNotes;
    }
    bool CanEditTeacherNotes() const noexcept
    {
        return canEditTeacherNotes && CanUseNotes();
    }
    bool NotesLoaded() const noexcept
    {
        return notesLoaded;
    }
    const std::string& NotesError() const noexcept
    {
        return notesError;
    }
    // changes whenever something shown by the Notes window changed (poll it per frame)
    uint64 NotesVersion() const noexcept
    {
        return notes.Version() + teacherNotesVersion;
    }
    std::vector<std::string> TakeNotesNotices();
    // Starts the due note requests (autosave after the debounce, retries). flushAll: everything now (editor closed).
    // Also called by Tick().
    void PumpNotes(bool flushAll);
    // teacher editor (course-staff tokens): explicit saves; done() runs on the UI thread
    Utils::GStatus SaveTeacherNote(SaveTeacherNoteRequest req, NoteOpCallback done);
    Utils::GStatus DeleteTeacherNote(int64 id, NoteOpCallback done);
    // note_add telemetry (a bare count) for a note created from a task window opened from the catalogue
    void RecordNoteAdd(const void* obj);

    // ---------------- course work and teacher solutions (UI thread, spec §10.12) ----------------
    // Each call starts one request; done() runs on the UI thread (not at all when the session ended or reconnected in
    // the meantime, like Download). A refusal before any request is the returned status (done() is not called).
    WorkAvailability GetWorkAvailability() const noexcept;
    bool CanUseWork() const noexcept
    {
        return GetWorkAvailability() == WorkAvailability::Available;
    }
    // course staff: publish / delete solutions (Connect user.canPublishSolutions, then every GetWork answer)
    bool CanPublishSolutions() const noexcept
    {
        return canPublishSolutions && CanUseWork();
    }
    // a course-staff token (solutions or teacher notes): staff-only commands such as the replay journal editor
    bool IsCourseStaff() const noexcept
    {
        return canPublishSolutions || canEditTeacherNotes;
    }
    // the audiences a solution may be published to (All first); {All} when the server did not announce them
    std::vector<NoteAudience> SolutionAudiences() const;
    // largest work document this client sends: min(policy.work.maxBytes, GetWork maxBytes, MAX_WORK_DOCUMENT_BYTES)
    size_t WorkMaxBytes() const noexcept;
    // the last revision of the own work of the problem seen by GetWork / SaveWork (none: SaveWork creates)
    std::optional<int64> WorkRevision(std::string_view problem) const;
    // GetWork: the own work (caches its revision), the solutions this token may see, canPublishSolutions, audiences
    Utils::GStatus GetWork(std::string_view problem, WorkCallback done);
    // SaveWork with the cached revision (none = create). The document is validated and canonicalized here (refused
    // above WorkMaxBytes()). Success caches the new revision and updates the catalogue's me.workSavedAt/workRevision;
    // a 409 sets outcome.conflict and keeps the cached revision (re-fetch with GetWork to overwrite deliberately).
    Utils::GStatus SaveWork(std::string_view problem, std::string document, bool hasReplay, uint32 replaySteps, SaveWorkCallback done);
    // GetSolution: id omitted = the solution of the student's audience (students); staff pass the id from GetWork
    Utils::GStatus GetSolution(std::string_view problem, std::optional<int64> id, SolutionCallback done);
    // course staff only (refused locally otherwise). id omitted = create; a 409 sets outcome.conflict and, when the
    // server names it, existingId / existingRevision: resend with them to replace that solution.
    Utils::GStatus PublishSolution(PublishSolutionRequest req, PublishCallback done);
    Utils::GStatus DeleteSolution(int64 id, DeleteSolutionCallback done);

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
    void RequestTelemetryFlush()
    {
        flusher.RequestFlush();
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
    // the current session belongs to this server and access token (constant-time token comparison)
    bool UsesConnection(const ConnectionInfo& ci) const noexcept;
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
    // the window of the pending binding (SetPendingBinding first) gets this work document and this role; false without a pending binding
    bool SetPendingWorkDocument(std::string json, WorkspaceRole role);
    // the work document of the window of the object, taken once (none when it has none); `role`: the role of the window (Normal: not bound)
    std::optional<std::string> TakePendingWork(const void* obj, WorkspaceRole& role);
    // inMemory: the object is not backed by a file on disk, so it may hold content derived from other open objects
    void OnObjectCreated(const void* obj, bool inMemory = false);
    void OnObjectClosed(const void* obj);
    const ItemBinding* FindBinding(const void* obj) const noexcept;
    bool IsMemoryDerived(const void* obj) const noexcept
    {
        return memoryDerived.find(obj) != memoryDerived.end();
    }
    size_t OpenLearningWindows() const noexcept
    {
        return bindings.size();
    }
    void OnFrame(const void* obj, std::string_view viewerKind, bool focused);
    void NoteActivity() noexcept; // any thread
    bool Record(const void* obj, EventType type, std::vector<FieldValue> fields = {});
    void RecordFeatureBlocked(RestrictedMode::Feature feature);
    void RecordClientError(std::string_view constantMessage, bool fatal);
    // role: the window being opened; Solution / Replay windows produce no item events (the telemetry whitelist is unchanged)
    void RecordItemOpened(const CatalogueItem& item, DeliveryMode mode, uint32 version, WorkspaceRole role = WorkspaceRole::Student);
};

// process-wide session used by the UI and the hooks
LearningSession& GetSession();
} // namespace GView::Security::Learning
