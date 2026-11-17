#pragma once

// Course work documents and teacher solutions of Learning and Evaluation Mode (spec §10.12, the sibling of the course
// notes of §10.11 / LearningNotes.hpp).
//
// The wire format only, pure (no I/O, no globals) so that it can be unit tested:
//   GetWork / SaveWork          the student's own work document of a problem (compare-and-set on "revision")
//   GetSolution                 a teacher solution the student may see (or any, for course staff)
//   PublishSolution / DeleteSolution   course staff only; one solution per (problem, audience)
//
// The work document is the JSON text built by the DissasmViewer (Instance::BuildWorkDocumentText: format
// "gview-disassembly-annotations", version 1, with "meta" and "replay"). Here it is an opaque JSON object: validated,
// re-serialized compactly (the canonical text) and size-checked; the bodies embed the canonical text as is.
//
// Privacy: annotation text and the replay journal leave the machine only in SaveWork / PublishSolution (explicit user
// commands) and are never written to telemetry or logs.

#include "LearningHttp.hpp"

namespace GView::Security::Learning
{
constexpr size_t MAX_WORK_DOCUMENT_BYTES = 2 * 1024 * 1024;                   // client cap of one document (canonical)
constexpr size_t MAX_WORK_REQUEST_BYTES  = MAX_WORK_DOCUMENT_BYTES + 64 * 1024; // SaveWork / PublishSolution bodies
constexpr size_t MAX_WORK_RESPONSE_BYTES = 4 * 1024 * 1024;                   // GetWork / GetSolution: document + envelope
constexpr size_t MAX_WORK_REPLY_BYTES    = 64 * 1024;                         // SaveWork / PublishSolution / DeleteSolution
constexpr size_t MAX_SOLUTIONS_LISTED    = 64;                                // defensive cap on hostile answers
constexpr uint32 WORK_MIN_MAX_BYTES      = 64 * 1024;                         // "maxBytes" clamp (policy and GetWork)
constexpr uint32 WORK_MAX_MAX_BYTES      = 16 * 1024 * 1024;
constexpr size_t WORK_CLIENT_VERSION_MAX = 64;
constexpr std::string_view WORK_DOCUMENT_FORMAT = "gview-disassembly-annotations";
constexpr int64 WORK_DOCUMENT_MAX_VERSION       = 1;

// JSON object, "format" == WORK_DOCUMENT_FORMAT, "version" an integer in [1, WORK_DOCUMENT_MAX_VERSION], no NUL
// anywhere (raw bytes or "\u0000" in a string), compact dump (the canonical text) of at most maxBytes bytes.
// canonical is set only on success.
Utils::GStatus ValidateWorkDocumentText(std::string_view json, size_t maxBytes, std::string& canonical);

// ---------------------------------------------------------------- data model
struct WorkSolutionInfo {
    int64 id{ 0 }; // server generated
    NoteAudience audience{ NoteAudience::All };
    int64 revision{ 0 };
    uint64 updatedAt{ 0 };
    bool enabled{ true }; // false only in staff answers (students never get disabled solutions)
    bool hasReplay{ false };
    uint32 replaySteps{ 0 };
};

struct WorkResponse {
    uint64 serverTime{ 0 };
    uint32 maxBytes{ static_cast<uint32>(MAX_WORK_DOCUMENT_BYTES) }; // clamped to [64 KiB, 16 MiB]
    bool canPublishSolutions{ false };
    std::vector<NoteAudience> audiences{ NoteAudience::All }; // All first, unknown names dropped
    // the caller's own saved work ("work": null = none)
    bool hasWork{ false };
    int64 revision{ 0 };
    uint64 updatedAt{ 0 };
    std::string clientVersion;
    bool hasReplay{ false };
    uint32 replaySteps{ 0 };
    std::string document; // canonical compact JSON text of the work document; empty when none
    std::string workError; // hasWork, but the own document can not be used (written by a newer GView, oversize): why
    std::vector<WorkSolutionInfo> solutions; // metadata only (GetSolution returns a document)
    uint32 rejected{ 0 };                    // malformed entries dropped defensively
};
Utils::GStatus ParseWorkResponse(BufferView body, WorkResponse& out);

struct SaveWorkRequest {
    std::string problem;
    std::string document; // canonical text (ValidateWorkDocumentText)
    bool hasReplay{ false };
    uint32 replaySteps{ 0 };
    std::optional<int64> revision; // last revision seen; omitted = create
};

struct SaveWorkResponse {
    int64 revision{ 0 };
    uint64 updatedAt{ 0 };
    bool created{ false };
};
Utils::GStatus ParseSaveWorkResponse(BufferView body, SaveWorkResponse& out);

struct SolutionResponse {
    WorkSolutionInfo info;
    std::string document; // canonical compact JSON text
};
Utils::GStatus ParseSolutionResponse(BufferView body, SolutionResponse& out);

struct PublishSolutionRequest {
    std::string problem;
    std::optional<int64> id; // omitted = create
    NoteAudience audience{ NoteAudience::All };
    std::string document; // canonical text (ValidateWorkDocumentText)
    bool hasReplay{ false };
    uint32 replaySteps{ 0 };
    bool enabled{ true };
    std::optional<int64> revision; // required with id
};

struct PublishSolutionResponse {
    int64 id{ 0 };
    int64 revision{ 0 };
    uint64 updatedAt{ 0 };
    bool created{ false };
};
Utils::GStatus ParsePublishSolutionResponse(BufferView body, PublishSolutionResponse& out);

// ---------------------------------------------------------------- request bodies (hand built; the document embedded as is)
SecureString BuildGetWorkBody(std::string_view problem);
SecureString BuildSaveWorkBody(const SaveWorkRequest& req);
SecureString BuildGetSolutionBody(std::string_view problem, std::optional<int64> id);
SecureString BuildPublishSolutionBody(const PublishSolutionRequest& req);
SecureString BuildDeleteSolutionBody(int64 id);

// ---------------------------------------------------------------- errors
// The envelope, with 409 => CONFLICT and 413 => PAYLOAD_TOO_LARGE (as NoteErrorFromResponse). A 409 of PublishSolution
// (a solution of this problem and audience exists) also names it: "id" / "revision" of the envelope, when present.
struct WorkServerError : ServerError {
    std::optional<int64> existingId;
    std::optional<int64> existingRevision;
};
WorkServerError WorkErrorFromResponse(const HttpResponse& resp);

// ---------------------------------------------------------------- outcomes of the endpoints
struct WorkResult {
    Utils::GStatus status;
    ServerError error;
    WorkResponse response;
};

struct SaveWorkOutcome {
    Utils::GStatus status;
    ServerError error;
    SaveWorkResponse result;
    bool conflict{ false }; // 409: the server has another revision; nothing was written
};

struct SolutionResult {
    Utils::GStatus status;
    ServerError error;
    SolutionResponse solution;
};

struct PublishOutcome {
    Utils::GStatus status;
    ServerError error;
    PublishSolutionResponse result;
    bool conflict{ false }; // 409: stale revision, or a solution of this audience exists (create)
    std::optional<int64> existingId;
    std::optional<int64> existingRevision;
};

struct DeleteSolutionOutcome {
    Utils::GStatus status;
    ServerError error;
};
} // namespace GView::Security::Learning
