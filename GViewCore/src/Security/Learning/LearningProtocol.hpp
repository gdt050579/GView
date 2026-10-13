#pragma once

// Wire/data contract of Learning and Evaluation Mode (plans/LEARNING_MODE_PROTOCOL_SPEC.md, protocol v2).
// Everything in here is pure (no I/O, no globals) so it can be unit tested exhaustively. All inputs coming from the
// network are treated as hostile: sizes are capped, strings are sanitised, item names are validated before they are
// ever placed in a URL path.

#include "SecureMemory.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace GView::Security::Learning
{
constexpr uint32 PROTOCOL_VERSION = 2;

// response size caps (bytes)
constexpr size_t MAX_CONNECT_RESPONSE_BYTES = 256 * 1024;
constexpr size_t MAX_POLICY_BYTES           = 64 * 1024;
constexpr size_t MAX_JSON_RESPONSE_BYTES    = 4 * 1024 * 1024;
constexpr size_t MAX_BINARY_RESPONSE_BYTES  = 256ull * 1024ull * 1024ull;
constexpr size_t MAX_TELEMETRY_BODY_BYTES   = 1024 * 1024; // server-side cap (PLAN_COURSE_SERVER.md §7)

// network timeouts (seconds)
constexpr long CONNECT_TIMEOUT_SECONDS  = 10;
constexpr long REQUEST_TIMEOUT_SECONDS  = 60;
constexpr long DOWNLOAD_TIMEOUT_SECONDS = 300;

// string caps for display fields received from the server
constexpr size_t MAX_ITEM_NAME_LENGTH   = 64;
constexpr size_t MAX_TITLE_LENGTH       = 256;
constexpr size_t MAX_DESCRIPTION_LENGTH = 64 * 1024;
constexpr size_t MAX_FLAG_LENGTH        = 512;

constexpr std::string_view CONTENT_INFO_LABEL = "GView-Content-v1";
constexpr std::string_view BLOB_MAGIC         = "GVE1";

using HeaderMap = std::vector<std::pair<std::string, std::string>>; // names lower-cased

std::string_view FindHeader(const HeaderMap& headers, std::string_view lowerName) noexcept;

std::string ClientVersion();
uint64 NowUnix() noexcept;

// ---------------------------------------------------------------- encoding helpers
std::string ToHex(BufferView data);
bool FromHex(std::string_view hex, std::vector<uint8>& out);
std::string Base64Encode(BufferView data);
// strict RFC 4648 decoding (standard alphabet, optional padding, no whitespace, no garbage)
bool Base64Decode(std::string_view text, SecureBytes& out, size_t maxDecodedSize);
std::optional<std::string> NewUuid4();
bool IsUuid4(std::string_view s) noexcept;

// ---------------------------------------------------------------- connection string (spec §1.2)
struct ConnectionInfo {
    uint32 version{ 1 };
    SecureString token;
    std::string serverUrl; // normalised: no trailing '/'
    std::vector<uint8> publicKey; // 32 bytes or empty
    std::string caPem;            // optional deployment CA (PEM text)
    std::string label;            // optional human readable label
};

Utils::GStatus ValidateServerUrl(std::string_view url, bool allowPlainHttpLocalhost, std::string& normalized);
Utils::GStatus ParseConnectionString(std::string_view connectionString, bool allowPlainHttpLocalhost, ConnectionInfo& out);
std::string BuildConnectionString(std::string_view token, std::string_view serverUrl, std::string_view publicKeyHex, std::string_view extraJson);

// hex(sha256(token))[0:16]
std::string SubjectForToken(const SecureString& token);
bool IsValidItemName(std::string_view name) noexcept;
// basename only, no separators / reserved names / control characters; never empty
std::string SanitizeFileName(std::string_view name);
// replaces control characters (except \n and \t when multiline) and truncates
std::string SanitizeDisplayText(std::string_view text, size_t maxLen, bool multiline);

// ---------------------------------------------------------------- errors (spec §1)
enum class ErrorCode : uint8 {
    None,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    PolicyExpired,
    PolicyNotStarted,
    AlreadySolved,
    ItemDisabled,
    UnsupportedClient,
    ServerError,
    Transport, // client side: no HTTP response at all
    Protocol,  // client side: response does not follow the contract
};

struct ServerError {
    ErrorCode code{ ErrorCode::None };
    long httpStatus{ 0 };
    std::string details;
    bool retryable{ false };
    uint32 retryAfterSeconds{ 0 };
};

std::string_view ErrorCodeName(ErrorCode code) noexcept;
ServerError ParseErrorEnvelope(long httpStatus, BufferView body, std::string_view retryAfterHeader);
std::string DescribeError(const ServerError& err);

// ---------------------------------------------------------------- connect (spec §2.1)
struct ConnectResponse {
    bool legacy{ false }; // empty / non-JSON 200 body from a pre-v2 server
    uint32 protocolVersion{ 0 };
    std::string serverVersion;
    uint64 serverTime{ 0 };
    std::vector<uint8> policyBytes;
    std::vector<uint8> signature;
    std::string displayName;
    int64 score{ 0 };
};
Utils::GStatus ParseConnectResponse(BufferView body, ConnectResponse& out);

// ---------------------------------------------------------------- catalogue (spec §3)
enum class DeliveryMode : uint8 { File, Memory };
enum class ItemKind : uint8 { Problem, ResourceFile, ResourceText, ResourceLink };

struct MeState {
    bool solved{ false };
    uint32 attempts{ 0 };
    int64 pointsAwarded{ 0 };
    uint64 firstDeliveredAt{ 0 };
};

struct CatalogueItem {
    ItemKind kind{ ItemKind::Problem };
    std::string name;
    std::string title;
    std::string description;
    int64 order{ 0 };
    DeliveryMode deliveryMode{ DeliveryMode::File };
    std::string fileName;
    std::string mimeType;
    std::string sha256;
    std::string url; // links only
    uint64 size{ 0 };
    int64 pointsMax{ 0 };
    int64 pointsCurrent{ 0 };
    int64 pointsMin{ 0 };
    bool requireExplanation{ false };
    bool hasMe{ false };
    MeState me;

    inline bool IsProblem() const noexcept
    {
        return kind == ItemKind::Problem;
    }
};

struct Week {
    int64 id{ 0 };
    std::string name;
    std::string title;
    std::string description;
    int64 order{ 0 };
    uint64 visibleFrom{ 0 };  // 0 = not set
    uint64 visibleUntil{ 0 }; // 0 = not set
    std::vector<CatalogueItem> problems;
    std::vector<CatalogueItem> resources;
};

struct Catalogue {
    bool legacy{ false };
    std::vector<Week> weeks;
    uint32 rejectedItems{ 0 }; // malformed / disabled entries that were dropped defensively

    const CatalogueItem* Find(std::string_view name, bool problem) const noexcept;
    const Week* FindWeekOf(std::string_view name) const noexcept;
};

Utils::GStatus ParseWeeks(BufferView body, Catalogue& out);
Utils::GStatus ParseLegacyProblems(BufferView body, Catalogue& out);

// ---------------------------------------------------------------- delivery (spec §3.3)
struct DeliveryHeaders {
    bool hasMode{ false };
    DeliveryMode mode{ DeliveryMode::File };
    bool encrypted{ false };
    std::string sha256; // lowercase hex of the plaintext, may be empty for legacy servers
    std::string fileName;
    uint32 itemVersion{ 0 };
};
Utils::GStatus ParseDeliveryHeaders(const HeaderMap& headers, bool requireV2, DeliveryHeaders& out);

// ---------------------------------------------------------------- submissions (spec §4)
struct SubmitRequest {
    std::string problem;
    SecureString flag;
    SecureString explanation;
    std::string clientSubmissionId;
    std::string policyId;
    std::string policyDigest;
    std::string clientVersion;
    uint64 clientTime{ 0 };
};
SecureString BuildSubmitBody(const SubmitRequest& req);

struct SubmitResult {
    bool correct{ false };
    int64 points{ 0 };
    uint32 attempts{ 0 };
    bool alreadySolved{ false };
    bool duplicate{ false };
    bool hasTotalScore{ false };
    int64 totalScore{ 0 };
    bool legacy{ false };
    std::string details;
};
// handles 200 (v2 and legacy bodies) and 409 ALREADY_SOLVED; other statuses are errors
Utils::GStatus ParseSubmitResponse(long httpStatus, BufferView body, SubmitResult& out, ServerError& err);
} // namespace GView::Security::Learning
