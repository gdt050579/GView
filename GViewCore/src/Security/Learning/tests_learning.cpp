// Unit tests for Learning and Evaluation Mode (plans/LEARNING_MODE_PROTOCOL_SPEC.md §8, T1-T8).
// No network: an in-process FakeTransport plays the course server; policies are signed with a fresh Ed25519 key.

#include "Learning/LearningSession.hpp"
#include "Learning/TaskFiles.hpp"

#include <catch.hpp>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>

using namespace GView::Security;
using namespace GView::Security::Learning;
using RestrictedMode::Feature;
using RestrictedMode::Policy;
using json = nlohmann::json;

namespace
{
// ------------------------------------------------------------------ fixtures
constexpr std::string_view TEST_TOKEN  = "tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd";
constexpr std::string_view TEST_SERVER = "https://course.example.edu";
constexpr uint64 NOW                   = 1759400000;

struct Ed25519Key {
    EVP_PKEY* key{ nullptr };
    std::vector<uint8> publicKey;

    Ed25519Key()
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        REQUIRE(ctx != nullptr);
        REQUIRE(EVP_PKEY_keygen_init(ctx) == 1);
        REQUIRE(EVP_PKEY_keygen(ctx, &key) == 1);
        EVP_PKEY_CTX_free(ctx);
        size_t len = 32;
        publicKey.resize(32);
        REQUIRE(EVP_PKEY_get_raw_public_key(key, publicKey.data(), &len) == 1);
        REQUIRE(len == 32);
    }
    ~Ed25519Key()
    {
        EVP_PKEY_free(key);
    }
    std::vector<uint8> Sign(std::string_view message) const
    {
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        REQUIRE(EVP_DigestSignInit(md, nullptr, nullptr, nullptr, key) == 1);
        std::vector<uint8> sig(64);
        size_t sigLen = sig.size();
        REQUIRE(EVP_DigestSign(md, sig.data(), &sigLen, reinterpret_cast<const uint8*>(message.data()), message.size()) == 1);
        EVP_MD_CTX_free(md);
        REQUIRE(sigLen == 64);
        return sig;
    }
    std::string PublicHex() const
    {
        return ToHex(BufferView(publicKey.data(), publicKey.size()));
    }
};

const Ed25519Key& ServerKey()
{
    static Ed25519Key k;
    return k;
}
const Ed25519Key& OtherKey()
{
    static Ed25519Key k;
    return k;
}

SecureString Token()
{
    return SecureString(TEST_TOKEN.data(), TEST_TOKEN.size());
}

std::string Sha256Hex(std::string_view s)
{
    uint8 h[32];
    REQUIRE(Crypto::Internal::ComputeSHA256(BufferView(s), h).ok);
    return ToHex(BufferView(h, 32));
}

struct PolicyOptions {
    uint64 schema{ 2 };
    std::string id{ "pol_2026w1_ab12cd" };
    std::string subject;
    uint64 startsAt{ NOW - 120 };
    uint64 endsAt{ NOW + 3600 };
    std::vector<std::string> features{ "Copy", "Export" };
    std::vector<std::string> plugins{ "PE", "ELF" };
    std::string storage{ "file" };
    bool telemetry{ true };
    uint32 flushInterval{ 60 };
    uint32 maxBatch{ 500 };
    uint32 idleThreshold{ 120 };
    bool requireScreen{ false };
    bool bestEffort{ false };
    bool requireExplanation{ false };
    bool allowInTool{ true };
    std::string serverUrl{ std::string(TEST_SERVER) };
    std::string contentKeyId;
    bool corruptDigest{ false };
    std::optional<json> notes; // the "notes" object (absent when empty)
    std::optional<json> work;  // the "work" object (absent when empty)
};

// Mirrors the server: digest over the compact, key-sorted document with "digest":"" (PLAN_COURSE_SERVER.md §4)
std::string BuildPolicy(PolicyOptions o)
{
    if (o.subject.empty())
        o.subject = SubjectForToken(Token());
    json p;
    p["schema"]                  = o.schema;
    p["id"]                      = o.id;
    p["digest"]                  = "";
    p["purpose"]                 = "Evaluation week 1";
    p["issuedAt"]                = NOW;
    p["startsAt"]                = o.startsAt;
    p["endsAt"]                  = o.endsAt;
    p["subject"]                 = o.subject;
    p["serverUrl"]               = o.serverUrl;
    p["disabledFeatures"]        = o.features;
    p["allowedPlugins"]          = o.plugins;
    p["storageMode"]             = o.storage;
    p["bestEffortScreenProtect"] = o.bestEffort;
    p["requireScreenProtect"]    = o.requireScreen;
    p["watermark"]               = "Student 17 - do not distribute";
    p["telemetry"]  = { { "enabled", o.telemetry }, { "flushIntervalSeconds", o.flushInterval }, { "maxBatchEvents", o.maxBatch },
                        { "idleThresholdSeconds", o.idleThreshold }, { "eventLevel", true } };
    p["submission"] = { { "allowInTool", o.allowInTool }, { "requireExplanation", o.requireExplanation }, { "explanationMaxChars", 2000 } };
    if (o.notes.has_value())
        p["notes"] = *o.notes;
    if (o.work.has_value())
        p["work"] = *o.work;
    if (o.storage == "memory")
    {
        if (o.contentKeyId.empty())
        {
            LockedBuffer key;
            REQUIRE(DeriveContentKey(Token(), o.id, key).ok);
            o.contentKeyId = ContentKeyId(key.View());
        }
        p["contentKeyId"]      = o.contentKeyId;
        p["contentEncryption"] = "aes-256-gcm-hkdf-v1";
    }
    const std::string blank = p.dump();
    p["digest"]             = o.corruptDigest ? std::string(64, 'a') : Sha256Hex(blank);
    return p.dump();
}

std::string ConnectBody(const std::string& policy, const std::vector<uint8>& sig)
{
    json r;
    r["status"]          = "ok";
    r["protocolVersion"] = 2;
    r["serverVersion"]   = "2.0.0";
    r["serverTime"]      = NOW;
    r["policy"]          = Base64Encode(BufferView(policy));
    r["policySignature"] = Base64Encode(BufferView(sig.data(), sig.size()));
    r["user"]            = { { "displayName", "Student 17" }, { "score", 120 } };
    return r.dump();
}

HttpResponse Response(long status, std::string_view body, HeaderMap headers = {})
{
    HttpResponse r;
    r.transportOk = true;
    r.status      = status;
    r.body.assign(body.begin(), body.end());
    r.headers = std::move(headers);
    return r;
}

HttpResponse TransportFailure()
{
    HttpResponse r;
    r.transportOk    = false;
    r.transportError = "Couldn't connect to server";
    return r;
}

// In-process course server
class FakeTransport : public IHttpTransport
{
  public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;
    std::map<std::string, Handler> routes;
    std::vector<std::pair<std::string, std::string>> requests; // path, body
    std::vector<std::string> policyHeaders;
    std::mutex m;
    std::string policyId;

    HttpResponse Post(const HttpRequest& req) override
    {
        std::lock_guard<std::mutex> lk(m);
        requests.emplace_back(req.path, std::string(req.body.data(), req.body.size()));
        policyHeaders.push_back(policyId);
        if (auto it = routes.find(req.path); it != routes.end())
            return it->second(req);
        for (auto& [prefix, h] : routes)
        {
            // "/GView/GetProblems/" style prefix routes ("/GView/" itself is an exact route)
            if (prefix.size() > 7 && prefix.back() == '/' && req.path.starts_with(prefix))
                return h(req);
        }
        return Response(404, R"({"status":"error","code":"NOT_FOUND","details":"no route","retryable":false})");
    }
    void SetPolicyId(std::string_view id) override
    {
        std::lock_guard<std::mutex> lk(m);
        policyId.assign(id);
    }
    size_t Count(std::string_view path)
    {
        std::lock_guard<std::mutex> lk(m);
        size_t n = 0;
        for (auto& r : requests)
            n += r.first == path;
        return n;
    }
    std::string LastBody(std::string_view path)
    {
        std::lock_guard<std::mutex> lk(m);
        for (auto it = requests.rbegin(); it != requests.rend(); ++it)
            if (it->first == path)
                return it->second;
        return {};
    }
};

struct SessionFixture {
    std::shared_ptr<FakeTransport> transport = std::make_shared<FakeTransport>();
    uint64 clock                             = NOW;
    uint64 mono                              = 1000;
    int activations                          = 0;
    int deactivations                        = 0;
    bool screenApplied                       = true;
    std::unique_ptr<LearningSession> session;

    SessionFixture()
    {
        LearningSession::Dependencies d;
        d.transportFactory = [this](const ConnectionInfo&, const LearningSettings&) -> std::shared_ptr<IHttpTransport> { return transport; };
        d.activate         = [this](const Policy& p, RestrictedMode::Internal::ActivationReport& r) {
            activations++;
            r.screenProtectRequested = p.requireScreenProtect || p.bestEffortScreenProtect;
            r.screenProtectApplied   = r.screenProtectRequested && screenApplied;
            r.platformNote           = screenApplied ? "test: applied" : "test: unsupported";
            r.applied                = p.disabledFeatures;
            return GView::Utils::GStatus::Ok();
        };
        d.deactivate  = [this]() { deactivations++; };
        d.clock       = [this]() { return clock; };
        d.monoClock   = [this]() { return mono; };
        d.synchronous     = true;
        d.telemetryThread = false;
        session       = std::make_unique<LearningSession>(std::move(d));
    }
    ~SessionFixture()
    {
        session->Shutdown();
    }

    void ServePolicy(const std::string& policy, const Ed25519Key& signer = ServerKey())
    {
        const auto sig                    = signer.Sign(policy);
        const auto body                   = ConnectBody(policy, sig);
        transport->routes["/GView/Connect"] = [body](const HttpRequest&) { return Response(200, body); };
    }
    std::string ConnectionString(bool withKey = true) const
    {
        return BuildConnectionString(TEST_TOKEN, TEST_SERVER, withKey ? ServerKey().PublicHex() : "", "");
    }
    GView::Utils::GStatus Connect(bool withKey = true)
    {
        GView::Utils::GStatus result = GView::Utils::GStatus::Error("callback not called");
        auto st = session->Connect(ConnectionString(withKey), LearningSettings{}, [&](const GView::Utils::GStatus& s) { result = s; });
        if (!st.ok)
            return st;
        return result;
    }
};

std::string WeeksFixture()
{
    // the GetWeeks example of spec §3.1 (placeholders replaced by valid values) + noise the client must tolerate
    return R"JSON({
      "status": "ok",
      "unknownTopLevel": {"x": 1},
      "weeks": [
        { "id": 2, "name": "Week 2", "title": "Later", "order": 2, "problems": [], "resources": [] },
        {
          "id": 1, "name": "Week 1", "title": "PE format & first disassembly", "description": "Markdown allowed.",
          "order": 1, "visibleFrom": 1759400000, "visibleUntil": null, "futureField": [1,2,3],
          "problems": [
            { "name": "w1_stack_var", "title": "Third variable on the stack", "description": "Determine the value of the third local",
              "order": 1, "pointsMax": 100, "pointsCurrent": 85, "pointsMin": 30, "deliveryMode": "memory",
              "fileName": "task1.exe", "size": 20480, "sha256": "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
              "submission": { "requireExplanation": true },
              "me": { "solved": false, "attempts": 2, "pointsAwarded": 0, "firstDeliveredAt": 1759401000 }, "extra": "ignored" },
            { "name": "w1_disabled", "title": "Should never be shown", "enabled": false },
            { "name": "../etc/passwd", "title": "Hostile name" },
            { "name": "w1_bad_mode", "title": "x", "deliveryMode": "cloud" }
          ],
          "resources": [
            { "name": "w1_slides", "title": "Lecture slides", "description": "", "order": 1, "kind": "file",
              "mimeType": "application/pdf", "fileName": "week1.pdf", "size": 1048576, "sha256": "", "deliveryMode": "file" },
            { "name": "w1_sample", "title": "Benign sample used in class", "kind": "file", "order": 2,
              "mimeType": "application/vnd.microsoft.portable-executable", "fileName": "demo.exe",
              "size": 8192, "deliveryMode": "memory" },
            { "name": "w1_reading", "title": "Reading", "kind": "link", "url": "https://example.edu/reading", "deliveryMode": "file", "order": 3 },
            { "name": "w1_notes", "title": "Lab notes", "kind": "text", "mimeType": "text/markdown", "size": 2200, "deliveryMode": "file", "order": 4 },
            { "name": "w1_badlink", "title": "JS link", "kind": "link", "url": "javascript:alert(1)" },
            { "name": "w1_unknown_kind", "title": "?", "kind": "video" }
          ]
        },
        { "id": 3, "name": "Week 3", "enabled": false, "problems": [ { "name": "hidden" } ] }
      ]
    })JSON";
}

// encrypts like the server (PLAN_COURSE_SERVER.md §5.4)
std::string EncryptBlob(std::string_view plaintext, std::string_view item, std::string_view policyId, const SecureString& token)
{
    LockedBuffer key;
    REQUIRE(DeriveContentKey(token, policyId, key).ok);
    std::vector<uint8_t> k(key.Data(), key.Data() + key.Size());
    std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
    SecureBytes aadS = BuildContentAad(item, policyId);
    std::vector<uint8_t> aad(aadS.begin(), aadS.end());
    Crypto::EncryptedBlob blob;
    REQUIRE(Crypto::Internal::EncryptAES256GCM(pt, k, aad, blob).ok);
    std::string out = "GVE1";
    out.append(reinterpret_cast<const char*>(blob.iv.data()), blob.iv.size());
    out.append(reinterpret_cast<const char*>(blob.ciphertext.data()), blob.ciphertext.size());
    out.append(reinterpret_cast<const char*>(blob.tag.data()), blob.tag.size());
    return out;
}

std::set<std::filesystem::path> ListDir(const std::filesystem::path& dir)
{
    std::set<std::filesystem::path> r;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(dir, ec); !ec && it != std::filesystem::directory_iterator(); it.increment(ec))
        r.insert(it->path());
    return r;
}
} // namespace

// ======================================================================== protocol / encoding
TEST_CASE("Learning: strict base64", "[learning][protocol]")
{
    SecureBytes out;
    REQUIRE(Base64Decode("aGVsbG8=", out, 64));
    REQUIRE(std::string(out.begin(), out.end()) == "hello");
    REQUIRE(Base64Decode("aGVsbG8", out, 64)); // padding optional
    REQUIRE(std::string(out.begin(), out.end()) == "hello");
    REQUIRE(Base64Encode(BufferView(std::string_view("hello"))) == "aGVsbG8=");
    REQUIRE_FALSE(Base64Decode("aGVs bG8=", out, 64)); // whitespace
    REQUIRE_FALSE(Base64Decode("aGVsbG8*", out, 64));  // garbage
    REQUIRE_FALSE(Base64Decode("a", out, 64));         // impossible length
    REQUIRE_FALSE(Base64Decode("aGVsbG9=", out, 64));  // non-canonical trailing bits
    REQUIRE_FALSE(Base64Decode("aGVsbG8=", out, 3));   // size cap
}

TEST_CASE("Learning: connection string v1/v2 parsing", "[learning][protocol]")
{
    ConnectionInfo ci;
    SECTION("v1")
    {
        auto cs = BuildConnectionString(TEST_TOKEN, "https://Course.Example.edu/", "", "");
        REQUIRE(ParseConnectionString(cs, false, ci).ok);
        REQUIRE(ci.version == 1);
        REQUIRE(std::string_view(ci.token.data(), ci.token.size()) == TEST_TOKEN);
        REQUIRE(ci.serverUrl == "https://course.example.edu");
        REQUIRE(ci.publicKey.empty());
    }
    SECTION("v2 with key and extra JSON")
    {
        const std::string pem   = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        const std::string extra = R"({"label":"RE 2026 - Group A","caPem":")" + Base64Encode(BufferView(pem)) + "\"}";
        auto cs                 = BuildConnectionString(TEST_TOKEN, TEST_SERVER, ServerKey().PublicHex(), extra);
        REQUIRE(ParseConnectionString("  " + cs + "\r\n", false, ci).ok); // copy/paste whitespace tolerated
        REQUIRE(ci.version == 2);
        REQUIRE(ci.publicKey == ServerKey().publicKey);
        REQUIRE(ci.label == "RE 2026 - Group A");
        REQUIRE(ci.caPem == pem);
    }
    SECTION("rejections")
    {
        REQUIRE_FALSE(ParseConnectionString("", false, ci).ok);
        REQUIRE_FALSE(ParseConnectionString("not base64!!", false, ci).ok);
        REQUIRE_FALSE(ParseConnectionString(Base64Encode(BufferView(std::string_view("no-separator"))), false, ci).ok); // missing '#'
        REQUIRE_FALSE(ParseConnectionString(BuildConnectionString(TEST_TOKEN, TEST_SERVER, "zz", ""), false, ci).ok);    // bad key
        REQUIRE_FALSE(ParseConnectionString(BuildConnectionString(TEST_TOKEN, TEST_SERVER, ServerKey().PublicHex(), "[1]"), false, ci).ok);
        // header injection through the token
        REQUIRE_FALSE(ParseConnectionString(BuildConnectionString("tok_aaaaaaaaaaaaaaaa\r\nX-Evil: 1", TEST_SERVER, "", ""), false, ci).ok);
        REQUIRE_FALSE(ParseConnectionString(BuildConnectionString("short", TEST_SERVER, "", ""), false, ci).ok);
        // inner part that is not base64
        const std::string inner = "!!!#" + Base64Encode(BufferView(TEST_SERVER));
        REQUIRE_FALSE(ParseConnectionString(Base64Encode(BufferView(inner)), false, ci).ok);
    }
    SECTION("server URL policy")
    {
        std::string n;
        REQUIRE_FALSE(ValidateServerUrl("http://course.example.edu", true, n).ok);
        REQUIRE_FALSE(ValidateServerUrl("http://localhost:8000", false, n).ok);
        REQUIRE(ValidateServerUrl("http://localhost:8000", true, n).ok);
        REQUIRE(ValidateServerUrl("http://127.0.0.1:8443/", true, n).ok);
        REQUIRE(n == "http://127.0.0.1:8443");
        REQUIRE_FALSE(ValidateServerUrl("https://user:pw@course.example.edu", false, n).ok);
        REQUIRE_FALSE(ValidateServerUrl("https://course.example.edu/?x=1", false, n).ok);
        REQUIRE_FALSE(ValidateServerUrl("https://course.example.edu:99999", false, n).ok);
        REQUIRE_FALSE(ValidateServerUrl("ftp://course.example.edu", false, n).ok);
        REQUIRE(ValidateServerUrl("https://[::1]:8443/gview", false, n).ok);
    }
}

TEST_CASE("Learning: launch link of the web build (origin, connection string, trusted origins)", "[learning][protocol]")
{
    SECTION("server origin, as URL.origin of a browser")
    {
        REQUIRE(ServerOrigin("https://Course.Example.edu/gview/") == "https://course.example.edu");
        REQUIRE(ServerOrigin("https://course.example.edu:443") == "https://course.example.edu");
        REQUIRE(ServerOrigin("https://course.example.edu:8443/x") == "https://course.example.edu:8443");
        REQUIRE(ServerOrigin("http://127.0.0.1:80") == "http://127.0.0.1");
        REQUIRE(ServerOrigin("http://127.0.0.1:8770") == "http://127.0.0.1:8770");
        REQUIRE(ServerOrigin("https://[::1]:8443/gview") == "https://[::1]:8443");
        REQUIRE(ServerOrigin("http://example.org").empty()); // plain http only for the loopback
        REQUIRE(ServerOrigin("https://user@course.example.edu").empty());
        REQUIRE(ServerOrigin("https://course.example.edu/?x").empty());
        REQUIRE(ServerOrigin("javascript:alert(1)").empty());
        REQUIRE(ServerOrigin("").empty());
    }
    SECTION("connection string redeemed with a launch code")
    {
        ConnectionInfo ci;
        const auto cs = BuildConnectionString(TEST_TOKEN, "https://course.example.edu/gview", ServerKey().PublicHex(), R"({"label":"x"})");
        REQUIRE(ValidateLaunchConnectionString(cs, "https://course.example.edu", false, ci).ok);
        REQUIRE(ci.serverUrl == "https://course.example.edu/gview");
        REQUIRE(ci.publicKey == ServerKey().publicKey);
        REQUIRE(ValidateLaunchConnectionString(cs, "https://COURSE.example.edu:443", false, ci).ok);

        // another server than the one the code was redeemed at
        auto st = ValidateLaunchConnectionString(cs, "https://evil.example.org", false, ci);
        REQUIRE_FALSE(st.ok);
        REQUIRE(st.message.find("another server") != std::string::npos);
        REQUIRE_FALSE(ValidateLaunchConnectionString(cs, "https://course.example.edu:8443", false, ci).ok);
        REQUIRE_FALSE(ValidateLaunchConnectionString(cs, "http://course.example.edu", false, ci).ok);
        const auto other = BuildConnectionString(TEST_TOKEN, "https://course.example.edu.evil.org", ServerKey().PublicHex(), "");
        REQUIRE_FALSE(ValidateLaunchConnectionString(other, "https://course.example.edu", false, ci).ok);

        // version 1 (no policy public key): refused, even if [GView] PolicyPublicKey would complete a pasted one
        REQUIRE_FALSE(ValidateLaunchConnectionString(BuildConnectionString(TEST_TOKEN, TEST_SERVER, "", ""), TEST_SERVER, false, ci).ok);
        // same parser as a pasted string
        REQUIRE_FALSE(ValidateLaunchConnectionString("not base64!!", TEST_SERVER, false, ci).ok);
        REQUIRE_FALSE(ValidateLaunchConnectionString(BuildConnectionString(TEST_TOKEN, TEST_SERVER, "zz", ""), TEST_SERVER, false, ci).ok);
        REQUIRE_FALSE(ValidateLaunchConnectionString(cs, "", false, ci).ok);

        // plain http: only with the setting, as for a pasted string
        const auto local = BuildConnectionString(TEST_TOKEN, "http://127.0.0.1:8770", ServerKey().PublicHex(), "");
        REQUIRE_FALSE(ValidateLaunchConnectionString(local, "http://127.0.0.1:8770", false, ci).ok);
        REQUIRE(ValidateLaunchConnectionString(local, "http://127.0.0.1:8770", true, ci).ok);
        REQUIRE_FALSE(ValidateLaunchConnectionString(local, "http://localhost:8770", true, ci).ok); // another origin
    }
    SECTION("trusted launch origins")
    {
        std::string list;
        REQUIRE_FALSE(OriginListContains(list, "https://course.example.edu"));
        list = OriginListAdd(list, "https://course.example.edu");
        REQUIRE(list == "https://course.example.edu");
        REQUIRE(OriginListContains(list, "https://course.example.edu"));
        REQUIRE_FALSE(OriginListContains(list, "https://course.example"));
        REQUIRE_FALSE(OriginListContains(list, ""));
        list = OriginListAdd(list, "https://course.example.edu"); // no duplicate
        list = OriginListAdd(list, "http://127.0.0.1:8770");
        REQUIRE(list == "https://course.example.edu http://127.0.0.1:8770");
        // not an origin: ignored
        REQUIRE(OriginListAdd(list, "https://x.example.edu/path") == list);
        REQUIRE(OriginListAdd(list, "https://a.edu https://b.edu") == list);
        REQUIRE(OriginListAdd(list, "http://example.org") == list);
        REQUIRE(OriginListContains("  https://a.edu,https://b.edu ", "https://b.edu"));
        // bounded: the oldest entries are dropped
        std::string many;
        for (size_t i = 0; i < MAX_TRUSTED_LAUNCH_ORIGINS + 3; i++)
            many = OriginListAdd(many, "https://h" + std::to_string(i) + ".example.edu");
        REQUIRE_FALSE(OriginListContains(many, "https://h0.example.edu"));
        REQUIRE_FALSE(OriginListContains(many, "https://h2.example.edu"));
        REQUIRE(OriginListContains(many, "https://h3.example.edu"));
        REQUIRE(OriginListContains(many, "https://h" + std::to_string(MAX_TRUSTED_LAUNCH_ORIGINS + 2) + ".example.edu"));
    }
}

TEST_CASE("Learning: transport requirements of the browser build", "[learning][protocol]")
{
    TransportConfig cfg;
    cfg.serverUrl = "https://course.example.edu";

    // desktop transport (libcurl): every connection string the protocol accepts can be honoured
    cfg.caPem = "-----BEGIN CERTIFICATE-----";
    REQUIRE(CheckTransportRequirements(cfg, false, false).ok);

    // browser: a private CA can not be pinned -> refused (fail closed), never silently widened to the OS store
    auto st = CheckTransportRequirements(cfg, true, true);
    REQUIRE_FALSE(st.ok);
    REQUIRE(st.message.find("private certificate authority") != std::string::npos);

    cfg.caPem.clear();
    REQUIRE(CheckTransportRequirements(cfg, true, false).ok);

    // plain HTTP only for local development: allowed by the setting AND page served from the same machine
    cfg.serverUrl               = "http://127.0.0.1:8770";
    cfg.allowPlainHttpLocalhost = false;
    REQUIRE_FALSE(CheckTransportRequirements(cfg, true, true).ok);
    cfg.allowPlainHttpLocalhost = true;
    REQUIRE_FALSE(CheckTransportRequirements(cfg, true, false).ok); // a public page must not reach the local machine
    REQUIRE(CheckTransportRequirements(cfg, true, true).ok);

    cfg.serverUrl = "ftp://course.example.edu";
    REQUIRE_FALSE(CheckTransportRequirements(cfg, true, true).ok);
}

TEST_CASE("Learning: Once runs the function on the desktop build", "[learning]")
{
    // re-runnable jobs only exist in the web build (JobReplay.hpp); elsewhere Once() is a plain call
    int calls = 0;
    REQUIRE(JobReplay::Once([&]() { return ++calls; }) == 1);
    REQUIRE(JobReplay::Once([&]() { return ++calls; }) == 2);
}

TEST_CASE("Learning: request headers", "[learning][protocol]")
{
    auto h = BuildRequestHeaders(Token(), "0.391.0", "");
    std::vector<std::string> v;
    for (auto& s : h)
        v.emplace_back(s.data(), s.size());
    REQUIRE(v.size() == 4);
    REQUIRE(v[0] == "XAppUserID: " + std::string(TEST_TOKEN));
    REQUIRE(v[1] == "X-GView-Client: 0.391.0");
    REQUIRE(v[2] == "X-GView-Protocol: 2");
    REQUIRE(v[3] == "X-GView-Platform: " + std::string(CurrentPlatform()));
    auto h2 = BuildRequestHeaders(Token(), "0.391.0", "pol_x");
    REQUIRE(h2.size() == 5);
    REQUIRE(std::string(h2[4].data(), h2[4].size()) == "X-GView-Policy: pol_x");
}

TEST_CASE("Learning: response size caps", "[learning][protocol]")
{
    HttpResponse r;
    const uint8 chunk[10] = {};
    REQUIRE(Detail::AppendBodyWithCap(r, chunk, 10, 25));
    REQUIRE(Detail::AppendBodyWithCap(r, chunk, 10, 25));
    REQUIRE_FALSE(Detail::AppendBodyWithCap(r, chunk, 10, 25)); // 30 > 25
    REQUIRE(r.tooLarge);
    REQUIRE(r.body.size() == 20);
    HttpResponse r2;
    REQUIRE_FALSE(Detail::AppendBodyWithCap(r2, chunk, SIZE_MAX, 25)); // no overflow
}

TEST_CASE("Learning: error envelope", "[learning][protocol]")
{
    auto e = ParseErrorEnvelope(403, BufferView(std::string_view(R"({"status":"error","code":"POLICY_EXPIRED","details":"gone","retryable":false})")), {});
    REQUIRE(e.code == ErrorCode::PolicyExpired);
    REQUIRE(e.details == "gone");
    REQUIRE_FALSE(e.retryable);
    e = ParseErrorEnvelope(429, BufferView(std::string_view("<html>busy</html>")), "17");
    REQUIRE(e.code == ErrorCode::RateLimited);
    REQUIRE(e.retryable);
    REQUIRE(e.retryAfterSeconds == 17);
    e = ParseErrorEnvelope(404, BufferView(), {});
    REQUIRE(e.code == ErrorCode::NotFound);
    e = ParseErrorEnvelope(503, BufferView(), {});
    REQUIRE(e.code == ErrorCode::ServerError);
    REQUIRE(e.retryable);
    e = ParseErrorEnvelope(426, BufferView(std::string_view(R"({"code":"UNSUPPORTED_CLIENT"})")), {});
    REQUIRE(e.code == ErrorCode::UnsupportedClient);
    REQUIRE(DescribeError(e).find("UNSUPPORTED_CLIENT") != std::string::npos);
}

TEST_CASE("Learning: GetWeeks parsing (spec fixture)", "[learning][catalogue]")
{
    Catalogue cat;
    const auto body = WeeksFixture();
    REQUIRE(ParseWeeks(BufferView(body), cat).ok);
    REQUIRE(cat.weeks.size() == 2); // disabled week dropped
    REQUIRE(cat.weeks[0].name == "Week 1"); // sorted by order
    const auto& w = cat.weeks[0];
    REQUIRE(w.problems.size() == 1);
    REQUIRE(w.resources.size() == 4);
    REQUIRE(cat.rejectedItems == 1 /*week*/ + 3 /*problems*/ + 2 /*resources*/);
    const auto& p = w.problems[0];
    REQUIRE(p.name == "w1_stack_var");
    REQUIRE(p.pointsCurrent == 85);
    REQUIRE(p.deliveryMode == DeliveryMode::Memory);
    REQUIRE(p.requireExplanation);
    REQUIRE(p.hasMe);
    REQUIRE(p.me.attempts == 2);
    REQUIRE(p.me.firstDeliveredAt == 1759401000);
    REQUIRE(p.sha256 == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"); // normalised
    REQUIRE(w.resources[2].kind == ItemKind::ResourceLink);
    REQUIRE(w.resources[2].url == "https://example.edu/reading");
    REQUIRE(w.resources[3].kind == ItemKind::ResourceText);
    REQUIRE(cat.Find("w1_disabled", true) == nullptr);
    REQUIRE(cat.FindWeekOf("w1_sample")->name == "Week 1");

    Catalogue legacy;
    REQUIRE(ParseLegacyProblems(BufferView(std::string_view(R"([{"name":"p1","title":"T","description":"D"},{"name":"bad name"}])")), legacy).ok);
    REQUIRE(legacy.legacy);
    REQUIRE(legacy.weeks.size() == 1);
    REQUIRE(legacy.weeks[0].problems.size() == 1);
    REQUIRE_FALSE(ParseWeeks(BufferView(std::string_view("[]")), cat).ok);
}

TEST_CASE("Learning: submission body and responses", "[learning][submit]")
{
    SubmitRequest req;
    req.problem            = "w1_stack_var";
    req.flag               = SecureString("3\"\\\n");
    req.explanation        = SecureString("cmp eax,ecx; jle not taken");
    req.clientSubmissionId = "0f6a0e5c-1111-4222-8333-444455556666";
    req.policyId           = "pol_x";
    req.policyDigest       = std::string(64, 'b');
    req.clientVersion      = "0.391.0";
    req.clientTime         = NOW;
    const auto body        = BuildSubmitBody(req);
    auto j                 = json::parse(std::string(body.data(), body.size()));
    REQUIRE(j["problem"] == "w1_stack_var");
    REQUIRE(j["flag"] == "3\"\\\n");
    REQUIRE(j["explanation"] == "cmp eax,ecx; jle not taken");
    REQUIRE(j["clientSubmissionId"] == req.clientSubmissionId);
    REQUIRE(j["policyId"] == "pol_x");
    REQUIRE(j["clientTime"] == NOW);
    REQUIRE(j.size() == 8);

    SubmitResult r;
    ServerError e;
    REQUIRE(ParseSubmitResponse(
                  200,
                  BufferView(std::string_view(
                        R"({"status":"ok","correct":true,"points":85,"attempts":3,"alreadySolved":false,"duplicate":true,"details":"Correct!","totalScore":205})")),
                  r,
                  e)
                  .ok);
    REQUIRE(r.correct);
    REQUIRE(r.duplicate);
    REQUIRE(r.totalScore == 205);
    REQUIRE(ParseSubmitResponse(200, BufferView(std::string_view(R"({"status":"error","details":"Wrong flag"})")), r, e).ok);
    REQUIRE(r.legacy);
    REQUIRE_FALSE(r.correct);
    REQUIRE(ParseSubmitResponse(200, BufferView(std::string_view(R"({"status":"ok","details":"Correct! 50 points"})")), r, e).ok);
    REQUIRE(r.correct);
    REQUIRE(ParseSubmitResponse(409, BufferView(std::string_view(R"({"status":"error","code":"ALREADY_SOLVED"})")), r, e).ok);
    REQUIRE(r.alreadySolved);
    REQUIRE_FALSE(ParseSubmitResponse(403, BufferView(std::string_view(R"({"code":"POLICY_EXPIRED"})")), r, e).ok);
    REQUIRE(e.code == ErrorCode::PolicyExpired);
}

TEST_CASE("Learning: idempotency keys (T6)", "[learning][submit]")
{
    SubmissionTracker t;
    const auto a1 = t.IdFor("p", SecureString("flag"), SecureString(""));
    REQUIRE(IsUuid4(a1));
    REQUIRE(t.IdFor("p", SecureString("flag"), SecureString("")) == a1); // retry => same id
    const auto b = t.IdFor("p", SecureString("flag2"), SecureString(""));
    REQUIRE(b != a1); // changed answer => new id
    REQUIRE(t.IdFor("p", SecureString("flag2"), SecureString("why")) != b);
    const auto c = t.IdFor("p", SecureString("flag3"), SecureString(""));
    t.Consume("p");
    REQUIRE(t.IdFor("p", SecureString("flag3"), SecureString("")) != c); // verdict received => next is a new attempt
    REQUIRE(t.IdFor("q", SecureString("flag3"), SecureString("")) != c);
}

// ======================================================================== policy engine (T2/T3)
TEST_CASE("Learning: policy verification (T1/T2/T3)", "[learning][policy]")
{
    const auto& key       = ServerKey();
    const auto subject    = SubjectForToken(Token());
    auto verify           = [&](const std::string& doc, const std::vector<uint8>& sig, const std::vector<uint8>& pub, uint64 now, Policy& out) {
        return RestrictedMode::VerifyAndParsePolicy(
              BufferView(doc), BufferView(sig.data(), sig.size()), BufferView(pub.data(), pub.size()), subject, TEST_SERVER, now, out);
    };
    auto codeOf = [](const GView::Utils::GStatus& s) { return s.message.substr(0, s.message.find(':')); };

    Policy p;
    const auto doc = BuildPolicy({});
    auto sig       = key.Sign(doc);
    SECTION("valid")
    {
        REQUIRE(verify(doc, sig, key.publicKey, NOW, p).ok);
        REQUIRE(p.schema == 2);
        REQUIRE(p.id == "pol_2026w1_ab12cd");
        REQUIRE(p.disabledFeatures.size() == 2);
        REQUIRE(p.telemetry.enabled);
        REQUIRE(p.digest.size() == 64);
        // clock skew: up to 120 s after endsAt is still accepted
        REQUIRE(verify(doc, sig, key.publicKey, NOW + 3600 + 100, p).ok);
    }
    SECTION("tampered byte")
    {
        std::string bad = doc;
        bad[bad.find("Evaluation")] = 'X';
        auto st = verify(bad, sig, key.publicKey, NOW, p);
        REQUIRE_FALSE(st.ok);
        REQUIRE(codeOf(st) == "POLICY_SIGNATURE_INVALID");
    }
    SECTION("wrong key")
    {
        auto st = verify(doc, sig, OtherKey().publicKey, NOW, p);
        REQUIRE(codeOf(st) == "POLICY_SIGNATURE_INVALID");
        std::vector<uint8> noKey;
        REQUIRE(codeOf(verify(doc, sig, noKey, NOW, p)) == "POLICY_KEY_MISSING");
    }
    SECTION("expired / not started")
    {
        REQUIRE(codeOf(verify(doc, sig, key.publicKey, NOW + 3600 + 121, p)) == "POLICY_EXPIRED");
        REQUIRE(codeOf(verify(doc, sig, key.publicKey, NOW - 1000, p)) == "POLICY_NOT_STARTED");
    }
    SECTION("subject mismatch")
    {
        PolicyOptions o;
        o.subject      = "0123456789abcdef";
        const auto d2  = BuildPolicy(o);
        REQUIRE(codeOf(verify(d2, key.Sign(d2), key.publicKey, NOW, p)) == "POLICY_SUBJECT_MISMATCH");
    }
    SECTION("schema 3")
    {
        PolicyOptions o;
        o.schema      = 3;
        const auto d2 = BuildPolicy(o);
        REQUIRE(codeOf(verify(d2, key.Sign(d2), key.publicKey, NOW, p)) == "POLICY_SCHEMA_UNSUPPORTED");
    }
    SECTION("unknown feature fails closed")
    {
        PolicyOptions o;
        o.features    = { "Copy", "Teleport" };
        const auto d2 = BuildPolicy(o);
        REQUIRE(codeOf(verify(d2, key.Sign(d2), key.publicKey, NOW, p)) == "POLICY_MALFORMED");
    }
    SECTION("digest mismatch")
    {
        PolicyOptions o;
        o.corruptDigest = true;
        const auto d2   = BuildPolicy(o);
        REQUIRE(codeOf(verify(d2, key.Sign(d2), key.publicKey, NOW, p)) == "POLICY_DIGEST_MISMATCH");
    }
    SECTION("server binding")
    {
        PolicyOptions o;
        o.serverUrl   = "https://other.example.edu";
        const auto d2 = BuildPolicy(o);
        REQUIRE(codeOf(verify(d2, key.Sign(d2), key.publicKey, NOW, p)) == "POLICY_SERVER_MISMATCH");
    }
    SECTION("memory mode requires content encryption fields")
    {
        json j = json::parse(BuildPolicy({}));
        j["storageMode"] = "memory";
        j.erase("contentKeyId");
        j["digest"]          = "";
        const auto blank     = j.dump();
        j["digest"]          = Sha256Hex(blank);
        const auto d2        = j.dump();
        REQUIRE(codeOf(verify(d2, key.Sign(d2), key.publicKey, NOW, p)) == "POLICY_MALFORMED");
    }
    SECTION("wrong JSON types fail closed")
    {
        json j           = json::parse(BuildPolicy({}));
        j["requireScreenProtect"] = "yes";
        j["digest"]      = "";
        const auto blank = j.dump();
        j["digest"]      = Sha256Hex(blank);
        const auto d2    = j.dump();
        REQUIRE(codeOf(verify(d2, key.Sign(d2), key.publicKey, NOW, p)) == "POLICY_MALFORMED");
    }
}

TEST_CASE("Learning: policy activation and enforcement state (T4)", "[learning][policy]")
{
    PolicyOptions o;
    o.features = { "Copy", "Export", "SaveAs", "Plugins", "LLMHints", "Clipboard", "Screenshots" };
    o.plugins  = { "PE", "Hashes" };
    Policy p;
    const auto doc = BuildPolicy(o);
    const auto sig = ServerKey().Sign(doc);
    REQUIRE(RestrictedMode::VerifyAndParsePolicy(
                  BufferView(doc),
                  BufferView(sig.data(), sig.size()),
                  BufferView(ServerKey().publicKey.data(), 32),
                  SubjectForToken(Token()),
                  TEST_SERVER,
                  NOW,
                  p)
                  .ok);
    // do not install real OS hooks from a unit test
    p.bestEffortScreenProtect = false;
    p.disabledFeatures.erase(std::remove(p.disabledFeatures.begin(), p.disabledFeatures.end(), Feature::Screenshots), p.disabledFeatures.end());
    p.startsAt = 0;
    p.endsAt   = 0;

    REQUIRE_FALSE(RestrictedMode::IsActive());
    REQUIRE(RestrictedMode::Internal::IsPluginAllowed("ZIP"));
    RestrictedMode::Internal::ActivationReport rep;
    REQUIRE(RestrictedMode::Internal::Activate(p, rep).ok);
    REQUIRE(RestrictedMode::IsActive());
    for (auto f : { Feature::Copy, Feature::Export, Feature::SaveAs, Feature::Plugins, Feature::LLMHints, Feature::Clipboard })
        REQUIRE(RestrictedMode::IsFeatureDisabled(f));
    REQUIRE_FALSE(RestrictedMode::IsFeatureDisabled(Feature::Screenshots));
    REQUIRE(RestrictedMode::Internal::IsPluginAllowed("PE"));
    REQUIRE(RestrictedMode::Internal::IsPluginAllowed("pe")); // INI section names are case-insensitive
    REQUIRE(RestrictedMode::Internal::IsPluginAllowed("Hashes"));
    REQUIRE_FALSE(RestrictedMode::Internal::IsPluginAllowed("ZIP"));
    REQUIRE_FALSE(RestrictedMode::Internal::IsPluginAllowed("PEX"));
    REQUIRE(RestrictedMode::Internal::GetWatermark() == "Student 17 - do not distribute");
    REQUIRE(GView::App::IsFeatureRestricted(Feature::Copy));

    // re-entrant: a newer validated policy replaces the current one
    Policy relaxed = p;
    relaxed.id     = "pol_2026w1_relaxed";
    relaxed.disabledFeatures = { Feature::Copy };
    REQUIRE(RestrictedMode::Internal::Activate(relaxed, rep).ok);
    REQUIRE(RestrictedMode::IsFeatureDisabled(Feature::Copy));
    REQUIRE_FALSE(RestrictedMode::IsFeatureDisabled(Feature::Export));
    REQUIRE(RestrictedMode::Internal::IsPluginAllowed("ZIP")); // Plugins no longer restricted
    REQUIRE(RestrictedMode::GetCurrentPolicy()->id == "pol_2026w1_relaxed");

    RestrictedMode::Internal::Deactivate();
    REQUIRE_FALSE(RestrictedMode::IsActive());
    REQUIRE_FALSE(RestrictedMode::IsFeatureDisabled(Feature::Copy));
    REQUIRE_FALSE(RestrictedMode::GetCurrentPolicy().has_value());
}

// ======================================================================== content delivery (T5)
TEST_CASE("Learning: content encryption round trip (T5)", "[learning][content]")
{
    const std::string plaintext = std::string("MZ\x90\x00", 4) + std::string(5000, 'A');
    const auto blob             = EncryptBlob(plaintext, "w1_stack_var", "pol_x", Token());
    LockedBuffer key;
    REQUIRE(DeriveContentKey(Token(), "pol_x", key).ok);
    REQUIRE(ContentKeyId(key.View()).size() == 16);

    LockedBuffer out;
    REQUIRE(DecryptContentBlob(BufferView(blob), key.View(), "w1_stack_var", "pol_x", out).ok);
    REQUIRE(std::string(reinterpret_cast<const char*>(out.Data()), out.Size()) == plaintext);

    std::string tampered = blob;
    tampered.back() ^= 0x01; // tag
    REQUIRE_FALSE(DecryptContentBlob(BufferView(tampered), key.View(), "w1_stack_var", "pol_x", out).ok);
    tampered = blob;
    tampered[20] ^= 0x01; // ciphertext
    REQUIRE_FALSE(DecryptContentBlob(BufferView(tampered), key.View(), "w1_stack_var", "pol_x", out).ok);
    REQUIRE_FALSE(DecryptContentBlob(BufferView(blob), key.View(), "other_item", "pol_x", out).ok); // AAD binds the item
    REQUIRE_FALSE(DecryptContentBlob(BufferView(blob.substr(0, 20)), key.View(), "w1_stack_var", "pol_x", out).ok);
    std::string badMagic = blob;
    badMagic[0]          = 'X';
    REQUIRE_FALSE(DecryptContentBlob(BufferView(badMagic), key.View(), "w1_stack_var", "pol_x", out).ok);
}

TEST_CASE("Learning: download processing (T5)", "[learning][content]")
{
    PolicyOptions o;
    o.storage = "memory";
    Policy policy;
    const auto doc = BuildPolicy(o);
    REQUIRE(RestrictedMode::Internal::ParsePolicyDocument(BufferView(doc), true, policy).ok);
    const SecureString token = Token();
    DeliveryContext ctx{ &policy, &token };

    CatalogueItem item;
    item.name         = "w1_stack_var";
    item.kind         = ItemKind::Problem;
    item.deliveryMode = DeliveryMode::File; // the policy is stricter: memory wins
    const std::string plaintext = "MZ-task-binary-content";
    const auto sha              = Sha256Hex(plaintext);

    auto encryptedResponse = [&](std::string_view sha256) {
        return Response(
              200,
              EncryptBlob(plaintext, item.name, policy.id, token),
              { { "x-gview-delivery", "memory" }, { "x-gview-encrypted", "1" }, { "x-gview-sha256", std::string(sha256) },
                { "x-gview-filename", "..\\..\\task1.exe" }, { "x-gview-item-version", "3" } });
    };

    SECTION("memory mode: decrypted into locked memory, nothing written to disk")
    {
        const auto cwd    = std::filesystem::current_path();
        const auto tmp    = std::filesystem::temp_directory_path();
        const auto before = ListDir(cwd);
        const auto tmpB   = ListDir(tmp);
        auto resp         = encryptedResponse(sha);
        DeliveredContent c;
        REQUIRE(ProcessDownloadResponse(resp, item, ctx, c).ok);
        REQUIRE(resp.body.empty()); // ciphertext released
        REQUIRE(c.mode == DeliveryMode::Memory);
        REQUIRE(c.wasEncrypted);
        REQUIRE(c.itemVersion == 3);
        REQUIRE(c.fileName == "task1.exe"); // path components stripped
        REQUIRE(std::string(reinterpret_cast<const char*>(c.data.Data()), c.data.Size()) == plaintext);
        // the viewer reads straight from the locked buffer
        LockedMemoryDataObject obj(std::move(c.data));
        REQUIRE(obj.GetSize() == plaintext.size());
        std::vector<uint8> readBack(plaintext.size());
        uint32 bytesRead = 0;
        REQUIRE(obj.Read(0, readBack.data(), static_cast<uint32>(readBack.size()), bytesRead));
        REQUIRE(bytesRead == plaintext.size());
        REQUIRE(std::string(readBack.begin(), readBack.end()) == plaintext);
        REQUIRE_FALSE(obj.SetSize(1)); // read-only
        obj.Close();
        REQUIRE(obj.GetSize() == 0);
        REQUIRE(ListDir(cwd) == before);
        REQUIRE(ListDir(tmp) == tmpB);
    }
    SECTION("sha mismatch")
    {
        auto resp = encryptedResponse(Sha256Hex("something else"));
        DeliveredContent c;
        REQUIRE_FALSE(ProcessDownloadResponse(resp, item, ctx, c).ok);
    }
    SECTION("content key id mismatch is detected before decryption")
    {
        Policy other              = policy;
        other.contentKeyId        = std::vector<uint8_t>{ 1, 2, 3, 4, 5, 6, 7, 8 };
        DeliveryContext otherCtx  = { &other, &token };
        auto resp                 = encryptedResponse(sha);
        DeliveredContent c;
        auto st = ProcessDownloadResponse(resp, item, otherCtx, c);
        REQUIRE_FALSE(st.ok);
        REQUIRE(st.message.find("content key id mismatch") != std::string::npos);
    }
    SECTION("unencrypted memory delivery is refused when the policy requires encryption")
    {
        auto resp = Response(200, plaintext, { { "x-gview-delivery", "memory" }, { "x-gview-encrypted", "0" }, { "x-gview-sha256", sha } });
        DeliveredContent c;
        REQUIRE_FALSE(ProcessDownloadResponse(resp, item, ctx, c).ok);
    }
    SECTION("v2 requires delivery headers")
    {
        auto resp = Response(200, plaintext);
        DeliveredContent c;
        REQUIRE_FALSE(ProcessDownloadResponse(resp, item, ctx, c).ok);
    }
    SECTION("legacy session: plain bytes, memory mode")
    {
        DeliveryContext legacy{ nullptr, &token };
        auto resp = Response(200, plaintext);
        DeliveredContent c;
        REQUIRE(ProcessDownloadResponse(resp, item, legacy, c).ok);
        REQUIRE(c.mode == DeliveryMode::Memory);
        REQUIRE(c.sha256 == sha);
    }
}

TEST_CASE("Learning: file mode atomic write", "[learning][content]")
{
    const auto dir = std::filesystem::temp_directory_path() / "gview_learning_test_dl";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    const std::string data = "file-mode-content";
    std::filesystem::path out;
    REQUIRE(WriteFileAtomic(dir, "../../evil.bin", BufferView(data), Sha256Hex(data), out).ok);
    REQUIRE(out.parent_path() == dir); // traversal neutralised
    REQUIRE(out.filename() == "evil.bin");
    std::ifstream f(out, std::ios::binary);
    REQUIRE(std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()) == data);
    f.close();
    REQUIRE_FALSE(WriteFileAtomic(dir, "bad.bin", BufferView(data), Sha256Hex("other"), out).ok);
    for (auto& e : std::filesystem::directory_iterator(dir))
        REQUIRE(e.path().extension() != ".part"); // no leftovers
    REQUIRE_FALSE(std::filesystem::exists(dir / "bad.bin"));
    REQUIRE(SanitizeFileName("CON.txt") == "_CON.txt");
    REQUIRE(SanitizeFileName("..") == "task.bin");
    REQUIRE(SanitizeFileName("a<b>:c|d?.exe") == "a_b__c_d_.exe");
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("Learning: path component sanitizing", "[learning][content]")
{
    const auto S = [](std::string_view s) { return SanitizePathComponent(s, "fallback", 32); };
    REQUIRE(S("Lab 3") == "Lab 3");
    REQUIRE(S("Lab 3/4") == "Lab 3_4"); // separators never survive (a folder name keeps both parts)
    REQUIRE(S("..\\..\\x") == "_.._x");
    REQUIRE(S("..") == "fallback");
    REQUIRE(S(" .hidden. ") == "hidden");
    REQUIRE(S("") == "fallback");
    REQUIRE(S("nul") == "_nul");
    REQUIRE(S("COM7.txt") == "_COM7.txt");
    REQUIRE(S("conin$") == "_conin$");
    REQUIRE(S("console") == "console");
    REQUIRE(S("a\tb\x7F" "c") == "a_b_c");
    REQUIRE(S("Săptămâna 3") == "Săptămâna 3");           // valid UTF-8 is kept
    REQUIRE(S("bad\xC3(\xFF") == "bad_(_");                 // invalid UTF-8 becomes '_'
    REQUIRE(S("\xED\xA0\x80" "x") == "___x");               // UTF-16 surrogate encoded in UTF-8
    REQUIRE(S("\xC0\xAF") == "__");                          // overlong '/'
    // long names: cut on a UTF-8 boundary, the extension is kept
    const std::string longName = std::string(40, 'a') + ".exe";
    REQUIRE(S(longName) == std::string(28, 'a') + ".exe");
    std::string accents;
    for (int i = 0; i < 20; i++)
        accents += "\xC4\x83"; // U+0103, two bytes each
    const std::string cut = S(accents);
    REQUIRE(cut.size() == 32);
    REQUIRE(cut == accents.substr(0, 32));
    REQUIRE(SanitizePathComponent(accents + "b", "x", 31).size() == 30); // never half a character
    // idempotent: the store relies on it to compare names
    for (const std::string_view s : { "a<b>:c", "CON.txt", "  x  ", "Săptămâna/3", "bad\xC3(" })
        REQUIRE(S(S(s)) == S(s));

    REQUIRE(ServerFolderName("https://rzaharia.dev") == "rzaharia.dev");
    REQUIRE(ServerFolderName("https://User:pw@Course.Example.EDU:8443/api/v2?x=1") == "course.example.edu_8443");
    REQUIRE(ServerFolderName("http://127.0.0.1:8770") == "127.0.0.1_8770");
    REQUIRE(ServerFolderName("http://[::1]:8770/") == "[__1]_8770");
    REQUIRE(ServerFolderName("") == "server");
    REQUIRE(ServerFolderName("https://../") == "server");

    const auto folder = TaskFolder("/base", "https://rzaharia.dev", "Lab 5: Heap/Stack");
    REQUIRE(folder.filename() == "Lab 5_ Heap_Stack");
    REQUIRE(folder.parent_path().filename() == "rzaharia.dev");
    REQUIRE(TaskFolder("/base", "https://rzaharia.dev", "..").filename() == "Course");
}

TEST_CASE("Learning: task file store", "[learning][content]")
{
    const auto dir = std::filesystem::temp_directory_path() / "gview_learning_test_store";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    const auto readAll = [](const std::filesystem::path& p) {
        std::ifstream f(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    const auto overwrite = [](const std::filesystem::path& p, std::string_view text) {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f.write(text.data(), static_cast<std::streamsize>(text.size()));
    };
    using State             = TaskFileStore::LocalState;
    const std::string v1    = "version one";
    const std::string v2    = "version two";
    const std::string other = "another task";

    std::filesystem::path p1;
    {
        TaskFileStore store(dir);
        REQUIRE_FALSE(store.FindUpToDate("p1", Sha256Hex(v1)).has_value());
        auto plan = store.PlanFor("p1", "task.exe", Sha256Hex(v1));
        REQUIRE(plan.state == State::Missing);
        REQUIRE(plan.file == "task.exe");
        REQUIRE(store.Store(plan, "p1", BufferView(v1), Sha256Hex(v1), 1, p1).ok);
        REQUIRE(readAll(p1) == v1);

        // another item delivering the same file name (any case) gets its own file
        auto planOther = store.PlanFor("p2", "TASK.EXE", Sha256Hex(other));
        REQUIRE(planOther.state == State::Missing);
        REQUIRE(planOther.file == "p2-TASK.EXE");
        std::filesystem::path p2;
        REQUIRE(store.Store(planOther, "p2", BufferView(other), Sha256Hex(other), 1, p2).ok);
        REQUIRE(readAll(p1) == v1);
        REQUIRE(readAll(p2) == other);
    }
    {
        // a new store reads the manifest back
        TaskFileStore store(dir);
        REQUIRE(store.FindUpToDate("p1", Sha256Hex(v1)) == p1);
        REQUIRE(store.RecordedVersion("p1") == 1);
        REQUIRE(store.KnownFile("p2").has_value());
        REQUIRE_FALSE(store.FindUpToDate("p1", Sha256Hex(v2)).has_value());
        // same content on disk and on the server
        REQUIRE(store.PlanFor("p1", "renamed.exe", Sha256Hex(v1)).state == State::SameAsServer);
        // unchanged on disk, new version on the server: replace without asking (the item keeps its file name)
        auto plan = store.PlanFor("p1", "renamed.exe", Sha256Hex(v2));
        REQUIRE(plan.state == State::Outdated);
        REQUIRE(plan.path == p1);
        std::filesystem::path out;
        REQUIRE(store.Store(plan, "p1", BufferView(v2), Sha256Hex(v2), 2, out).ok);
        REQUIRE(readAll(p1) == v2);
        REQUIRE(store.RecordedVersion("p1") == 2);
    }
    {
        // the student changed the file: Modified, even when the server version changes again
        overwrite(p1, "patched by the student");
        TaskFileStore store(dir);
        REQUIRE_FALSE(store.FindUpToDate("p1", Sha256Hex(v2)).has_value());
        auto plan = store.PlanFor("p1", "task.exe", Sha256Hex(v2));
        REQUIRE(plan.state == State::Modified);
        store.Keep(plan, "p1", Sha256Hex(v2), 2); // "No": keep the student's file
        REQUIRE(store.PlanFor("p1", "task.exe", Sha256Hex(v2)).state == State::Modified);
        REQUIRE(store.PlanFor("p1", "task.exe", Sha256Hex("v3")).state == State::Modified);
        REQUIRE(readAll(p1) == "patched by the student");
    }
    {
        // a file GView did not record (no manifest entry) is never taken for the server version
        overwrite(dir / "foreign.bin", "unrelated");
        TaskFileStore store(dir);
        auto plan = store.PlanFor("p3", "foreign.bin", Sha256Hex(v1));
        REQUIRE(plan.state == State::Modified);
        store.Keep(plan, "p3", Sha256Hex(v1), 7); // "No": the bytes kept are not the server's version 7
        REQUIRE(store.RecordedVersion("p3") == 0);
        REQUIRE(store.PlanFor("p3", "foreign.bin", Sha256Hex(v1)).state == State::Modified);
        // "x" and "x.part" (the temporary file of a write) never belong to two items
        std::filesystem::path part;
        auto planPart = store.PlanFor("p6", "notes.part", Sha256Hex(v1));
        REQUIRE(store.Store(planPart, "p6", BufferView(v1), Sha256Hex(v1), 1, part).ok);
        REQUIRE(store.PlanFor("p7", "notes", Sha256Hex(v2)).file == "p7-notes");
        REQUIRE(store.PlanFor("p8", "NOTES.PART.part", Sha256Hex(v2)).file == "p8-NOTES.PART.part");
        overwrite(dir / "same.bin", v1);
        auto same = store.PlanFor("p4", "same.bin", Sha256Hex(v1));
        REQUIRE(same.state == State::SameAsServer);
        store.Keep(same, "p4", Sha256Hex(v1), 1);
        REQUIRE(store.FindUpToDate("p4", Sha256Hex(v1)).has_value());
        // the manifest itself can never be a task file
        REQUIRE(store.PlanFor("p5", ".gview-items.json", Sha256Hex(v1)).file != TASK_MANIFEST_FILE_NAME);
    }
    {
        // a tampered manifest: bad names and paths are ignored (it is hidden on Windows: delete it before rewriting it)
        std::filesystem::remove(dir / TASK_MANIFEST_FILE_NAME, ec);
        overwrite(
              dir / TASK_MANIFEST_FILE_NAME,
              R"({"items":{"p1":{"file":"../../evil","sha256":"00"},"bad name":{"file":"x"},"p9":{"file":"ok.bin","itemVersion":-1},)"
              R"("p3":{"file":"dup.bin","itemVersion":3},"p4":{"file":"DUP.BIN","itemVersion":4}}})");
        TaskFileStore store(dir);
        REQUIRE_FALSE(store.KnownFile("p1").has_value());
        REQUIRE(store.RecordedVersion("p9") == 0);
        REQUIRE(store.RecordedVersion("p3") == 3);
        REQUIRE(store.RecordedVersion("p4") == 0); // a second item claiming the same file is dropped
        REQUIRE(store.PlanFor("p4", "DUP.BIN", Sha256Hex(v1)).file == "p4-DUP.BIN");
        auto plan = store.PlanFor("p1", "task.exe", Sha256Hex(v1));
        REQUIRE(plan.path.parent_path() == dir);
        std::filesystem::remove(dir / TASK_MANIFEST_FILE_NAME, ec);
        overwrite(dir / TASK_MANIFEST_FILE_NAME, "not json");
        TaskFileStore damaged(dir);
        REQUIRE_FALSE(damaged.KnownFile("p2").has_value());
    }
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("Learning: locked buffer hygiene", "[learning][content]")
{
    LockedBuffer b;
    REQUIRE(b.Allocate(64));
    for (size_t i = 0; i < 64; i++)
        b.Data()[i] = 0xAA;
    b.Truncate(16);
    REQUIRE(b.Size() == 16);
    // the tail is wiped (still inside the allocation, so reading it is defined)
    for (size_t i = 16; i < 64; i++)
        REQUIRE(b.Data()[i] == 0);
    LockedBuffer moved = std::move(b);
    REQUIRE(b.Data() == nullptr);
    REQUIRE(moved.Size() == 16);
    moved.Wipe();
    REQUIRE(moved.Empty());
    REQUIRE_FALSE(b.Allocate(0));
    REQUIRE_FALSE(b.Allocate(LockedBuffer::MAX_SIZE + 1));
}

// ======================================================================== telemetry (T7)
TEST_CASE("Learning: telemetry contract table", "[learning][telemetry]")
{
    const std::set<std::string> expected = { "session_start", "session_end",   "policy_applied", "policy_rejected", "task_open",
                                             "task_close",    "resource_open", "viewer_open",    "jump_follow",     "jump_back",
                                             "jump_forward",  "goto_entrypoint", "goto_dialog",  "comment_add",     "comment_edit",
                                             "comment_remove", "label_rename", "note_add",       "idle",            "feature_blocked",
                                             "submit",        "client_error",  "screen_protect_failed" };
    std::set<std::string> names;
    for (uint32 i = 0; i < static_cast<uint32>(EventType::Count); i++)
        names.insert(std::string(EventTypeName(static_cast<EventType>(i))));
    REQUIRE(names == expected);
    // privacy: no event may carry free text except client_error.message (constant strings only)
    for (uint32 i = 0; i < static_cast<uint32>(EventType::Count); i++)
    {
        const auto t = static_cast<EventType>(i);
        if (t != EventType::ClientError)
            REQUIRE_FALSE(IsFieldAllowed(t, Field::Message));
    }
    REQUIRE(IsFieldAllowed(EventType::JumpFollow, Field::From));
    REQUIRE_FALSE(IsFieldAllowed(EventType::CommentAdd, Field::Kind));
    REQUIRE(NormalizeViewerName("Dissasm") == "Dissasm");
    REQUIRE(NormalizeViewerName("My custom viewer") == "Other");
}

TEST_CASE("Learning: telemetry known sequence (T7)", "[learning][telemetry]")
{
    uint64 t = NOW;
    TelemetryCollector c([&]() { return t++; });
    RestrictedMode::TelemetrySettings s;
    s.enabled        = true;
    s.maxBatchEvents = 500;
    c.Configure(s);
    for (int i = 0; i < 5; i++)
        REQUIRE(c.Record(
              EventType::JumpFollow,
              "w1_stack_var",
              { FieldValue{ Field::From, std::string("0x401000") }, FieldValue{ Field::To, std::string("0x401050") }, FieldValue{ Field::Kind, std::string("jle") } }));
    REQUIRE(c.Record(EventType::CommentAdd, "w1_stack_var"));
    REQUIRE(c.Record(EventType::CommentAdd, "w1_stack_var"));
    REQUIRE(c.Record(EventType::CommentEdit, "w1_stack_var"));
    REQUIRE(c.Record(EventType::ViewerOpen, "w1_stack_var", { FieldValue{ Field::Viewer, std::string("Dissasm") } }));

    BatchMeta meta{ "11111111-2222-4333-8444-555555555555", "pol_x", std::string(64, 'c'), "0.391.0", "windows-x64", NOW + 100 };
    auto body = c.BeginBatch(meta);
    REQUIRE(body.has_value());
    auto j = json::parse(*body);
    REQUIRE(j["sessionId"] == meta.sessionId);
    REQUIRE(j["events"].size() == 9);
    for (size_t i = 0; i < 9; i++)
        REQUIRE(j["events"][i]["seq"] == i + 1);
    REQUIRE(j["events"][0]["type"] == "jump_follow");
    REQUIRE(j["events"][0]["from"] == "0x401000");
    REQUIRE(j["events"][0]["kind"] == "jle");
    REQUIRE(j["events"][5]["type"] == "comment_add");
    REQUIRE(j["events"][7]["type"] == "comment_edit");
    REQUIRE_FALSE(j["events"][7].contains("text"));
    const auto& counters = j["counters"]["w1_stack_var"];
    REQUIRE(counters["jump_follow"] == 5);
    REQUIRE(counters["comment_add"] == 2);
    REQUIRE(counters["comment_edit"] == 1);
    REQUIRE(counters["comment_remove"] == 0);
    REQUIRE(counters["viewer_open"]["Dissasm"] == 1);
    REQUIRE(c.InFlightCount() == 9);
    REQUIRE_FALSE(c.BeginBatch(meta).has_value()); // only one batch in flight
    c.OnFlushResult(FlushOutcome::Accepted);
    REQUIRE(c.PendingCount() == 0);
    REQUIRE(c.LastSeq() == 9);
}

TEST_CASE("Learning: telemetry whitelist, bounds and flush outcomes", "[learning][telemetry]")
{
    TelemetryCollector c([]() { return NOW; });
    RestrictedMode::TelemetrySettings s;
    SECTION("disabled telemetry is a no-op")
    {
        s.enabled = false;
        c.Configure(s);
        REQUIRE_FALSE(c.Record(EventType::SessionStart, ""));
        REQUIRE_FALSE(c.BeginBatch({}).has_value());
    }
    SECTION("whitelist violations are refused")
    {
        s.enabled = true;
        c.Configure(s);
        REQUIRE_FALSE(c.Record(EventType::CommentAdd, "w1", { FieldValue{ Field::Message, std::string("the comment text") } }));
        REQUIRE_FALSE(c.Record(EventType::ClientError, "w1", { FieldValue{ Field::Message, std::string("x") } })); // item not allowed
        REQUIRE(c.WhitelistViolations() == 2);
        REQUIRE(c.PendingCount() == 0);
    }
    SECTION("bounded queue drops the oldest")
    {
        s.enabled        = true;
        s.maxBatchEvents = 2; // capacity 8
        c.Configure(s);
        for (int i = 0; i < 20; i++)
            c.Record(EventType::JumpBack, "w1");
        REQUIRE(c.PendingCount() == 8);
        REQUIRE(c.DroppedCount() == 12);
        auto body = c.BeginBatch({});
        REQUIRE(json::parse(*body)["events"][0]["seq"] == 13); // oldest dropped
    }
    SECTION("503 keeps the batch, 400 drops it, 429 retries")
    {
        s.enabled = true;
        c.Configure(s);
        c.Record(EventType::JumpBack, "w1");
        c.Record(EventType::JumpForward, "w1");
        FakeTransport t;
        long status = 503;
        t.routes["/GView/Telemetry"] = [&](const HttpRequest&) { return Response(status, "{}"); };
        REQUIRE(TelemetryFlusher::FlushOnce(t, c, {}, 5, nullptr) == FlushOutcome::Retry);
        REQUIRE(c.PendingCount() == 2);
        status = 429;
        REQUIRE(TelemetryFlusher::FlushOnce(t, c, {}, 5, nullptr) == FlushOutcome::Retry);
        REQUIRE(c.PendingCount() == 2);
        // same seq numbers on retry: the server de-duplicates on (sessionId, seq)
        const auto first = json::parse(t.requests[0].second)["events"];
        const auto again = json::parse(t.requests[1].second)["events"];
        REQUIRE(first == again);
        status = 400;
        REQUIRE(TelemetryFlusher::FlushOnce(t, c, {}, 5, nullptr) == FlushOutcome::Dropped);
        REQUIRE(c.PendingCount() == 0);
        c.Record(EventType::JumpBack, "w1");
        status = 200;
        REQUIRE(TelemetryFlusher::FlushOnce(t, c, {}, 5, nullptr) == FlushOutcome::Accepted);
        REQUIRE(c.PendingCount() == 0);
        REQUIRE(json::parse(t.requests.back().second)["events"][0]["seq"] == 3); // seq stays monotonic
        bool expired = false;
        c.Record(EventType::JumpBack, "w1");
        t.routes["/GView/Telemetry"] = [&](const HttpRequest&) { return Response(403, R"({"code":"POLICY_EXPIRED"})"); };
        REQUIRE(TelemetryFlusher::FlushOnce(t, c, {}, 5, nullptr, &expired) == FlushOutcome::Dropped);
        REQUIRE(expired);
    }
    SECTION("network failure keeps events (T8)")
    {
        s.enabled = true;
        c.Configure(s);
        c.Record(EventType::JumpBack, "w1");
        FakeTransport t;
        t.routes["/GView/Telemetry"] = [](const HttpRequest&) { return TransportFailure(); };
        REQUIRE(TelemetryFlusher::FlushOnce(t, c, {}, 5, nullptr) == FlushOutcome::Retry);
        REQUIRE(c.PendingCount() == 1);
    }
}

// ======================================================================== session state machine
TEST_CASE("Learning: session connect T1 (valid policy)", "[learning][session]")
{
    SessionFixture fx;
    fx.ServePolicy(BuildPolicy({}));
    REQUIRE(fx.Connect().ok);
    auto& s = *fx.session;
    REQUIRE(s.GetState() == SessionState::Active);
    REQUIRE(fx.activations == 1);
    REQUIRE(s.CanOpenItems());
    REQUIRE(s.CanSubmit());
    REQUIRE(IsUuid4(s.GetSessionId()));
    const auto st = s.GetStatus();
    REQUIRE(st.displayName == "Student 17");
    REQUIRE(st.policyId == "pol_2026w1_ab12cd");
    REQUIRE(fx.transport->policyId == "pol_2026w1_ab12cd"); // X-GView-Policy on later requests
    REQUIRE(s.Telemetry().PendingCount() == 2);            // session_start + policy_applied

    fx.transport->routes["/GView/GetWeeks"] = [](const HttpRequest&) { return Response(200, WeeksFixture()); };
    GView::Utils::GStatus refreshed = GView::Utils::GStatus::Error("not called");
    REQUIRE(s.RefreshCatalogue([&](const GView::Utils::GStatus& r) { refreshed = r; }).ok);
    REQUIRE(refreshed.ok);
    REQUIRE(s.IsCatalogueLoaded());
    REQUIRE(fx.transport->policyHeaders.back() == "pol_2026w1_ab12cd");

    // UsesConnection: the launch of the web build decides with it whether the current session must be ended first
    ConnectionInfo same, otherToken, otherServer;
    REQUIRE(ParseConnectionString(fx.ConnectionString(), false, same).ok);
    REQUIRE(ParseConnectionString(BuildConnectionString("tok_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ0123456789abcd", TEST_SERVER, "", ""), false, otherToken).ok);
    REQUIRE(ParseConnectionString(BuildConnectionString(TEST_TOKEN, "https://other.example.edu", "", ""), false, otherServer).ok);
    REQUIRE(s.UsesConnection(same));
    REQUIRE_FALSE(s.UsesConnection(otherToken));
    REQUIRE_FALSE(s.UsesConnection(otherServer));
    REQUIRE(s.EndSession("user").ok);
    REQUIRE_FALSE(s.UsesConnection(same));
}

TEST_CASE("Learning: session rejects invalid policies (T2/T3)", "[learning][session]")
{
    SECTION("tampered")
    {
        SessionFixture fx;
        const auto policy = BuildPolicy({});
        auto sig          = ServerKey().Sign(policy);
        sig[0] ^= 0xFF;
        const auto body                        = ConnectBody(policy, sig);
        fx.transport->routes["/GView/Connect"] = [body](const HttpRequest&) { return Response(200, body); };
        auto st                                = fx.Connect();
        REQUIRE_FALSE(st.ok);
        REQUIRE(st.message.starts_with("POLICY_SIGNATURE_INVALID"));
        REQUIRE(fx.session->GetState() == SessionState::Error);
        REQUIRE(fx.activations == 0);
        REQUIRE_FALSE(fx.session->CanOpenItems());
        CatalogueItem item;
        item.name = "w1";
        REQUIRE_FALSE(fx.session->Download(item, nullptr).ok);
    }
    SECTION("wrong key")
    {
        SessionFixture fx;
        fx.ServePolicy(BuildPolicy({}), OtherKey());
        REQUIRE_FALSE(fx.Connect().ok);
        REQUIRE(fx.session->GetState() == SessionState::Error);
    }
    SECTION("expired")
    {
        SessionFixture fx;
        PolicyOptions o;
        o.startsAt = NOW - 7200;
        o.endsAt   = NOW - 3600;
        fx.ServePolicy(BuildPolicy(o));
        auto st = fx.Connect();
        REQUIRE(st.message.starts_with("POLICY_EXPIRED"));
        REQUIRE(fx.session->GetState() == SessionState::Error);
    }
    SECTION("no public key: restricted policy refused")
    {
        SessionFixture fx;
        fx.ServePolicy(BuildPolicy({}));
        auto st = fx.Connect(false);
        REQUIRE(st.message.starts_with("POLICY_KEY_MISSING"));
        REQUIRE(fx.activations == 0);
    }
    SECTION("server error envelope")
    {
        SessionFixture fx;
        fx.transport->routes["/GView/Connect"] = [](const HttpRequest&) {
            return Response(401, R"({"status":"error","code":"UNAUTHORIZED","details":"bad token","retryable":false})");
        };
        auto st = fx.Connect();
        REQUIRE(st.message.find("UNAUTHORIZED") != std::string::npos);
        REQUIRE(fx.session->GetState() == SessionState::Error);
    }
}

TEST_CASE("Learning: legacy server compatibility", "[learning][session]")
{
    SessionFixture fx;
    // pre-v2 server: no /GView/Connect, "/GView/" answers an empty 200
    fx.transport->routes["/GView/"]            = [](const HttpRequest&) { return Response(200, ""); };
    fx.transport->routes["/GView/GetProblems"] = [](const HttpRequest&) { return Response(200, R"([{"name":"p1","title":"T","description":"D"}])"); };
    fx.transport->routes["/GView/SubmitFlag"]  = [](const HttpRequest&) { return Response(200, R"({"status":"error","details":"Wrong"})"); };
    REQUIRE(fx.Connect().ok);
    auto& s = *fx.session;
    REQUIRE(s.GetState() == SessionState::Legacy);
    REQUIRE(fx.activations == 0); // nothing to verify => no restrictions
    REQUIRE(fx.transport->Count("/GView/Connect") == 1);
    REQUIRE(s.RefreshCatalogue(nullptr).ok);
    REQUIRE(s.GetCatalogue().legacy);
    REQUIRE(s.GetCatalogue().weeks[0].problems.size() == 1);
    SubmitOutcome out;
    REQUIRE(s.Submit("p1", SecureString("x"), SecureString(""), [&](const SubmitOutcome& o) { out = o; }).ok);
    REQUIRE(out.status.ok);
    REQUIRE(out.result.legacy);
    REQUIRE_FALSE(out.result.correct);
}

TEST_CASE("Learning: requireScreenProtect unsupported => refusal (T8)", "[learning][session]")
{
    SessionFixture fx;
    fx.screenApplied = false;
    PolicyOptions o;
    o.requireScreen = true;
    fx.ServePolicy(BuildPolicy(o));
    REQUIRE_FALSE(fx.Connect().ok);
    auto& s = *fx.session;
    REQUIRE(s.GetState() == SessionState::Error);
    REQUIRE(fx.activations == 1); // restrictions are applied (fail closed) ...
    REQUIRE_FALSE(s.CanOpenItems()); // ... but no task can be opened
    REQUIRE(s.GetStatus().screenRequirementUnmet);
    auto body = s.Telemetry().BeginBatch({});
    REQUIRE(body.has_value());
    REQUIRE(body->find("screen_protect_failed") != std::string::npos);
}

TEST_CASE("Learning: reconnect re-validates and keeps the current policy (T8)", "[learning][session]")
{
    SessionFixture fx;
    fx.ServePolicy(BuildPolicy({}));
    REQUIRE(fx.Connect().ok);
    // the next connect returns a tampered policy: it is rejected and the verified one stays in force
    const auto policy = BuildPolicy({});
    auto sig          = ServerKey().Sign(policy);
    sig[10] ^= 0x01;
    const auto body                        = ConnectBody(policy, sig);
    fx.transport->routes["/GView/Connect"] = [body](const HttpRequest&) { return Response(200, body); };
    REQUIRE_FALSE(fx.Connect().ok);
    REQUIRE(fx.session->GetState() == SessionState::Active);
    REQUIRE(fx.session->GetPolicy()->id == "pol_2026w1_ab12cd");
    // a legacy answer never downgrades a verified session
    fx.transport->routes["/GView/Connect"] = [](const HttpRequest&) { return Response(200, ""); };
    REQUIRE_FALSE(fx.Connect().ok);
    REQUIRE(fx.session->GetState() == SessionState::Active);
    // a newer valid policy replaces the current one
    PolicyOptions o;
    o.id = "pol_2026w1_new";
    fx.ServePolicy(BuildPolicy(o));
    REQUIRE(fx.Connect().ok);
    REQUIRE(fx.session->GetPolicy()->id == "pol_2026w1_new");
    REQUIRE(fx.activations == 2);
}

TEST_CASE("Learning: POLICY_EXPIRED from the server => Expired", "[learning][session]")
{
    SessionFixture fx;
    fx.ServePolicy(BuildPolicy({}));
    REQUIRE(fx.Connect().ok);
    fx.transport->routes["/GView/GetWeeks"] = [](const HttpRequest&) {
        return Response(403, R"({"status":"error","code":"POLICY_EXPIRED","details":"x","retryable":false})");
    };
    REQUIRE(fx.session->RefreshCatalogue(nullptr).ok);
    REQUIRE(fx.session->GetState() == SessionState::Expired);
    REQUIRE_FALSE(fx.session->CanOpenItems());
    REQUIRE_FALSE(fx.session->CanSubmit());
    REQUIRE(fx.deactivations == 0); // restrictions stay applied (fail closed)
    // local expiry after endsAt
    SessionFixture fx2;
    fx2.ServePolicy(BuildPolicy({}));
    REQUIRE(fx2.Connect().ok);
    fx2.clock = NOW + 3600 + 200;
    fx2.mono += 1000;
    fx2.session->Tick();
    REQUIRE(fx2.session->GetState() == SessionState::Expired);
}

TEST_CASE("Learning: encrypted memory download through the session (T1/T5)", "[learning][session]")
{
    SessionFixture fx;
    PolicyOptions o;
    o.storage = "memory";
    fx.ServePolicy(BuildPolicy(o));
    REQUIRE(fx.Connect().ok);
    const std::string plaintext = "MZ...task";
    const std::string policyId  = fx.session->GetPolicy()->id;
    fx.transport->routes["/GView/GetProblems/"] = [&](const HttpRequest& r) {
        const std::string name = r.path.substr(std::string("/GView/GetProblems/").size());
        return Response(
              200,
              EncryptBlob(plaintext, name, policyId, Token()),
              { { "x-gview-delivery", "memory" }, { "x-gview-encrypted", "1" }, { "x-gview-sha256", Sha256Hex(plaintext) }, { "x-gview-item-version", "2" } });
    };
    CatalogueItem item;
    item.name = "w1_stack_var";
    item.kind = ItemKind::Problem;
    DownloadResult result;
    bool called = false;
    REQUIRE(fx.session
                  ->Download(
                        item,
                        [&](DownloadResult& r) {
                            called = true;
                            result = std::move(r);
                        })
                  .ok);
    REQUIRE(called);
    REQUIRE(result.status.ok);
    REQUIRE(result.content.mode == DeliveryMode::Memory);
    REQUIRE(std::string(reinterpret_cast<const char*>(result.content.data.Data()), result.content.data.Size()) == plaintext);
    // a hostile item name never reaches the URL
    CatalogueItem bad;
    bad.name = "../../admin";
    REQUIRE_FALSE(fx.session->Download(bad, nullptr).ok);
}

TEST_CASE("Learning: submission flow and idempotent retries (T6)", "[learning][session]")
{
    SessionFixture fx;
    PolicyOptions o;
    o.requireExplanation = true;
    fx.ServePolicy(BuildPolicy(o));
    REQUIRE(fx.Connect().ok);
    auto& s       = *fx.session;
    bool failNext = true;
    std::vector<std::string> ids;
    fx.transport->routes["/GView/SubmitFlag"] = [&](const HttpRequest& r) {
        ids.push_back(json::parse(std::string(r.body.data(), r.body.size()))["clientSubmissionId"]);
        if (failNext)
            return TransportFailure();
        return Response(200, R"({"status":"ok","correct":false,"points":0,"attempts":1,"alreadySolved":false,"duplicate":false,"details":"Wrong"})");
    };
    SubmitOutcome out;
    auto cb = [&](const SubmitOutcome& r) { out = r; };
    REQUIRE_FALSE(s.Submit("w1_stack_var", SecureString("3"), SecureString(""), cb).ok); // explanation required
    REQUIRE(s.Submit("w1_stack_var", SecureString(" 3 "), SecureString("because"), cb).ok);
    REQUIRE_FALSE(out.status.ok);
    REQUIRE_FALSE(out.definitive);
    failNext = false;
    REQUIRE(s.Submit("w1_stack_var", SecureString("3"), SecureString("because"), cb).ok); // retry (flag trimmed => same answer)
    REQUIRE(out.status.ok);
    REQUIRE(out.definitive);
    REQUIRE(ids.size() == 2);
    REQUIRE(ids[0] == ids[1]);
    REQUIRE(s.Submit("w1_stack_var", SecureString("3"), SecureString("because"), cb).ok); // after a verdict: new attempt
    REQUIRE(ids[2] != ids[1]);
    const auto body = json::parse(fx.transport->LastBody("/GView/SubmitFlag"));
    REQUIRE(body["policyId"] == "pol_2026w1_ab12cd");
    REQUIRE(body["explanation"] == "because");
    REQUIRE(body["flag"] == "3");
    REQUIRE_FALSE(s.Submit("w1_stack_var", SecureString(std::string(600, 'a')), SecureString("x"), cb).ok);
}

TEST_CASE("Learning: in-memory objects opened while memory-only content is open are memory-only", "[learning][session]")
{
    SessionFixture fx;
    fx.ServePolicy(BuildPolicy(PolicyOptions{}));
    REQUIRE(fx.Connect().ok);
    auto& s        = *fx.session;
    int taskObject = 0, extracted = 0, ownFile = 0, nested = 0, later = 0; // stand-ins for GView::Object addresses
    ItemBinding b;
    b.item = "w1_memory";
    b.mode = DeliveryMode::Memory;
    s.SetPendingBinding(b);
    s.OnObjectCreated(&taskObject, true);
    s.OnObjectCreated(&extracted, true); // e.g. an entry extracted from the memory-only archive
    s.OnObjectCreated(&ownFile, false);  // opened from disk => can not hold derived content
    REQUIRE(s.IsMemoryDerived(&extracted));
    REQUIRE(s.FindBinding(&extracted) == nullptr); // not a course window (no telemetry, no time accounting)
    REQUIRE_FALSE(s.IsMemoryDerived(&ownFile));
    REQUIRE_FALSE(s.IsMemoryDerived(&taskObject)); // protected by its own binding

    // the task window is closed, but derived content is still open => what is extracted from it is tainted as well
    s.OnObjectClosed(&taskObject);
    s.OnObjectCreated(&nested, true);
    REQUIRE(s.IsMemoryDerived(&nested));
    s.OnObjectClosed(&extracted);
    s.OnObjectClosed(&nested);
    REQUIRE_FALSE(s.IsMemoryDerived(&extracted));

    // nothing memory-only is open anymore
    s.OnObjectCreated(&later, true);
    REQUIRE_FALSE(s.IsMemoryDerived(&later));

    // file-mode items do not taint
    int fileTask = 0, fromFileTask = 0;
    ItemBinding f;
    f.item = "w2_file";
    f.mode = DeliveryMode::File;
    s.SetPendingBinding(f);
    s.OnObjectCreated(&fileTask, false);
    s.OnObjectCreated(&fromFileTask, true);
    REQUIRE_FALSE(s.IsMemoryDerived(&fromFileTask));

    s.OnObjectClosed(&fileTask);
    s.OnObjectClosed(&fromFileTask);
    s.OnObjectClosed(&later);
    s.OnObjectClosed(&ownFile);
}

TEST_CASE("Learning: window bindings, telemetry scope and time accounting", "[learning][session]")
{
    SessionFixture fx;
    PolicyOptions o;
    o.idleThreshold = 10;
    fx.ServePolicy(BuildPolicy(o));
    REQUIRE(fx.Connect().ok);
    auto& s = *fx.session;
    int taskObject = 0, ownFile = 0; // stand-ins for GView::Object addresses
    ItemBinding b;
    b.item    = "w1_stack_var";
    b.problem = true;
    b.mode    = DeliveryMode::Memory;
    s.SetPendingBinding(b);
    s.OnObjectCreated(&taskObject);
    s.OnObjectCreated(&ownFile); // a later window is not bound
    REQUIRE(s.FindBinding(&taskObject) != nullptr);
    REQUIRE(s.FindBinding(&ownFile) == nullptr);
    // telemetry is scoped to course windows only
    REQUIRE(s.Record(&taskObject, EventType::JumpBack));
    REQUIRE_FALSE(s.Record(&ownFile, EventType::JumpBack));

    for (int i = 0; i < 30; i++) // 6 s of focused, active Dissasm time in 200 ms frames
    {
        fx.mono += 200;
        s.NoteActivity();
        s.OnFrame(&taskObject, "Dissasm", true);
    }
    fx.mono += 15000; // idle beyond the 10 s threshold
    s.OnFrame(&taskObject, "Dissasm", true);
    fx.mono += 200;
    s.OnFrame(&taskObject, "Dissasm", true);
    s.NoteActivity(); // activity resumes => one idle event
    const auto counters = json::parse(s.Telemetry().CountersJson())["w1_stack_var"];
    REQUIRE(counters["active_seconds"].get<uint64>() >= 5);
    REQUIRE(counters["dissasm_seconds"].get<uint64>() >= 5);
    REQUIRE(counters["idle_seconds"].get<uint64>() >= 15);
    REQUIRE(counters["viewer_open"]["Dissasm"] == 1);
    REQUIRE(counters["jump_back"] == 1);

    REQUIRE_FALSE(s.EndSession("user").ok); // a course window is still open
    s.OnObjectClosed(&taskObject);
    auto batch = s.Telemetry().BeginBatch({});
    REQUIRE(batch->find("\"task_close\"") != std::string::npos);
    REQUIRE(batch->find("\"idle\"") != std::string::npos);
    s.Telemetry().OnFlushResult(FlushOutcome::Accepted);
    REQUIRE(s.EndSession("user").ok);
    REQUIRE(fx.deactivations == 1);
    REQUIRE(s.GetState() == SessionState::Disconnected);
}

// ======================================================================== course notes (spec §2.2, §10.11)
namespace
{
json NotesObject(bool enabled = true, int64 maxChars = 1000)
{
    return json{ { "enabled", enabled }, { "maxChars", maxChars } };
}

GView::Utils::GStatus ParsePolicyWith(const PolicyOptions& o, Policy& p)
{
    const auto policy = BuildPolicy(o);
    const auto sig    = ServerKey().Sign(policy);
    return RestrictedMode::VerifyAndParsePolicy(
          BufferView(policy),
          BufferView(sig.data(), sig.size()),
          BufferView(ServerKey().publicKey.data(), ServerKey().publicKey.size()),
          SubjectForToken(Token()),
          TEST_SERVER,
          NOW,
          p);
}

std::string BodyOf(const HttpRequest& r)
{
    return std::string(r.body.data(), r.body.size());
}

HttpResponse ErrorResponse(long status, std::string_view code, std::string_view details = "x")
{
    return Response(status, json{ { "status", "error" }, { "code", code }, { "details", details }, { "retryable", status == 429 } }.dump());
}

// In-process course server for the note endpoints, with the compare-and-set and idempotency rules of spec §10.11
struct FakeNotesServer {
    struct Note {
        std::string title, body, scope; // scope as compact JSON
        int64 revision{ 1 };
        std::string lastUpdate; // fingerprint of the last applied update (base revision + content)
    };
    std::map<std::string, Note> notes;
    json teacher = json::array();
    bool staff{ false };
    bool forbidden{ false };
    int failNext{ 0 };       // transport failures before the request reaches the server
    int loseNextAnswer{ 0 }; // the request is applied, its answer is lost
    std::vector<std::string> saveBodies, teacherBodies, deleteIds;
    int64 now{ 1760000000 };

    static std::string Fingerprint(int64 rev, const std::string& t, const std::string& b, const std::string& s)
    {
        return std::to_string(rev) + '\x1f' + t + '\x1f' + b + '\x1f' + s;
    }
    json NoteJson(const std::string& id, const Note& n) const
    {
        return json{ { "id", id },         { "title", n.title }, { "body", n.body },   { "scope", json::parse(n.scope) },
                     { "revision", n.revision }, { "createdAt", now }, { "updatedAt", now } };
    }
    void Install(FakeTransport& t)
    {
        t.routes["/GView/GetNotes"] = [this](const HttpRequest&) {
            if (forbidden)
                return ErrorResponse(403, "FORBIDDEN", "Course notes are disabled for this week.");
            json mine = json::array();
            for (const auto& [id, n] : notes)
                mine.push_back(NoteJson(id, n));
            return Response(
                  200,
                  json{ { "status", "ok" }, { "maxChars", 1000 }, { "serverTime", now }, { "canEditTeacherNotes", staff }, { "mine", mine }, { "teacher", teacher } }
                        .dump());
        };
        t.routes["/GView/SaveNote"] = [this](const HttpRequest& r) {
            if (failNext > 0)
            {
                failNext--;
                return TransportFailure();
            }
            if (forbidden)
                return ErrorResponse(403, "FORBIDDEN", "Course notes are disabled for this week.");
            saveBodies.push_back(BodyOf(r));
            const auto j          = json::parse(BodyOf(r));
            const std::string id  = j["id"];
            const std::string ti  = j["title"];
            const std::string bo  = j["body"];
            const std::string sc  = j["scope"].dump();
            auto it               = notes.find(id);
            HttpResponse answer;
            if (!j.contains("revision"))
            {
                if (it != notes.end())
                {
                    if (it->second.title != ti || it->second.body != bo || it->second.scope != sc)
                        return ErrorResponse(409, "CONFLICT");
                    answer = Response(200, json{ { "status", "ok" }, { "id", id }, { "revision", it->second.revision }, { "updatedAt", now }, { "created", false } }.dump());
                }
                else
                {
                    notes[id] = Note{ ti, bo, sc, 1, "" };
                    answer    = Response(200, json{ { "status", "ok" }, { "id", id }, { "revision", 1 }, { "updatedAt", now }, { "created", true } }.dump());
                }
            }
            else
            {
                const int64 rev = j["revision"];
                if (it == notes.end())
                    return ErrorResponse(404, "NOT_FOUND");
                const auto fp = Fingerprint(rev, ti, bo, sc);
                if (it->second.revision == rev)
                {
                    it->second = Note{ ti, bo, sc, rev + 1, fp };
                    answer     = Response(200, json{ { "status", "ok" }, { "id", id }, { "revision", rev + 1 }, { "updatedAt", now }, { "created", false } }.dump());
                }
                else if (it->second.revision == rev + 1 && it->second.lastUpdate == fp)
                    answer = Response(200, json{ { "status", "ok" }, { "id", id }, { "revision", rev + 1 }, { "updatedAt", now }, { "created", false } }.dump());
                else
                    return ErrorResponse(409, "CONFLICT");
            }
            if (loseNextAnswer > 0)
            {
                loseNextAnswer--;
                return TransportFailure();
            }
            return answer;
        };
        t.routes["/GView/DeleteNote"] = [this](const HttpRequest& r) {
            if (forbidden)
                return ErrorResponse(403, "FORBIDDEN");
            const std::string id = json::parse(BodyOf(r))["id"];
            deleteIds.push_back(id);
            if (notes.erase(id) == 0)
                return ErrorResponse(404, "NOT_FOUND");
            return Response(200, R"({"status":"ok"})");
        };
        t.routes["/GView/SaveTeacherNote"] = [this](const HttpRequest& r) {
            if (!staff)
                return ErrorResponse(403, "FORBIDDEN", "Only course staff can edit course notes.");
            teacherBodies.push_back(BodyOf(r));
            const auto j = json::parse(BodyOf(r));
            if (!j.contains("id"))
                return Response(200, R"({"status":"ok","id":7,"revision":1,"updatedAt":1760000000,"created":true})");
            for (auto& tn : teacher)
            {
                if (tn["id"] == j["id"])
                {
                    if (tn["revision"] != j["revision"])
                        return ErrorResponse(409, "CONFLICT");
                    tn["revision"] = tn["revision"].get<int64>() + 1;
                    tn["title"]    = j["title"];
                    return Response(200, json{ { "status", "ok" }, { "id", tn["id"] }, { "revision", tn["revision"] }, { "updatedAt", now }, { "created", false } }.dump());
                }
            }
            return ErrorResponse(404, "NOT_FOUND");
        };
    }
};

struct NotesFixture : SessionFixture {
    FakeNotesServer server;
    explicit NotesFixture(json notesObject = NotesObject(), bool staff = false)
    {
        server.staff   = staff;
        server.teacher = json::array({ { { "id", 12 }, { "title", "Conditional jumps" }, { "body", "jle / jg" }, { "scope", { { "kind", "general" } } }, { "audience", "all" },
                                         { "updatedAt", 1759900000 }, { "enabled", true }, { "order", 1 }, { "revision", 3 }, { "createdAt", 1759800000 } },
                                       { { "id", 13 }, { "title", "Stack" }, { "body", "rbp-4" }, { "scope", { { "kind", "problem" }, { "name", "w1_stack_var" } } },
                                         { "audience", "G1" }, { "updatedAt", 1759900000 } } });
        server.Install(*transport);
        PolicyOptions o;
        o.notes = std::move(notesObject);
        ServePolicy(BuildPolicy(o));
    }
    ~NotesFixture()
    {
        // the final note saves of Shutdown() still reach the routes of `server`: end the session while it exists
        session->Shutdown();
    }
    NotesSync& Notes()
    {
        return session->Notes();
    }
    void Advance(uint64 ms)
    {
        mono += ms;
    }
};

const NoteScope STACK_SCOPE{ NoteScopeKind::Problem, "w1_stack_var" };
} // namespace

TEST_CASE("Learning: policy notes object (absent, present, clamping)", "[learning][notes][policy]")
{
    Policy p;
    PolicyOptions o;
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE_FALSE(p.notes.present); // absent = server without notes => no Notes UI

    o.notes = NotesObject(true, 20000);
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE(p.notes.present);
    REQUIRE(p.notes.enabled);
    REQUIRE(p.notes.maxChars == 20000);

    o.notes = NotesObject(true, 5);
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE(p.notes.maxChars == 100); // clamped to [100, 100000]
    o.notes = NotesObject(true, 5000000);
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE(p.notes.maxChars == 100000);

    o.notes = json{ { "enabled", false } };
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE(p.notes.present);
    REQUIRE_FALSE(p.notes.enabled);
    REQUIRE(p.notes.maxChars == 20000);
    o.notes = json::object();
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE_FALSE(p.notes.enabled); // a notes object without "enabled" does not switch the feature on
    o.notes = json(nullptr);
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE_FALSE(p.notes.present);

    // a present field with a wrong JSON type is POLICY_MALFORMED (spec §9.2)
    for (const json bad : { json("on"), json{ { "enabled", "yes" } }, json{ { "maxChars", -1 } }, json{ { "maxChars", "20000" } } })
    {
        o.notes  = bad;
        auto st  = ParsePolicyWith(o, p);
        INFO(bad.dump());
        REQUIRE_FALSE(st.ok);
        REQUIRE(st.message.starts_with("POLICY_MALFORMED"));
    }
}

TEST_CASE("Learning: note text helpers", "[learning][notes]")
{
    const std::string e = "\xC3\xA9"; // U+00E9
    REQUIRE(Utf8Length("abc" + e) == 4);
    REQUIRE(TruncateUtf8("ab" + e + "cd", 3) == "ab" + e);
    REQUIRE(TruncateUtf8("ab" + e, 2) == "ab");
    REQUIRE(TruncateUtf8("abc", 10) == "abc");
    REQUIRE(NormalizeNoteBody(std::string("a\r\nb\rc\n\0d", 9)) == "a\nb\nc\nd");
    REQUIRE(NormalizeNoteTitle("a\tb\x01" "c") == "a b c");
    REQUIRE(Utf8Length(NormalizeNoteTitle(std::string(300, 'x'))) == NOTE_TITLE_MAX_CHARS);
    REQUIRE(IsValidNoteScope({}));
    REQUIRE(IsValidNoteScope({ NoteScopeKind::Week, "Week 1" }));
    REQUIRE_FALSE(IsValidNoteScope({ NoteScopeKind::Week, "" }));
    REQUIRE_FALSE(IsValidNoteScope({ NoteScopeKind::Week, "a\nb" }));
    REQUIRE(IsValidNoteScope(STACK_SCOPE));
    REQUIRE_FALSE(IsValidNoteScope({ NoteScopeKind::Resource, "../x" }));
    REQUIRE_FALSE(IsValidNoteScope({ NoteScopeKind::General, "x" }));
    REQUIRE(IsValidNoteId("0f6a0e5c-1111-4222-8333-444455556666"));
    REQUIRE_FALSE(IsValidNoteId(""));
    REQUIRE_FALSE(IsValidNoteId("a b"));
    REQUIRE_FALSE(IsValidNoteId(std::string(65, 'a')));
}

TEST_CASE("Learning: note request bodies (JSON round trips)", "[learning][notes]")
{
    SaveNoteRequest create;
    create.id    = "0f6a0e5c-1111-4222-8333-444455556666";
    create.title = "if / else \"quoted\"";
    create.body  = "cmp eax, ecx\n\tjle 0x401050 ; \xC3\xA9\\";
    auto body    = BuildSaveNoteBody(create);
    auto j       = json::parse(std::string(body.data(), body.size()));
    REQUIRE(j.size() == 4);
    REQUIRE_FALSE(j.contains("revision")); // omitted => create
    REQUIRE(j["id"] == create.id);
    REQUIRE(j["title"] == create.title);
    REQUIRE(j["body"] == create.body);
    REQUIRE(j["scope"] == json{ { "kind", "general" } });

    SaveNoteRequest update = create;
    update.scope           = STACK_SCOPE;
    update.revision        = 3;
    body                   = BuildSaveNoteBody(update);
    j                      = json::parse(std::string(body.data(), body.size()));
    REQUIRE(j["revision"] == 3);
    REQUIRE(j["scope"] == json{ { "kind", "problem" }, { "name", "w1_stack_var" } });
    update.scope = { NoteScopeKind::Week, "Week 1" };
    body         = BuildSaveNoteBody(update);
    REQUIRE(json::parse(std::string(body.data(), body.size()))["scope"] == json{ { "kind", "week" }, { "name", "Week 1" } });

    body = BuildDeleteNoteBody(create.id);
    REQUIRE(json::parse(std::string(body.data(), body.size())) == json{ { "id", create.id } });
    body = BuildDeleteTeacherNoteBody(12);
    REQUIRE(json::parse(std::string(body.data(), body.size())) == json{ { "id", 12 } });

    // teacher notes: omitted fields are not sent (the server keeps them on an update)
    SaveTeacherNoteRequest tc;
    tc.title = "T";
    tc.body  = "B";
    body     = BuildSaveTeacherNoteBody(tc);
    j        = json::parse(std::string(body.data(), body.size()));
    REQUIRE(j == json{ { "title", "T" }, { "body", "B" } });
    tc.id       = 12;
    tc.revision = 4;
    tc.scope    = NoteScope{};
    tc.audience = NoteAudience::G2;
    tc.enabled  = false;
    tc.order    = -2;
    body        = BuildSaveTeacherNoteBody(tc);
    j           = json::parse(std::string(body.data(), body.size()));
    REQUIRE(j["id"] == 12);
    REQUIRE(j["revision"] == 4);
    REQUIRE(j["scope"] == json{ { "kind", "general" } }); // detach
    REQUIRE(j["audience"] == "G2");
    REQUIRE(j["enabled"] == false);
    REQUIRE(j["order"] == -2);

    // answers
    SaveNoteResult r;
    REQUIRE(ParseSaveNoteResponse(BufferView(std::string_view(R"({"status":"ok","id":"abc-1","revision":2,"updatedAt":1760000000,"created":false})")), false, r).ok);
    REQUIRE(r.id == "abc-1");
    REQUIRE(r.revision == 2);
    REQUIRE_FALSE(r.created);
    REQUIRE(ParseSaveNoteResponse(BufferView(std::string_view(R"({"status":"ok","id":12,"revision":1,"updatedAt":1,"created":true})")), true, r).ok);
    REQUIRE(r.teacherId == 12);
    REQUIRE(r.created);
    REQUIRE_FALSE(ParseSaveNoteResponse(BufferView(std::string_view(R"({"status":"ok","id":"abc","revision":0})")), false, r).ok);
    REQUIRE_FALSE(ParseSaveNoteResponse(BufferView(std::string_view(R"({"status":"ok","id":"a b","revision":1})")), false, r).ok);
    REQUIRE_FALSE(ParseSaveNoteResponse(BufferView(std::string_view(R"({"status":"ok","id":"12","revision":1})")), true, r).ok);
    REQUIRE_FALSE(ParseSaveNoteResponse(BufferView(std::string_view("<html>")), false, r).ok);
}

TEST_CASE("Learning: GetNotes parsing (student, staff, hostile)", "[learning][notes]")
{
    // the example of spec §10.11 + entries the client must drop or sanitise
    const std::string body = std::string(R"JSON({"status": "ok", "maxChars": 50, "serverTime": 1760000000, "canEditTeacherNotes": false,
      "mine": [
        {"id": "0f6a0e5c-1111-4222-8333-444455556666", "title": "if / else", "body": "cmp; jcc \u2026\r\nline2\u0007", "scope": {"kind": "problem", "name": "w1_stack_var"},
         "revision": 3, "createdAt": 1759990000, "updatedAt": 1759999000},
        {"id": "0f6a0e5c-1111-4222-8333-444455556666", "title": "duplicate", "revision": 1},
        {"id": "no revision", "title": "x"},
        {"id": "n2", "title": "t\u0001", "body": "b", "revision": 1},
        {"id": "n3", "title": "unknown scope", "body": "", "scope": {"kind": "video", "name": "x"}, "revision": 1},
        {"id": "n4", "title": "bad item", "body": "", "scope": {"kind": "problem", "name": "../etc"}, "revision": 1},
        {"id": "n5", "title": "week", "body": "", "scope": {"kind": "week", "name": "Week 1"}, "revision": 2},
        {"id": "n6", "title": "nul\u0000", "body": "", "revision": 1},
        "not an object"
      ],
      "teacher": [
        {"id": 12, "title": "Conditional jumps", "body": "...", "scope": {"kind": "general"}, "audience": "all", "updatedAt": 1759900000},
        {"id": 13, "title": "G2", "body": "", "audience": "G2", "updatedAt": 1},
        {"id": "14", "title": "string id"},
        {"id": 0, "title": "zero id"}
      ]})JSON");
    NotesSnapshot s;
    auto st = ParseNotesResponse(BufferView(body), s);
    INFO(st.message);
    REQUIRE(st.ok);
    REQUIRE(s.maxChars == 100); // clamped
    REQUIRE_FALSE(s.canEditTeacherNotes);
    REQUIRE(s.mine.size() == 6);
    REQUIRE(s.rejected == 3 /*mine: duplicate, invalid id, non-object*/ + 2 /*teacher*/);
    REQUIRE(s.mine[0].revision == 3);
    REQUIRE(s.mine[0].scope == STACK_SCOPE);
    REQUIRE(s.mine[0].body == "cmp; jcc \xE2\x80\xA6\nline2 "); // CR dropped, BEL => space, UTF-8 kept
    REQUIRE(s.mine[1].title == "t ");
    REQUIRE(s.mine[1].scope.IsGeneral()); // missing scope = general
    REQUIRE(s.mine[2].scope.IsGeneral()); // unknown kind
    REQUIRE(s.mine[3].scope.IsGeneral()); // invalid item name
    REQUIRE(s.mine[4].scope == NoteScope{ NoteScopeKind::Week, "Week 1" });
    REQUIRE(s.mine[5].title == "nul "); // NUL => space
    REQUIRE(s.teacher.size() == 2);
    REQUIRE(s.teacher[0].id == 12);
    REQUIRE(s.teacher[0].enabled); // student view: no extra fields => defaults
    REQUIRE(s.teacher[1].audience == NoteAudience::G2);

    const std::string staff = R"JSON({"status":"ok","maxChars":20000,"canEditTeacherNotes":true,"mine":[],
      "teacher":[{"id":3,"title":"Draft","body":"","scope":{"kind":"week","name":"Week 2"},"audience":"G1","updatedAt":5,
                  "enabled":false,"order":7,"revision":4,"createdAt":2}]})JSON";
    REQUIRE(ParseNotesResponse(BufferView(staff), s).ok);
    REQUIRE(s.canEditTeacherNotes);
    REQUIRE(s.maxChars == 20000);
    REQUIRE(s.teacher.size() == 1);
    REQUIRE_FALSE(s.teacher[0].enabled);
    REQUIRE(s.teacher[0].order == 7);
    REQUIRE(s.teacher[0].revision == 4);
    REQUIRE(s.teacher[0].createdAt == 2);
    REQUIRE(s.teacher[0].audience == NoteAudience::G1);

    REQUIRE_FALSE(ParseNotesResponse(BufferView(std::string_view(R"({"status":"error"})")), s).ok);
    REQUIRE_FALSE(ParseNotesResponse(BufferView(std::string_view(R"({"status":"ok","mine":{}})")), s).ok);
    REQUIRE_FALSE(ParseNotesResponse(BufferView(std::string_view("[]")), s).ok);
    // invalid UTF-8 is not JSON: the whole answer is refused (a GetNotes retry follows)
    REQUIRE_FALSE(ParseNotesResponse(BufferView(std::string_view("{\"status\":\"ok\",\"mine\":[{\"id\":\"a\",\"title\":\"\xFF\",\"revision\":1}]}")), s).ok);
}

TEST_CASE("Learning: note error mapping (CONFLICT from the status)", "[learning][notes]")
{
    auto err = NoteErrorFromResponse(Response(409, R"({"status":"error","code":"CONFLICT","details":"changed","retryable":false})"));
    REQUIRE(err.code == ErrorCode::Conflict);
    REQUIRE_FALSE(err.retryable);
    REQUIRE(ErrorCodeName(err.code) == "CONFLICT");
    REQUIRE(NoteErrorFromResponse(Response(409, "")).code == ErrorCode::Conflict); // mapped from the status
    REQUIRE(NoteErrorFromResponse(Response(413, "")).code == ErrorCode::PayloadTooLarge);
    REQUIRE(ParseErrorEnvelope(413, BufferView(), {}).code == ErrorCode::PayloadTooLarge);
    REQUIRE(ParseErrorEnvelope(409, BufferView(), {}).code == ErrorCode::AlreadySolved); // SubmitFlag keeps its meaning
    auto limited = NoteErrorFromResponse(Response(429, "", { { "retry-after", "7" } }));
    REQUIRE(limited.retryAfterSeconds == 7);

    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(TransportFailure())) == NoteFailure::Retry);
    REQUIRE(ClassifyNoteError(limited) == NoteFailure::Retry);
    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(Response(503, ""))) == NoteFailure::Retry);
    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(Response(408, ""))) == NoteFailure::Retry);
    REQUIRE(ClassifyNoteError(err) == NoteFailure::Conflict);
    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(Response(404, ""))) == NoteFailure::NotFound);
    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(ErrorResponse(403, "FORBIDDEN"))) == NoteFailure::Disabled);
    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(ErrorResponse(403, "POLICY_EXPIRED"))) == NoteFailure::Expired);
    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(ErrorResponse(400, "BAD_REQUEST"))) == NoteFailure::Refused);
    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(Response(413, ""))) == NoteFailure::Refused);
    REQUIRE(ClassifyNoteError(NoteErrorFromResponse(ErrorResponse(401, "UNAUTHORIZED"))) == NoteFailure::Refused);
}

TEST_CASE("Learning: notes availability follows the policy", "[learning][notes][session]")
{
    SECTION("absent: no Notes UI, GetNotes never called")
    {
        NotesFixture fx(json(nullptr));
        REQUIRE(fx.Connect().ok);
        REQUIRE(fx.session->GetNotesAvailability() == NotesAvailability::Absent);
        REQUIRE(fx.transport->Count("/GView/GetNotes") == 0);
        REQUIRE_FALSE(fx.session->RefreshNotes().ok);
    }
    SECTION("enabled=false at connect: disabled, GetNotes never called")
    {
        NotesFixture fx(NotesObject(false));
        REQUIRE(fx.Connect().ok);
        REQUIRE(fx.session->GetNotesAvailability() == NotesAvailability::DisabledByPolicy);
        REQUIRE(fx.session->GetStatus().notes == NotesAvailability::DisabledByPolicy);
        REQUIRE(fx.transport->Count("/GView/GetNotes") == 0);
        REQUIRE_FALSE(fx.session->RefreshNotes().ok);
        fx.Notes().Create("t", "local text", {}, fx.mono);
        fx.Advance(5000);
        fx.session->PumpNotes(true);
        REQUIRE(fx.transport->Count("/GView/SaveNote") == 0);
    }
    SECTION("enabled: GetNotes after connect")
    {
        NotesFixture fx;
        REQUIRE(fx.Connect().ok);
        REQUIRE(fx.session->CanUseNotes());
        REQUIRE(fx.transport->Count("/GView/GetNotes") == 1);
        REQUIRE(fx.session->NotesLoaded());
        REQUIRE(fx.session->TeacherNotes().size() == 2);
        REQUIRE_FALSE(fx.session->CanEditTeacherNotes());
        REQUIRE(fx.Notes().MaxChars() == 1000);
        REQUIRE(fx.session->GetStatus().notesMaxChars == 1000);
    }
}

TEST_CASE("Learning: notes autosave (debounce, create, update with revisions)", "[learning][notes][session]")
{
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s       = *fx.session;
    const auto id = fx.Notes().Create("", "", STACK_SCOPE, fx.mono);
    REQUIRE(IsUuid4(id));
    fx.Advance(5000);
    s.PumpNotes(false);
    REQUIRE(fx.transport->Count("/GView/SaveNote") == 0); // a new note nobody typed into is not created yet

    REQUIRE(fx.Notes().Edit(id, "if / else", "cmp", STACK_SCOPE, fx.mono));
    fx.Advance(1000);
    s.PumpNotes(false);
    REQUIRE(fx.transport->Count("/GView/SaveNote") == 0); // debounce: ~2 s after the last keystroke
    fx.Advance(1100);
    s.PumpNotes(false);
    REQUIRE(fx.transport->Count("/GView/SaveNote") == 1);
    auto j = json::parse(fx.server.saveBodies.back());
    REQUIRE_FALSE(j.contains("revision")); // create
    REQUIRE(j["id"] == id);
    REQUIRE(j["scope"]["name"] == "w1_stack_var");
    REQUIRE(fx.Notes().Find(id)->revision == 1);
    REQUIRE(fx.Notes().StateOf(*fx.Notes().Find(id)) == NoteSyncState::Saved);

    // typing: never one save per keystroke
    for (int i = 0; i < 10; i++)
    {
        fx.Notes().Edit(id, "if / else", "cmp" + std::string(i + 1, ';'), STACK_SCOPE, fx.mono);
        fx.Advance(150);
        s.PumpNotes(false);
    }
    REQUIRE(fx.transport->Count("/GView/SaveNote") == 1);
    REQUIRE(fx.Notes().StateOf(*fx.Notes().Find(id)) == NoteSyncState::Unsaved);
    fx.Advance(2000);
    s.PumpNotes(false);
    REQUIRE(fx.transport->Count("/GView/SaveNote") == 2);
    j = json::parse(fx.server.saveBodies.back());
    REQUIRE(j["revision"] == 1); // the last revision the server returned
    REQUIRE(j["body"] == "cmp;;;;;;;;;;");
    REQUIRE(fx.Notes().Find(id)->revision == 2);

    // Tick drives the autosave as well (Notes window closed)
    fx.Notes().Edit(id, "if / else", "final", STACK_SCOPE, fx.mono);
    fx.Advance(2500);
    s.Tick();
    REQUIRE(fx.transport->Count("/GView/SaveNote") == 3);
    REQUIRE(fx.server.notes[id].body == "final");
    REQUIRE(fx.server.notes[id].revision == 3);
    REQUIRE_FALSE(fx.Notes().HasUnsavedChanges());
    REQUIRE_FALSE(s.GetStatus().busy); // autosave does not mark the session busy

    // flush (editor closed): no debounce; CR LF normalised, NUL removed before sending
    fx.Notes().Edit(id, "if / else", std::string("a\r\nb\0c", 6), STACK_SCOPE, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes[id].body == "a\nbc");
}

TEST_CASE("Learning: notes network errors retry the same request", "[learning][notes][session]")
{
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s       = *fx.session;
    const auto id = fx.Notes().Create("t", "v1", {}, fx.mono);

    SECTION("lost answer of a create")
    {
        fx.server.loseNextAnswer = 1;
        s.PumpNotes(true);
        REQUIRE(fx.server.notes.count(id) == 1); // applied on the server
        REQUIRE(fx.Notes().StateOf(*fx.Notes().Find(id)) == NoteSyncState::Retrying);
        REQUIRE_FALSE(fx.Notes().Find(id)->revision.has_value());
        fx.Notes().Edit(id, "t", "v2", {}, fx.mono); // typed while the answer was missing
        fx.Advance(1000);
        s.PumpNotes(false);
        REQUIRE(fx.server.saveBodies.size() == 1); // back-off
        fx.Advance(1500);
        s.PumpNotes(false);
        // the very same create first (answered 200 created:false), then the newer text as an update
        REQUIRE(fx.server.saveBodies.size() >= 2);
        REQUIRE(fx.server.saveBodies[1] == fx.server.saveBodies[0]);
        fx.Advance(2500);
        s.PumpNotes(false);
        REQUIRE(fx.server.saveBodies.size() == 3);
        auto j = json::parse(fx.server.saveBodies[2]);
        REQUIRE(j["revision"] == 1);
        REQUIRE(j["body"] == "v2");
        REQUIRE(fx.server.notes[id].body == "v2");
        REQUIRE(fx.server.notes[id].revision == 2);
        REQUIRE(fx.Notes().Find(id)->revision == 2);
    }
    SECTION("lost answer of an update")
    {
        s.PumpNotes(true);
        REQUIRE(fx.Notes().Find(id)->revision == 1);
        fx.Notes().Edit(id, "t", "v2", {}, fx.mono);
        fx.server.loseNextAnswer = 1;
        s.PumpNotes(true);
        REQUIRE(fx.server.notes[id].revision == 2); // applied, answer lost
        REQUIRE(fx.Notes().Find(id)->revision == 1);
        fx.Advance(3000);
        s.PumpNotes(false); // the same update retried => 200 with the already-applied revision (no 409)
        REQUIRE(fx.server.saveBodies.back() == fx.server.saveBodies[fx.server.saveBodies.size() - 2]);
        REQUIRE(fx.Notes().Find(id)->revision == 2);
        REQUIRE(fx.Notes().TakeNotices().empty());
    }
    SECTION("transport failure before the server")
    {
        fx.server.failNext = 3;
        for (int i = 0; i < 3; i++)
        {
            fx.Advance(NOTES_RETRY_MAX_MS);
            s.PumpNotes(false);
        }
        REQUIRE(fx.server.notes.empty());
        REQUIRE(fx.Notes().Find(id)->body == "v1"); // nothing lost
        fx.Advance(NOTES_RETRY_MAX_MS);
        s.PumpNotes(false);
        REQUIRE(fx.server.notes[id].body == "v1");
        REQUIRE(fx.server.saveBodies.size() == 1);
    }
    SECTION("429 Retry-After")
    {
        fx.transport->routes["/GView/SaveNote"] = [](const HttpRequest&) {
            HttpResponse r = ErrorResponse(429, "RATE_LIMITED");
            r.headers.push_back({ "retry-after", "30" });
            return r;
        };
        s.PumpNotes(true);
        fx.server.Install(*fx.transport);
        fx.Advance(20000);
        s.PumpNotes(false);
        REQUIRE(fx.server.notes.empty()); // still waiting for Retry-After
        fx.Advance(11000);
        s.PumpNotes(false);
        REQUIRE(fx.server.notes.count(id) == 1);
    }
}

TEST_CASE("Learning: notes 409 keeps the server copy and the local text", "[learning][notes][session]")
{
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s       = *fx.session;
    const auto id = fx.Notes().Create("loops", "v1", STACK_SCOPE, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.Notes().Find(id)->revision == 1);

    // another GView instance of the same student saved revision 2 in the meantime
    fx.server.notes[id] = FakeNotesServer::Note{ "loops", "edited elsewhere", json{ { "kind", "problem" }, { "name", "w1_stack_var" } }.dump(), 2, "" };
    fx.Notes().Edit(id, "loops", "typed here", STACK_SCOPE, fx.mono);
    const size_t fetchesBefore = fx.transport->Count("/GView/GetNotes");
    s.PumpNotes(true);
    REQUIRE(fx.transport->Count("/GView/GetNotes") == fetchesBefore + 1); // re-fetched after the 409
    // the server copy is kept, never overwritten silently
    REQUIRE(fx.server.notes[id].body == "edited elsewhere");
    REQUIRE(fx.Notes().Find(id)->body == "edited elsewhere");
    REQUIRE(fx.Notes().Find(id)->revision == 2);
    // the local text survives as a new note
    const LocalNote* copy = nullptr;
    for (const auto& n : fx.Notes().Notes())
        if (n.id != id)
            copy = &n;
    REQUIRE(copy != nullptr);
    REQUIRE(copy->title == "loops (local copy)");
    REQUIRE(copy->body == "typed here");
    REQUIRE(copy->scope == STACK_SCOPE);
    const std::string copyId = copy->id;
    auto notices             = s.TakeNotesNotices();
    REQUIRE(notices.size() == 1);
    REQUIRE(notices[0].find("local copy") != std::string::npos);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes[copyId].body == "typed here"); // created on the server
    REQUIRE_FALSE(fx.Notes().HasUnsavedChanges());

    // identical text on both sides: no copy
    fx.server.notes[id].revision = 5;
    fx.Notes().Edit(id, "loops", "edited elsewhere ", STACK_SCOPE, fx.mono);
    fx.server.notes[id].body = "edited elsewhere ";
    s.PumpNotes(true);
    REQUIRE(fx.Notes().Notes().size() == 2);
    REQUIRE(fx.Notes().Find(id)->revision == 5);
}

TEST_CASE("Learning: notes 403 hides the Notes UI", "[learning][notes][session]")
{
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s       = *fx.session;
    const auto id = fx.Notes().Create("t", "kept in memory", {}, fx.mono);
    fx.server.forbidden = true; // the teacher turned notes off (exam)
    s.PumpNotes(true);
    REQUIRE(s.GetNotesAvailability() == NotesAvailability::DisabledByServer);
    REQUIRE_FALSE(s.CanUseNotes());
    auto notices = s.TakeNotesNotices();
    REQUIRE(std::find(notices.begin(), notices.end(), "Course notes are disabled by your teacher.") != notices.end());
    REQUIRE(fx.Notes().Find(id)->body == "kept in memory");
    const size_t saves = fx.transport->Count("/GView/SaveNote");
    fx.Advance(NOTES_RETRY_MAX_MS * 2);
    s.PumpNotes(true);
    s.Tick();
    REQUIRE(fx.transport->Count("/GView/SaveNote") == saves); // nothing is sent while notes are off
    REQUIRE_FALSE(s.RefreshNotes().ok);

    // a 403 on GetNotes does the same
    NotesFixture fx2;
    fx2.server.forbidden = true;
    REQUIRE(fx2.Connect().ok);
    REQUIRE(fx2.session->GetNotesAvailability() == NotesAvailability::DisabledByServer);

    // the next connect tries again; the unsaved text is saved once notes are back
    fx.server.forbidden = false;
    REQUIRE(fx.Connect().ok);
    REQUIRE(s.CanUseNotes());
    s.PumpNotes(true);
    REQUIRE(fx.server.notes[id].body == "kept in memory");
}

TEST_CASE("Learning: notes 404, refusals and deletion", "[learning][notes][session]")
{
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s = *fx.session;

    // too long: never sent, kept, shown
    const auto longId = fx.Notes().Create("long", std::string(1001, 'x'), {}, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes.count(longId) == 0);
    REQUIRE(fx.Notes().StateOf(*fx.Notes().Find(longId)) == NoteSyncState::Error);
    fx.Notes().Edit(longId, "long", std::string(1000, 'x'), {}, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes.count(longId) == 1);

    // 400: shown, no retry until the next edit
    fx.transport->routes["/GView/SaveNote"] = [](const HttpRequest&) { return ErrorResponse(400, "BAD_REQUEST", "at most 500 notes per student"); };
    const auto refused = fx.Notes().Create("t", "b", {}, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.Notes().StateOf(*fx.Notes().Find(refused)) == NoteSyncState::Error);
    REQUIRE(fx.Notes().Find(refused)->error.find("500 notes") != std::string::npos);
    const size_t attempts = fx.transport->Count("/GView/SaveNote");
    fx.Advance(NOTES_RETRY_MAX_MS * 3);
    s.PumpNotes(false);
    REQUIRE(fx.transport->Count("/GView/SaveNote") == attempts);
    fx.server.Install(*fx.transport);
    fx.Notes().Edit(refused, "t", "b2", {}, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes.count(refused) == 1);

    // 404 on an update (deleted on another machine): the re-fetch shows it is gone => the next save creates it again
    const std::string gone = longId;
    fx.server.notes.erase(gone);
    fx.Notes().Edit(gone, "long", "changed", {}, fx.mono);
    s.PumpNotes(true);
    REQUIRE_FALSE(fx.Notes().Find(gone)->revision.has_value());
    REQUIRE(fx.Notes().StateOf(*fx.Notes().Find(gone)) == NoteSyncState::Unsaved);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes[gone].body == "changed");
    REQUIRE(json::parse(fx.server.saveBodies.back()).contains("revision") == false);

    // 404 because the scope is not visible (the note exists): shown, waits for an edit (no loop)
    fx.transport->routes["/GView/SaveNote"] = [](const HttpRequest&) { return ErrorResponse(404, "NOT_FOUND", "no such item"); };
    fx.Notes().Edit(gone, "long", "changed again", STACK_SCOPE, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.Notes().StateOf(*fx.Notes().Find(gone)) == NoteSyncState::Error);
    const size_t refused404 = fx.transport->Count("/GView/SaveNote");
    fx.Advance(NOTES_RETRY_MAX_MS * 3);
    s.PumpNotes(false);
    REQUIRE(fx.transport->Count("/GView/SaveNote") == refused404);
    fx.server.Install(*fx.transport);
    fx.Notes().Edit(gone, "long", "changed again", {}, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes[gone].body == "changed again");

    // delete: a note that never reached the server sends nothing
    const auto local = fx.Notes().Create("", "", {}, fx.mono);
    fx.Notes().Delete(local);
    REQUIRE(fx.Notes().Find(local) == nullptr);
    s.PumpNotes(true);
    REQUIRE(fx.server.deleteIds.empty());
    // a saved note is deleted on the server; 404 (already gone) is fine
    fx.Notes().Delete(refused);
    s.PumpNotes(true);
    REQUIRE(fx.server.deleteIds.back() == refused);
    REQUIRE(fx.server.notes.count(refused) == 0);
    REQUIRE(fx.Notes().Find(refused) == nullptr);
    fx.server.notes.erase(gone);
    fx.Notes().Delete(gone);
    s.PumpNotes(true);
    REQUIRE(fx.Notes().Find(gone) == nullptr);
    REQUIRE(fx.Notes().TakeNotices().empty());
}

TEST_CASE("Learning: notes are saved at session end, then wiped", "[learning][notes][session]")
{
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s       = *fx.session;
    const auto id = fx.Notes().Create("t", "typed just before ending", {}, fx.mono);
    REQUIRE(fx.transport->Count("/GView/SaveNote") == 0); // debounce not elapsed
    REQUIRE(s.EndSession("user").ok);
    REQUIRE(fx.server.notes[id].body == "typed just before ending");
    REQUIRE(s.Notes().Notes().empty());
    REQUIRE(s.TeacherNotes().empty());
    REQUIRE(s.GetNotesAvailability() == NotesAvailability::Absent);
}

TEST_CASE("Learning: notes conflicts left unresolved, deletions and GetNotes failures", "[learning][notes][session]")
{
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s       = *fx.session;
    const auto a  = fx.Notes().Create("a", "a1", {}, fx.mono);
    const auto b  = fx.Notes().Create("b", "b1", {}, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes.size() == 2);
    // the re-fetch after a 409 fails: the conflicts stay pending
    fx.transport->routes["/GView/GetNotes"] = [](const HttpRequest&) { return ErrorResponse(503, "SERVER_ERROR"); };
    fx.server.notes[a].revision = 9;
    fx.server.notes[b].revision = 9;
    fx.Notes().Edit(a, "a", "a typed here", {}, fx.mono);
    fx.Notes().Edit(b, "b", "b typed here", {}, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.Notes().Find(a)->conflictPending);

    SECTION("a deleted note is not brought back by its conflict")
    {
        fx.Notes().Delete(a);
        fx.server.Install(*fx.transport);
        fx.Advance(NOTES_RETRY_MAX_MS);
        s.PumpNotes(true);
        REQUIRE(fx.server.notes.count(a) == 0);
        REQUIRE(fx.Notes().Find(a) == nullptr);
        for (const auto& n : fx.Notes().Notes())
            REQUIRE(n.title != "a (local copy)");
    }
    SECTION("session end: the local text of an unresolved conflict is saved as a copy")
    {
        REQUIRE(s.EndSession("user").ok);
        bool aCopy = false, bCopy = false;
        for (const auto& [id, n] : fx.server.notes)
        {
            aCopy |= n.title == "a (local copy)" && n.body == "a typed here";
            bCopy |= n.title == "b (local copy)" && n.body == "b typed here";
        }
        REQUIRE(aCopy);
        REQUIRE(bCopy);
        REQUIRE(fx.server.notes[a].body == "a1"); // the server copy is untouched
    }
    SECTION("a GetNotes failure that is not retryable stops the re-fetching")
    {
        fx.transport->routes["/GView/GetNotes"] = [](const HttpRequest&) { return ErrorResponse(401, "UNAUTHORIZED"); };
        fx.Advance(NOTES_RETRY_MAX_MS);
        s.PumpNotes(false); // the retry after the 503 gets a 401
        const size_t fetches = fx.transport->Count("/GView/GetNotes");
        for (int i = 0; i < 20; i++)
        {
            fx.Advance(300);
            s.PumpNotes(false);
        }
        REQUIRE(fx.transport->Count("/GView/GetNotes") == fetches);
        REQUIRE_FALSE(s.NotesError().empty());
    }
}

TEST_CASE("Learning: notes of another account are dropped at connect", "[learning][notes][session]")
{
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    fx.server.failNext = 100; // nothing can be saved for the first account
    fx.Notes().Create("t", "first account", {}, fx.mono);
    fx.session->PumpNotes(true);
    REQUIRE(fx.Notes().HasUnsavedChanges());

    const std::string other = "tok_OTHERSTUDENT_ABCDEFGHIJKLMNOPQRSTUVWXYZ012";
    PolicyOptions o;
    o.notes   = NotesObject();
    o.subject = SubjectForToken(SecureString(other.data(), other.size()));
    fx.ServePolicy(BuildPolicy(o));
    const size_t savesBefore     = fx.transport->Count("/GView/SaveNote");
    GView::Utils::GStatus result = GView::Utils::GStatus::Error("not called");
    REQUIRE(fx.session->Connect(BuildConnectionString(other, TEST_SERVER, ServerKey().PublicHex(), ""), LearningSettings{}, [&](const GView::Utils::GStatus& r) {
                    result = r;
                }).ok);
    REQUIRE(result.ok);
    // one last bounded attempt went to the first account's transport (still failing here), then the text was wiped
    REQUIRE(fx.transport->Count("/GView/SaveNote") > savesBefore);
    fx.server.failNext = 0;
    fx.session->PumpNotes(true);
    REQUIRE(fx.Notes().Notes().empty());
    REQUIRE(fx.server.notes.empty()); // the first account's text never reaches the second account
}

TEST_CASE("Learning: course notes of the teacher (staff editor payloads)", "[learning][notes][session]")
{
    SECTION("student token")
    {
        NotesFixture fx;
        REQUIRE(fx.Connect().ok);
        REQUIRE_FALSE(fx.session->CanEditTeacherNotes());
        SaveTeacherNoteRequest req;
        req.title = "x";
        REQUIRE_FALSE(fx.session->SaveTeacherNote(req, nullptr).ok); // refused locally, nothing sent
        REQUIRE_FALSE(fx.session->DeleteTeacherNote(12, nullptr).ok);
        REQUIRE(fx.transport->Count("/GView/SaveTeacherNote") == 0);
    }
    SECTION("course staff")
    {
        NotesFixture fx(NotesObject(), true);
        REQUIRE(fx.Connect().ok);
        auto& s = *fx.session;
        REQUIRE(s.CanEditTeacherNotes());
        REQUIRE(s.TeacherNotes()[0].revision == 3);
        REQUIRE(s.TeacherNotes()[0].order == 1);

        SaveTeacherNoteRequest create;
        create.title    = "New hint";
        create.body     = "a\r\nb";
        create.scope    = STACK_SCOPE;
        create.audience = NoteAudience::G2;
        NoteOpOutcome out;
        REQUIRE(s.SaveTeacherNote(create, [&](const NoteOpOutcome& o) { out = o; }).ok);
        REQUIRE(out.status.ok);
        REQUIRE(out.result.teacherId == 7);
        auto j = json::parse(fx.server.teacherBodies.back());
        REQUIRE_FALSE(j.contains("id"));
        REQUIRE_FALSE(j.contains("revision"));
        REQUIRE(j["body"] == "a\nb");
        REQUIRE(j["audience"] == "G2");
        REQUIRE(j["scope"] == json{ { "kind", "problem" }, { "name", "w1_stack_var" } });
        REQUIRE_FALSE(j.contains("enabled")); // not set => server default

        const size_t fetches = fx.transport->Count("/GView/GetNotes");
        SaveTeacherNoteRequest update;
        update.id       = 12;
        update.revision = 3;
        update.title    = "Conditional jumps (signed)";
        update.body     = "jl / jg";
        update.enabled  = false;
        update.order    = 4;
        REQUIRE(s.SaveTeacherNote(update, [&](const NoteOpOutcome& o) { out = o; }).ok);
        REQUIRE(out.status.ok);
        REQUIRE(out.result.revision == 4);
        j = json::parse(fx.server.teacherBodies.back());
        REQUIRE(j["id"] == 12);
        REQUIRE(j["revision"] == 3);
        REQUIRE(j["enabled"] == false);
        REQUIRE(j["order"] == 4);
        REQUIRE_FALSE(j.contains("scope")); // omitted => kept by the server
        REQUIRE(fx.transport->Count("/GView/GetNotes") == fetches + 1); // list reloaded

        update.revision = 3; // stale
        REQUIRE(s.SaveTeacherNote(update, [&](const NoteOpOutcome& o) { out = o; }).ok);
        REQUIRE_FALSE(out.status.ok);
        REQUIRE(out.error.code == ErrorCode::Conflict);

        SaveTeacherNoteRequest noRevision;
        noRevision.id = 12;
        REQUIRE(s.SaveTeacherNote(noRevision, [&](const NoteOpOutcome& o) { out = o; }).ok);
        REQUIRE_FALSE(out.status.ok); // an update needs its revision: refused before sending
        REQUIRE(out.error.code == ErrorCode::BadRequest);

        // 403 on a teacher endpoint: not staff (anymore) => the teacher editor goes away, student notes stay
        fx.server.staff = false;
        REQUIRE(s.SaveTeacherNote(create, [&](const NoteOpOutcome& o) { out = o; }).ok);
        REQUIRE_FALSE(out.status.ok);
        REQUIRE_FALSE(s.CanEditTeacherNotes());
        REQUIRE(s.CanUseNotes());
    }
}

TEST_CASE("Learning: note text never reaches telemetry or the disk", "[learning][notes][session]")
{
    const auto cwd  = std::filesystem::current_path();
    const auto temp = std::filesystem::temp_directory_path();
    const auto cwdBefore = ListDir(cwd), tempBefore = ListDir(temp);
    NotesFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s = *fx.session;
    int taskObject = 0;
    ItemBinding b;
    b.item    = "w1_stack_var";
    b.problem = true;
    s.SetPendingBinding(b);
    s.OnObjectCreated(&taskObject);
    const auto id = fx.Notes().Create("SECRET-TITLE", "SECRET-NOTE-BODY", STACK_SCOPE, fx.mono);
    s.RecordNoteAdd(&taskObject);
    s.PumpNotes(true);
    fx.Notes().Edit(id, "SECRET-TITLE", "SECRET-NOTE-BODY-2", STACK_SCOPE, fx.mono);
    s.PumpNotes(true);
    REQUIRE(fx.server.notes[id].body == "SECRET-NOTE-BODY-2");
    const auto batch = s.Telemetry().BeginBatch({});
    REQUIRE(batch.has_value());
    REQUIRE(batch->find("note_add") != std::string::npos);
    REQUIRE(batch->find("SECRET") == std::string::npos);
    REQUIRE(s.Telemetry().CountersJson().find("SECRET") == std::string::npos);
    s.Telemetry().OnFlushResult(FlushOutcome::Accepted);
    s.OnObjectClosed(&taskObject);
    // only the course server got the text
    for (auto& [path, body] : fx.transport->requests)
        if (body.find("SECRET") != std::string::npos)
            REQUIRE(path == "/GView/SaveNote");
    REQUIRE(ListDir(cwd) == cwdBefore);
    REQUIRE(ListDir(temp) == tempBefore);
}

// ======================================================================== published test vectors
// Produced by tools/learning_mode_stub_server.py (Python `cryptography`) and reproduced in
// docs/source/learning_mode_protocol.rst §"Test vectors": the server implementation must match them byte for byte.
TEST_CASE("Learning: cross-implementation test vectors", "[learning][vectors]")
{
    const SecureString token("tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd");
    REQUIRE(SubjectForToken(token) == "f1988ba4bd709819");

    LockedBuffer key;
    REQUIRE(DeriveContentKey(token, "pol_2026w1_ab12cd", key).ok);
    REQUIRE(ToHex(key.View()) == "7e6629f6db625710f19a7c0bdac5dd6881699b65aa8a90659966bd24539c35fb");
    REQUIRE(ContentKeyId(key.View()) == "4ae23e4dafdc826d");
    const auto aad = BuildContentAad("w1_stack_var", "pol_2026w1_ab12cd");
    REQUIRE(ToHex(ToView(aad)) == "77315f737461636b5f76617200706f6c5f3230323677315f616231326364");

    const std::string v2 =
          "ZEc5clgwRkNRMFJGUmtkSVNVcExURTFPVDFCUlVsTlVWVlpYV0ZsYU1ERXlNelExTmpjNE9XRmlZMlE9I2FIUjBjSE02THk5eVpTNWxlR0Z0Y0d4bExtVmtkUT09I04y"
          "WmtPREEyWXpkbU1tRTVaVGc0WldNNE9XSmlObU5qWVRoaVlUWmhNbUkwWWpJeU5XRmhPRFZsTkRnNFpUZ3lNakppWlRsa1l6SmhZMkZrWmpBNU5BPT0=";
    REQUIRE(BuildConnectionString(
                  "tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
                  "https://re.example.edu",
                  "7fd806c7f2a9e88ec89bb6cca8ba6a2b4b225aa85e488e8222be9dc2acadf094",
                  "") == v2);
    ConnectionInfo ci;
    REQUIRE(ParseConnectionString(v2, false, ci).ok);

    const std::string policy =
          R"JSON({"allowedPlugins":[],"bestEffortScreenProtect":true,"digest":"5e6a9108d33760ebce5fc15585d40a7081d3eddaaa743eab771d0e535039eff8","disabledFeatures":["Copy","Export"],"endsAt":1760004800,"id":"pol_2026w1_ab12cd","issuedAt":1759400000,"purpose":"Evaluation week 1","requireScreenProtect":false,"schema":2,"serverUrl":"https://re.example.edu","startsAt":1759399880,"storageMode":"file","subject":"f1988ba4bd709819","submission":{"allowInTool":true,"explanationMaxChars":2000,"requireExplanation":false},"telemetry":{"enabled":true,"eventLevel":true,"flushIntervalSeconds":60,"idleThresholdSeconds":120,"maxBatchEvents":500},"watermark":"Student 17"})JSON";
    SecureBytes sig;
    REQUIRE(Base64Decode("LnnH52/44aGmbhfBVmmv7LwdQoUSTaNppaRMhuE4W4tBy0rKPLyUIbVAlUa2Jw/cuy3jjOSjIkWPkFzbPNdWBQ==", sig, 64));
    Policy p;
    auto st = RestrictedMode::VerifyAndParsePolicy(
          BufferView(policy), ToView(sig), BufferView(ci.publicKey.data(), ci.publicKey.size()), SubjectForToken(token), ci.serverUrl, 1759400000, p);
    INFO(st.message);
    REQUIRE(st.ok);
    REQUIRE(p.digest == "5e6a9108d33760ebce5fc15585d40a7081d3eddaaa743eab771d0e535039eff8");
}

// ======================================================================== end-to-end against tools/learning_mode_stub_server.py
// Hidden by default. Run:  python tools/learning_mode_stub_server.py --quiet --require-explanation
//                          set GVIEW_LEARNING_STUB_CS=<printed connection string>
//                          libGViewCore.exe "[integration]"
TEST_CASE("Learning: end-to-end against the stub server (TLS, curl, Python crypto interop)", "[.integration][learning]")
{
    const char* cs = std::getenv("GVIEW_LEARNING_STUB_CS");
    if (cs == nullptr || cs[0] == 0)
        SKIP("GVIEW_LEARNING_STUB_CS is not set");

    LearningSession::Dependencies d;
    d.synchronous     = true;
    d.telemetryThread = false;
    LearningSession s(std::move(d)); // real libcurl transport + real policy activation

    GView::Utils::GStatus result = GView::Utils::GStatus::Error("not called");
    REQUIRE(s.Connect(cs, LearningSettings{}, [&](const GView::Utils::GStatus& r) { result = r; }).ok);
    INFO(result.message);
    REQUIRE(result.ok);
    REQUIRE(s.GetState() == SessionState::Active);
    REQUIRE(RestrictedMode::IsActive());
    const Policy policy = *s.GetPolicy();
    REQUIRE(policy.storageMode == RestrictedMode::StorageMode::Memory);
    REQUIRE(policy.contentEncryption == "aes-256-gcm-hkdf-v1");

    // catalogue: visibility rule enforced server-side, parsed client-side
    REQUIRE(s.RefreshCatalogue([&](const GView::Utils::GStatus& r) { result = r; }).ok);
    REQUIRE(result.ok);
    const auto& cat = s.GetCatalogue();
    REQUIRE(cat.weeks.size() == 1);
    REQUIRE(cat.Find("w1_stack_var", true) != nullptr);
    REQUIRE(cat.Find("w1_hidden", true) == nullptr);
    REQUIRE(cat.Find("w2_problem", true) == nullptr);
    REQUIRE(cat.Find("w1_reading", false)->kind == ItemKind::ResourceLink);

    // memory-only delivery: HKDF + AES-256-GCM produced by Python `cryptography`, decrypted by OpenSSL
    for (const char* name : { "w1_stack_var", "w1_xor_key" })
    {
        DownloadResult dl;
        REQUIRE(s.Download(*cat.Find(name, true), [&](DownloadResult& r) { dl = std::move(r); }).ok);
        INFO(dl.status.message);
        REQUIRE(dl.status.ok);
        REQUIRE(dl.content.mode == DeliveryMode::Memory);
        REQUIRE(dl.content.wasEncrypted);
        REQUIRE(dl.content.data.Size() > 64);
        REQUIRE(dl.content.data.Data()[0] == 'M');
        REQUIRE(dl.content.data.Data()[1] == 'Z');
        REQUIRE(dl.content.sha256 == cat.Find(name, true)->sha256);
    }
    {
        DownloadResult dl;
        REQUIRE(s.Download(*cat.Find("w1_notes", false), [&](DownloadResult& r) { dl = std::move(r); }).ok);
        REQUIRE(dl.status.ok);
        REQUIRE(std::string(reinterpret_cast<const char*>(dl.content.data.Data()), 11) == "# Lab notes");
    }
    {
        CatalogueItem hidden; // disabled items answer 404 as if they did not exist
        hidden.name = "w1_hidden";
        hidden.kind = ItemKind::Problem;
        DownloadResult dl;
        REQUIRE(s.Download(hidden, [&](DownloadResult& r) { dl = std::move(r); }).ok);
        REQUIRE_FALSE(dl.status.ok);
        REQUIRE(dl.error.code == ErrorCode::NotFound);
    }

    // submissions: explanation required, wrong, correct, already solved
    SubmitOutcome out;
    auto cb = [&](const SubmitOutcome& o) { out = o; };
    REQUIRE(s.Submit("w1_stack_var", SecureString("4"), SecureString("guess"), cb).ok);
    REQUIRE(out.status.ok);
    REQUIRE_FALSE(out.result.correct);
    REQUIRE(out.result.attempts == 1);
    REQUIRE(s.Submit("w1_stack_var", SecureString("3"), SecureString("cmp eax,ecx; jle not taken"), cb).ok);
    REQUIRE(out.result.correct);
    REQUIRE(out.result.points == 100);
    REQUIRE(s.Submit("w1_stack_var", SecureString("3"), SecureString("again"), cb).ok);
    REQUIRE(out.result.alreadySolved);

    // T6: a transport retry with the same clientSubmissionId is answered with duplicate:true and no new attempt
    ConnectionInfo ci;
    REQUIRE(ParseConnectionString(cs, false, ci).ok);
    TransportConfig cfg{ ci.serverUrl, ci.token, ci.caPem, false, ClientVersion() };
    auto t = CreateCurlTransport(cfg);
    t->SetPolicyId(policy.id);
    SubmitRequest req;
    req.problem            = "w1_xor_key";
    req.flag               = SecureString("0x00");
    req.clientSubmissionId = *NewUuid4();
    req.policyId           = policy.id;
    req.clientVersion      = ClientVersion();
    const auto first       = LearningSession::PerformSubmit(*t, req);
    const auto replay      = LearningSession::PerformSubmit(*t, req);
    REQUIRE(first.status.ok);
    REQUIRE_FALSE(first.result.duplicate);
    REQUIRE(replay.status.ok);
    REQUIRE(replay.result.duplicate);
    REQUIRE(replay.result.attempts == first.result.attempts);

    // telemetry: accepted, and an identical resend is fully de-duplicated on (sessionId, seq)
    REQUIRE(s.Telemetry().PendingCount() > 0);
    BatchMeta meta{ s.GetSessionId(), policy.id, policy.digest, ClientVersion(), std::string(CurrentPlatform()), NowUnix() };
    auto body = s.Telemetry().BeginBatch(meta);
    REQUIRE(body.has_value());
    HttpRequest tr;
    tr.path = "/GView/Telemetry";
    tr.body.assign(body->data(), body->size());
    auto r1 = t->Post(tr);
    auto r2 = t->Post(tr);
    REQUIRE(r1.IsSuccess());
    const auto j1 = json::parse(std::string(r1.body.begin(), r1.body.end()));
    const auto j2 = json::parse(std::string(r2.body.begin(), r2.body.end()));
    REQUIRE(j1["accepted"].get<int>() > 0);
    REQUIRE(j2["accepted"] == 0);
    REQUIRE(j2["duplicates"] == j1["accepted"]);
    s.Telemetry().OnFlushResult(FlushOutcome::Accepted);

    // the token must never be accepted over a connection that is not verified: same server, no CA => TLS failure
    TransportConfig noCa{ ci.serverUrl, ci.token, "", false, ClientVersion() };
    auto untrusted = CreateCurlTransport(noCa);
    HttpRequest probe;
    probe.path = "/GView/Connect";
    auto pr    = untrusted->Post(probe);
    REQUIRE_FALSE(pr.transportOk);

    s.Shutdown();
    REQUIRE_FALSE(RestrictedMode::IsActive());
}

// Hostile server checks (hidden). Run the stub with --tamper-policy (port A) and --corrupt-blob (port B) and set
// GVIEW_LEARNING_STUB_TAMPER_CS / GVIEW_LEARNING_STUB_CORRUPT_CS.
TEST_CASE("Learning: end-to-end against a hostile stub server (T2/T5)", "[.integration-hostile][learning]")
{
    if (const char* cs = std::getenv("GVIEW_LEARNING_STUB_TAMPER_CS"); cs != nullptr && cs[0] != 0)
    {
        LearningSession::Dependencies d;
        d.synchronous     = true;
        d.telemetryThread = false;
        LearningSession s(std::move(d));
        GView::Utils::GStatus result = GView::Utils::GStatus::Ok();
        REQUIRE(s.Connect(cs, LearningSettings{}, [&](const GView::Utils::GStatus& r) { result = r; }).ok);
        REQUIRE_FALSE(result.ok);
        REQUIRE(result.message.starts_with("POLICY_SIGNATURE_INVALID"));
        REQUIRE(s.GetState() == SessionState::Error);
        REQUIRE_FALSE(RestrictedMode::IsActive());
        s.Shutdown();
    }
    if (const char* cs = std::getenv("GVIEW_LEARNING_STUB_CORRUPT_CS"); cs != nullptr && cs[0] != 0)
    {
        LearningSession::Dependencies d;
        d.synchronous     = true;
        d.telemetryThread = false;
        LearningSession s(std::move(d));
        GView::Utils::GStatus result = GView::Utils::GStatus::Error("x");
        REQUIRE(s.Connect(cs, LearningSettings{}, [&](const GView::Utils::GStatus& r) { result = r; }).ok);
        REQUIRE(result.ok);
        REQUIRE(s.RefreshCatalogue([&](const GView::Utils::GStatus& r) { result = r; }).ok);
        DownloadResult dl;
        REQUIRE(s.Download(*s.GetCatalogue().Find("w1_stack_var", true), [&](DownloadResult& r) { dl = std::move(r); }).ok);
        REQUIRE_FALSE(dl.status.ok);
        REQUIRE(dl.status.message.find("tampered") != std::string::npos);
        REQUIRE(dl.content.data.Empty());
        s.Shutdown();
    }
}

// Course notes against the stub server (hidden). The default stub (GVIEW_LEARNING_STUB_CS) has notes on; the other
// variants are optional:
//   GVIEW_LEARNING_STUB_STAFF_CS      stub started with --staff            (teacher editor)
//   GVIEW_LEARNING_STUB_FORBIDDEN_CS  stub started with --notes-forbidden  (403 after connect)
//   GVIEW_LEARNING_STUB_NOTES_OFF_CS  stub started with --notes off        (policy notes.enabled=false)
TEST_CASE("Learning: course notes end-to-end against the stub server", "[.integration][learning][notes]")
{
    auto connect = [](LearningSession& s, const char* cs) {
        GView::Utils::GStatus result = GView::Utils::GStatus::Error("not called");
        REQUIRE(s.Connect(cs, LearningSettings{}, [&](const GView::Utils::GStatus& r) { result = r; }).ok);
        INFO(result.message);
        REQUIRE(result.ok);
    };
    auto makeSession = []() {
        LearningSession::Dependencies d;
        d.synchronous     = true;
        d.telemetryThread = false;
        return std::make_unique<LearningSession>(std::move(d));
    };
    auto directTransport = [](const char* cs, const Policy& policy) {
        ConnectionInfo ci;
        REQUIRE(ParseConnectionString(cs, false, ci).ok);
        auto t = CreateCurlTransport(TransportConfig{ ci.serverUrl, ci.token, ci.caPem, false, ClientVersion() });
        t->SetPolicyId(policy.id);
        return t;
    };

    if (const char* cs = std::getenv("GVIEW_LEARNING_STUB_CS"); cs != nullptr && cs[0] != 0)
    {
        auto session = makeSession();
        auto& s      = *session;
        connect(s, cs);
        REQUIRE(s.GetPolicy()->notes.present);
        REQUIRE(s.CanUseNotes());
        REQUIRE(s.NotesLoaded()); // GetNotes right after Connect
        REQUIRE_FALSE(s.CanEditTeacherNotes());
        std::set<int64> teacherIds;
        for (const auto& t : s.TeacherNotes())
            teacherIds.insert(t.id);
        // hidden (3), another lab group (4) and an item that is not visible (6) are never sent to a student
        REQUIRE(teacherIds == std::set<int64>{ 1, 2, 5 });
        const auto policy = *s.GetPolicy();
        auto t            = directTransport(cs, policy);

        // create + update through the session (autosave flush), with the revisions of the server
        const auto id = s.Notes().Create("stack frame", "rbp-4 = first local", STACK_SCOPE, NowUnix() * 1000);
        s.PumpNotes(true);
        REQUIRE(s.Notes().Find(id)->revision == 1);
        s.Notes().Edit(id, "stack frame", "rbp-4 = first local\nrbp-8 = second", STACK_SCOPE, 0);
        s.PumpNotes(true);
        REQUIRE(s.Notes().Find(id)->revision == 2);

        // idempotency: a retried create with identical content, a retried update after a lost answer
        SaveNoteRequest create{ id, "stack frame", "rbp-4 = first local", STACK_SCOPE, std::nullopt };
        SaveNoteRequest update{ id, "stack frame", "rbp-4 = first local\nrbp-8 = second", STACK_SCOPE, 1 };
        auto o = LearningSession::PerformSaveNote(*t, update);
        INFO(o.status.message);
        REQUIRE(o.status.ok);
        REQUIRE(o.result.revision == 2);
        o = LearningSession::PerformSaveNote(*t, create);
        REQUIRE_FALSE(o.status.ok); // the content differs now: a create with this id conflicts
        REQUIRE(o.error.code == ErrorCode::Conflict);
        // compare-and-set: a stale revision with other content => 409, nothing written
        update.body = "stale";
        o           = LearningSession::PerformSaveNote(*t, update);
        REQUIRE(o.error.code == ErrorCode::Conflict);
        REQUIRE(ClassifyNoteError(o.error) == NoteFailure::Conflict);
        // students can attach notes only to visible items (a hidden one is 404, like a download)
        SaveNoteRequest hidden{ *NewUuid4(), "x", "y", { NoteScopeKind::Problem, "w1_hidden" }, std::nullopt };
        REQUIRE(LearningSession::PerformSaveNote(*t, hidden).error.code == ErrorCode::NotFound);
        // the server refuses NUL / too long bodies (the client strips NUL and checks maxChars before sending)
        SaveNoteRequest nul{ *NewUuid4(), "x", std::string("a\0b", 3), {}, std::nullopt };
        REQUIRE(LearningSession::PerformSaveNote(*t, nul).error.code == ErrorCode::BadRequest);

        // a conflict through the session: another device saved revision 3 in the meantime
        SaveNoteRequest elsewhere{ id, "stack frame", "edited on another machine", STACK_SCOPE, 2 };
        REQUIRE(LearningSession::PerformSaveNote(*t, elsewhere).status.ok);
        s.Notes().Edit(id, "stack frame", "typed in this GView", STACK_SCOPE, 0);
        s.PumpNotes(true);
        REQUIRE(s.Notes().Find(id)->body == "edited on another machine"); // server copy kept
        REQUIRE(s.Notes().Find(id)->revision == 3);
        auto notices = s.TakeNotesNotices();
        REQUIRE(notices.size() == 1);
        s.PumpNotes(true); // the local copy is created
        auto fetched = LearningSession::PerformGetNotes(*t);
        REQUIRE(fetched.status.ok);
        REQUIRE(fetched.snapshot.mine.size() == 2);
        std::string copyId;
        for (const auto& n : fetched.snapshot.mine)
        {
            if (n.id == id)
                REQUIRE(n.body == "edited on another machine");
            else
            {
                copyId = n.id;
                REQUIRE(n.title == "stack frame (local copy)");
                REQUIRE(n.body == "typed in this GView");
                REQUIRE(n.scope == STACK_SCOPE);
            }
        }

        // delete (unknown => 404), teacher endpoints refused for a student token
        s.Notes().Delete(copyId);
        s.PumpNotes(true);
        REQUIRE(LearningSession::PerformDeleteNote(*t, copyId).error.code == ErrorCode::NotFound);
        REQUIRE(LearningSession::PerformGetNotes(*t).snapshot.mine.size() == 1);
        SaveTeacherNoteRequest tn;
        tn.title = "x";
        REQUIRE(LearningSession::PerformSaveTeacherNote(*t, tn).error.code == ErrorCode::Forbidden);

        // privacy: the note text is in no telemetry batch
        auto batch = s.Telemetry().BeginBatch({ s.GetSessionId(), policy.id, policy.digest, ClientVersion(), std::string(CurrentPlatform()), NowUnix() });
        if (batch.has_value())
            REQUIRE(batch->find("rbp-4") == std::string::npos);
        s.Notes().Delete(id);
        s.PumpNotes(true);
        s.Shutdown();
        REQUIRE_FALSE(RestrictedMode::IsActive());
    }
    else
        WARN("GVIEW_LEARNING_STUB_CS is not set: student notes part skipped");

    if (const char* cs = std::getenv("GVIEW_LEARNING_STUB_STAFF_CS"); cs != nullptr && cs[0] != 0)
    {
        auto session = makeSession();
        auto& s      = *session;
        connect(s, cs);
        REQUIRE(s.CanEditTeacherNotes());
        REQUIRE(s.TeacherNotes().size() == 6); // every teacher note, hidden ones too, with the staff fields
        const auto draft = std::find_if(s.TeacherNotes().begin(), s.TeacherNotes().end(), [](const TeacherNote& t) { return t.id == 3; });
        REQUIRE(draft != s.TeacherNotes().end());
        REQUIRE_FALSE(draft->enabled);
        REQUIRE(draft->revision == 1);

        SaveTeacherNoteRequest create;
        create.title    = "Exam rules";
        create.body     = "No internet.";
        create.audience = NoteAudience::G1;
        NoteOpOutcome out;
        REQUIRE(s.SaveTeacherNote(create, [&](const NoteOpOutcome& o) { out = o; }).ok);
        INFO(out.status.message);
        REQUIRE(out.status.ok);
        REQUIRE(out.result.created);
        const int64 newId = out.result.teacherId;
        REQUIRE(s.TeacherNotes().size() == 7);

        SaveTeacherNoteRequest update;
        update.id       = newId;
        update.revision = 1;
        update.title    = "Exam rules";
        update.body     = "No internet. No phones.";
        update.enabled  = false;
        REQUIRE(s.SaveTeacherNote(update, [&](const NoteOpOutcome& o) { out = o; }).ok);
        REQUIRE(out.status.ok);
        REQUIRE(out.result.revision == 2);
        const auto saved = std::find_if(s.TeacherNotes().begin(), s.TeacherNotes().end(), [&](const TeacherNote& t) { return t.id == newId; });
        REQUIRE(saved != s.TeacherNotes().end());
        REQUIRE_FALSE(saved->enabled);
        REQUIRE(saved->audience == NoteAudience::G1); // omitted on the update => kept
        REQUIRE(s.SaveTeacherNote(update, [&](const NoteOpOutcome& o) { out = o; }).ok); // revision 1 is stale now
        REQUIRE(out.error.code == ErrorCode::Conflict);
        REQUIRE(s.DeleteTeacherNote(newId, [&](const NoteOpOutcome& o) { out = o; }).ok);
        REQUIRE(out.status.ok);
        REQUIRE(s.TeacherNotes().size() == 6);
        s.Shutdown();
    }
    if (const char* cs = std::getenv("GVIEW_LEARNING_STUB_FORBIDDEN_CS"); cs != nullptr && cs[0] != 0)
    {
        auto session = makeSession();
        auto& s      = *session;
        connect(s, cs);
        REQUIRE(s.GetPolicy()->notes.enabled);
        REQUIRE(s.GetNotesAvailability() == NotesAvailability::DisabledByServer); // GetNotes answered 403
        s.Notes().Create("t", "never sent", {}, 0);
        s.PumpNotes(true);
        REQUIRE_FALSE(s.RefreshNotes().ok);
        s.Shutdown();
    }
    if (const char* cs = std::getenv("GVIEW_LEARNING_STUB_NOTES_OFF_CS"); cs != nullptr && cs[0] != 0)
    {
        auto session = makeSession();
        auto& s      = *session;
        connect(s, cs);
        REQUIRE(s.GetNotesAvailability() == NotesAvailability::DisabledByPolicy);
        REQUIRE_FALSE(s.NotesLoaded()); // GetNotes is not called
        s.Shutdown();
    }
}

// ======================================================================== course work and solutions (spec §10.12)
namespace
{
// a work document as the DissasmViewer builds it (Instance::BuildWorkDocumentText), pretty-printed with noise
const std::string WORK_DOC = R"JSON({
  "version": 1, "format": "gview-disassembly-annotations", "file": "p16.exe",
  "zones": [ { "fileOffset": "0x400", "comments": [ { "address": "0x401000", "text": "entry \"main\"" } ] } ],
  "meta": { "kind": "work", "clientVersion": "0.409.0", "savedAt": 1760000000, "problem": "w1_stack_var" },
  "replay": { "version": 1, "startedAt": 1759990000, "zones": [ { "fileOffset": "0x400", "addressBase": "0x401000" } ],
              "events": [ ["v", 12, 0, "0x401000", "l", "m"], ["e", 20, 0, "name", "0x401080", { "before": "sub_401080", "after": "decrypt" }] ] }
})JSON";

std::string Canonical(std::string_view doc)
{
    std::string c;
    REQUIRE(ValidateWorkDocumentText(doc, MAX_WORK_DOCUMENT_BYTES, c).ok);
    return c;
}

json WorkObject(bool enabled = true, int64 maxBytes = 1024 * 1024)
{
    return json{ { "enabled", enabled }, { "maxBytes", maxBytes } };
}

// In-process course server for the work / solution endpoints (compare-and-set as spec §10.12)
struct FakeWorkServer {
    bool staff{ false };
    bool forbidden{ false }; // 403 FORBIDDEN on GetWork / SaveWork (turned off after connect)
    bool expired{ false };   // 403 POLICY_EXPIRED everywhere
    json audiences = json::array({ "all", "G1", "G2" });
    int64 workRevision{ 0 };
    json workDocument;
    std::map<std::string, json> solutions; // audience -> {"id", "revision", "document", "enabled", ...}
    int64 nextId{ 1 };

    std::optional<HttpResponse> Gate(bool ownWork) const
    {
        if (expired)
            return ErrorResponse(403, "POLICY_EXPIRED");
        if (ownWork && forbidden && !staff)
            return ErrorResponse(403, "FORBIDDEN");
        return std::nullopt;
    }
    json SolutionMeta(const json& s) const
    {
        json r = s;
        r.erase("document");
        return r;
    }
    HttpResponse Conflict(const json* existing) const
    {
        json e{ { "status", "error" }, { "code", "CONFLICT" }, { "details", "x" }, { "retryable", false } };
        if (existing != nullptr)
        {
            e["id"]       = (*existing)["id"];
            e["revision"] = (*existing)["revision"];
        }
        return Response(409, e.dump());
    }
    void Install(FakeTransport& t)
    {
        t.routes["/GView/GetWork"] = [this](const HttpRequest& r) {
            if (auto g = Gate(true))
                return *g;
            json sols = json::array();
            for (const auto& [a, s] : solutions)
                if (staff || (s["enabled"].get<bool>() && (a == "all" || a == "G1")))
                    sols.push_back(SolutionMeta(s));
            json work = nullptr;
            if (workRevision > 0)
                work = json{ { "revision", workRevision }, { "updatedAt", NOW }, { "clientVersion", "0.409.0" }, { "hasReplay", true },
                             { "replaySteps", 2 }, { "document", workDocument } };
            return Response(200, json{ { "status", "ok" }, { "serverTime", NOW }, { "maxBytes", 1024 * 1024 }, { "canPublishSolutions", staff },
                                       { "audiences", audiences }, { "work", work }, { "solutions", sols } }.dump());
        };
        t.routes["/GView/SaveWork"] = [this](const HttpRequest& r) {
            if (auto g = Gate(true))
                return *g;
            const auto b = json::parse(BodyOf(r));
            const bool create = !b.contains("revision");
            if ((create && workRevision != 0) || (!create && b["revision"].get<int64>() != workRevision))
                return Conflict(nullptr);
            workRevision++;
            workDocument = b["document"];
            return Response(200, json{ { "status", "ok" }, { "revision", workRevision }, { "updatedAt", NOW + workRevision }, { "created", create } }.dump());
        };
        t.routes["/GView/GetSolution"] = [this](const HttpRequest& r) {
            if (auto g = Gate(false))
                return *g;
            const auto b = json::parse(BodyOf(r));
            for (const auto& [a, s] : solutions)
                if ((b.contains("id") && s["id"] == b["id"]) || (!b.contains("id") && a == "all"))
                    return Response(200, json{ { "status", "ok" }, { "solution", s } }.dump());
            return ErrorResponse(404, "NOT_FOUND");
        };
        t.routes["/GView/PublishSolution"] = [this](const HttpRequest& r) {
            if (auto g = Gate(false))
                return *g;
            if (!staff)
                return ErrorResponse(403, "FORBIDDEN");
            const auto b        = json::parse(BodyOf(r));
            const auto audience = b["audience"].get<std::string>();
            auto it             = solutions.find(audience);
            if (!b.contains("id"))
            {
                if (it != solutions.end())
                    return Conflict(&it->second);
                json s{ { "id", nextId++ },        { "audience", audience },        { "revision", 1 },          { "updatedAt", NOW },
                        { "enabled", b["enabled"] }, { "hasReplay", b["hasReplay"] }, { "replaySteps", b["replaySteps"] }, { "document", b["document"] } };
                solutions[audience] = s;
                return Response(200, json{ { "status", "ok" }, { "id", s["id"] }, { "revision", 1 }, { "updatedAt", NOW }, { "created", true } }.dump());
            }
            if (it == solutions.end() || it->second["id"] != b["id"] || it->second["revision"] != b["revision"])
                return Conflict(it == solutions.end() ? nullptr : &it->second);
            it->second["revision"] = it->second["revision"].get<int64>() + 1;
            it->second["document"] = b["document"];
            return Response(200, json{ { "status", "ok" }, { "id", b["id"] }, { "revision", it->second["revision"] }, { "updatedAt", NOW }, { "created", false } }.dump());
        };
        t.routes["/GView/DeleteSolution"] = [this](const HttpRequest& r) {
            if (!staff)
                return ErrorResponse(403, "FORBIDDEN");
            const auto b = json::parse(BodyOf(r));
            for (auto it = solutions.begin(); it != solutions.end(); ++it)
                if (it->second["id"] == b["id"])
                {
                    solutions.erase(it);
                    return Response(200, R"({"status":"ok"})");
                }
            return ErrorResponse(404, "NOT_FOUND");
        };
    }
};

struct WorkFixture : SessionFixture {
    FakeWorkServer server;
    // connectUser: extra "user" fields of the Connect answer (canPublishSolutions / audiences)
    explicit WorkFixture(std::optional<json> workObject = WorkObject(), bool staff = false, json connectUser = json::object())
    {
        server.staff = staff;
        server.Install(*transport);
        PolicyOptions o;
        o.work            = std::move(workObject);
        const auto policy = BuildPolicy(o);
        const auto sig    = ServerKey().Sign(policy);
        auto body         = json::parse(ConnectBody(policy, sig));
        for (auto& [k, v] : connectUser.items())
            body["user"][k] = v;
        transport->routes["/GView/Connect"] = [d = body.dump()](const HttpRequest&) { return Response(200, d); };
        transport->routes["/GView/GetWeeks"] = [](const HttpRequest&) { return Response(200, WeeksFixture()); };
    }
    WorkResult GetWork(std::string_view problem = "w1_stack_var")
    {
        WorkResult r;
        r.status = GView::Utils::GStatus::Error("callback not called");
        auto st  = session->GetWork(problem, [&](WorkResult& x) { r = std::move(x); });
        if (!st.ok)
            r.status = st;
        return r;
    }
    SaveWorkOutcome SaveWork(std::string_view doc, std::string_view problem = "w1_stack_var")
    {
        SaveWorkOutcome r;
        r.status = GView::Utils::GStatus::Error("callback not called");
        auto st  = session->SaveWork(problem, std::string(doc), true, 2, [&](const SaveWorkOutcome& x) { r = x; });
        if (!st.ok)
            r.status = st;
        return r;
    }
    PublishOutcome Publish(PublishSolutionRequest req)
    {
        PublishOutcome r;
        r.status = GView::Utils::GStatus::Error("callback not called");
        auto st  = session->PublishSolution(std::move(req), [&](const PublishOutcome& x) { r = x; });
        if (!st.ok)
            r.status = st;
        return r;
    }
};

std::string OtherDoc(std::string_view text)
{
    json d = json::parse(WORK_DOC);
    d["zones"][0]["comments"][0]["text"] = text;
    return d.dump();
}
} // namespace

TEST_CASE("Learning: work error mapping (CONFLICT and the existing solution)", "[learning][work]")
{
    auto e = WorkErrorFromResponse(Response(409, R"({"status":"error","code":"CONFLICT","details":"x","retryable":false,"id":7,"revision":3})"));
    REQUIRE(e.code == ErrorCode::Conflict);
    REQUIRE_FALSE(e.retryable);
    REQUIRE(e.existingId == 7);
    REQUIRE(e.existingRevision == 3);
    // a 409 without an envelope is still a conflict (the status decides), without an existing solution
    e = WorkErrorFromResponse(Response(409, "conflict"));
    REQUIRE(e.code == ErrorCode::Conflict);
    REQUIRE_FALSE(e.existingId.has_value());
    // hostile ids are ignored
    e = WorkErrorFromResponse(Response(409, R"({"code":"CONFLICT","id":"7","revision":-1})"));
    REQUIRE_FALSE(e.existingId.has_value());
    REQUIRE_FALSE(e.existingRevision.has_value());
    // only a 409 carries them
    e = WorkErrorFromResponse(Response(400, R"({"code":"BAD_REQUEST","id":7,"revision":3})"));
    REQUIRE(e.code == ErrorCode::BadRequest);
    REQUIRE_FALSE(e.existingId.has_value());
    REQUIRE(WorkErrorFromResponse(Response(413, "")).code == ErrorCode::PayloadTooLarge);
    REQUIRE(WorkErrorFromResponse(Response(403, R"({"code":"FORBIDDEN"})")).code == ErrorCode::Forbidden);
    REQUIRE(WorkErrorFromResponse(TransportFailure()).code == ErrorCode::Transport);
    // regression: SubmitFlag keeps 409 => ALREADY_SOLVED
    REQUIRE(ParseErrorEnvelope(409, {}, {}).code == ErrorCode::AlreadySolved);
    SubmitResult sr;
    ServerError err;
    REQUIRE(ParseSubmitResponse(409, BufferView(std::string_view(R"({"status":"error","code":"ALREADY_SOLVED","details":"x"})")), sr, err).ok);
    REQUIRE(sr.alreadySolved);
}

TEST_CASE("Learning: work document validation and canonical text", "[learning][work]")
{
    std::string c;
    REQUIRE(ValidateWorkDocumentText(WORK_DOC, MAX_WORK_DOCUMENT_BYTES, c).ok);
    REQUIRE(c == json::parse(WORK_DOC).dump()); // compact, keys sorted, nothing else changed
    REQUIRE(c.find('\n') == std::string::npos);
    REQUIRE(c.starts_with(R"({"file":"p16.exe","format":"gview-disassembly-annotations","meta":)"));
    std::string again;
    REQUIRE(ValidateWorkDocumentText(c, MAX_WORK_DOCUMENT_BYTES, again).ok);
    REQUIRE(again == c); // idempotent
    REQUIRE(ValidateWorkDocumentText(R"({"format":"gview-disassembly-annotations","version":1})", 1000, c).ok);

    const std::string tooLarge = "x";
    for (const std::string bad : {
               std::string(""),
               std::string("[1,2]"),
               std::string("\"text\""),
               std::string("{\"format\":\"gview-disassembly-annotations\",\"version\":1"), // truncated
               std::string(R"({"version":1})"),
               std::string(R"({"format":"other","version":1})"),
               std::string(R"({"format":"gview-disassembly-annotations"})"),
               std::string(R"({"format":"gview-disassembly-annotations","version":"1"})"),
               std::string(R"({"format":"gview-disassembly-annotations","version":1.0})"),
               std::string(R"({"format":"gview-disassembly-annotations","version":0})"),
               std::string(R"({"format":"gview-disassembly-annotations","version":2})"),
               std::string(R"({"format":"gview-disassembly-annotations","version":1,"t":"a\u0000b"})"),
               std::string(R"({"format":"gview-disassembly-annotations","version":1,"a\u0000":1})"),
               std::string("{\"format\":\"gview-disassembly-annotations\",\"version\":1,\"t\":\"a\0b\"}", 52),
               std::string(R"({"format":"gview-disassembly-annotations","version":1,"t":"\xff"})"), // invalid UTF-8
               R"({"format":"gview-disassembly-annotations","version":1,"d":)" + std::string(200, '[') + std::string(200, ']') + "}",
         })
    {
        INFO(bad.substr(0, 80));
        std::string out = "unchanged";
        REQUIRE_FALSE(ValidateWorkDocumentText(bad, MAX_WORK_DOCUMENT_BYTES, out).ok);
        REQUIRE(out == "unchanged");
    }
    // the size limit applies to the canonical text: exactly maxBytes passes, one byte more does not
    const std::string head = R"({"format":"gview-disassembly-annotations","pad":")";
    const std::string tail = R"(","version":1})";
    const std::string doc  = head + std::string(1000, 'a') + tail;
    REQUIRE(ValidateWorkDocumentText(doc, doc.size(), c).ok);
    auto st = ValidateWorkDocumentText(doc, doc.size() - 1, c);
    REQUIRE_FALSE(st.ok);
    REQUIRE(st.message.find("too large") != std::string::npos);
    // a newer document says so (the user must update GView)
    st = ValidateWorkDocumentText(R"({"format":"gview-disassembly-annotations","version":3})", 1000, c);
    REQUIRE(st.message.find("newer GView") != std::string::npos);
}

TEST_CASE("Learning: work request bodies (exact)", "[learning][work]")
{
    const std::string doc = R"({"format":"gview-disassembly-annotations","version":1})";
    auto str              = [](const SecureString& s) { return std::string(s.data(), s.size()); };
    REQUIRE(str(BuildGetWorkBody("w1_stack_var")) == R"({"problem":"w1_stack_var"})");
    // escaped (never sent: not a valid item name); the literal is kept out of the macro (MSVC stringizes raw strings badly)
    const std::string escaped = "{\"problem\":\"a\\\"b\\\\c\\n\"}";
    REQUIRE(str(BuildGetWorkBody("a\"b\\c\n")) == escaped);

    SaveWorkRequest save{ "w1_stack_var", doc, true, 57, std::nullopt };
    REQUIRE(str(BuildSaveWorkBody(save)) ==
            R"({"problem":"w1_stack_var","document":{"format":"gview-disassembly-annotations","version":1},"hasReplay":true,"replaySteps":57})");
    save.revision  = 4;
    save.hasReplay = false;
    save.replaySteps = 0;
    REQUIRE(str(BuildSaveWorkBody(save)) ==
            R"({"problem":"w1_stack_var","document":{"format":"gview-disassembly-annotations","version":1},"hasReplay":false,"replaySteps":0,"revision":4})");
    REQUIRE(json::parse(str(BuildSaveWorkBody(save)))["document"] == json::parse(doc));

    REQUIRE(str(BuildGetSolutionBody("w1_stack_var", std::nullopt)) == R"({"problem":"w1_stack_var"})");
    REQUIRE(str(BuildGetSolutionBody("w1_stack_var", 12)) == R"({"problem":"w1_stack_var","id":12})");

    PublishSolutionRequest pub;
    pub.problem     = "w1_stack_var";
    pub.audience    = NoteAudience::G2;
    pub.document    = doc;
    pub.hasReplay   = true;
    pub.replaySteps = 9;
    REQUIRE(str(BuildPublishSolutionBody(pub)) ==
            R"({"problem":"w1_stack_var","audience":"G2","document":{"format":"gview-disassembly-annotations","version":1},"hasReplay":true,"replaySteps":9,"enabled":true})");
    pub.id       = 5;
    pub.revision = 2;
    pub.enabled  = false;
    pub.audience = NoteAudience::All;
    REQUIRE(str(BuildPublishSolutionBody(pub)) ==
            R"({"problem":"w1_stack_var","id":5,"audience":"all","document":{"format":"gview-disassembly-annotations","version":1},"hasReplay":true,"replaySteps":9,"enabled":false,"revision":2})");
    REQUIRE(str(BuildDeleteSolutionBody(5)) == R"({"id":5})");
}

TEST_CASE("Learning: GetWork / SaveWork / GetSolution / PublishSolution answers (hostile)", "[learning][work]")
{
    const json doc = json::parse(WORK_DOC);
    json answer{ { "status", "ok" },
                 { "serverTime", NOW },
                 { "maxBytes", 1048576 },
                 { "canPublishSolutions", false },
                 { "futureField", { 1, 2 } },
                 { "audiences", json::array({ "G1", "all", "hacker", 5, "G1", "g2" }) },
                 { "work", { { "revision", 3 }, { "updatedAt", NOW - 10 }, { "clientVersion", "0.409.0\x01" }, { "hasReplay", true }, { "replaySteps", 41 }, { "document", doc }, { "x", 1 } } },
                 { "solutions",
                   json::array({ { { "id", 7 }, { "audience", "all" }, { "revision", 2 }, { "updatedAt", NOW }, { "enabled", true }, { "hasReplay", true }, { "replaySteps", 30 } },
                                 { { "id", 8 }, { "audience", "G1" }, { "revision", 1 }, { "hasReplay", false }, { "replaySteps", 99 } },
                                 "not an object",
                                 { { "id", 0 }, { "audience", "all" }, { "revision", 1 } },
                                 { { "id", "9" }, { "audience", "all" }, { "revision", 1 } },
                                 { { "id", 1.5 }, { "audience", "all" }, { "revision", 1 } },
                                 { { "id", 10 }, { "audience", "G3" }, { "revision", 1 } },
                                 { { "id", 11 }, { "audience", "all" } },
                                 { { "id", 12 }, { "audience", "all" }, { "revision", 1 }, { "enabled", "yes" } },
                                 { { "id", 7 }, { "audience", "G2" }, { "revision", 1 } } }) } };
    WorkResponse r;
    // BufferView does not own: keep the text alive
    auto parseText = [&](const std::string& text) { return ParseWorkResponse(BufferView(std::string_view(text)), r); };
    std::string text = answer.dump();
    REQUIRE(parseText(text).ok);
    REQUIRE(r.serverTime == NOW);
    REQUIRE(r.maxBytes == 1048576);
    REQUIRE_FALSE(r.canPublishSolutions);
    REQUIRE(r.audiences == std::vector<NoteAudience>{ NoteAudience::All, NoteAudience::G1 });
    REQUIRE(r.hasWork);
    REQUIRE(r.revision == 3);
    REQUIRE(r.updatedAt == NOW - 10);
    REQUIRE(r.clientVersion == "0.409.0 "); // control characters sanitized
    REQUIRE(r.hasReplay);
    REQUIRE(r.replaySteps == 41);
    REQUIRE(r.document == doc.dump());
    REQUIRE(r.solutions.size() == 2);
    REQUIRE(r.solutions[0].id == 7);
    REQUIRE(r.solutions[0].audience == NoteAudience::All);
    REQUIRE(r.solutions[0].hasReplay);
    REQUIRE(r.solutions[0].replaySteps == 30);
    REQUIRE(r.solutions[1].enabled); // missing => true
    REQUIRE(r.solutions[1].replaySteps == 0); // no replay => no steps
    REQUIRE(r.rejected == 3 /* audiences */ + 8 /* solutions */);

    // work: null / missing = none; empty answer is fine
    answer["work"] = nullptr;
    text           = answer.dump();
    REQUIRE(parseText(text).ok);
    REQUIRE_FALSE(r.hasWork);
    REQUIRE(r.document.empty());
    REQUIRE(r.revision == 0);
    text = R"({"status":"ok"})";
    REQUIRE(parseText(text).ok);
    REQUIRE(r.audiences == std::vector<NoteAudience>{ NoteAudience::All });
    REQUIRE(r.maxBytes == MAX_WORK_DOCUMENT_BYTES);
    // maxBytes clamped to [64 KiB, 16 MiB]
    text = R"({"status":"ok","maxBytes":10})";
    REQUIRE(parseText(text).ok);
    REQUIRE(r.maxBytes == WORK_MIN_MAX_BYTES);
    text = R"({"status":"ok","maxBytes":100000000000})";
    REQUIRE(parseText(text).ok);
    REQUIRE(r.maxBytes == WORK_MAX_MAX_BYTES);
    text = R"({"status":"ok","canPublishSolutions":"true","audiences":"all"})";
    REQUIRE(parseText(text).ok);
    REQUIRE_FALSE(r.canPublishSolutions);
    REQUIRE(r.rejected == 1);

    // errors: the whole answer is refused
    auto refused = [&](json j) {
        const std::string t = j.dump();
        WorkResponse before;
        before.revision = 99;
        r               = before;
        const bool ok   = ParseWorkResponse(BufferView(std::string_view(t)), r).ok;
        if (!ok)
            REQUIRE(r.revision == 99); // out untouched on errors
        return !ok;
    };
    json base{ { "status", "ok" }, { "work", { { "revision", 1 }, { "document", doc } } } };
    REQUIRE_FALSE(refused(base));
    // an own document that can not be used (not an object, a newer version): the answer is kept, the work has no document
    auto unusable = [&](const json& j) {
        WorkResponse r;
        const std::string t = j.dump();
        return ParseWorkResponse(BufferView(std::string_view(t)), r).ok && r.hasWork && r.document.empty() && !r.workError.empty() && r.revision == 1;
    };
    json bad = base;
    bad["work"]["document"] = "a string";
    REQUIRE(unusable(bad));
    bad["work"]["document"] = json::array({ 1 });
    REQUIRE(unusable(bad));
    bad = base;
    bad["work"]["document"]["version"] = 2;
    REQUIRE(unusable(bad));
    bad = base;
    bad["work"].erase("document");
    REQUIRE(refused(bad));
    bad = base;
    bad["work"]["revision"] = 0;
    REQUIRE(refused(bad));
    bad = base;
    bad["work"] = "yes";
    REQUIRE(refused(bad));
    bad = base;
    bad["solutions"] = json::object();
    REQUIRE(refused(bad));
    bad = base;
    bad["status"] = "error";
    REQUIRE(refused(bad));
    bad = base;
    bad["work"]["document"]["pad"] = std::string(MAX_WORK_DOCUMENT_BYTES, 'a'); // above the client cap: unusable, the answer is kept
    REQUIRE(unusable(bad));
    REQUIRE(refused(json::array()));
    text = "not json";
    REQUIRE_FALSE(parseText(text).ok);

    // SaveWork / PublishSolution answers
    SaveWorkResponse sw;
    text = R"({"status":"ok","revision":4,"updatedAt":1760000000,"created":false,"extra":1})";
    REQUIRE(ParseSaveWorkResponse(BufferView(std::string_view(text)), sw).ok);
    REQUIRE(sw.revision == 4);
    REQUIRE(sw.updatedAt == 1760000000);
    for (const std::string b : { std::string(R"({"status":"ok"})"), std::string(R"({"status":"ok","revision":"4"})"), std::string(R"({"status":"ok","revision":0})"),
                                 std::string(R"({"status":"error","revision":4})"), std::string("[]") })
        REQUIRE_FALSE(ParseSaveWorkResponse(BufferView(std::string_view(b)), sw).ok);
    PublishSolutionResponse pr;
    text = R"({"status":"ok","id":3,"revision":1,"updatedAt":5,"created":true})";
    REQUIRE(ParsePublishSolutionResponse(BufferView(std::string_view(text)), pr).ok);
    REQUIRE(pr.id == 3);
    REQUIRE(pr.created);
    text = R"({"status":"ok","revision":1})";
    REQUIRE_FALSE(ParsePublishSolutionResponse(BufferView(std::string_view(text)), pr).ok);

    // GetSolution
    SolutionResponse sol;
    json s{ { "status", "ok" },
            { "solution", { { "id", 7 }, { "audience", "G1" }, { "revision", 2 }, { "updatedAt", NOW }, { "enabled", true }, { "hasReplay", true }, { "replaySteps", 3 }, { "document", doc } } } };
    text = s.dump();
    REQUIRE(ParseSolutionResponse(BufferView(std::string_view(text)), sol).ok);
    REQUIRE(sol.info.id == 7);
    REQUIRE(sol.info.audience == NoteAudience::G1);
    REQUIRE(sol.info.replaySteps == 3);
    REQUIRE(sol.document == doc.dump());
    for (auto mutate : std::vector<std::function<void(json&)>>{
               [](json& j) { j["solution"]["document"] = 5; },
               [](json& j) { j["solution"]["document"]["format"] = "x"; },
               [](json& j) { j["solution"].erase("document"); },
               [](json& j) { j["solution"]["audience"] = "everyone"; },
               [](json& j) { j["solution"]["id"] = -1; },
               [](json& j) { j.erase("solution"); },
         })
    {
        json m = s;
        mutate(m);
        text = m.dump();
        INFO(text.substr(0, 120));
        REQUIRE_FALSE(ParseSolutionResponse(BufferView(std::string_view(text)), sol).ok);
    }
}

TEST_CASE("Learning: policy work object (absent, present, clamping)", "[learning][work][policy]")
{
    Policy p;
    PolicyOptions o;
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE_FALSE(p.work.present); // absent = server without work documents => no Save / Resume UI

    o.work = WorkObject(true, 1048576);
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE(p.work.present);
    REQUIRE(p.work.enabled);
    REQUIRE(p.work.maxBytes == 1048576);
    o.work = WorkObject(true, 10);
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE(p.work.maxBytes == 64 * 1024);
    o.work = WorkObject(true, 1ll << 40);
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE(p.work.maxBytes == 16 * 1024 * 1024);
    o.work = json{ { "enabled", false } };
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE(p.work.present);
    REQUIRE_FALSE(p.work.enabled);
    REQUIRE(p.work.maxBytes == 2 * 1024 * 1024);
    o.work = json::object();
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE_FALSE(p.work.enabled);
    o.work = json(nullptr);
    REQUIRE(ParsePolicyWith(o, p).ok);
    REQUIRE_FALSE(p.work.present);

    for (const json bad : { json("on"), json::array(), json{ { "enabled", "yes" } }, json{ { "maxBytes", -1 } }, json{ { "maxBytes", "2097152" } } })
    {
        o.work  = bad;
        auto st = ParsePolicyWith(o, p);
        INFO(bad.dump());
        REQUIRE_FALSE(st.ok);
        REQUIRE(st.message.starts_with("POLICY_MALFORMED"));
    }
}

TEST_CASE("Learning: connect and catalogue announce course work and solutions", "[learning][work]")
{
    const auto policy = BuildPolicy({});
    const auto sig    = ServerKey().Sign(policy);
    ConnectResponse cr;
    std::string body = ConnectBody(policy, sig);
    REQUIRE(ParseConnectResponse(BufferView(std::string_view(body)), cr).ok);
    REQUIRE_FALSE(cr.canPublishSolutions.has_value()); // older servers: not announced
    REQUIRE_FALSE(cr.audiences.has_value());

    auto j                           = json::parse(body);
    j["user"]["canPublishSolutions"] = true;
    j["user"]["audiences"]           = json::array({ "G2", "x", "all" });
    body                             = j.dump();
    REQUIRE(ParseConnectResponse(BufferView(std::string_view(body)), cr).ok);
    REQUIRE(cr.canPublishSolutions == true);
    REQUIRE(cr.audiences == std::vector<NoteAudience>{ NoteAudience::All, NoteAudience::G2 });
    j["user"]["canPublishSolutions"] = "yes"; // wrong type = not announced
    j["user"]["audiences"]           = "all";
    body                             = j.dump();
    REQUIRE(ParseConnectResponse(BufferView(std::string_view(body)), cr).ok);
    REQUIRE_FALSE(cr.canPublishSolutions.has_value());
    REQUIRE_FALSE(cr.audiences.has_value());

    auto weeks = json::parse(WeeksFixture());
    auto& p    = weeks["weeks"][1]["problems"][0];
    p["me"]["workSavedAt"]  = 1760000000;
    p["me"]["workRevision"] = 4;
    p["solutionAvailable"]  = true;
    p["solutionHasReplay"]  = true;
    std::string text        = weeks.dump();
    Catalogue cat;
    REQUIRE(ParseWeeks(BufferView(std::string_view(text)), cat).ok);
    const auto* item = cat.Find("w1_stack_var", true);
    REQUIRE(item != nullptr);
    REQUIRE(item->me.workSavedAt == 1760000000);
    REQUIRE(item->me.workRevision == 4);
    REQUIRE(item->solutionAvailable);
    REQUIRE(item->solutionHasReplay);
    p["me"]["workRevision"] = -3;
    p["solutionAvailable"]  = "yes";
    text                    = weeks.dump();
    REQUIRE(ParseWeeks(BufferView(std::string_view(text)), cat).ok);
    item = cat.Find("w1_stack_var", true);
    REQUIRE(item->me.workRevision == 0);
    REQUIRE_FALSE(item->solutionAvailable);
    REQUIRE_FALSE(item->solutionHasReplay); // only with a solution
}

TEST_CASE("Learning: work availability follows the policy and the server", "[learning][work][session]")
{
    {
        WorkFixture fx(std::nullopt); // a server without work documents
        REQUIRE(fx.Connect().ok);
        REQUIRE(fx.session->GetWorkAvailability() == WorkAvailability::Absent);
        REQUIRE_FALSE(fx.GetWork().status.ok);
        REQUIRE(fx.transport->Count("/GView/GetWork") == 0);
    }
    {
        WorkFixture fx(WorkObject(false));
        REQUIRE(fx.Connect().ok);
        REQUIRE(fx.session->GetWorkAvailability() == WorkAvailability::DisabledByPolicy);
        REQUIRE(fx.session->GetStatus().work == WorkAvailability::DisabledByPolicy);
        REQUIRE_FALSE(fx.SaveWork(WORK_DOC).status.ok);
        REQUIRE(fx.transport->requests.size() == 1); // Connect only
    }
    {
        // course staff are never gated by the switch (Connect announces the capability)
        WorkFixture fx(WorkObject(false), true, json{ { "canPublishSolutions", true }, { "audiences", { "all", "G1" } } });
        REQUIRE(fx.Connect().ok);
        REQUIRE(fx.session->GetWorkAvailability() == WorkAvailability::Available);
        REQUIRE(fx.session->CanPublishSolutions());
        REQUIRE(fx.session->IsCourseStaff());
        REQUIRE(fx.session->SolutionAudiences() == std::vector<NoteAudience>{ NoteAudience::All, NoteAudience::G1 });
    }
    {
        // 403 FORBIDDEN after connect: hidden until the next connect
        WorkFixture fx;
        REQUIRE(fx.Connect().ok);
        REQUIRE(fx.session->CanUseWork());
        REQUIRE(fx.session->GetStatus().workMaxBytes == 1024 * 1024); // the policy's maxBytes
        fx.server.forbidden = true;
        auto r              = fx.GetWork();
        REQUIRE(r.error.code == ErrorCode::Forbidden);
        REQUIRE(fx.session->GetWorkAvailability() == WorkAvailability::DisabledByServer);
        const auto before = fx.transport->requests.size();
        REQUIRE_FALSE(fx.GetWork().status.ok); // refused locally now
        REQUIRE(fx.transport->requests.size() == before);
        fx.server.forbidden = false;
        REQUIRE(fx.Connect().ok);
        REQUIRE(fx.session->CanUseWork());
    }
}

TEST_CASE("Learning: work revisions, conflicts and the catalogue", "[learning][work][session]")
{
    WorkFixture fx;
    REQUIRE(fx.Connect().ok);
    REQUIRE(fx.session->RefreshCatalogue(nullptr).ok);
    auto& s = *fx.session;

    // nothing saved yet: the first save creates (no revision on the wire)
    auto r = fx.GetWork();
    REQUIRE(r.status.ok);
    REQUIRE_FALSE(r.response.hasWork);
    REQUIRE_FALSE(s.WorkRevision("w1_stack_var").has_value());
    auto o = fx.SaveWork(WORK_DOC);
    INFO(o.status.message);
    REQUIRE(o.status.ok);
    REQUIRE(o.result.created);
    REQUIRE(o.result.revision == 1);
    REQUIRE(s.WorkRevision("w1_stack_var") == 1);
    auto sent = json::parse(fx.transport->LastBody("/GView/SaveWork"));
    REQUIRE_FALSE(sent.contains("revision"));
    REQUIRE(sent["document"] == json::parse(WORK_DOC)); // canonical text embedded as is
    REQUIRE(sent["hasReplay"] == true);
    REQUIRE(sent["replaySteps"] == 2);
    REQUIRE(fx.transport->LastBody("/GView/SaveWork").find("\n") == std::string::npos);
    const auto* item = s.GetCatalogue().Find("w1_stack_var", true);
    REQUIRE(item->me.workRevision == 1);
    REQUIRE(item->me.workSavedAt == NOW + 1);

    // another machine saved revision 2: this save sends revision 1 and conflicts; nothing changes locally
    fx.server.workRevision = 2;
    o                      = fx.SaveWork(OtherDoc("from this GView"));
    REQUIRE_FALSE(o.status.ok);
    REQUIRE(o.conflict);
    REQUIRE(o.error.code == ErrorCode::Conflict);
    REQUIRE(json::parse(fx.transport->LastBody("/GView/SaveWork"))["revision"] == 1);
    REQUIRE(s.WorkRevision("w1_stack_var") == 1);
    REQUIRE(s.GetState() == SessionState::Active);
    REQUIRE(s.CanUseWork());

    // overwrite deliberately: GetWork (caches revision 2 and the capability), then save again
    r = fx.GetWork();
    REQUIRE(r.status.ok);
    REQUIRE(r.response.hasWork);
    REQUIRE(r.response.revision == 2);
    REQUIRE(r.response.document == Canonical(WORK_DOC));
    REQUIRE(s.WorkRevision("w1_stack_var") == 2);
    REQUIRE_FALSE(s.CanPublishSolutions());
    REQUIRE(s.GetStatus().audiences == std::vector<NoteAudience>{ NoteAudience::All, NoteAudience::G1, NoteAudience::G2 });
    o = fx.SaveWork(OtherDoc("from this GView"));
    REQUIRE(o.status.ok);
    REQUIRE(o.result.revision == 3);
    REQUIRE(json::parse(fx.transport->LastBody("/GView/SaveWork"))["revision"] == 2);
    REQUIRE(s.WorkRevision("w1_stack_var") == 3);

    // refused locally: invalid documents, documents above the limit (GetWork said 1 MiB), invalid problems
    const auto before = fx.transport->requests.size();
    REQUIRE_FALSE(s.SaveWork("w1_stack_var", "[]", false, 0, nullptr).ok);
    REQUIRE_FALSE(s.SaveWork("w1_stack_var", R"({"format":"x","version":1})", false, 0, nullptr).ok);
    REQUIRE_FALSE(s.SaveWork("w1_stack_var", OtherDoc(std::string(1024 * 1024, 'a')), false, 0, nullptr).ok);
    REQUIRE_FALSE(s.SaveWork("../x", WORK_DOC, false, 0, nullptr).ok);
    REQUIRE_FALSE(s.GetWork("", nullptr).ok);
    REQUIRE(fx.transport->requests.size() == before);

    // the server deleted the work (website): GetWork forgets the revision, the next save creates
    fx.server.workRevision = 0;
    REQUIRE(fx.GetWork().status.ok);
    REQUIRE_FALSE(s.WorkRevision("w1_stack_var").has_value());

    // solutions: a student fetches the one of its audience
    fx.server.solutions["all"] = json{ { "id", 4 }, { "audience", "all" }, { "revision", 1 }, { "updatedAt", NOW }, { "enabled", true },
                                       { "hasReplay", true }, { "replaySteps", 5 }, { "document", json::parse(WORK_DOC) } };
    r = fx.GetWork();
    REQUIRE(r.response.solutions.size() == 1);
    REQUIRE(r.response.solutions[0].id == 4);
    SolutionResult sol;
    REQUIRE(s.GetSolution("w1_stack_var", std::nullopt, [&](SolutionResult& x) { sol = std::move(x); }).ok);
    REQUIRE(sol.status.ok);
    REQUIRE(sol.solution.info.id == 4);
    REQUIRE(sol.solution.document == Canonical(WORK_DOC));
    REQUIRE(fx.transport->LastBody("/GView/GetSolution") == R"({"problem":"w1_stack_var"})");
    REQUIRE(s.GetSolution("w1_stack_var", 99, [&](SolutionResult& x) { sol = std::move(x); }).ok);
    REQUIRE(sol.error.code == ErrorCode::NotFound);
    REQUIRE(s.CanUseWork()); // a 404 changes nothing

    // a student can not publish: refused locally, nothing sent
    PublishSolutionRequest pub;
    pub.problem  = "w1_stack_var";
    pub.document = WORK_DOC;
    auto po      = fx.Publish(pub);
    REQUIRE_FALSE(po.status.ok);
    REQUIRE(po.status.message.find("course staff") != std::string::npos);
    REQUIRE_FALSE(s.DeleteSolution(4, nullptr).ok);
    REQUIRE(fx.transport->Count("/GView/PublishSolution") == 0);
    REQUIRE(fx.transport->Count("/GView/DeleteSolution") == 0);
}

TEST_CASE("Learning: course staff publish solutions (create, 409, republish, delete)", "[learning][work][session]")
{
    WorkFixture fx(WorkObject(), true);
    REQUIRE(fx.Connect().ok);
    auto& s = *fx.session;
    REQUIRE_FALSE(s.CanPublishSolutions()); // not announced at connect
    fx.server.audiences = json::array({ "all", "G1" });
    REQUIRE(fx.GetWork().status.ok);       // GetWork is authoritative
    REQUIRE(s.CanPublishSolutions());
    REQUIRE(s.GetStatus().canPublishSolutions);

    PublishSolutionRequest pub;
    pub.problem     = "w1_stack_var";
    pub.audience    = NoteAudience::All;
    pub.document    = WORK_DOC;
    pub.hasReplay   = true;
    pub.replaySteps = 12;
    auto o          = fx.Publish(pub);
    INFO(o.status.message);
    REQUIRE(o.status.ok);
    REQUIRE(o.result.created);
    const int64 id = o.result.id;
    auto sent      = json::parse(fx.transport->LastBody("/GView/PublishSolution"));
    REQUIRE(sent["audience"] == "all");
    REQUIRE(sent["document"] == json::parse(WORK_DOC));
    REQUIRE(sent["replaySteps"] == 12);
    REQUIRE_FALSE(sent.contains("id"));

    // a second create for the same audience: 409 naming the existing solution
    pub.document = OtherDoc("better");
    o            = fx.Publish(pub);
    REQUIRE_FALSE(o.status.ok);
    REQUIRE(o.conflict);
    REQUIRE(o.existingId == id);
    REQUIRE(o.existingRevision == 1);
    REQUIRE(s.CanPublishSolutions()); // a conflict is not a refusal
    // republish over it
    pub.id       = o.existingId;
    pub.revision = o.existingRevision;
    o            = fx.Publish(pub);
    REQUIRE(o.status.ok);
    REQUIRE(o.result.revision == 2);
    REQUIRE_FALSE(o.result.created);
    sent = json::parse(fx.transport->LastBody("/GView/PublishSolution"));
    REQUIRE(sent["id"] == id);
    REQUIRE(sent["revision"] == 1);
    // stale revision
    o = fx.Publish(pub);
    REQUIRE(o.conflict);
    REQUIRE(o.existingRevision == 2);

    // an audience the server did not announce, an update without its revision: refused locally
    const auto before = fx.transport->requests.size();
    PublishSolutionRequest g2 = pub;
    g2.id.reset();
    g2.revision.reset();
    g2.audience = NoteAudience::G2;
    REQUIRE_FALSE(fx.Publish(g2).status.ok);
    PublishSolutionRequest noRev = pub;
    noRev.revision.reset();
    REQUIRE_FALSE(fx.Publish(noRev).status.ok);
    REQUIRE(fx.transport->requests.size() == before);

    DeleteSolutionOutcome d;
    REQUIRE(s.DeleteSolution(id, [&](const DeleteSolutionOutcome& x) { d = x; }).ok);
    REQUIRE(d.status.ok);
    REQUIRE(fx.transport->LastBody("/GView/DeleteSolution") == "{\"id\":" + std::to_string(id) + "}");
    REQUIRE(s.DeleteSolution(id, [&](const DeleteSolutionOutcome& x) { d = x; }).ok);
    REQUIRE(d.error.code == ErrorCode::NotFound);
    REQUIRE(s.CanPublishSolutions());

    // the server says: not staff (any more) => the capability is dropped
    fx.server.staff = false;
    o               = fx.Publish(pub);
    REQUIRE(o.error.code == ErrorCode::Forbidden);
    REQUIRE_FALSE(s.CanPublishSolutions());

    // EndSession clears revisions and capabilities
    REQUIRE(s.EndSession("user").ok);
    REQUIRE_FALSE(s.CanPublishSolutions());
    REQUIRE_FALSE(s.IsCourseStaff());
    REQUIRE_FALSE(s.WorkRevision("w1_stack_var").has_value());
    REQUIRE(s.GetStatus().audiences.empty());
    REQUIRE(s.GetWorkAvailability() == WorkAvailability::Absent);
}

TEST_CASE("Learning: work requests and POLICY_EXPIRED, end of session", "[learning][work][session]")
{
    WorkFixture fx;
    REQUIRE(fx.Connect().ok);
    REQUIRE(fx.SaveWork(WORK_DOC).status.ok);
    REQUIRE(fx.session->WorkRevision("w1_stack_var") == 1);
    fx.server.expired = true;
    auto o            = fx.SaveWork(OtherDoc("x"));
    REQUIRE(o.error.code == ErrorCode::PolicyExpired);
    REQUIRE_FALSE(o.conflict);
    REQUIRE(fx.session->GetState() == SessionState::Expired);
    REQUIRE(fx.session->GetWorkAvailability() == WorkAvailability::Unavailable);
    REQUIRE_FALSE(fx.GetWork().status.ok); // refused locally
    REQUIRE(fx.deactivations == 0);        // restrictions stay applied

    // the session ended while a request ran: its completion is dropped (callbacks of another session never run)
    WorkFixture fx2;
    REQUIRE(fx2.Connect().ok);
    bool called                       = false;
    fx2.transport->routes["/GView/GetWork"] = [&](const HttpRequest&) {
        REQUIRE(fx2.session->EndSession("user").ok); // inline (synchronous) frontend: ends before the completion
        return Response(200, R"({"status":"ok","work":null})");
    };
    REQUIRE(fx2.session->GetWork("w1_stack_var", [&](WorkResult&) { called = true; }).ok);
    REQUIRE_FALSE(called);
}

TEST_CASE("Learning: each work operation is one Post with a constant path", "[learning][work]")
{
    const std::string doc = WORK_DOC;
    PublishSolutionRequest pub;
    pub.problem  = "w1_stack_var";
    pub.document = doc;
    struct Case {
        std::string path;
        std::function<void(IHttpTransport&)> call;
    };
    const std::vector<Case> cases = {
        { "/GView/GetWork", [](IHttpTransport& t) { LearningSession::PerformGetWork(t, "w1_stack_var"); } },
        { "/GView/SaveWork", [&](IHttpTransport& t) { LearningSession::PerformSaveWork(t, SaveWorkRequest{ "w1_stack_var", doc, false, 0, 3 }); } },
        { "/GView/GetSolution", [](IHttpTransport& t) { LearningSession::PerformGetSolution(t, "w1_stack_var", 2); } },
        { "/GView/PublishSolution", [&](IHttpTransport& t) { LearningSession::PerformPublishSolution(t, pub); } },
        { "/GView/DeleteSolution", [](IHttpTransport& t) { LearningSession::PerformDeleteSolution(t, 2); } },
    };
    for (const auto& c : cases)
    {
        INFO(c.path);
        for (long status : { 200L, 409L, 500L })
        {
            FakeTransport t;
            t.routes[c.path] = [status](const HttpRequest&) { return Response(status, R"({"status":"ok"})"); };
            c.call(t);
            REQUIRE(t.requests.size() == 1);
            REQUIRE(t.requests[0].first == c.path);
        }
    }
    // the documents travel canonical even when the caller passes pretty-printed text
    FakeTransport t;
    LearningSession::PerformSaveWork(t, SaveWorkRequest{ "w1_stack_var", doc, true, 4, std::nullopt });
    REQUIRE(t.requests[0].second.find(Canonical(doc)) != std::string::npos);
    // invalid requests are not sent at all
    FakeTransport none;
    REQUIRE(LearningSession::PerformGetWork(none, "../x").error.code == ErrorCode::BadRequest);
    REQUIRE_FALSE(LearningSession::PerformSaveWork(none, SaveWorkRequest{ "w1_stack_var", "{}", false, 0, std::nullopt }).status.ok);
    REQUIRE_FALSE(LearningSession::PerformSaveWork(none, SaveWorkRequest{ "w1_stack_var", doc, false, 0, 0 }).status.ok);
    REQUIRE_FALSE(LearningSession::PerformGetSolution(none, "w1_stack_var", 0).status.ok);
    PublishSolutionRequest noRevision = pub;
    noRevision.id                     = 3;
    REQUIRE_FALSE(LearningSession::PerformPublishSolution(none, noRevision).status.ok);
    REQUIRE_FALSE(LearningSession::PerformDeleteSolution(none, 0).status.ok);
    REQUIRE(none.requests.empty());
    // a malformed 2xx is a protocol error, a transport failure stays one
    FakeTransport odd;
    odd.routes["/GView/SaveWork"] = [](const HttpRequest&) { return Response(200, R"({"status":"ok"})"); };
    auto o                        = LearningSession::PerformSaveWork(odd, SaveWorkRequest{ "w1_stack_var", doc, false, 0, std::nullopt });
    REQUIRE(o.error.code == ErrorCode::Protocol);
    odd.routes["/GView/GetWork"] = [](const HttpRequest&) { return TransportFailure(); };
    REQUIRE(LearningSession::PerformGetWork(odd, "w1_stack_var").error.code == ErrorCode::Transport);
}

TEST_CASE("Learning: solution and replay windows (pending document, roles, telemetry)", "[learning][work][session]")
{
    WorkFixture fx;
    REQUIRE(fx.Connect().ok);
    auto& s = *fx.session;
    int student = 0, solution = 0, replay = 0, other = 0; // stand-ins for GView::Object addresses

    REQUIRE_FALSE(s.SetPendingWorkDocument(WORK_DOC, WorkspaceRole::Solution)); // no pending binding
    ItemBinding b;
    b.item    = "w1_stack_var";
    b.problem = true;
    b.mode    = DeliveryMode::File;
    s.SetPendingBinding(b);
    s.OnObjectCreated(&student);

    s.SetPendingBinding(b);
    REQUIRE_FALSE(s.SetPendingWorkDocument(WORK_DOC, WorkspaceRole::Normal)); // Normal is never a binding
    REQUIRE(s.SetPendingWorkDocument(Canonical(WORK_DOC), WorkspaceRole::Solution));
    s.OnObjectCreated(&solution);
    s.SetPendingBinding(b);
    REQUIRE(s.SetPendingWorkDocument("{}", WorkspaceRole::Replay));
    s.OnObjectCreated(&replay);

    WorkspaceRole role = WorkspaceRole::Student;
    auto doc           = s.TakePendingWork(&solution, role);
    REQUIRE(role == WorkspaceRole::Solution);
    REQUIRE(doc == Canonical(WORK_DOC));
    doc = s.TakePendingWork(&solution, role); // taken once
    REQUIRE_FALSE(doc.has_value());
    REQUIRE(role == WorkspaceRole::Solution);
    REQUIRE(s.TakePendingWork(&replay, role) == std::string("{}"));
    REQUIRE(role == WorkspaceRole::Replay);
    REQUIRE_FALSE(s.TakePendingWork(&student, role).has_value());
    REQUIRE(role == WorkspaceRole::Student);
    REQUIRE_FALSE(s.TakePendingWork(&other, role).has_value());
    REQUIRE(role == WorkspaceRole::Normal);

    // telemetry: only the student's window produces item events
    if (auto pending = s.Telemetry().BeginBatch({}); pending.has_value())
        s.Telemetry().OnFlushResult(FlushOutcome::Accepted); // drop what connect / open recorded
    REQUIRE(s.Record(&student, EventType::JumpBack));
    REQUIRE_FALSE(s.Record(&solution, EventType::JumpBack));
    REQUIRE_FALSE(s.Record(&replay, EventType::CommentAdd));
    CatalogueItem item;
    item.name = "w1_stack_var";
    s.RecordItemOpened(item, DeliveryMode::File, 1, WorkspaceRole::Solution);
    s.RecordItemOpened(item, DeliveryMode::File, 1, WorkspaceRole::Replay);
    for (int i = 0; i < 3; i++)
    {
        fx.mono += 200;
        s.OnFrame(&solution, "Dissasm", true); // no viewer_open for the solution window
    }
    s.OnObjectClosed(&solution);
    s.OnObjectClosed(&replay);
    auto batch = s.Telemetry().BeginBatch({});
    REQUIRE(batch.has_value());
    INFO(*batch);
    REQUIRE(batch->find("\"type\":\"task_close\"") == std::string::npos);
    REQUIRE(batch->find("\"type\":\"task_open\"") == std::string::npos);
    REQUIRE(batch->find("\"type\":\"viewer_open\"") == std::string::npos);
    REQUIRE(batch->find("\"type\":\"jump_back\"") != std::string::npos);
    s.Telemetry().OnFlushResult(FlushOutcome::Accepted);
    s.OnObjectClosed(&student);
    batch = s.Telemetry().BeginBatch({});
    REQUIRE(batch.has_value());
    REQUIRE(batch->find("\"type\":\"task_close\"") != std::string::npos);
    s.Telemetry().OnFlushResult(FlushOutcome::Accepted);
    REQUIRE(s.OpenLearningWindows() == 0);
}

// ======================================================================== course work end-to-end (hidden)
// Stubs (HTTPS with the generated certificate pinned by the connection string: the desktop transport refuses plain
// HTTP outside DISSASM_DEV builds; fresh processes: their state is in memory):
//   python tools/learning_mode_stub_server.py --port 8781 --quiet --staff-token tok_STAFF_0123456789abcdef
//       GVIEW_LEARNING_STUB_CS        = its "connection string"
//       GVIEW_LEARNING_STUB_STAFF_CS  = its "staff connection" (same course: the student sees the published solution)
//                                       or the connection string of a stub started with --staff (staff part only)
//   python tools/learning_mode_stub_server.py --port 8783 --quiet --work off
//       GVIEW_LEARNING_STUB_WORK_OFF_CS (optional)
//   libGViewCore.exe "[integration][work]"
TEST_CASE("Learning: course work and solutions end-to-end against the stub server", "[.integration][learning][work]")
{
    LearningSettings settings;
    settings.allowPlainHttpLocalhost = true;
    auto connect = [&](LearningSession& s, const char* cs) {
        GView::Utils::GStatus result = GView::Utils::GStatus::Error("not called");
        REQUIRE(s.Connect(cs, settings, [&](const GView::Utils::GStatus& r) { result = r; }).ok);
        INFO(result.message);
        REQUIRE(result.ok);
    };
    auto makeSession = []() {
        LearningSession::Dependencies d;
        d.synchronous     = true;
        d.telemetryThread = false;
        return std::make_unique<LearningSession>(std::move(d));
    };
    auto directTransport = [](const char* cs, const Policy& policy) {
        ConnectionInfo ci;
        REQUIRE(ParseConnectionString(cs, true, ci).ok);
        auto t = CreateCurlTransport(TransportConfig{ ci.serverUrl, ci.token, ci.caPem, true, ClientVersion() });
        t->SetPolicyId(policy.id);
        return t;
    };
    auto serverOf = [](const char* cs) {
        ConnectionInfo ci;
        REQUIRE(ParseConnectionString(cs, true, ci).ok);
        return ci.serverUrl;
    };
    auto getWork = [](LearningSession& s, std::string_view problem) {
        WorkResult r;
        REQUIRE(s.GetWork(problem, [&](WorkResult& x) { r = std::move(x); }).ok);
        INFO(r.status.message);
        REQUIRE(r.status.ok);
        return r.response;
    };
    auto saveWork = [](LearningSession& s, const std::string& doc, bool replay, uint32 steps) {
        SaveWorkOutcome o;
        o.status = GView::Utils::GStatus::Error("not called");
        auto st  = s.SaveWork("w1_stack_var", doc, replay, steps, [&](const SaveWorkOutcome& x) { o = x; });
        if (!st.ok)
            o.status = st;
        return o;
    };
    auto publish = [](LearningSession& s, PublishSolutionRequest req) {
        PublishOutcome o;
        o.status = GView::Utils::GStatus::Error("not called");
        auto st  = s.PublishSolution(std::move(req), [&](const PublishOutcome& x) { o = x; });
        if (!st.ok)
            o.status = st;
        return o;
    };

    const char* studentCs = std::getenv("GVIEW_LEARNING_STUB_CS");
    const char* staffCs   = std::getenv("GVIEW_LEARNING_STUB_STAFF_CS");
    std::unique_ptr<LearningSession> student;
    std::unique_ptr<IHttpTransport> studentT;
    if (studentCs != nullptr && studentCs[0] != 0)
    {
        student = makeSession();
        auto& s = *student;
        connect(s, studentCs);
        REQUIRE(s.GetPolicy()->work.present);
        REQUIRE(s.GetPolicy()->work.enabled);
        REQUIRE(s.CanUseWork());
        REQUIRE_FALSE(s.CanPublishSolutions()); // Connect user.canPublishSolutions = false
        studentT = directTransport(studentCs, *s.GetPolicy());

        auto w = getWork(s, "w1_stack_var");
        REQUIRE_FALSE(w.hasWork); // a fresh stub
        REQUIRE_FALSE(w.canPublishSolutions);
        REQUIRE(w.audiences == std::vector<NoteAudience>{ NoteAudience::All, NoteAudience::G1, NoteAudience::G2 });
        REQUIRE(w.maxBytes == 2 * 1024 * 1024);

        // create, read back (Python re-serializes the document: the client's canonical text is the same)
        auto o = saveWork(s, WORK_DOC, true, 2);
        INFO(o.status.message);
        REQUIRE(o.status.ok);
        REQUIRE(o.result.created);
        REQUIRE(o.result.revision == 1);
        w = getWork(s, "w1_stack_var");
        REQUIRE(w.hasWork);
        REQUIRE(w.revision == 1);
        REQUIRE(w.document == Canonical(WORK_DOC));
        REQUIRE(w.hasReplay);
        REQUIRE(w.replaySteps == 2);
        REQUIRE(w.clientVersion == ClientVersion());

        // update (revision 1 => 2), the same update retried after a lost answer, a stale revision => 409
        o = saveWork(s, OtherDoc("second"), false, 0);
        REQUIRE(o.status.ok);
        REQUIRE(o.result.revision == 2);
        SaveWorkRequest retry{ "w1_stack_var", OtherDoc("second"), false, 0, 1 };
        auto direct = LearningSession::PerformSaveWork(*studentT, retry);
        REQUIRE(direct.status.ok);
        REQUIRE(direct.result.revision == 2);
        retry.document = OtherDoc("stale");
        direct         = LearningSession::PerformSaveWork(*studentT, retry);
        REQUIRE(direct.conflict);
        REQUIRE(direct.error.code == ErrorCode::Conflict);
        REQUIRE_FALSE(direct.error.retryable);
        retry.revision.reset(); // a create when work exists
        REQUIRE(LearningSession::PerformSaveWork(*studentT, retry).conflict);
        REQUIRE(s.WorkRevision("w1_stack_var") == 2);

        // the server's own checks: hidden problems, invalid documents, oversized bodies
        REQUIRE(LearningSession::PerformGetWork(*studentT, "w1_hidden").error.code == ErrorCode::NotFound);
        REQUIRE(LearningSession::PerformSaveWork(*studentT, SaveWorkRequest{ "w1_hidden", WORK_DOC, false, 0, std::nullopt }).error.code ==
                ErrorCode::NotFound);
        HttpRequest raw;
        raw.path = "/GView/SaveWork";
        raw.body = SecureString(R"({"problem":"w1_xor_key","document":{"format":"gview-disassembly-annotations","version":2}})");
        REQUIRE(WorkErrorFromResponse(studentT->Post(raw)).code == ErrorCode::BadRequest);
        raw.body = SecureString(R"({"problem":"w1_xor_key","document":[1]})");
        REQUIRE(WorkErrorFromResponse(studentT->Post(raw)).code == ErrorCode::BadRequest);
        const std::string big = R"({"problem":"w1_xor_key","document":{"format":"gview-disassembly-annotations","version":1,"pad":")" +
                                std::string(2 * 1024 * 1024 + 70 * 1024, 'a') + "\"}}";
        raw.body = SecureString(big.data(), big.size());
        REQUIRE(WorkErrorFromResponse(studentT->Post(raw)).code == ErrorCode::PayloadTooLarge);

        // a student can not publish: refused locally, and by the server
        PublishSolutionRequest pub;
        pub.problem  = "w1_stack_var";
        pub.document = WORK_DOC;
        REQUIRE_FALSE(publish(s, pub).status.ok);
        auto po = LearningSession::PerformPublishSolution(*studentT, pub);
        REQUIRE(po.error.code == ErrorCode::Forbidden);
        REQUIRE(LearningSession::PerformDeleteSolution(*studentT, 1).error.code == ErrorCode::Forbidden);
        REQUIRE(getWork(s, "w1_stack_var").solutions.empty());
    }
    else
        WARN("GVIEW_LEARNING_STUB_CS is not set: student work part skipped");

    if (staffCs != nullptr && staffCs[0] != 0)
    {
        auto staff = makeSession();
        auto& s    = *staff;
        connect(s, staffCs);
        REQUIRE(s.CanPublishSolutions()); // announced at connect
        REQUIRE(s.IsCourseStaff());
        auto w = getWork(s, "w1_stack_var");
        REQUIRE(w.canPublishSolutions);
        REQUIRE_FALSE(w.hasWork); // the staff token's own work (another subject)
        REQUIRE(getWork(s, "w1_hidden").solutions.empty()); // staff may open hidden problems

        PublishSolutionRequest pub;
        pub.problem     = "w1_stack_var";
        pub.audience    = NoteAudience::All;
        pub.document    = WORK_DOC;
        pub.hasReplay   = true;
        pub.replaySteps = 2;
        auto o          = publish(s, pub);
        INFO(o.status.message);
        REQUIRE(o.status.ok);
        REQUIRE(o.result.created);
        const int64 allId = o.result.id;
        REQUIRE(publish(s, pub).result.created == false); // the same create retried: 200, created false
        pub.document = OtherDoc("solution v2");
        o            = publish(s, pub);
        REQUIRE(o.conflict);
        REQUIRE(o.existingId == allId);
        REQUIRE(o.existingRevision == 1);
        pub.id       = o.existingId;
        pub.revision = o.existingRevision;
        o            = publish(s, pub);
        REQUIRE(o.status.ok);
        REQUIRE(o.result.revision == 2);
        o = publish(s, pub); // revision 1 again with the same content: the retried update
        REQUIRE(o.status.ok);
        pub.document = OtherDoc("solution v3");
        o            = publish(s, pub); // stale
        REQUIRE(o.conflict);
        REQUIRE(o.existingRevision == 2);

        // G2 (another lab group) and a disabled draft for G1
        PublishSolutionRequest g2 = pub;
        g2.id.reset();
        g2.revision.reset();
        g2.audience  = NoteAudience::G2;
        g2.hasReplay = false;
        o            = publish(s, g2);
        REQUIRE(o.status.ok);
        const int64 g2Id = o.result.id;
        PublishSolutionRequest draft = g2;
        draft.audience               = NoteAudience::G1;
        draft.enabled                = false;
        REQUIRE(publish(s, draft).status.ok);
        w = getWork(s, "w1_stack_var");
        REQUIRE(w.solutions.size() == 3); // staff see every one
        SolutionResult sol;
        REQUIRE(s.GetSolution("w1_stack_var", g2Id, [&](SolutionResult& x) { sol = std::move(x); }).ok);
        REQUIRE(sol.status.ok);
        REQUIRE(sol.solution.info.audience == NoteAudience::G2);

        if (student && serverOf(staffCs) == serverOf(studentCs))
        {
            // the student (group G1) sees the enabled solution of "all" only
            auto& st = *student;
            auto sw  = getWork(st, "w1_stack_var");
            REQUIRE(sw.solutions.size() == 1);
            REQUIRE(sw.solutions[0].id == allId);
            REQUIRE(sw.solutions[0].hasReplay);
            REQUIRE(sw.solutions[0].revision == 2);
            REQUIRE(st.GetSolution("w1_stack_var", std::nullopt, [&](SolutionResult& x) { sol = std::move(x); }).ok);
            INFO(sol.status.message);
            REQUIRE(sol.status.ok);
            REQUIRE(sol.solution.info.id == allId);
            REQUIRE(sol.solution.document == Canonical(OtherDoc("solution v2")));
            REQUIRE(st.GetSolution("w1_stack_var", g2Id, [&](SolutionResult& x) { sol = std::move(x); }).ok);
            REQUIRE(sol.error.code == ErrorCode::NotFound); // another group's solution can not be fetched by id
            // the catalogue announces it, with the student's own work
            REQUIRE(st.RefreshCatalogue(nullptr).ok);
            const auto* item = st.GetCatalogue().Find("w1_stack_var", true);
            REQUIRE(item != nullptr);
            REQUIRE(item->solutionAvailable);
            REQUIRE(item->solutionHasReplay);
            REQUIRE(item->me.workRevision == 2);
            REQUIRE(item->me.workSavedAt > 0);
            REQUIRE_FALSE(st.GetCatalogue().Find("w1_xor_key", true)->solutionAvailable);
        }
        else
            WARN("the staff stub is another server: the student's view of the solutions is not checked");

        DeleteSolutionOutcome d;
        REQUIRE(s.DeleteSolution(g2Id, [&](const DeleteSolutionOutcome& x) { d = x; }).ok);
        REQUIRE(d.status.ok);
        REQUIRE(s.DeleteSolution(g2Id, [&](const DeleteSolutionOutcome& x) { d = x; }).ok);
        REQUIRE(d.error.code == ErrorCode::NotFound);
        s.Shutdown();
    }
    else
        WARN("GVIEW_LEARNING_STUB_STAFF_CS is not set: staff part skipped");

    if (const char* cs = std::getenv("GVIEW_LEARNING_STUB_WORK_OFF_CS"); cs != nullptr && cs[0] != 0)
    {
        auto session = makeSession();
        auto& s      = *session;
        connect(s, cs);
        REQUIRE(s.GetWorkAvailability() == WorkAvailability::DisabledByPolicy);
        auto t = directTransport(cs, *s.GetPolicy());
        REQUIRE(LearningSession::PerformGetWork(*t, "w1_stack_var").error.code == ErrorCode::Forbidden);
        REQUIRE(LearningSession::PerformSaveWork(*t, SaveWorkRequest{ "w1_stack_var", WORK_DOC, false, 0, std::nullopt }).error.code ==
                ErrorCode::Forbidden);
        REQUIRE(LearningSession::PerformGetSolution(*t, "w1_stack_var", std::nullopt).error.code == ErrorCode::NotFound); // not gated
        s.Shutdown();
    }
    if (student)
        student->Shutdown();
}
