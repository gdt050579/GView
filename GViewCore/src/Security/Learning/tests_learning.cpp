// Unit tests for Learning and Evaluation Mode (plans/LEARNING_MODE_PROTOCOL_SPEC.md §8, T1-T8).
// No network: an in-process FakeTransport plays the course server; policies are signed with a fresh Ed25519 key.

#include <catch.hpp>

#include "Learning/LearningSession.hpp"

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

TEST_CASE("Learning: request headers", "[learning][protocol]")
{
    auto h = BuildRequestHeaders(Token(), "0.391.0", "");
    std::vector<std::string> v;
    for (auto& s : h)
        v.emplace_back(s.data(), s.size());
    REQUIRE(v.size() == 3);
    REQUIRE(v[0] == "XAppUserID: " + std::string(TEST_TOKEN));
    REQUIRE(v[1] == "X-GView-Client: 0.391.0");
    REQUIRE(v[2] == "X-GView-Protocol: 2");
    auto h2 = BuildRequestHeaders(Token(), "0.391.0", "pol_x");
    REQUIRE(h2.size() == 4);
    REQUIRE(std::string(h2[3].data(), h2[3].size()) == "X-GView-Policy: pol_x");
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
