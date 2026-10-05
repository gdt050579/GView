/**
 * Restricted-mode policy engine (Learning and Evaluation Mode)
 * - Policy v1 (file based) and v2 (course server) parsing with fail-closed validation
 * - Ed25519 signature verification via OpenSSL over the raw policy bytes
 * - Runtime enforcement state: feature mask, plugin whitelist, watermark
 * - Best-effort screen protection (capture exclusion + PrintScreen blocker on a dedicated hook thread)
 *
 * The policy itself is signed public data and is not kept in locked memory; secrets (access token, content key,
 * decrypted task content) are handled by GView::Security::Learning (LockedBuffer).
 */

#include "Internal.hpp"
#include <mutex>
#include <atomic>
#include <cstring>
#include <chrono>
#include <fstream>
#include <thread>
#include <condition_variable>
#include <algorithm>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/err.h>

// Platform-specific headers for screen protection
#ifdef BUILD_FOR_WINDOWS
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
#    include <Windows.h>
#elif defined(BUILD_FOR_OSX) || defined(BUILD_FOR_UNIX)
#    include <unistd.h>
#    ifdef BUILD_FOR_UNIX
#        include <sys/prctl.h>
#    endif
#endif

// JSON parsing
#include <nlohmann/json.hpp>

namespace GView::Security::RestrictedMode
{
namespace
{
    struct FeatureName {
        Feature feature;
        std::string_view name;
    };
    constexpr FeatureName FEATURE_NAMES[] = {
        { Feature::Copy, "Copy" },           { Feature::Export, "Export" },       { Feature::SaveAs, "SaveAs" },
        { Feature::Plugins, "Plugins" },     { Feature::LLMHints, "LLMHints" },   { Feature::Clipboard, "Clipboard" },
        { Feature::Screenshots, "Screenshots" },
    };

    constexpr size_t MAX_POLICY_FILE_SIZE     = 64 * 1024;
    constexpr size_t MAX_POLICY_ID_LENGTH     = 64;
    constexpr size_t MAX_POLICY_TEXT_LENGTH   = 256;
    constexpr size_t MAX_WATERMARK_LENGTH     = 128;
    constexpr size_t MAX_PLUGIN_NAME_LENGTH   = 64;
    constexpr size_t MAX_ALLOWED_PLUGINS      = 256;
    constexpr std::string_view CONTENT_ENCRYPTION_V1 = "aes-256-gcm-hkdf-v1";

    // Thread-safe global state
    std::mutex g_policyMutex;
    std::atomic<bool> g_isActive{ false };
    std::atomic<uint32> g_featureMask{ 0 };
    Policy g_policy; // guarded by g_policyMutex

    Utils::GStatus Fail(std::string_view code, std::string_view details)
    {
        std::string msg;
        msg.reserve(code.size() + 2 + details.size());
        msg.append(code);
        msg.append(": ");
        msg.append(details);
        return Utils::GStatus::Error(std::move(msg));
    }

    // ------------------------------------------------------------------------
    // Screen protection
    // ------------------------------------------------------------------------
#ifdef BUILD_FOR_WINDOWS
    std::atomic<bool> g_blockCaptureKeys{ false };

    LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) noexcept
    {
        if (nCode == HC_ACTION && g_blockCaptureKeys.load(std::memory_order_acquire))
        {
            const KBDLLHOOKSTRUCT* pKeyboard = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
            if (pKeyboard != nullptr)
            {
                // Block Print Screen key (all variants: plain, Alt+PrtSc, Win+PrtSc)
                if (pKeyboard->vkCode == VK_SNAPSHOT)
                    return 1;
                // Block Win+Shift+S (Snipping Tool / Snip & Sketch)
                const bool winDown   = (GetAsyncKeyState(VK_LWIN) & 0x8000) || (GetAsyncKeyState(VK_RWIN) & 0x8000);
                const bool shiftDown = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                if (pKeyboard->vkCode == 'S' && winDown && shiftDown)
                    return 1;
            }
        }
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }

    // A low-level keyboard hook is called in the context of the thread that installed it, and that thread MUST pump
    // messages, otherwise every keystroke in the whole session stalls until the hook times out. GView's UI thread
    // reads console input and does not pump window messages, so the hook lives on its own thread.
    class KeyboardHookThread
    {
        std::thread worker;
        DWORD threadId{ 0 };
        bool running{ false };

      public:
        bool Start() noexcept
        {
            if (running)
                return true;
            try
            {
                std::mutex m;
                std::condition_variable cv;
                bool ready     = false;
                bool installed = false;
                worker         = std::thread([&]() {
                    MSG msg;
                    // force the creation of the thread message queue before signalling readiness
                    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
                    HMODULE self = nullptr;
                    GetModuleHandleExW(
                          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          reinterpret_cast<LPCWSTR>(&LowLevelKeyboardProc),
                          &self);
                    HHOOK hook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, self, 0);
                    {
                        std::lock_guard<std::mutex> lk(m);
                        threadId  = GetCurrentThreadId();
                        installed = hook != nullptr;
                        ready     = true;
                    }
                    cv.notify_one();
                    if (hook == nullptr)
                        return;
                    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
                    {
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                    UnhookWindowsHookEx(hook);
                });
                std::unique_lock<std::mutex> lk(m);
                cv.wait(lk, [&]() { return ready; });
                if (!installed)
                {
                    lk.unlock();
                    worker.join();
                    return false;
                }
                running = true;
                return true;
            }
            catch (...)
            {
                if (worker.joinable())
                    worker.join();
                return false;
            }
        }
        void Stop() noexcept
        {
            if (!running)
                return;
            PostThreadMessageW(threadId, WM_QUIT, 0, 0);
            if (worker.joinable())
                worker.join();
            running  = false;
            threadId = 0;
        }
        bool IsRunning() const noexcept
        {
            return running;
        }
    };
    KeyboardHookThread g_keyboardHook; // guarded by g_policyMutex

    std::vector<HWND> g_protectedWindows; // guarded by g_policyMutex

    BOOL CALLBACK CollectOwnTopLevelWindows(HWND hwnd, LPARAM lParam) noexcept
    {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == GetCurrentProcessId() && IsWindowVisible(hwnd))
        {
            auto* list = reinterpret_cast<std::vector<HWND>*>(lParam);
            try
            {
                list->push_back(hwnd);
            }
            catch (...)
            {
                return FALSE;
            }
        }
        return TRUE;
    }
#endif

    struct ScreenProtectionResult {
        bool applied{ false };
        bool keyboardHook{ false };
        std::string note;
    };

    // must be called with g_policyMutex held
    ScreenProtectionResult ApplyScreenProtectionLocked() noexcept
    {
        ScreenProtectionResult r;
#ifdef BUILD_FOR_WINDOWS
        r.keyboardHook = g_keyboardHook.Start();
        g_blockCaptureKeys.store(r.keyboardHook, std::memory_order_release);

        std::vector<HWND> candidates;
        try
        {
            EnumWindows(CollectOwnTopLevelWindows, reinterpret_cast<LPARAM>(&candidates));
            if (HWND console = GetConsoleWindow(); console != nullptr)
            {
                if (std::find(candidates.begin(), candidates.end(), console) == candidates.end())
                    candidates.push_back(console);
            }
        }
        catch (...)
        {
        }
        uint32 protectedCount = 0;
        for (HWND hwnd : candidates)
        {
            if (std::find(g_protectedWindows.begin(), g_protectedWindows.end(), hwnd) != g_protectedWindows.end())
            {
                protectedCount++;
                continue;
            }
            if (Internal::EnableWindowScreenProtection(hwnd).ok)
            {
                try
                {
                    g_protectedWindows.push_back(hwnd);
                }
                catch (...)
                {
                }
                protectedCount++;
            }
        }
        r.applied = protectedCount > 0;
        if (!r.applied)
        {
            // SetWindowDisplayAffinity only works on windows owned by the calling process. A console window belongs to
            // conhost.exe / Windows Terminal, so the Windows console frontend cannot be excluded from capture.
            r.note = "Windows console frontend: the terminal window is owned by another process, capture exclusion unavailable";
        }
        else
        {
            r.note = "Windows: capture exclusion (SetWindowDisplayAffinity) applied";
        }
        if (!r.keyboardHook)
            r.note += "; PrintScreen blocker could not be installed";
        else
            r.note += "; PrintScreen/Win+Shift+S blocked";
#elif defined(BUILD_FOR_UNIX)
        // There is no portable capture-exclusion API on X11/Wayland. Only prevent core dumps of a process holding task
        // content; this is NOT screen protection and is reported as such.
        Internal::EnableWindowScreenProtection(nullptr);
        r.note = "Linux: screen capture cannot be prevented (core dumps disabled only)";
#elif defined(BUILD_FOR_OSX)
        r.note = "macOS: screen capture protection is not implemented for the terminal frontend";
#else
        r.note = "Unsupported platform: no screen protection";
#endif
        return r;
    }

    // must be called with g_policyMutex held
    void RemoveScreenProtectionLocked() noexcept
    {
#ifdef BUILD_FOR_WINDOWS
        g_blockCaptureKeys.store(false, std::memory_order_release);
        g_keyboardHook.Stop();
        for (HWND hwnd : g_protectedWindows)
            Internal::DisableWindowScreenProtection(hwnd);
        g_protectedWindows.clear();
#elif defined(BUILD_FOR_UNIX)
        Internal::DisableWindowScreenProtection(nullptr);
#endif
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------
    std::string GetOpenSSLError() noexcept
    {
        try
        {
            unsigned long err = ERR_get_error();
            if (err == 0)
                return "Unknown OpenSSL error";
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            return std::string(buf);
        }
        catch (...)
        {
            return {};
        }
    }

    bool ReadFileToVector(const std::filesystem::path& path, std::vector<uint8_t>& out) noexcept
    {
        try
        {
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file.is_open())
                return false;
            const auto size = file.tellg();
            if (size <= 0 || static_cast<uint64_t>(size) > MAX_POLICY_FILE_SIZE)
                return false;
            out.resize(static_cast<size_t>(size));
            file.seekg(0);
            file.read(reinterpret_cast<char*>(out.data()), size);
            return file.good();
        }
        catch (...)
        {
            return false;
        }
    }

    bool IsLowerHex(std::string_view s) noexcept
    {
        for (char c : s)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        }
        return true;
    }

    bool HasControlCharacters(std::string_view s) noexcept
    {
        for (unsigned char c : s)
        {
            if (c < 0x20 || c == 0x7F)
                return true;
        }
        return false;
    }

    bool IsValidIdentifier(std::string_view s, size_t maxLen) noexcept
    {
        if (s.empty() || s.size() > maxLen)
            return false;
        for (char c : s)
        {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
                return false;
        }
        return true;
    }

    // --- strict JSON accessors: a present field with the wrong type is an error (fail closed) ---
    using json = nlohmann::json;

    Utils::GStatus ReadString(const json& j, const char* key, std::string& out, bool required, size_t maxLen)
    {
        auto it = j.find(key);
        if (it == j.end() || it->is_null())
        {
            if (required)
                return Fail("POLICY_MALFORMED", std::string("missing field '") + key + "'");
            return Utils::GStatus::Ok();
        }
        if (!it->is_string())
            return Fail("POLICY_MALFORMED", std::string("field '") + key + "' must be a string");
        const auto& s = it->get_ref<const std::string&>();
        if (s.size() > maxLen)
            return Fail("POLICY_MALFORMED", std::string("field '") + key + "' is too long");
        if (HasControlCharacters(s))
            return Fail("POLICY_MALFORMED", std::string("field '") + key + "' contains control characters");
        out = s;
        return Utils::GStatus::Ok();
    }

    Utils::GStatus ReadUInt(const json& j, const char* key, uint64_t& out, bool required)
    {
        auto it = j.find(key);
        if (it == j.end() || it->is_null())
        {
            if (required)
                return Fail("POLICY_MALFORMED", std::string("missing field '") + key + "'");
            return Utils::GStatus::Ok();
        }
        if (it->is_number_unsigned())
        {
            out = it->get<uint64_t>();
            return Utils::GStatus::Ok();
        }
        if (it->is_number_integer())
        {
            const auto v = it->get<int64_t>();
            if (v < 0)
                return Fail("POLICY_MALFORMED", std::string("field '") + key + "' must be non-negative");
            out = static_cast<uint64_t>(v);
            return Utils::GStatus::Ok();
        }
        return Fail("POLICY_MALFORMED", std::string("field '") + key + "' must be an integer");
    }

    Utils::GStatus ReadBool(const json& j, const char* key, bool& out)
    {
        auto it = j.find(key);
        if (it == j.end() || it->is_null())
            return Utils::GStatus::Ok();
        if (!it->is_boolean())
            return Fail("POLICY_MALFORMED", std::string("field '") + key + "' must be a boolean");
        out = it->get<bool>();
        return Utils::GStatus::Ok();
    }

    uint32 ClampToRange(uint64_t v, uint32 lo, uint32 hi) noexcept
    {
        if (v < lo)
            return lo;
        if (v > hi)
            return hi;
        return static_cast<uint32>(v);
    }

#define POLICY_TRY(expr)                                                                                                                   \
    do {                                                                                                                                   \
        auto _st = (expr);                                                                                                                 \
        if (!_st.ok)                                                                                                                       \
            return _st;                                                                                                                    \
    } while (false)

    Utils::GStatus ParsePolicyJsonImpl(const json& j, bool requireSchema2, Policy& p)
    {
        if (!j.is_object())
            return Fail("POLICY_MALFORMED", "policy must be a JSON object");

        uint64_t schema = 1;
        POLICY_TRY(ReadUInt(j, "schema", schema, requireSchema2));
        if (schema != 1 && schema != 2)
            return Fail("POLICY_SCHEMA_UNSUPPORTED", "schema " + std::to_string(schema) + " is not supported (max 2)");
        if (requireSchema2 && schema != 2)
            return Fail("POLICY_SCHEMA_UNSUPPORTED", "course server policies must use schema 2");
        p.schema = static_cast<uint32>(schema);
        const bool v2 = schema == 2;

        POLICY_TRY(ReadString(j, "id", p.id, v2, MAX_POLICY_ID_LENGTH));
        if (v2 && !IsValidIdentifier(p.id, MAX_POLICY_ID_LENGTH))
            return Fail("POLICY_MALFORMED", "invalid policy id");
        POLICY_TRY(ReadString(j, "digest", p.digest, v2, 64));
        if (v2 && (p.digest.size() != 64 || !IsLowerHex(p.digest)))
            return Fail("POLICY_MALFORMED", "digest must be 64 lowercase hex characters");
        POLICY_TRY(ReadString(j, "purpose", p.purpose, false, MAX_POLICY_TEXT_LENGTH));
        POLICY_TRY(ReadUInt(j, "issuedAt", p.issuedAt, false));
        POLICY_TRY(ReadUInt(j, "startsAt", p.startsAt, v2));
        POLICY_TRY(ReadUInt(j, "endsAt", p.endsAt, v2));
        if (v2 && p.endsAt == 0)
            return Fail("POLICY_MALFORMED", "endsAt must be set");
        if (p.endsAt != 0 && p.endsAt < p.startsAt)
            return Fail("POLICY_MALFORMED", "endsAt precedes startsAt");
        POLICY_TRY(ReadString(j, "subject", p.subject, v2, 16));
        if (v2 && (p.subject.size() != 16 || !IsLowerHex(p.subject)))
            return Fail("POLICY_MALFORMED", "subject must be 16 lowercase hex characters");
        POLICY_TRY(ReadString(j, "serverUrl", p.serverUrl, false, 512));

        // features: unknown names are rejected (never silently ignored in a restricted context)
        p.disabledFeatures.clear();
        if (auto it = j.find("disabledFeatures"); it != j.end() && !it->is_null())
        {
            if (!it->is_array())
                return Fail("POLICY_MALFORMED", "disabledFeatures must be an array");
            for (const auto& f : *it)
            {
                if (!f.is_string())
                    return Fail("POLICY_MALFORMED", "disabledFeatures entries must be strings");
                Feature feat;
                if (!Internal::ParseFeature(f.get_ref<const std::string&>(), feat))
                    return Fail("POLICY_MALFORMED", "unknown feature '" + f.get<std::string>().substr(0, 32) + "'");
                if (std::find(p.disabledFeatures.begin(), p.disabledFeatures.end(), feat) == p.disabledFeatures.end())
                    p.disabledFeatures.push_back(feat);
            }
        }

        p.allowedPlugins.clear();
        if (auto it = j.find("allowedPlugins"); it != j.end() && !it->is_null())
        {
            if (!it->is_array())
                return Fail("POLICY_MALFORMED", "allowedPlugins must be an array");
            if (it->size() > MAX_ALLOWED_PLUGINS)
                return Fail("POLICY_MALFORMED", "allowedPlugins has too many entries");
            for (const auto& pl : *it)
            {
                if (!pl.is_string() || !IsValidIdentifier(pl.get_ref<const std::string&>(), MAX_PLUGIN_NAME_LENGTH))
                    return Fail("POLICY_MALFORMED", "invalid plugin name in allowedPlugins");
                p.allowedPlugins.push_back(pl.get<std::string>());
            }
        }

        std::string storageMode = "file";
        POLICY_TRY(ReadString(j, "storageMode", storageMode, false, 16));
        if (storageMode == "file")
            p.storageMode = StorageMode::File;
        else if (storageMode == "memory")
            p.storageMode = StorageMode::Memory;
        else
            return Fail("POLICY_MALFORMED", "storageMode must be 'file' or 'memory'");

        POLICY_TRY(ReadString(j, "watermark", p.watermark, false, MAX_WATERMARK_LENGTH));
        POLICY_TRY(ReadBool(j, "bestEffortScreenProtect", p.bestEffortScreenProtect));
        POLICY_TRY(ReadBool(j, "requireScreenProtect", p.requireScreenProtect));

        if (auto it = j.find("telemetry"); it != j.end() && !it->is_null())
        {
            if (!it->is_object())
                return Fail("POLICY_MALFORMED", "telemetry must be an object");
            uint64_t v = 0;
            POLICY_TRY(ReadBool(*it, "enabled", p.telemetry.enabled));
            v = p.telemetry.flushIntervalSeconds;
            POLICY_TRY(ReadUInt(*it, "flushIntervalSeconds", v, false));
            p.telemetry.flushIntervalSeconds = ClampToRange(v, 5, 3600);
            v                                = p.telemetry.maxBatchEvents;
            POLICY_TRY(ReadUInt(*it, "maxBatchEvents", v, false));
            p.telemetry.maxBatchEvents = ClampToRange(v, 1, 5000);
            v                          = p.telemetry.idleThresholdSeconds;
            POLICY_TRY(ReadUInt(*it, "idleThresholdSeconds", v, false));
            p.telemetry.idleThresholdSeconds = ClampToRange(v, 10, 86400);
            POLICY_TRY(ReadBool(*it, "eventLevel", p.telemetry.eventLevel));
        }

        if (auto it = j.find("submission"); it != j.end() && !it->is_null())
        {
            if (!it->is_object())
                return Fail("POLICY_MALFORMED", "submission must be an object");
            POLICY_TRY(ReadBool(*it, "allowInTool", p.submission.allowInTool));
            POLICY_TRY(ReadBool(*it, "requireExplanation", p.submission.requireExplanation));
            uint64_t v = p.submission.explanationMaxChars;
            POLICY_TRY(ReadUInt(*it, "explanationMaxChars", v, false));
            p.submission.explanationMaxChars = ClampToRange(v, 0, 100000);
        }

        std::string keyIdHex;
        POLICY_TRY(ReadString(j, "contentKeyId", keyIdHex, false, 16));
        POLICY_TRY(ReadString(j, "contentEncryption", p.contentEncryption, false, 32));
        p.contentKeyId.clear();
        if (!keyIdHex.empty())
        {
            if (keyIdHex.size() != 16 || !IsLowerHex(keyIdHex))
                return Fail("POLICY_MALFORMED", "contentKeyId must be 16 lowercase hex characters");
            for (size_t i = 0; i < keyIdHex.size(); i += 2)
            {
                auto nib = [](char c) -> uint8_t { return static_cast<uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10); };
                p.contentKeyId.push_back(static_cast<uint8_t>((nib(keyIdHex[i]) << 4) | nib(keyIdHex[i + 1])));
            }
        }
        if (!p.contentEncryption.empty() && p.contentEncryption != CONTENT_ENCRYPTION_V1)
            return Fail("POLICY_MALFORMED", "unsupported contentEncryption");
        if (v2 && p.storageMode == StorageMode::Memory && (p.contentEncryption.empty() || p.contentKeyId.empty()))
            return Fail("POLICY_MALFORMED", "memory storage mode requires contentEncryption and contentKeyId");
        if (!p.contentEncryption.empty() && p.contentKeyId.empty())
            return Fail("POLICY_MALFORMED", "contentEncryption requires contentKeyId");
        return Utils::GStatus::Ok();
    }

    Utils::GStatus ValidateTimeWindow(const Policy& policy, uint64_t now, uint64_t skew) noexcept
    {
        if (policy.startsAt > 0 && now + skew < policy.startsAt)
            return Fail("POLICY_NOT_STARTED", "policy is not active yet");
        if (policy.endsAt > 0 && now > policy.endsAt + skew)
            return Fail("POLICY_EXPIRED", "policy has expired");
        return Utils::GStatus::Ok();
    }

    uint64_t NowSeconds() noexcept
    {
        return static_cast<uint64_t>(
              std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }

    uint32 ComputeMask(const std::vector<Feature>& features) noexcept
    {
        uint32 mask = 0;
        for (auto f : features)
            mask |= static_cast<uint32>(f);
        return mask;
    }

    std::string NormalizeUrl(std::string_view url)
    {
        std::string r(url);
        while (!r.empty() && r.back() == '/')
            r.pop_back();
        // lowercase scheme and authority (everything up to the first '/' after "://")
        auto schemeEnd    = r.find("://");
        size_t authorityE = r.size();
        if (schemeEnd != std::string::npos)
        {
            auto slash = r.find('/', schemeEnd + 3);
            if (slash != std::string::npos)
                authorityE = slash;
        }
        for (size_t i = 0; i < authorityE; i++)
        {
            if (r[i] >= 'A' && r[i] <= 'Z')
                r[i] = static_cast<char>(r[i] - 'A' + 'a');
        }
        return r;
    }

} // anonymous namespace

// ============================================================================
// Public API Implementation
// ============================================================================

CORE_EXPORT Utils::GStatus LoadPolicyFromFiles(
      const std::filesystem::path& jsonPath,
      const std::filesystem::path& signaturePath,
      const std::vector<uint8_t>& publicKey,
      Policy& outPolicy) noexcept
{
    if (publicKey.size() != 32)
        return Utils::GStatus::Error("Invalid public key size (expected 32 bytes for Ed25519)");

    std::vector<uint8_t> jsonData;
    if (!ReadFileToVector(jsonPath, jsonData))
        return Utils::GStatus::Error("Failed to read policy JSON file");
    std::vector<uint8_t> signature;
    if (!ReadFileToVector(signaturePath, signature))
        return Utils::GStatus::Error("Failed to read signature file");
    if (signature.size() != 64)
        return Utils::GStatus::Error("Invalid signature size (expected 64 bytes for Ed25519)");

    const BufferView raw(jsonData.data(), jsonData.size());
    auto sig = Internal::VerifyEd25519(raw, BufferView(signature.data(), signature.size()), BufferView(publicKey.data(), publicKey.size()));
    if (!sig.ok)
        return sig;

    Policy parsed;
    auto parseResult = Internal::ParsePolicyDocument(raw, false, parsed);
    if (!parseResult.ok)
        return parseResult;
    if (parsed.schema == 2)
    {
        auto dig = Internal::VerifyPolicyDigest(raw, parsed.digest);
        if (!dig.ok)
            return dig;
    }
    auto timeResult = ValidateTimeWindow(parsed, NowSeconds(), POLICY_CLOCK_SKEW_SECONDS);
    if (!timeResult.ok)
        return timeResult;
    outPolicy = std::move(parsed);
    return Utils::GStatus::Ok();
}

CORE_EXPORT Utils::GStatus VerifyAndParsePolicy(
      BufferView rawJson,
      BufferView signature,
      BufferView publicKey,
      std::string_view expectedSubjectHex,
      std::string_view expectedServerUrl,
      uint64_t nowSeconds,
      Policy& outPolicy) noexcept
{
    try
    {
        if (publicKey.GetLength() != 32)
            return Fail("POLICY_KEY_MISSING", "no valid Ed25519 policy public key (expected 32 bytes)");
        if (rawJson.GetLength() == 0 || rawJson.GetLength() > MAX_POLICY_FILE_SIZE)
            return Fail("POLICY_MALFORMED", "policy size out of bounds");
        // 1. signature over the exact bytes, before any parsing
        auto sig = Internal::VerifyEd25519(rawJson, signature, publicKey);
        if (!sig.ok)
            return sig;
        // 2. schema + structure
        Policy parsed;
        auto st = Internal::ParsePolicyDocument(rawJson, true, parsed);
        if (!st.ok)
            return st;
        // 3. digest (reproducibility marker, cross-checked)
        st = Internal::VerifyPolicyDigest(rawJson, parsed.digest);
        if (!st.ok)
            return st;
        // 4. subject binding
        if (expectedSubjectHex.size() != parsed.subject.size() ||
            !Crypto::Internal::ConstantTimeEquals(expectedSubjectHex.data(), parsed.subject.data(), parsed.subject.size()))
            return Fail("POLICY_SUBJECT_MISMATCH", "policy was issued for a different access token");
        // 5. server binding (additional check, see "Deviations" in the implementation report)
        if (!parsed.serverUrl.empty() && !expectedServerUrl.empty() && NormalizeUrl(parsed.serverUrl) != NormalizeUrl(expectedServerUrl))
            return Fail("POLICY_SERVER_MISMATCH", "policy was issued by a different server");
        // 6. validity window with clock skew
        st = ValidateTimeWindow(parsed, nowSeconds, POLICY_CLOCK_SKEW_SECONDS);
        if (!st.ok)
            return st;
        outPolicy = std::move(parsed);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Fail("POLICY_MALFORMED", "unexpected error while validating the policy");
    }
}

CORE_EXPORT bool IsActive() noexcept
{
    return g_isActive.load(std::memory_order_acquire);
}

CORE_EXPORT std::optional<Policy> GetCurrentPolicy()
{
    std::lock_guard<std::mutex> lock(g_policyMutex);
    if (!g_isActive.load(std::memory_order_acquire))
        return std::nullopt;
    return g_policy;
}

CORE_EXPORT bool IsFeatureDisabled(Feature feature) noexcept
{
    if (!g_isActive.load(std::memory_order_acquire))
        return false;
    return (g_featureMask.load(std::memory_order_acquire) & static_cast<uint32>(feature)) != 0;
}

CORE_EXPORT std::string_view FeatureToString(Feature feature) noexcept
{
    for (const auto& f : FEATURE_NAMES)
    {
        if (f.feature == feature)
            return f.name;
    }
    return "Unknown";
}

} // namespace GView::Security::RestrictedMode

// ============================================================================
// Internal API (declared in Internal.hpp, used by GViewCore)
// ============================================================================

namespace GView::Security::RestrictedMode::Internal
{

bool ParseFeature(std::string_view name, Feature& out) noexcept
{
    for (const auto& f : FEATURE_NAMES)
    {
        if (f.name == name)
        {
            out = f.feature;
            return true;
        }
    }
    return false;
}

Utils::GStatus VerifyEd25519(BufferView message, BufferView signature, BufferView publicKey) noexcept
{
    if (publicKey.GetLength() != 32 || publicKey.GetData() == nullptr)
        return Fail("POLICY_KEY_MISSING", "invalid Ed25519 public key size");
    if (signature.GetLength() != 64 || signature.GetData() == nullptr)
        return Fail("POLICY_SIGNATURE_INVALID", "invalid Ed25519 signature size");
    if (message.GetData() == nullptr && message.GetLength() != 0)
        return Fail("POLICY_SIGNATURE_INVALID", "invalid message");

    struct PKeyDeleter {
        void operator()(EVP_PKEY* k) const noexcept
        {
            EVP_PKEY_free(k);
        }
    };
    struct MdCtxDeleter {
        void operator()(EVP_MD_CTX* c) const noexcept
        {
            EVP_MD_CTX_free(c);
        }
    };
    std::unique_ptr<EVP_PKEY, PKeyDeleter> pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey.GetData(), publicKey.GetLength()));
    if (!pkey)
        return Fail("POLICY_KEY_MISSING", "public key rejected by OpenSSL: " + GetOpenSSLError());
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> mdctx(EVP_MD_CTX_new());
    if (!mdctx)
        return Fail("POLICY_SIGNATURE_INVALID", "EVP_MD_CTX_new failed");
    if (EVP_DigestVerifyInit(mdctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1)
        return Fail("POLICY_SIGNATURE_INVALID", "EVP_DigestVerifyInit failed: " + GetOpenSSLError());
    static const uint8 empty = 0;
    const uint8* msg         = message.GetData() != nullptr ? message.GetData() : &empty;
    if (EVP_DigestVerify(mdctx.get(), signature.GetData(), signature.GetLength(), msg, message.GetLength()) != 1)
    {
        ERR_clear_error();
        return Fail("POLICY_SIGNATURE_INVALID", "Ed25519 signature verification failed");
    }
    return Utils::GStatus::Ok();
}

Utils::GStatus ParsePolicyDocument(BufferView raw, bool requireSchema2, Policy& out) noexcept
{
    try
    {
        if (raw.GetLength() == 0 || raw.GetData() == nullptr)
            return Fail("POLICY_MALFORMED", "empty policy");
        auto j = json::parse(raw.GetData(), raw.GetData() + raw.GetLength());
        Policy p;
        auto st = ParsePolicyJsonImpl(j, requireSchema2, p);
        if (!st.ok)
            return st;
        out = std::move(p);
        return Utils::GStatus::Ok();
    }
    catch (const json::exception& e)
    {
        return Fail("POLICY_MALFORMED", std::string("JSON parse error: ") + e.what());
    }
    catch (...)
    {
        return Fail("POLICY_MALFORMED", "unknown error parsing policy");
    }
}

Utils::GStatus VerifyPolicyDigest(BufferView raw, std::string_view digestHex) noexcept
{
    try
    {
        if (digestHex.size() != 64 || !IsLowerHex(digestHex))
            return Fail("POLICY_DIGEST_MISMATCH", "digest is not a sha256 hex string");
        // The server hashes the document serialised with "digest":"" and then embeds the digest value. Reconstruct the
        // hashed bytes by blanking the (unique) digest value. Both compact and ": " separators are accepted.
        std::string_view doc(reinterpret_cast<const char*>(raw.GetData()), raw.GetLength());
        const std::string patterns[] = { std::string("\"digest\":\"").append(digestHex).append("\""),
                                         std::string("\"digest\": \"").append(digestHex).append("\"") };
        size_t foundAt = std::string_view::npos, foundLen = 0, occurrences = 0;
        for (const auto& pat : patterns)
        {
            for (size_t pos = doc.find(pat); pos != std::string_view::npos; pos = doc.find(pat, pos + 1))
            {
                occurrences++;
                foundAt  = pos;
                foundLen = pat.size();
            }
        }
        if (occurrences != 1)
            return Fail("POLICY_DIGEST_MISMATCH", "digest field must appear exactly once");
        std::string blanked;
        blanked.reserve(doc.size());
        blanked.append(doc.substr(0, foundAt));
        // keep the separator exactly as received, drop only the 64 hex characters
        const auto& keyPart = foundLen == patterns[0].size() ? std::string_view("\"digest\":\"\"") : std::string_view("\"digest\": \"\"");
        blanked.append(keyPart);
        blanked.append(doc.substr(foundAt + foundLen));

        uint8_t hash[32];
        auto st = Crypto::Internal::ComputeSHA256(BufferView(blanked.data(), blanked.size()), hash);
        if (!st.ok)
            return Fail("POLICY_DIGEST_MISMATCH", st.message);
        static constexpr char HEX[] = "0123456789abcdef";
        char computed[64];
        for (size_t i = 0; i < 32; i++)
        {
            computed[i * 2]     = HEX[hash[i] >> 4];
            computed[i * 2 + 1] = HEX[hash[i] & 0x0F];
        }
        if (!Crypto::Internal::ConstantTimeEquals(computed, digestHex.data(), 64))
            return Fail("POLICY_DIGEST_MISMATCH", "policy digest does not match its content");
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Fail("POLICY_DIGEST_MISMATCH", "unexpected error while checking the digest");
    }
}

Utils::GStatus Activate(const Policy& policy, ActivationReport& report) noexcept
{
    try
    {
        report = ActivationReport{};
        auto timeResult = ValidateTimeWindow(policy, NowSeconds(), POLICY_CLOCK_SKEW_SECONDS);
        if (!timeResult.ok)
            return timeResult;

        Policy copy = policy; // allocate before taking the lock / changing any state
        std::lock_guard<std::mutex> lock(g_policyMutex);

        const bool screenRequested = policy.requireScreenProtect || policy.bestEffortScreenProtect ||
                                     (ComputeMask(policy.disabledFeatures) & static_cast<uint32>(Feature::Screenshots)) != 0;
        report.screenProtectRequested = screenRequested;
        if (screenRequested)
        {
            auto sp                       = ApplyScreenProtectionLocked();
            report.screenProtectApplied   = sp.applied;
            report.keyboardHookInstalled  = sp.keyboardHook;
            report.platformNote           = std::move(sp.note);
        }
        else
        {
            // a newer policy may relax protections that an older one requested
            RemoveScreenProtectionLocked();
            report.platformNote = "screen protection not requested by policy";
        }

        report.applied = copy.disabledFeatures;
        g_policy       = std::move(copy);
        g_featureMask.store(ComputeMask(g_policy.disabledFeatures), std::memory_order_release);
        g_isActive.store(true, std::memory_order_release);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("Failed to activate policy (out of memory)");
    }
}

void Deactivate() noexcept
{
    std::lock_guard<std::mutex> lock(g_policyMutex);
    g_isActive.store(false, std::memory_order_release);
    g_featureMask.store(0, std::memory_order_release);
    RemoveScreenProtectionLocked();
    g_policy = Policy{};
}

bool IsFeatureDisabled(Feature feature) noexcept
{
    return RestrictedMode::IsFeatureDisabled(feature);
}

bool IsPluginAllowed(std::string_view pluginName) noexcept
{
    if (!g_isActive.load(std::memory_order_acquire))
        return true; // All plugins allowed when not in restricted mode
    if ((g_featureMask.load(std::memory_order_acquire) & static_cast<uint32>(Feature::Plugins)) == 0)
        return true; // no whitelist requested

    std::lock_guard<std::mutex> lock(g_policyMutex);
    for (const auto& allowed : g_policy.allowedPlugins)
    {
        if (allowed.size() == pluginName.size() && AppCUI::Utils::String::StartsWith(allowed, pluginName, true))
            return true;
    }
    return false;
}

std::string GetWatermark()
{
    std::lock_guard<std::mutex> lock(g_policyMutex);
    if (!g_isActive.load(std::memory_order_acquire))
        return "";
    return g_policy.watermark;
}

Utils::GStatus EnableWindowScreenProtection(void* nativeWindowHandle) noexcept
{
#ifdef BUILD_FOR_WINDOWS
    if (nativeWindowHandle == nullptr)
        return Utils::GStatus::Error("ScreenProtect: null HWND");

    HWND hwnd = static_cast<HWND>(nativeWindowHandle);
    // WDA_EXCLUDEFROMCAPTURE = 0x11 (Windows 10 2004+): window is omitted from captures and recordings
#    ifndef WDA_EXCLUDEFROMCAPTURE
#        define WDA_EXCLUDEFROMCAPTURE 0x00000011
#    endif
    if (!SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE))
    {
        // Fallback for older Windows: the window appears black in captures
#    ifndef WDA_MONITOR
#        define WDA_MONITOR 0x00000001
#    endif
        if (!SetWindowDisplayAffinity(hwnd, WDA_MONITOR))
            return Utils::GStatus::Error("ScreenProtect: SetWindowDisplayAffinity failed");
    }
    return Utils::GStatus::Ok();

#elif defined(BUILD_FOR_UNIX)
    // Prevent core dumps (reduces leakage in crash scenarios)
    (void) nativeWindowHandle;
    if (prctl(PR_SET_DUMPABLE, 0) != 0)
        return Utils::GStatus::Error("ScreenProtect: prctl(PR_SET_DUMPABLE,0) failed");
    return Utils::GStatus::Ok();
#else
    (void) nativeWindowHandle;
    return Utils::GStatus::Error("ScreenProtect: not supported on this platform");
#endif
}

void DisableWindowScreenProtection(void* nativeWindowHandle) noexcept
{
#ifdef BUILD_FOR_WINDOWS
    if (nativeWindowHandle == nullptr)
        return;
    SetWindowDisplayAffinity(static_cast<HWND>(nativeWindowHandle), 0 /* WDA_NONE */);
#elif defined(BUILD_FOR_UNIX)
    (void) nativeWindowHandle;
    prctl(PR_SET_DUMPABLE, 1);
#else
    (void) nativeWindowHandle;
#endif
}

} // namespace GView::Security::RestrictedMode::Internal
