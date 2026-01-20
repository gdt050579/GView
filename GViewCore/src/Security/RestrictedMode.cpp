/**
 * - Policy-based feature restriction
 * - Ed25519 signature verification via OpenSSL
 * - Protected memory for sensitive data
 * - Best-effort screen capture prevention
 */

#include "GView.hpp"
#include <mutex>
#include <atomic>
#include <cstring>
#include <chrono>
#include <fstream>
#include <sstream>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Platform-specific headers for protected memory and screen protection
#ifdef BUILD_FOR_WINDOWS
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
#    include <Windows.h>
#elif defined(BUILD_FOR_OSX) || defined(BUILD_FOR_UNIX)
#    include <sys/mman.h>
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
    // Thread-safe global state
    std::mutex g_policyMutex;
    std::atomic<bool> g_isActive{ false };

    // Protected memory block for the policy
    struct ProtectedPolicyStorage {
        Policy policy;
        bool isLocked{ false };

        ProtectedPolicyStorage() = default;
        ~ProtectedPolicyStorage()
        {
            Clear();
        }

        void Clear() noexcept
        {
            if (isLocked)
            {
                Unlock();
            }
            // Secure erase
            volatile char* p = reinterpret_cast<volatile char*>(&policy);
            for (size_t i = 0; i < sizeof(Policy); ++i)
            {
                p[i] = 0;
            }
            policy = Policy{};
        }

        bool Lock() noexcept
        {
            if (isLocked)
                return true;

#ifdef BUILD_FOR_WINDOWS
            if (VirtualLock(&policy, sizeof(Policy)))
            {
                isLocked = true;
                return true;
            }
#elif defined(BUILD_FOR_OSX) || defined(BUILD_FOR_UNIX)
            if (mlock(&policy, sizeof(Policy)) == 0)
            {
                isLocked = true;
                return true;
            }
#endif
            return false;
        }

        void Unlock() noexcept
        {
            if (!isLocked)
                return;

#ifdef BUILD_FOR_WINDOWS
            VirtualUnlock(&policy, sizeof(Policy));
#elif defined(BUILD_FOR_OSX) || defined(BUILD_FOR_UNIX)
            munlock(&policy, sizeof(Policy));
#endif
            isLocked = false;
        }
    };

    ProtectedPolicyStorage g_policyStorage;

    // Screen protection state
#ifdef BUILD_FOR_WINDOWS
    HHOOK g_keyboardHook = nullptr;

    LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) noexcept
    {
        if (nCode == HC_ACTION && g_isActive.load(std::memory_order_acquire))
        {
            KBDLLHOOKSTRUCT* pKeyboard = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
            if (pKeyboard != nullptr)
            {
                // Block Print Screen key
                if (pKeyboard->vkCode == VK_SNAPSHOT)
                {
                    return 1; // Block the key
                }
                // Block Win+Shift+S (Windows Snipping Tool)
                if ((pKeyboard->vkCode == 'S') &&
                    (GetAsyncKeyState(VK_LWIN) & 0x8000) &&
                    (GetAsyncKeyState(VK_SHIFT) & 0x8000))
                {
                    return 1;
                }
            }
        }
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
#endif

    bool InstallScreenProtection() noexcept
    {
#ifdef BUILD_FOR_WINDOWS
        if (g_keyboardHook == nullptr)
        {
            g_keyboardHook = SetWindowsHookExW(
                  WH_KEYBOARD_LL,
                  LowLevelKeyboardProc,
                  GetModuleHandleW(nullptr),
                  0);
        }
        // Set window to prevent screen capture (Windows 10 2004+)
        // This is handled at the window level in AppCUI
        return g_keyboardHook != nullptr;
#elif defined(BUILD_FOR_OSX)
        // macOS: CGWindowSharingType is set at the window level
        // Implementation would go in AppCUI
        return true;
#else
        // Linux: Limited protection available
        return true;
#endif
    }

    void RemoveScreenProtection() noexcept
    {
#ifdef BUILD_FOR_WINDOWS
        if (g_keyboardHook != nullptr)
        {
            UnhookWindowsHookEx(g_keyboardHook);
            g_keyboardHook = nullptr;
        }
#endif
    }

    // OpenSSL error helper
    std::string GetOpenSSLError() noexcept
    {
        unsigned long err = ERR_get_error();
        if (err == 0)
            return "Unknown OpenSSL error";

        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        return std::string(buf);
    }

    // Ed25519 signature verification using OpenSSL
    bool VerifyEd25519Signature(
          const std::vector<uint8_t>& message,
          const std::vector<uint8_t>& signature,
          const std::vector<uint8_t>& publicKey) noexcept
    {
        if (publicKey.size() != 32 || signature.size() != 64)
        {
            return false;
        }
        //TODO: consider using DEFER{}
        // Create EVP_PKEY from raw Ed25519 public key
        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
              EVP_PKEY_ED25519,
              nullptr,
              publicKey.data(),
              publicKey.size());

        if (!pkey)
        {
            return false;
        }
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx)
        {
            EVP_PKEY_free(pkey);
            return false;
        }

        if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) != 1)
        {
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(mdctx);
            return false;
        }

        bool result = false;
        if (EVP_DigestVerify(
                  mdctx,
                  signature.data(),
                  signature.size(),
                  message.data(),
                  message.size()) == 1)
        {
            result = true;
        }

        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);

        return result;
    }

    // Read file into vector
    bool ReadFileToVector(const std::filesystem::path& path, std::vector<uint8_t>& out) noexcept
    {
        try
        {
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file.is_open())
                return false;

            const auto size = file.tellg();
            if (size <= 0 || size > 10 * 1024 * 1024) // Max 10MB
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

    // Parse policy JSON
    Utils::GStatus ParsePolicyJson(const std::vector<uint8_t>& jsonData, Policy& policy) noexcept
    {
        try
        {
            std::string jsonStr(jsonData.begin(), jsonData.end());
            auto j = nlohmann::json::parse(jsonStr);

            policy.id = j.value("id", "");
            policy.purpose = j.value("purpose", "");
            policy.startsAt = j.value("startsAt", 0ULL);
            policy.endsAt = j.value("endsAt", 0ULL);
            policy.watermark = j.value("watermark", "");
            policy.bestEffortScreenProtect = j.value("bestEffortScreenProtect", true);

            // Parse disabled features
            policy.disabledFeatures.clear();
            if (j.contains("disabledFeatures") && j["disabledFeatures"].is_array())
            {
                for (const auto& feat : j["disabledFeatures"])
                {
                    std::string featStr = feat.get<std::string>();
                    if (featStr == "Copy")
                        policy.disabledFeatures.push_back(Feature::Copy);
                    else if (featStr == "Export")
                        policy.disabledFeatures.push_back(Feature::Export);
                    else if (featStr == "SaveAs")
                        policy.disabledFeatures.push_back(Feature::SaveAs);
                    else if (featStr == "Plugins")
                        policy.disabledFeatures.push_back(Feature::Plugins);
                    else if (featStr == "LLMHints")
                        policy.disabledFeatures.push_back(Feature::LLMHints);
                    else if (featStr == "Clipboard")
                        policy.disabledFeatures.push_back(Feature::Clipboard);
                    else if (featStr == "Screenshots")
                        policy.disabledFeatures.push_back(Feature::Screenshots);
                }
            }

            // Parse allowed plugins
            policy.allowedPlugins.clear();
            if (j.contains("allowedPlugins") && j["allowedPlugins"].is_array())
            {
                for (const auto& plugin : j["allowedPlugins"])
                {
                    policy.allowedPlugins.push_back(plugin.get<std::string>());
                }
            }

            // Parse content key ID
            policy.contentKeyId.clear();
            if (j.contains("contentKeyId") && j["contentKeyId"].is_string())
            {
                std::string keyIdHex = j["contentKeyId"].get<std::string>();
                // Parse hex string
                for (size_t i = 0; i + 1 < keyIdHex.size(); i += 2)
                {
                    uint8_t byte = static_cast<uint8_t>(
                          std::stoul(keyIdHex.substr(i, 2), nullptr, 16));
                    policy.contentKeyId.push_back(byte);
                }
            }

            return Utils::GStatus::Ok();
        }
        catch (const nlohmann::json::exception& e)
        {
            return Utils::GStatus::Error(std::string("JSON parse error: ") + e.what());
        }
        catch (const std::exception& e)
        {
            return Utils::GStatus::Error(std::string("Policy parse error: ") + e.what());
        }
        catch (...)
        {
            return Utils::GStatus::Error("Unknown error parsing policy");
        }
    }

    // Validate policy time window
    Utils::GStatus ValidatePolicyTimeWindow(const Policy& policy) noexcept
    {
        const auto now = static_cast<uint64_t>(
              std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());

        if (policy.startsAt > 0 && now < policy.startsAt)
        {
            return Utils::GStatus::Error("Policy not yet active (starts in the future)");
        }

        if (policy.endsAt > 0 && now > policy.endsAt)
        {
            return Utils::GStatus::Error("Policy has expired");
        }

        return Utils::GStatus::Ok();
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
    // Validate inputs
    if (publicKey.size() != 32)
    {
        return Utils::GStatus::Error("Invalid public key size (expected 32 bytes for Ed25519)");
    }

    // Read policy JSON
    std::vector<uint8_t> jsonData;
    if (!ReadFileToVector(jsonPath, jsonData))
    {
        return Utils::GStatus::Error("Failed to read policy JSON file");
    }

    // Read signature
    std::vector<uint8_t> signature;
    if (!ReadFileToVector(signaturePath, signature))
    {
        return Utils::GStatus::Error("Failed to read signature file");
    }

    if (signature.size() != 64)
    {
        return Utils::GStatus::Error("Invalid signature size (expected 64 bytes for Ed25519)");
    }

    // Verify signature
    if (!VerifyEd25519Signature(jsonData, signature, publicKey))
    {
        return Utils::GStatus::Error("Policy signature verification failed");
    }

    // Parse JSON
    auto parseResult = ParsePolicyJson(jsonData, outPolicy);
    if (!parseResult.ok)
    {
        return parseResult;
    }

    // Validate time window
    auto timeResult = ValidatePolicyTimeWindow(outPolicy);
    if (!timeResult.ok)
    {
        return timeResult;
    }

    return Utils::GStatus::Ok();
}

CORE_EXPORT bool IsActive() noexcept
{
    return g_isActive.load(std::memory_order_acquire);
}

CORE_EXPORT const Policy* GetCurrentPolicy() noexcept
{
    if (!g_isActive.load(std::memory_order_acquire))
    {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(g_policyMutex);
    return &g_policyStorage.policy;
}

} // namespace GView::Security::RestrictedMode

// ============================================================================
// Internal API (declared in Internal.hpp, used by GViewCore)
// ============================================================================

namespace GView::Security::RestrictedMode::Internal
{

Utils::GStatus Activate(const Policy& policy) noexcept
{
    std::lock_guard<std::mutex> lock(g_policyMutex);

    if (g_isActive.load(std::memory_order_acquire))
    {
        return Utils::GStatus::Error("Restricted mode already active");
    }

    // Validate time window
    auto timeResult = ValidatePolicyTimeWindow(policy);
    if (!timeResult.ok)
    {
        return timeResult;
    }

    // Copy policy to protected storage
    g_policyStorage.Clear();
    g_policyStorage.policy = policy;

    // Lock memory to prevent swapping
    if (!g_policyStorage.Lock())
    {
        // Non-fatal: continue without memory protection
        // TODO: Log warning in debug builds
    }

    // Install screen protection if requested
    bool hasScreenshotRestriction = false;
    for (const auto& feat : policy.disabledFeatures)
    {
        if (feat == Feature::Screenshots)
        {
            hasScreenshotRestriction = true;
            break;
        }
    }

    if (hasScreenshotRestriction && policy.bestEffortScreenProtect)
    {
        InstallScreenProtection();
    }

    g_isActive.store(true, std::memory_order_release);
    return Utils::GStatus::Ok();
}

void Deactivate() noexcept
{
    std::lock_guard<std::mutex> lock(g_policyMutex);

    if (!g_isActive.load(std::memory_order_acquire))
    {
        return;
    }

    RemoveScreenProtection();
    g_policyStorage.Clear();
    g_isActive.store(false, std::memory_order_release);
}

bool IsFeatureDisabled(Feature feature) noexcept
{
    if (!g_isActive.load(std::memory_order_acquire))
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_policyMutex);
    for (const auto& f : g_policyStorage.policy.disabledFeatures)
    {
        if (f == feature)
            return true;
    }
    return false;
}

bool IsPluginAllowed(std::string_view pluginName) noexcept
{
    //TODO: consider doing this at load time
    if (!g_isActive.load(std::memory_order_acquire))
    {
        return true; // All plugins allowed when not in restricted mode
    }

    std::lock_guard<std::mutex> lock(g_policyMutex);

    // If no plugin restrictions, allow all
    bool hasPluginRestriction = false;
    for (const auto& f : g_policyStorage.policy.disabledFeatures)
    {
        if (f == Feature::Plugins)
        {
            hasPluginRestriction = true;
            break;
        }
    }

    if (!hasPluginRestriction)
    {
        return true;
    }

    // Check whitelist
    for (const auto& allowed : g_policyStorage.policy.allowedPlugins)
    {
        if (allowed == pluginName)
        {
            return true;
        }
    }

    return false;
}

std::string GetWatermark() noexcept
{
    if (!g_isActive.load(std::memory_order_acquire))
    {
        return "";
    }

    std::lock_guard<std::mutex> lock(g_policyMutex);
    return g_policyStorage.policy.watermark;
}

Utils::GStatus EnableWindowScreenProtection(void* nativeWindowHandle) noexcept
{
#ifdef BUILD_FOR_WINDOWS
    if (nativeWindowHandle == nullptr)
    {
        return Utils::GStatus::Error("ScreenProtect: null HWND");
    }

    HWND hwnd = static_cast<HWND>(nativeWindowHandle);

    // WDA_EXCLUDEFROMCAPTURE = 0x11 (Windows 10 2004+)
    // Prevents the window from appearing in screen captures and recordings
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

    if (!SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE))
    {
        // Fallback: try WDA_MONITOR which works on older Windows versions
        // This makes the window appear black in captures instead of invisible
#ifndef WDA_MONITOR
#define WDA_MONITOR 0x00000001
#endif
        if (!SetWindowDisplayAffinity(hwnd, WDA_MONITOR))
        {
            return Utils::GStatus::Error("ScreenProtect: SetWindowDisplayAffinity failed");
        }
    }
    return Utils::GStatus::Ok();

#elif defined(BUILD_FOR_UNIX)
    // Prevent core dumps (reduces leakage in crash scenarios)
    if (prctl(PR_SET_DUMPABLE, 0) != 0)
    {
        return Utils::GStatus::Error("ScreenProtect: prctl(PR_SET_DUMPABLE,0) failed");
    }
    (void) nativeWindowHandle;
    return Utils::GStatus::Ok();

#elif defined(BUILD_FOR_OSX)
    // macOS: Would need CGWindowSharingType at window creation
    // or NSWindow setSharingType:NSWindowSharingNone
    // This requires Objective-C++ and is best done in AppCUI
    (void) nativeWindowHandle;
    return Utils::GStatus::Ok();

#else
    (void) nativeWindowHandle;
    return Utils::GStatus::Ok();
#endif
}

void DisableWindowScreenProtection(void* nativeWindowHandle) noexcept
{
#ifdef BUILD_FOR_WINDOWS
    if (nativeWindowHandle == nullptr)
        return;

    HWND hwnd = static_cast<HWND>(nativeWindowHandle);
    // WDA_NONE = 0 - restore normal capture behavior
    SetWindowDisplayAffinity(hwnd, 0);

#elif defined(BUILD_FOR_UNIX)
    // Re-enable core dumps
    prctl(PR_SET_DUMPABLE, 1);
    (void) nativeWindowHandle;

#else
    (void) nativeWindowHandle;
#endif
}

} // namespace GView::Security::RestrictedMode::Internal

