#pragma once

// Pure (no UI, no network, no file system) building blocks of the GView auto-updater.
// Everything in this header is deterministic and covered by tests_update.cpp.
// Design: plans/AUTO_UPDATER_PLAN.md (local) / docs/source/updates.rst.

#include "GView.hpp"

#include <compare>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace GView::Update
{
// ------------------------------------------------------------------ limits
constexpr size_t MAX_FEED_BYTES             = 1024 * 1024;               // GitHub releases JSON (10 releases ~ 60 KB)
constexpr size_t MAX_MANIFEST_BYTES         = 64 * 1024;                 // SHA256SUMS
constexpr uint64 MAX_ASSET_BYTES            = 512ull * 1024ull * 1024ull; // release zip
constexpr uint64 MAX_EXTRACTED_BYTES        = 2048ull * 1024ull * 1024ull;
constexpr uint32 MAX_ZIP_ENTRIES            = 10000;
constexpr size_t MAX_RELEASES_CONSIDERED    = 100;
constexpr size_t MAX_NOTES_INPUT_BYTES      = 64 * 1024;
constexpr size_t MAX_NOTES_OUTPUT_BYTES     = 32 * 1024;
constexpr size_t MAX_NOTES_OUTPUT_LINES     = 300;
constexpr size_t MAX_ZIP_PATH_LENGTH        = 512;
constexpr std::string_view DEFAULT_FEED_URL = "https://api.github.com/repos/gdt050579/GView/releases?per_page=10";
constexpr std::string_view MANIFEST_NAME    = "apply.manifest";
constexpr std::string_view MANIFEST_HEADER  = "GViewUpdate 1";

#ifdef BUILD_FOR_WINDOWS
constexpr std::string_view GVIEW_EXECUTABLE_NAME   = "GView.exe";
constexpr std::string_view UPDATER_EXECUTABLE_NAME = "GViewUpdater.exe";
#else
constexpr std::string_view GVIEW_EXECUTABLE_NAME   = "GView";
constexpr std::string_view UPDATER_EXECUTABLE_NAME = "GViewUpdater";
#endif

// ------------------------------------------------------------------ version
struct Version {
    uint32 major{ 0 };
    uint32 minor{ 0 };
    uint32 patch{ 0 };

    auto operator<=>(const Version&) const = default;
    std::string ToString() const;
    // "M.m.p" or "vM.m.p"; every component 1..9 digits; nothing else accepted
    static std::optional<Version> Parse(std::string_view text) noexcept;
};
// GVIEW_VERSION parsed once (always valid: the build fails otherwise)
Version CurrentVersion() noexcept;

// ------------------------------------------------------------------ platform / release model
enum class PlatformOS : uint8 { Windows, Linux, MacOS };
enum class Arch : uint8 { X64, Arm64, Unknown };
struct Platform {
    PlatformOS os;
    Arch arch;
    static Platform Current() noexcept;
};

struct ReleaseInfo {
    Version version;
    std::string tag;
    std::string name;
    std::string htmlUrl;     // release page (shown / copied, never opened automatically)
    std::string notes;       // release body, flattened for the TUI (see FlattenReleaseNotes)
    std::string publishedAt; // "YYYY-MM-DD" (empty when unknown)
    bool prerelease{ false };
    std::string assetName;
    std::string assetUrl;    // https only
    uint64 assetSize{ 0 };
    std::string checksumsUrl; // SHA256SUMS asset of the same release (empty when not published)
};

struct FeedResult {
    bool ok{ false };                   // the JSON was understood
    std::optional<ReleaseInfo> release; // newest eligible release that has an asset for the platform
    std::string error;                  // set when !ok
};

// Picks the newest (by version, not by order) non-draft release with an asset for 'platform'.
// Pre-releases are considered only when includePreReleases is true.
FeedResult ParseReleaseFeed(std::string_view json, bool includePreReleases, Platform platform);

// Chooses the release asset for a platform from the asset names (index into names or -1).
int32 SelectAsset(const std::vector<std::string>& names, Platform platform);

// Markdown -> plain text suitable for a read-only TextArea: headings, emphasis, inline code and link syntax are removed,
// bullets become "- ", control characters and invalid UTF-8 are replaced, output is capped in lines and bytes.
std::string FlattenReleaseNotes(std::string_view markdown);

// http(s) URL policy: https only (plain http is accepted only in DISSASM_DEV builds, for a local test server)
bool IsAllowedUrl(std::string_view url) noexcept;

// ------------------------------------------------------------------ zip payload helpers
// Normalises a zip entry name into a safe relative path with '/' separators.
// Returns nullopt for absolute paths, drive letters, '..' / '.' components, empty components, control characters, ':' and
// over-long names. Backslashes are treated as separators (Windows tools sometimes emit them).
std::optional<std::string> NormalizeZipEntryPath(std::string_view name);
// Finds the folder that holds the GView executable inside the archive ("" for a flat zip, "bin/Release/" for Unix zips).
// Returns nullopt when the executable is missing or present more than once.
std::optional<std::string> FindPayloadPrefix(const std::vector<std::string>& normalizedNames, std::string_view executableName);
// Files of the archive that must never overwrite user data in the installation folder.
bool IsProtectedPayloadPath(std::string_view relativePath) noexcept;
// Looks up "<64 hex>  <name>" (sha256sum format, optional '*' binary marker) and returns the lowercase digest.
std::optional<std::string> FindChecksum(std::string_view manifest, std::string_view assetName);

// ------------------------------------------------------------------ settings / decision state machine
struct UpdateSettings {
    // configuration
    bool autoCheck{ true };
    bool includePreReleases{ true }; // every GView release so far is published as a pre-release
    std::string feedUrl{ DEFAULT_FEED_URL };
    uint32 checkIntervalHours{ 24 };
    uint32 remindAfterDays{ 7 };
    std::string proxy;
    // state
    uint64 lastCheck{ 0 };
    std::string lastSeenVersion;
    uint64 remindAt{ 0 };
    std::string skippedVersion;
    std::string etag;
    std::string cachedFeedVersion; // newest version found by the last successful (200) check, used with a 304 answer

    static UpdateSettings Load(AppCUI::Utils::IniObject* ini);
    // writes only the state keys (configuration keys are owned by the user)
    void SaveState(AppCUI::Utils::IniObject* ini) const;
    static void WriteDefaults(AppCUI::Utils::IniObject& ini);

    bool ShouldCheckNow(uint64 now) const noexcept;
    // automatic mode: newer than the running build, not skipped, and either never shown or the remind delay is over
    bool ShouldNotify(const Version& found, const Version& current, uint64 now) const;
    void OnNotified(const Version& found, uint64 now); // the dialog was shown (closing it counts as "remind me later")
    void OnRemindLater(const Version& found, uint64 now);
    void OnSkip(const Version& found);
};

// ETags are echoed back to the server: accept only printable ASCII without control characters
bool IsSafeHeaderValue(std::string_view value) noexcept;
} // namespace GView::Update
