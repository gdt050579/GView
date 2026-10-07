// Unit tests for the auto-updater: release feed, versioning, settings state machine, zip staging and the
// GViewUpdater apply/rollback logic. No network access.

#include <catch.hpp>

#include "UpdateCore.hpp"
#include "Stager.hpp"
#include "../../../GViewUpdater/src/Apply.hpp"

#include <mz.h>
#include <mz_strm.h>
#include <mz_zip.h>
#include <mz_zip_rw.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <random>
#include <sstream>

using namespace GView::Update;
namespace fs = std::filesystem;

namespace
{
// ------------------------------------------------------------------ helpers
struct TempDir {
    fs::path path;
    TempDir()
    {
        std::random_device rd;
        path = fs::temp_directory_path() / ("gview-update-test-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(path);
    }
    ~TempDir()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void WriteFile(const fs::path& p, std::string_view content)
{
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string ReadFile(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

struct ZipEntry {
    std::string name;
    std::string content;
};

void MakeZip(const fs::path& zipPath, const std::vector<ZipEntry>& entries)
{
    void* writer = mz_zip_writer_create();
    REQUIRE(writer != nullptr);
    const auto u8 = zipPath.u8string();
    REQUIRE(mz_zip_writer_open_file(writer, reinterpret_cast<const char*>(u8.c_str()), 0, 0) == MZ_OK);
    for (const auto& e : entries) {
        mz_zip_file info{};
        info.filename           = e.name.c_str();
        info.modified_date      = 1759400000;
        info.version_madeby     = (MZ_HOST_SYSTEM_MSDOS << 8) | 20;
        info.compression_method = MZ_COMPRESS_METHOD_DEFLATE;
        info.flag               = MZ_ZIP_FLAG_UTF8;
        std::string data        = e.content;
        REQUIRE(mz_zip_writer_add_buffer(writer, data.data(), static_cast<int32_t>(data.size()), &info) == MZ_OK);
    }
    REQUIRE(mz_zip_writer_close(writer) == MZ_OK);
    mz_zip_writer_delete(&writer);
}

std::string ExeName()
{
    return std::string(GVIEW_EXECUTABLE_NAME);
}

// a GitHub "list releases" answer (trimmed to the fields the updater reads)
std::string FeedJson()
{
    return R"([
  { "tag_name": "0.400.0", "name": "draft", "draft": true, "prerelease": false, "html_url": "https://github.com/gdt050579/GView/releases/tag/0.400.0",
    "assets": [ { "name": "build-Windows-Release.zip", "size": 100, "browser_download_url": "https://github.com/x/w400.zip" },
                { "name": "build-Linux-Release.zip", "size": 100, "browser_download_url": "https://github.com/x/l400.zip" },
                { "name": "build-macOS-Release.zip", "size": 100, "browser_download_url": "https://github.com/x/m400.zip" } ] },
  { "tag_name": "0.399.0", "name": "GView Build 0.399.0", "draft": false, "prerelease": true, "published_at": "2026-10-03T10:00:00Z",
    "html_url": "https://github.com/gdt050579/GView/releases/tag/0.399.0", "body": "## What's Changed\r\n* Fix by @someone in https://github.com/gdt050579/GView/pull/1\r\n",
    "assets": [ { "name": "build-Windows-Release.zip", "size": 18323620, "browser_download_url": "https://github.com/x/w399.zip" },
                { "name": "build-Linux-Release.zip", "size": 89165487, "browser_download_url": "https://github.com/x/l399.zip" },
                { "name": "build-macOS-Release.zip", "size": 19361196, "browser_download_url": "https://github.com/x/m399.zip" },
                { "name": "SHA256SUMS.txt", "size": 300, "browser_download_url": "https://github.com/x/sums.txt" } ] },
  { "tag_name": "0.398.0", "name": "stable", "draft": false, "prerelease": false, "html_url": "https://github.com/gdt050579/GView/releases/tag/0.398.0",
    "assets": [ { "name": "GView-Windows-X64-0.398.0.zip", "size": 1000, "browser_download_url": "https://github.com/x/w398.zip" },
                { "name": "GView-Linux-X64-0.398.0.zip", "size": 1000, "browser_download_url": "https://github.com/x/l398.zip" },
                { "name": "GView-macOS-X64-0.398.0.zip", "size": 1000, "browser_download_url": "https://github.com/x/m398.zip" } ] },
  { "tag_name": "nightly", "draft": false, "prerelease": true, "assets": [] },
  { "tag_name": "v0.500.0", "draft": false, "prerelease": true,
    "assets": [ { "name": "build-Windows-Release.zip", "size": 100, "browser_download_url": "http://insecure.example/w.zip" },
                { "name": "build-Linux-Release.zip", "size": 100, "browser_download_url": "http://insecure.example/l.zip" },
                { "name": "build-macOS-Release.zip", "size": 100, "browser_download_url": "http://insecure.example/m.zip" } ] }
])";
}
} // namespace

// ==================================================================== versions
TEST_CASE("Update.Version.Parse", "[update]")
{
    REQUIRE(Version::Parse("0.394.0") == Version{ 0, 394, 0 });
    REQUIRE(Version::Parse("v1.2.3") == Version{ 1, 2, 3 });
    REQUIRE(Version::Parse("V10.0.7") == Version{ 10, 0, 7 });
    for (const char* bad : { "", "1", "1.2", "1.2.3.4", "1.2.x", "a1.2.3", "1.2.3-beta", " 1.2.3", "1..3", "1.2.3 ", "1234567890.0.0", "-1.2.3", "nightly" })
        REQUIRE_FALSE(Version::Parse(bad).has_value());
    REQUIRE(Version{ 0, 394, 0 } < Version{ 0, 395, 0 });
    REQUIRE(Version{ 0, 999, 9 } < Version{ 1, 0, 0 });
    REQUIRE(Version{ 1, 2, 10 } > Version{ 1, 2, 9 });
    REQUIRE(Version{ 1, 2, 3 }.ToString() == "1.2.3");
    REQUIRE(Version::Parse(GVIEW_VERSION).has_value());
    REQUIRE(CurrentVersion() == *Version::Parse(GVIEW_VERSION));
}

// ==================================================================== feed
TEST_CASE("Update.SelectAsset", "[update]")
{
    const std::vector<std::string> current = { "build-Linux-Release.zip", "build-macOS-Release.zip", "build-Windows-Release.zip" };
    REQUIRE(SelectAsset(current, { PlatformOS::Windows, Arch::X64 }) == 2);
    REQUIRE(SelectAsset(current, { PlatformOS::Linux, Arch::X64 }) == 0);
    REQUIRE(SelectAsset(current, { PlatformOS::MacOS, Arch::Arm64 }) == 1);

    const std::vector<std::string> legacy = { "GView-Linux-X64-0.380.0.zip", "GView-macOS-X64-0.380.0.zip", "GView-Windows-X64-0.380.0.zip" };
    REQUIRE(SelectAsset(legacy, { PlatformOS::Windows, Arch::X64 }) == 2);
    REQUIRE(SelectAsset(legacy, { PlatformOS::MacOS, Arch::Arm64 }) == 1);  // Rosetta
    REQUIRE(SelectAsset(legacy, { PlatformOS::Linux, Arch::Arm64 }) == -1); // x64 does not run on arm64 Linux

    const std::vector<std::string> multiArch = { "GView-macOS-x86_64.zip", "GView-macOS-arm64.zip", "GView-Linux-aarch64.zip", "GView-Linux-amd64.zip" };
    REQUIRE(SelectAsset(multiArch, { PlatformOS::MacOS, Arch::Arm64 }) == 1);
    REQUIRE(SelectAsset(multiArch, { PlatformOS::MacOS, Arch::X64 }) == 0);
    REQUIRE(SelectAsset(multiArch, { PlatformOS::Linux, Arch::Arm64 }) == 2);
    REQUIRE(SelectAsset(multiArch, { PlatformOS::Linux, Arch::X64 }) == 3);
    REQUIRE(SelectAsset(multiArch, { PlatformOS::Windows, Arch::X64 }) == -1);

    REQUIRE(SelectAsset({ "build-Windows-Release.tar.gz", "windows-notes.txt" }, { PlatformOS::Windows, Arch::X64 }) == -1);
}

TEST_CASE("Update.ParseReleaseFeed", "[update]")
{
    const auto json = FeedJson();
    SECTION("pre-releases included: newest non-draft release with a safe asset")
    {
        const auto r = ParseReleaseFeed(json, true, { PlatformOS::Windows, Arch::X64 });
        REQUIRE(r.ok);
        REQUIRE(r.release.has_value());
        REQUIRE(r.release->version == Version{ 0, 399, 0 }); // 0.400.0 is a draft, 0.500.0 only has http:// assets
        REQUIRE(r.release->prerelease);
        REQUIRE(r.release->assetName == "build-Windows-Release.zip");
        REQUIRE(r.release->assetUrl == "https://github.com/x/w399.zip");
        REQUIRE(r.release->assetSize == 18323620);
        REQUIRE(r.release->checksumsUrl == "https://github.com/x/sums.txt");
        REQUIRE(r.release->publishedAt == "2026-10-03");
        REQUIRE(r.release->htmlUrl == "https://github.com/gdt050579/GView/releases/tag/0.399.0");
        REQUIRE(r.release->notes == "What's Changed\n- Fix by @someone in https://github.com/gdt050579/GView/pull/1");
    }
    SECTION("stable only")
    {
        const auto r = ParseReleaseFeed(json, false, { PlatformOS::Linux, Arch::X64 });
        REQUIRE(r.ok);
        REQUIRE(r.release.has_value());
        REQUIRE(r.release->version == Version{ 0, 398, 0 });
        REQUIRE(r.release->assetName == "GView-Linux-X64-0.398.0.zip");
        REQUIRE(r.release->checksumsUrl.empty());
    }
    SECTION("no asset for the platform")
    {
        const auto r = ParseReleaseFeed(R"([{"tag_name":"1.0.0","draft":false,"prerelease":false,"assets":[{"name":"build-Linux-Release.zip","size":5,"browser_download_url":"https://a/b"}]}])",
                                        true,
                                        { PlatformOS::Windows, Arch::X64 });
        REQUIRE(r.ok);
        REQUIRE_FALSE(r.release.has_value());
    }
    SECTION("hostile or broken input never throws")
    {
        for (const char* bad : { "", "{", "{}", "null", "[1,2,3]", "[{\"tag_name\":5}]", "[{\"tag_name\":\"1.0.0\",\"draft\":false,\"assets\":{}}]",
                                 "[{\"tag_name\":\"1.0.0\",\"draft\":false,\"prerelease\":false,\"assets\":[{\"name\":\"x-windows.zip\",\"size\":-5,\"browser_download_url\":\"https://a/b\"}]}]",
                                 "[{\"tag_name\":\"1.0.0\",\"draft\":false,\"prerelease\":false,\"assets\":[{\"name\":\"x-windows.zip\",\"size\":99999999999,\"browser_download_url\":\"https://a/b\"}]}]" }) {
            const auto r = ParseReleaseFeed(bad, true, { PlatformOS::Windows, Arch::X64 });
            REQUIRE_FALSE(r.release.has_value());
        }
        REQUIRE_FALSE(ParseReleaseFeed("{}", true, { PlatformOS::Windows, Arch::X64 }).ok);
        REQUIRE_FALSE(ParseReleaseFeed(std::string(MAX_FEED_BYTES + 1, ' '), true, { PlatformOS::Windows, Arch::X64 }).ok);
    }
}

TEST_CASE("Update.FlattenReleaseNotes", "[update]")
{
    // the body of the real 0.389.0 release (shortened)
    const std::string body =
          "## What's Changed\r\n* 385 add support for themes by @rzaharia in https://github.com/gdt050579/GView/pull/387\r\n"
          "* 388 convert iniconfigsetting to properties by @rzaharia in https://github.com/gdt050579/GView/pull/390\r\n\r\n\r\n"
          "**Full Changelog**: https://github.com/gdt050579/GView/compare/0.380.0...0.389.0";
    REQUIRE(FlattenReleaseNotes(body) ==
            "What's Changed\n"
            "- 385 add support for themes by @rzaharia in https://github.com/gdt050579/GView/pull/387\n"
            "- 388 convert iniconfigsetting to properties by @rzaharia in https://github.com/gdt050579/GView/pull/390\n"
            "\n"
            "Full Changelog: https://github.com/gdt050579/GView/compare/0.380.0...0.389.0");
    REQUIRE(FlattenReleaseNotes("See [the docs](https://x.y/z) and `code`\n---\n  - nested") == "See the docs (https://x.y/z) and code\n  - nested");
    // control characters (terminal escape sequences) and invalid UTF-8 never reach the UI
    const auto hostile = FlattenReleaseNotes(std::string("a\x1b[31mred\x07\tb\xff\xc3\x28") + "\xc3\xa9");
    REQUIRE(hostile == "a[31mred b??(\xc3\xa9");
    // caps
    std::string many;
    for (int i = 0; i < 1000; i++)
        many += "line\n";
    const auto capped = FlattenReleaseNotes(many);
    REQUIRE(static_cast<size_t>(std::count(capped.begin(), capped.end(), '\n')) < MAX_NOTES_OUTPUT_LINES);
    REQUIRE(FlattenReleaseNotes(std::string(200000, 'x')).size() <= MAX_NOTES_OUTPUT_BYTES);
}

TEST_CASE("Update.IsAllowedUrl", "[update]")
{
    REQUIRE(IsAllowedUrl("https://api.github.com/repos/gdt050579/GView/releases?per_page=10"));
    REQUIRE_FALSE(IsAllowedUrl("ftp://x/y"));
    REQUIRE_FALSE(IsAllowedUrl("file:///etc/passwd"));
    REQUIRE_FALSE(IsAllowedUrl("https://"));
    REQUIRE_FALSE(IsAllowedUrl("https://user:pass@host/x"));
    REQUIRE_FALSE(IsAllowedUrl("https://host/a b"));
    REQUIRE_FALSE(IsAllowedUrl("https://host/\r\nInjected: 1"));
#ifndef DISSASM_DEV
    REQUIRE_FALSE(IsAllowedUrl("http://127.0.0.1:8080/releases.json"));
#endif
    REQUIRE(IsSafeHeaderValue("W/\"abc\""));
    REQUIRE_FALSE(IsSafeHeaderValue("abc\r\nX-Evil: 1"));
    REQUIRE_FALSE(IsSafeHeaderValue(""));
}

// ==================================================================== zip helpers
TEST_CASE("Update.NormalizeZipEntryPath", "[update]")
{
    REQUIRE(NormalizeZipEntryPath("GView.exe") == "GView.exe");
    REQUIRE(NormalizeZipEntryPath("bin/Release/Types/libPE.tpl") == "bin/Release/Types/libPE.tpl");
    REQUIRE(NormalizeZipEntryPath("Types\\libPE.tpl") == "Types/libPE.tpl");
    REQUIRE(NormalizeZipEntryPath("Types/") == "Types/");
    for (const char* bad : { "", "/etc/passwd", "\\Windows\\x.dll", "../evil", "a/../../evil", "a/./b", "a//b", "C:/x", "C:x", "a/b.", "a/b ",
                             "Types/CON", "Types/nul.tpl", "COM1", "lpt9.txt", "a\x01" "b", "x/.." })
        REQUIRE_FALSE(NormalizeZipEntryPath(bad).has_value());
    REQUIRE_FALSE(NormalizeZipEntryPath(std::string(600, 'a')).has_value());
    REQUIRE(NormalizeZipEntryPath("console.dll") == "console.dll"); // only exact device names are reserved
}

TEST_CASE("Update.FindPayloadPrefix", "[update]")
{
    const auto exe = ExeName();
    REQUIRE(FindPayloadPrefix({ exe, "libGViewCore.dll", "Types/libPE.tpl" }, exe) == "");
    REQUIRE(FindPayloadPrefix({ "bin/Release/" + exe, "bin/Release/Types/libPE.tpl" }, exe) == "bin/Release/");
    REQUIRE_FALSE(FindPayloadPrefix({ "libGViewCore.dll" }, exe).has_value());
    REQUIRE_FALSE(FindPayloadPrefix({ exe, "old/" + exe }, exe).has_value());
}

TEST_CASE("Update.IsProtectedPayloadPath", "[update]")
{
    REQUIRE(IsProtectedPayloadPath("GView.ini"));
    REQUIRE(IsProtectedPayloadPath("gview.INI"));
    REQUIRE(IsProtectedPayloadPath("GView.ini.bak"));
    REQUIRE(IsProtectedPayloadPath(".update/x"));
    REQUIRE_FALSE(IsProtectedPayloadPath("Types/libINI.tpl"));
    REQUIRE_FALSE(IsProtectedPayloadPath("Themes/x.ini"));
    REQUIRE_FALSE(IsProtectedPayloadPath(ExeName()));
}

TEST_CASE("Update.FindChecksum", "[update]")
{
    const std::string a(64, 'a'), b(64, 'B');
    const std::string sums = a + "  build-Linux-Release.zip\n" + b + " *build-Windows-Release.zip\r\n" + "garbage line\n";
    REQUIRE(FindChecksum(sums, "build-Windows-Release.zip") == std::string(64, 'b'));
    REQUIRE(FindChecksum(sums, "build-Linux-Release.zip") == a);
    REQUIRE_FALSE(FindChecksum(sums, "build-macOS-Release.zip").has_value());
    REQUIRE_FALSE(FindChecksum(sums + a + "  build-Linux-Release.zip\n", "build-Linux-Release.zip").has_value()); // duplicated
    REQUIRE_FALSE(FindChecksum(std::string(63, 'a') + "g  x.zip\n", "x.zip").has_value());
}

// ==================================================================== settings state machine
TEST_CASE("Update.Settings.Decisions", "[update]")
{
    const Version current{ 0, 394, 0 };
    const Version newer{ 0, 395, 0 };
    const uint64 now = 1790000000;
    UpdateSettings s;

    SECTION("check interval")
    {
        REQUIRE(s.ShouldCheckNow(now)); // never checked
        s.lastCheck = now - 3600;
        REQUIRE_FALSE(s.ShouldCheckNow(now));
        s.lastCheck = now - 24 * 3600;
        REQUIRE(s.ShouldCheckNow(now));
        s.lastCheck = now + 10 * 86400; // clock moved backwards
        REQUIRE(s.ShouldCheckNow(now));
        s.autoCheck = false;
        REQUIRE_FALSE(s.ShouldCheckNow(now));
    }
    SECTION("first time seen, remind later, skip")
    {
        REQUIRE_FALSE(s.ShouldNotify(current, current, now));
        REQUIRE_FALSE(s.ShouldNotify(Version{ 0, 393, 0 }, current, now));
        REQUIRE(s.ShouldNotify(newer, current, now));

        s.OnNotified(newer, now); // shown once: quiet until the remind delay is over
        REQUIRE_FALSE(s.ShouldNotify(newer, current, now + 3600));
        REQUIRE_FALSE(s.ShouldNotify(newer, current, now + 6 * 86400));
        REQUIRE(s.ShouldNotify(newer, current, now + 7 * 86400));
        REQUIRE(s.ShouldNotify(Version{ 0, 396, 0 }, current, now + 3600)); // a newer version is a new first time

        s.OnSkip(newer);
        REQUIRE_FALSE(s.ShouldNotify(newer, current, now + 365 * 86400));
        REQUIRE(s.ShouldNotify(Version{ 0, 396, 0 }, current, now));
    }
    SECTION("remind delay 0 = never again for that version")
    {
        s.remindAfterDays = 0;
        s.OnRemindLater(newer, now);
        REQUIRE(s.remindAt == std::numeric_limits<uint64>::max());
        REQUIRE_FALSE(s.ShouldNotify(newer, current, std::numeric_limits<uint64>::max() - 1));
    }
}

TEST_CASE("Update.Settings.IniRoundTrip", "[update]")
{
    TempDir t;
    AppCUI::Utils::IniObject ini;
    REQUIRE(ini.Create());
    UpdateSettings::WriteDefaults(ini);
    auto s = UpdateSettings::Load(&ini);
    REQUIRE(s.autoCheck);
    REQUIRE(s.includePreReleases);
    REQUIRE(s.feedUrl == DEFAULT_FEED_URL);
    REQUIRE(s.lastCheck == 0);

    s.lastCheck         = 1790000000;
    s.etag              = "W/\"c9e0b1f2a3d4e5f60718293a4b5c6d7e\""; // GitHub format
    s.skippedVersion    = "0.395.0";
    s.cachedFeedVersion = "0.396.0";
    s.OnRemindLater(Version{ 0, 396, 0 }, 1790000000);
    s.SaveState(&ini);

    // through the text form, as GView.ini would be written and read back
    REQUIRE(ini.Save(t.path / "GView.ini"));
    AppCUI::Utils::IniObject reloaded;
    INFO(ReadFile(t.path / "GView.ini"));
    REQUIRE(reloaded.CreateFromFile(t.path / "GView.ini"));
    const auto r = UpdateSettings::Load(&reloaded);
    REQUIRE(r.lastCheck == 1790000000);
    REQUIRE(r.etag == s.etag);
    // quotes of both kinds and other odd characters survive as well
    s.etag = "W/\"a'b\" ; # = [x]";
    s.SaveState(&ini);
    REQUIRE(ini.Save(t.path / "GView2.ini"));
    AppCUI::Utils::IniObject reloaded2;
    REQUIRE(reloaded2.CreateFromFile(t.path / "GView2.ini"));
    REQUIRE(UpdateSettings::Load(&reloaded2).etag == s.etag);
    REQUIRE(r.skippedVersion == "0.395.0");
    REQUIRE(r.lastSeenVersion == "0.396.0");
    REQUIRE(r.cachedFeedVersion == "0.396.0");
    REQUIRE(r.remindAt == s.remindAt);
    REQUIRE(r.feedUrl == DEFAULT_FEED_URL);

    // invalid values fall back to safe defaults
    AppCUI::Utils::IniObject hostile;
    REQUIRE(hostile.CreateFromString("[GView]\nUpdateFeedUrl = \"http://evil/\"\nUpdateSkippedVersion = \"x\"\nUpdateCheckIntervalHours = 0\n"));
    const auto h = UpdateSettings::Load(&hostile);
    REQUIRE(h.feedUrl == DEFAULT_FEED_URL);
    REQUIRE(h.skippedVersion.empty());
    REQUIRE(h.checkIntervalHours == 1);
}

// ==================================================================== staging
TEST_CASE("Update.Sha256File", "[update]")
{
    TempDir t;
    WriteFile(t.path / "abc.txt", "abc");
    std::atomic<bool> cancel{ false };
    REQUIRE(Sha256File(t.path / "abc.txt", cancel) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    REQUIRE(Sha256File(t.path / "missing", cancel).empty());
}

TEST_CASE("Update.ExtractRelease", "[update]")
{
    TempDir t;
    const auto exe = ExeName();
    std::atomic<bool> cancel{ false };
    StageProgress progress;

    SECTION("unix layout: prefix stripped, user files skipped, manifest written")
    {
        MakeZip(t.path / "r.zip",
                { { "bin/Release/" + exe, "new-exe" },
                  { "bin/Release/Types/libPE.tpl", "pe" },
                  { "bin/Release/GView.ini", "user settings must not be shipped" },
                  { "README.md", "outside the payload" } });
        const auto r = ExtractRelease(t.path / "r.zip", t.path / "staging", Version{ 1, 2, 3 }, progress, cancel);
        REQUIRE(r.ok);
        REQUIRE(r.files == std::vector<std::string>{ exe, "Types/libPE.tpl" });
        REQUIRE(ReadFile(t.path / "staging" / exe) == "new-exe");
        REQUIRE(ReadFile(t.path / "staging" / "Types" / "libPE.tpl") == "pe");
        REQUIRE_FALSE(fs::exists(t.path / "staging" / "GView.ini"));
        REQUIRE_FALSE(fs::exists(t.path / "staging" / "README.md"));
        REQUIRE(ReadFile(t.path / "staging" / "apply.manifest") == "GViewUpdate 1\nversion 1.2.3\nfile " + exe + "\nfile Types/libPE.tpl\nend\n");

        GViewUpdater::Manifest m;
        std::string error;
        REQUIRE(GViewUpdater::ParseManifest(ReadFile(t.path / "staging" / "apply.manifest"), m, error));
        REQUIRE(m.files == r.files);
    }
    SECTION("windows layout with backslashes")
    {
        MakeZip(t.path / "r.zip", { { exe, "x" }, { "GenericPlugins\\libHashes.gpl", "h" } });
        const auto r = ExtractRelease(t.path / "r.zip", t.path / "staging", Version{ 1, 2, 3 }, progress, cancel);
        REQUIRE(r.ok);
        REQUIRE(ReadFile(t.path / "staging" / "GenericPlugins" / "libHashes.gpl") == "h");
    }
    SECTION("hostile archives are refused and nothing is left behind")
    {
        const std::vector<std::vector<ZipEntry>> hostile = {
            { { exe, "x" }, { "../evil.dll", "e" } },
            { { exe, "x" }, { "Types/../../evil.dll", "e" } },
            { { exe, "x" }, { "/abs.dll", "e" } },
            { { exe, "x" }, { "Types/CON", "e" } },
            { { exe, "x" }, { "a.dll", "1" }, { "A.dll", "2" } },
            { { "libGViewCore.dll", "no executable" } },
            { { exe, "x" }, { "sub/" + exe, "two executables" } },
        };
        int index = 0;
        for (const auto& entries : hostile) {
            const auto zip = t.path / ("h" + std::to_string(index++) + ".zip");
            MakeZip(zip, entries);
            const auto staging = t.path / ("staging" + std::to_string(index));
            const auto r       = ExtractRelease(zip, staging, Version{ 1, 2, 3 }, progress, cancel);
            REQUIRE_FALSE(r.ok);
            REQUIRE_FALSE(r.error.empty());
            REQUIRE_FALSE(fs::exists(staging));
            REQUIRE_FALSE(fs::exists(t.path / "evil.dll"));
            REQUIRE_FALSE(fs::exists(t.path.parent_path() / "evil.dll"));
        }
    }
    SECTION("not a zip")
    {
        WriteFile(t.path / "r.zip", "this is not a zip archive");
        REQUIRE_FALSE(ExtractRelease(t.path / "r.zip", t.path / "staging", Version{ 1, 2, 3 }, progress, cancel).ok);
    }
}

TEST_CASE("Update.CleanupWorkDir", "[update]")
{
    TempDir t;
    const auto work = UpdateWorkDir(t.path);
    WriteFile(work / "staging-1.0.0" / "x", "x");
    WriteFile(work / "download-1.0.0.zip", "x");
    WriteFile(work / "old-0.9.0" / "DONE", "ok");
    WriteFile(work / "old-0.9.0" / "GView.exe", "old");
    WriteFile(work / "old-0.8.0" / "journal.txt", "M GView.exe"); // incomplete rollback: kept for manual recovery
    CleanupWorkDir(t.path);
    REQUIRE_FALSE(fs::exists(work / "staging-1.0.0"));
    REQUIRE_FALSE(fs::exists(work / "download-1.0.0.zip"));
    REQUIRE_FALSE(fs::exists(work / "old-0.9.0"));
    REQUIRE(fs::exists(work / "old-0.8.0" / "journal.txt"));
}

// ==================================================================== GViewUpdater apply / rollback
namespace
{
struct ApplyFixture {
    TempDir t;
    fs::path target, staging, old;
    std::vector<std::string> log;

    ApplyFixture()
    {
        target  = t.path / "install";
        staging = target / ".update" / "staging-1.0.0";
        old     = target / ".update" / "old-1.0.0";
        const auto exe = ExeName();
        WriteFile(target / exe, "old-exe");
        WriteFile(target / "libGViewCore.dll", "old-core");
        WriteFile(target / "Types" / "libPE.tpl", "old-pe");
        WriteFile(target / "GView.ini", "user settings");
        WriteFile(target / "Types" / "libMine.tpl", "user plugin");
        WriteFile(staging / exe, "new-exe");
        WriteFile(staging / "libGViewCore.dll", "new-core");
        WriteFile(staging / "Types" / "libPE.tpl", "new-pe");
        WriteFile(staging / "Types" / "libNEW.tpl", "new-type");
        WriteFile(staging / "GenericPlugins" / "libX.gpl", "new-generic");
        WriteManifest({ exe, "libGViewCore.dll", "Types/libPE.tpl", "Types/libNEW.tpl", "GenericPlugins/libX.gpl" });
    }
    void WriteManifest(const std::vector<std::string>& files)
    {
        std::string m = "GViewUpdate 1\nversion 1.0.0\n";
        for (const auto& f : files)
            m += "file " + f + "\n";
        m += "end\n";
        WriteFile(staging / "apply.manifest", m);
    }
    GViewUpdater::Options Options()
    {
        GViewUpdater::Options o;
        o.staging = staging;
        o.target  = target;
        o.old     = old;
        o.output  = [this](std::string_view line) { log.emplace_back(line); };
        return o;
    }
    void RequireOriginalInstall()
    {
        REQUIRE(ReadFile(target / ExeName()) == "old-exe");
        REQUIRE(ReadFile(target / "libGViewCore.dll") == "old-core");
        REQUIRE(ReadFile(target / "Types" / "libPE.tpl") == "old-pe");
        REQUIRE(ReadFile(target / "GView.ini") == "user settings");
        REQUIRE(ReadFile(target / "Types" / "libMine.tpl") == "user plugin");
        REQUIRE_FALSE(fs::exists(target / "Types" / "libNEW.tpl"));
        REQUIRE_FALSE(fs::exists(target / "GenericPlugins"));
    }
};
} // namespace

TEST_CASE("GViewUpdater.Apply", "[update]")
{
    ApplyFixture f;

    SECTION("success: files replaced, user files untouched, backup marked DONE")
    {
        REQUIRE(GViewUpdater::Apply(f.Options()) == GViewUpdater::EXIT_APPLIED);
        REQUIRE(ReadFile(f.target / ExeName()) == "new-exe");
        REQUIRE(ReadFile(f.target / "libGViewCore.dll") == "new-core");
        REQUIRE(ReadFile(f.target / "Types" / "libPE.tpl") == "new-pe");
        REQUIRE(ReadFile(f.target / "Types" / "libNEW.tpl") == "new-type");
        REQUIRE(ReadFile(f.target / "GenericPlugins" / "libX.gpl") == "new-generic");
        REQUIRE(ReadFile(f.target / "GView.ini") == "user settings");
        REQUIRE(ReadFile(f.target / "Types" / "libMine.tpl") == "user plugin");
        REQUIRE(ReadFile(f.old / ExeName()) == "old-exe");
        REQUIRE(ReadFile(f.old / "Types" / "libPE.tpl") == "old-pe");
        REQUIRE(fs::exists(f.old / "DONE"));
        REQUIRE(fs::exists(f.old / "updater.log"));
        REQUIRE_FALSE(fs::exists(f.staging));
        // the next GView start removes the backup
        CleanupWorkDir(f.target);
        REQUIRE_FALSE(fs::exists(f.old));
    }
    SECTION("a failure at any step is rolled back completely")
    {
        // 3 existing files moved + 5 staged files placed = 8 renames
        const int failAt = GENERATE(0, 1, 2, 3, 4, 5, 6, 7);
        auto o           = f.Options();
        o.failAtRename   = failAt;
        REQUIRE(GViewUpdater::Apply(o) == GViewUpdater::EXIT_ROLLED_BACK);
        f.RequireOriginalInstall();
        REQUIRE(fs::exists(f.old / "DONE")); // nothing to recover
        // the staged files are back in the staging folder
        REQUIRE(ReadFile(f.staging / ExeName()) == "new-exe");
        REQUIRE(ReadFile(f.staging / "GenericPlugins" / "libX.gpl") == "new-generic");
    }
    SECTION("an incomplete rollback is reported and the backup is kept")
    {
        auto o         = f.Options();
        o.failAtRename = 4;
        o.failRollback = true;
        REQUIRE(GViewUpdater::Apply(o) == GViewUpdater::EXIT_ROLLBACK_INCOMPLETE);
        REQUIRE_FALSE(fs::exists(f.old / "DONE"));
        REQUIRE(fs::exists(f.old / "journal.txt"));
        CleanupWorkDir(f.target);
        REQUIRE(fs::exists(f.old / "journal.txt"));
    }
    SECTION("refused before touching anything")
    {
        SECTION("missing manifest")
        {
            fs::remove(f.staging / "apply.manifest");
        }
        SECTION("truncated manifest")
        {
            WriteFile(f.staging / "apply.manifest", "GViewUpdate 1\nversion 1.0.0\nfile " + ExeName() + "\n");
        }
        SECTION("manifest without the executable")
        {
            f.WriteManifest({ "libGViewCore.dll" });
        }
        SECTION("unsafe manifest path")
        {
            f.WriteManifest({ ExeName(), "../outside.dll" });
        }
        SECTION("staged file missing")
        {
            f.WriteManifest({ ExeName(), "missing.dll" });
        }
        SECTION("folder in the way of a file")
        {
            fs::create_directories(f.target / "libX.dll");
            WriteFile(f.staging / "libX.dll", "x");
            f.WriteManifest({ ExeName(), "libX.dll" });
        }
        SECTION("backup folder already exists")
        {
            fs::create_directories(f.old);
        }
        const bool oldExisted = fs::exists(f.old);
        REQUIRE(GViewUpdater::Apply(f.Options()) == GViewUpdater::EXIT_REFUSED);
        REQUIRE(ReadFile(f.target / ExeName()) == "old-exe");
        REQUIRE(ReadFile(f.target / "libGViewCore.dll") == "old-core");
        REQUIRE(fs::exists(f.old) == oldExisted);
    }
}

TEST_CASE("GViewUpdater.ParseManifest", "[update]")
{
    GViewUpdater::Manifest m;
    std::string error;
    const auto exe = ExeName();
    REQUIRE(GViewUpdater::ParseManifest("GViewUpdate 1\r\nversion 1.0.0\r\nfile " + exe + "\r\nend\r\n", m, error));
    REQUIRE(m.version == "1.0.0");
    REQUIRE_FALSE(GViewUpdater::ParseManifest("GViewUpdate 2\nfile " + exe + "\nend\n", m, error));
    REQUIRE_FALSE(GViewUpdater::ParseManifest("GViewUpdate 1\nfile " + exe + "\nfile " + exe + "\nend\n", m, error));
    REQUIRE_FALSE(GViewUpdater::ParseManifest("GViewUpdate 1\nfile " + exe + "\nend\nfile x\n", m, error));
    REQUIRE_FALSE(GViewUpdater::ParseManifest("GViewUpdate 1\nfile " + exe + "\nrm -rf /\nend\n", m, error));
    for (const char* bad : { "/abs", "a\\b", "C:x", "..", "a/../b", "a//b", "a/", "x." })
        REQUIRE_FALSE(GViewUpdater::IsSafeRelativePath(bad));
    REQUIRE(GViewUpdater::IsSafeRelativePath("Types/libPE.tpl"));
}
