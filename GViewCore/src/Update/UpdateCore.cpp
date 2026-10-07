#include "UpdateCore.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <limits>

namespace GView::Update
{
namespace
{
    constexpr std::string_view SECTION = "GView";

    char ToLowerAscii(char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }
    std::string ToLower(std::string_view s)
    {
        std::string r(s);
        for (auto& c : r)
            c = ToLowerAscii(c);
        return r;
    }
    bool Contains(std::string_view haystack, std::string_view needle) noexcept
    {
        return haystack.find(needle) != std::string_view::npos;
    }

    // ---------------------------------------------------------------- json accessors (never throw)
    const nlohmann::json* Member(const nlohmann::json& obj, const char* key) noexcept
    {
        if (!obj.is_object())
            return nullptr;
        auto it = obj.find(key);
        return it == obj.end() ? nullptr : &(*it);
    }
    std::string_view StringMember(const nlohmann::json& obj, const char* key) noexcept
    {
        const auto* m = Member(obj, key);
        if (m == nullptr || !m->is_string())
            return {};
        return m->get_ref<const std::string&>();
    }
    bool BoolMember(const nlohmann::json& obj, const char* key, bool defaultValue) noexcept
    {
        const auto* m = Member(obj, key);
        if (m == nullptr || !m->is_boolean())
            return defaultValue;
        return m->get<bool>();
    }
    std::optional<uint64> UIntMember(const nlohmann::json& obj, const char* key) noexcept
    {
        const auto* m = Member(obj, key);
        if (m == nullptr || !m->is_number_unsigned())
            return std::nullopt;
        return m->get<uint64>();
    }

    // ---------------------------------------------------------------- utf-8 sanitising
    // Returns the length of a valid UTF-8 sequence starting at s[i] (0 when invalid).
    size_t Utf8SequenceLength(std::string_view s, size_t i) noexcept
    {
        const auto c = static_cast<uint8>(s[i]);
        size_t len = 0;
        uint32 cp  = 0;
        if (c < 0x80)
            return 1;
        if ((c & 0xE0) == 0xC0) {
            len = 2;
            cp  = c & 0x1F;
        } else if ((c & 0xF0) == 0xE0) {
            len = 3;
            cp  = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
            len = 4;
            cp  = c & 0x07;
        } else {
            return 0;
        }
        if (len > s.size() - i)
            return 0;
        for (size_t k = 1; k < len; k++) {
            const auto cc = static_cast<uint8>(s[i + k]);
            if ((cc & 0xC0) != 0x80)
                return 0;
            cp = (cp << 6) | (cc & 0x3F);
        }
        // reject overlong encodings, surrogates and out of range code points
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return 0;
        return len;
    }

    std::string_view TrimSpaces(std::string_view s) noexcept
    {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
            s.remove_prefix(1);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
            s.remove_suffix(1);
        return s;
    }

    // [text](url) -> "text (url)"; **x** / __x__ / `x` -> x
    std::string FlattenInline(std::string_view line)
    {
        std::string out;
        out.reserve(line.size());
        size_t i = 0;
        while (i < line.size()) {
            const char c = line[i];
            if (c == '`') {
                i++;
                continue;
            }
            if ((c == '*' || c == '_') && i + 1 < line.size() && line[i + 1] == c) {
                i += 2;
                continue;
            }
            if (c == '[') {
                const auto close = line.find(']', i + 1);
                if (close != std::string_view::npos && close + 1 < line.size() && line[close + 1] == '(') {
                    const auto end = line.find(')', close + 2);
                    if (end != std::string_view::npos) {
                        out.append(line.substr(i + 1, close - i - 1));
                        out.append(" (");
                        out.append(line.substr(close + 2, end - close - 2));
                        out.push_back(')');
                        i = end + 1;
                        continue;
                    }
                }
            }
            out.push_back(c);
            i++;
        }
        return out;
    }

    bool IsDigit(char c) noexcept
    {
        return c >= '0' && c <= '9';
    }

    // CON, PRN, AUX, NUL, COM1-9, LPT1-9 (with or without extension) open devices on Windows
    bool IsReservedDeviceName(std::string_view component) noexcept
    {
        const auto dot  = component.find('.');
        const auto base = ToLower(component.substr(0, dot));
        if (base == "con" || base == "prn" || base == "aux" || base == "nul")
            return true;
        return base.size() == 4 && (base.starts_with("com") || base.starts_with("lpt")) && base[3] >= '1' && base[3] <= '9';
    }
    bool IsHex(char c) noexcept
    {
        return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    uint8 HexValue(char c) noexcept
    {
        if (IsDigit(c))
            return static_cast<uint8>(c - '0');
        if (c >= 'a' && c <= 'f')
            return static_cast<uint8>(c - 'a' + 10);
        return static_cast<uint8>(c - 'A' + 10);
    }
    // ETags contain quotes (W/"..."): stored hex encoded so that any value survives the ini quoting rules
    std::string HexEncode(std::string_view s)
    {
        static constexpr char HEX[] = "0123456789abcdef";
        std::string r;
        r.reserve(s.size() * 2);
        for (char c : s) {
            r.push_back(HEX[static_cast<uint8>(c) >> 4]);
            r.push_back(HEX[static_cast<uint8>(c) & 0x0F]);
        }
        return r;
    }
    std::string HexDecode(std::string_view s)
    {
        if (s.size() % 2 != 0)
            return {};
        std::string r;
        r.reserve(s.size() / 2);
        for (size_t i = 0; i < s.size(); i += 2) {
            if (!IsHex(s[i]) || !IsHex(s[i + 1]))
                return {};
            r.push_back(static_cast<char>((HexValue(s[i]) << 4) | HexValue(s[i + 1])));
        }
        return r;
    }
} // namespace

// ==================================================================== Version
std::string Version::ToString() const
{
    return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
}

std::optional<Version> Version::Parse(std::string_view text) noexcept
{
    if (!text.empty() && (text.front() == 'v' || text.front() == 'V'))
        text.remove_prefix(1);
    uint32 parts[3]{};
    for (uint32 idx = 0; idx < 3; idx++) {
        size_t digits = 0;
        uint32 value  = 0;
        while (!text.empty() && IsDigit(text.front())) {
            if (++digits > 9)
                return std::nullopt;
            value = value * 10 + static_cast<uint32>(text.front() - '0');
            text.remove_prefix(1);
        }
        if (digits == 0)
            return std::nullopt;
        parts[idx] = value;
        if (idx < 2) {
            if (text.empty() || text.front() != '.')
                return std::nullopt;
            text.remove_prefix(1);
        }
    }
    if (!text.empty())
        return std::nullopt;
    return Version{ parts[0], parts[1], parts[2] };
}

Version CurrentVersion() noexcept
{
    static const Version current = Version::Parse(GVIEW_VERSION).value_or(Version{});
    return current;
}

Platform Platform::Current() noexcept
{
    Platform p{};
#if defined(BUILD_FOR_WINDOWS)
    p.os = PlatformOS::Windows;
#elif defined(BUILD_FOR_OSX)
    p.os = PlatformOS::MacOS;
#else
    p.os = PlatformOS::Linux;
#endif
#if defined(_M_X64) || defined(__x86_64__)
    p.arch = Arch::X64;
#elif defined(_M_ARM64) || defined(__aarch64__)
    p.arch = Arch::Arm64;
#else
    p.arch = Arch::Unknown;
#endif
    return p;
}

bool IsAllowedUrl(std::string_view url) noexcept
{
    if (url.size() > 2048)
        return false;
    for (char c : url) {
        if (static_cast<uint8>(c) <= 0x20 || static_cast<uint8>(c) >= 0x7F)
            return false;
    }
    std::string_view rest;
    if (url.starts_with("https://"))
        rest = url.substr(8);
#ifdef DISSASM_DEV
    else if (url.starts_with("http://"))
        rest = url.substr(7);
#endif
    else
        return false;
    // a host is required and credentials in the URL are not allowed
    const auto hostEnd = rest.find_first_of("/?#");
    const auto host    = rest.substr(0, hostEnd);
    return !host.empty() && host.find('@') == std::string_view::npos;
}

bool IsSafeHeaderValue(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 256)
        return false;
    for (char c : value) {
        if (static_cast<uint8>(c) < 0x20 || static_cast<uint8>(c) >= 0x7F)
            return false;
    }
    return true;
}

// ==================================================================== asset selection
int32 SelectAsset(const std::vector<std::string>& names, Platform platform)
{
    std::string_view osTokens[2];
    switch (platform.os) {
    case PlatformOS::Windows:
        osTokens[0] = "windows";
        osTokens[1] = "win64";
        break;
    case PlatformOS::MacOS:
        osTokens[0] = "macos";
        osTokens[1] = "darwin";
        break;
    default:
        osTokens[0] = "linux";
        osTokens[1] = "linux";
        break;
    }
    const auto archOf = [](std::string_view lower) -> Arch {
        if (Contains(lower, "arm64") || Contains(lower, "aarch64"))
            return Arch::Arm64;
        if (Contains(lower, "x64") || Contains(lower, "x86_64") || Contains(lower, "amd64"))
            return Arch::X64;
        return Arch::Unknown;
    };

    int32 exact = -1, generic = -1, emulated = -1;
    const size_t count = std::min<size_t>(names.size(), 64);
    for (size_t i = 0; i < count; i++) {
        const auto lower = ToLower(names[i]);
        if (!lower.ends_with(".zip"))
            continue;
        if (!Contains(lower, osTokens[0]) && !Contains(lower, osTokens[1]))
            continue;
        const auto arch = archOf(lower);
        if (arch == platform.arch && arch != Arch::Unknown) {
            if (exact < 0)
                exact = static_cast<int32>(i);
        } else if (arch == Arch::Unknown) {
            if (generic < 0)
                generic = static_cast<int32>(i);
        } else if (arch == Arch::X64 && platform.arch == Arch::Arm64 && platform.os != PlatformOS::Linux) {
            // Windows on ARM and macOS (Rosetta) run x64 builds; Linux does not
            if (emulated < 0)
                emulated = static_cast<int32>(i);
        }
    }
    if (exact >= 0)
        return exact;
    if (generic >= 0)
        return generic;
    return emulated;
}

// ==================================================================== feed
FeedResult ParseReleaseFeed(std::string_view json, bool includePreReleases, Platform platform)
{
    FeedResult result;
    if (json.size() > MAX_FEED_BYTES) {
        result.error = "the release list is too large";
        return result;
    }
    const auto doc = nlohmann::json::parse(json.begin(), json.end(), nullptr, false);
    if (doc.is_discarded() || !doc.is_array()) {
        result.error = "the release list is not a JSON array";
        return result;
    }
    result.ok = true;

    size_t considered = 0;
    for (const auto& rel : doc) {
        if (++considered > MAX_RELEASES_CONSIDERED)
            break;
        if (!rel.is_object() || BoolMember(rel, "draft", true))
            continue;
        const bool prerelease = BoolMember(rel, "prerelease", true);
        if (prerelease && !includePreReleases)
            continue;
        const auto tag     = StringMember(rel, "tag_name");
        const auto version = Version::Parse(tag);
        if (!version.has_value())
            continue;
        if (result.release.has_value() && !(*version > result.release->version))
            continue;

        const auto* assets = Member(rel, "assets");
        if (assets == nullptr || !assets->is_array())
            continue;
        std::vector<std::string> names;
        std::vector<const nlohmann::json*> assetObjects;
        std::string checksumsUrl;
        for (const auto& a : *assets) {
            if (!a.is_object() || names.size() >= 64)
                continue;
            const auto name = StringMember(a, "name");
            const auto url  = StringMember(a, "browser_download_url");
            if (name.empty() || name.size() > 256 || !IsAllowedUrl(url))
                continue;
            const auto lower = ToLower(name);
            if (lower == "sha256sums.txt" || lower == "sha256sums") {
                checksumsUrl.assign(url);
                continue;
            }
            names.emplace_back(name);
            assetObjects.push_back(&a);
        }
        const auto index = SelectAsset(names, platform);
        if (index < 0)
            continue;
        const auto& asset = *assetObjects[static_cast<size_t>(index)];
        const auto size   = UIntMember(asset, "size");
        if (!size.has_value() || *size == 0 || *size > MAX_ASSET_BYTES)
            continue;

        ReleaseInfo info;
        info.version    = *version;
        info.tag        = std::string(tag.substr(0, 64));
        info.name       = std::string(StringMember(rel, "name").substr(0, 128));
        info.prerelease = prerelease;
        const auto html = StringMember(rel, "html_url");
        if (IsAllowedUrl(html))
            info.htmlUrl.assign(html);
        const auto published = StringMember(rel, "published_at");
        if (published.size() >= 10 && IsDigit(published[0]) && published[4] == '-' && published[7] == '-')
            info.publishedAt.assign(published.substr(0, 10));
        const auto body = StringMember(rel, "body");
        info.notes      = FlattenReleaseNotes(body.substr(0, std::min(body.size(), MAX_NOTES_INPUT_BYTES)));
        info.assetName  = names[static_cast<size_t>(index)];
        info.assetUrl.assign(StringMember(asset, "browser_download_url"));
        info.assetSize    = *size;
        info.checksumsUrl = std::move(checksumsUrl);
        result.release    = std::move(info);
    }
    return result;
}

// ==================================================================== release notes
std::string FlattenReleaseNotes(std::string_view markdown)
{
    // 1. sanitise: valid UTF-8 only, no control characters except '\n' (tabs become spaces, '\r' is dropped)
    std::string clean;
    clean.reserve(std::min(markdown.size(), MAX_NOTES_INPUT_BYTES));
    for (size_t i = 0; i < markdown.size() && clean.size() < MAX_NOTES_INPUT_BYTES;) {
        const char c = markdown[i];
        const auto len = Utf8SequenceLength(markdown, i);
        if (len == 0) {
            clean.push_back('?');
            i++;
            continue;
        }
        if (len == 1) {
            if (c == '\t')
                clean.push_back(' ');
            else if (c == '\n')
                clean.push_back('\n');
            else if (static_cast<uint8>(c) >= 0x20 && c != 0x7F)
                clean.push_back(c);
            i++;
            continue;
        }
        clean.append(markdown.substr(i, len));
        i += len;
    }

    // 2. line by line markdown flattening
    std::string out;
    size_t lines      = 0;
    bool lastWasBlank = true; // drops leading blank lines
    std::string_view rest(clean);
    while (!rest.empty() && lines < MAX_NOTES_OUTPUT_LINES) {
        const auto nl         = rest.find('\n');
        std::string_view line = rest.substr(0, nl);
        rest                  = (nl == std::string_view::npos) ? std::string_view{} : rest.substr(nl + 1);

        // keep up to 8 spaces of indentation for nested lists
        size_t indent = 0;
        while (indent < line.size() && line[indent] == ' ')
            indent++;
        line = TrimSpaces(line);
        if (line.empty()) {
            if (!lastWasBlank) {
                out.push_back('\n');
                lines++;
            }
            lastWasBlank = true;
            continue;
        }
        std::string prefix(std::min<size_t>(indent, 8), ' ');
        if (line.front() == '#') {
            while (!line.empty() && line.front() == '#')
                line.remove_prefix(1);
            line = TrimSpaces(line);
        } else if (line.size() >= 2 && (line[0] == '*' || line[0] == '-' || line[0] == '+') && line[1] == ' ') {
            prefix += "- ";
            line = TrimSpaces(line.substr(2));
        } else if (line.size() >= 3 && (line == "---" || line == "***" || line == "___")) {
            continue;
        }
        const auto flattened = FlattenInline(line);
        if (out.size() + prefix.size() + flattened.size() + 1 > MAX_NOTES_OUTPUT_BYTES)
            break;
        out += prefix;
        out += flattened;
        out.push_back('\n');
        lines++;
        lastWasBlank = false;
    }
    while (!out.empty() && out.back() == '\n')
        out.pop_back();
    return out;
}

// ==================================================================== zip payload helpers
std::optional<std::string> NormalizeZipEntryPath(std::string_view name)
{
    if (name.empty() || name.size() > MAX_ZIP_PATH_LENGTH)
        return std::nullopt;
    std::string path(name);
    for (auto& c : path) {
        if (c == '\\')
            c = '/';
        if (static_cast<uint8>(c) < 0x20 || c == ':' || c == 0x7F)
            return std::nullopt;
    }
    if (path.front() == '/')
        return std::nullopt;
    // directories end with '/': keep the marker out of the component check
    const bool isDir = path.back() == '/';
    if (isDir)
        path.pop_back();
    if (path.empty())
        return std::nullopt;
    std::string_view rest(path);
    while (true) {
        const auto slash = rest.find('/');
        const auto part  = rest.substr(0, slash);
        if (part.empty() || part == "." || part == "..")
            return std::nullopt;
        // trailing dots/spaces are silently stripped by Windows: "GView.exe." would alias "GView.exe"
        if (part.back() == '.' || part.back() == ' ' || IsReservedDeviceName(part))
            return std::nullopt;
        if (slash == std::string_view::npos)
            break;
        rest = rest.substr(slash + 1);
    }
    if (isDir)
        path.push_back('/');
    return path;
}

std::optional<std::string> FindPayloadPrefix(const std::vector<std::string>& normalizedNames, std::string_view executableName)
{
    std::optional<std::string> prefix;
    for (const auto& n : normalizedNames) {
        const auto slash = n.rfind('/');
        const auto file  = (slash == std::string::npos) ? std::string_view(n) : std::string_view(n).substr(slash + 1);
#ifdef BUILD_FOR_WINDOWS
        const bool match = ToLower(file) == ToLower(executableName);
#else
        const bool match = file == executableName;
#endif
        if (!match)
            continue;
        if (prefix.has_value())
            return std::nullopt; // ambiguous payload
        prefix = (slash == std::string::npos) ? std::string() : n.substr(0, slash + 1);
    }
    return prefix;
}

bool IsProtectedPayloadPath(std::string_view relativePath) noexcept
{
    const auto lower = ToLower(relativePath);
    // user configuration (generated next to the executable at first start) and its backups
    if (lower.find('/') == std::string::npos && (lower.ends_with(".ini") || lower.ends_with(".ini.bak")))
        return true;
    // the updater work folder
    return lower == ".update" || lower.starts_with(".update/");
}

std::optional<std::string> FindChecksum(std::string_view manifest, std::string_view assetName)
{
    if (manifest.size() > MAX_MANIFEST_BYTES)
        return std::nullopt;
    std::optional<std::string> found;
    while (!manifest.empty()) {
        const auto nl         = manifest.find('\n');
        std::string_view line = manifest.substr(0, nl);
        manifest              = (nl == std::string_view::npos) ? std::string_view{} : manifest.substr(nl + 1);
        line                  = TrimSpaces(line);
        if (line.size() < 66)
            continue;
        bool hex = true;
        for (size_t i = 0; i < 64; i++)
            hex &= IsHex(line[i]);
        if (!hex || (line[64] != ' ' && line[64] != '\t'))
            continue;
        auto name = TrimSpaces(line.substr(65));
        if (!name.empty() && name.front() == '*')
            name.remove_prefix(1);
        if (name != assetName)
            continue;
        if (found.has_value())
            return std::nullopt; // duplicated entries: refuse rather than guess
        found = ToLower(line.substr(0, 64));
    }
    return found;
}

// ==================================================================== settings
UpdateSettings UpdateSettings::Load(AppCUI::Utils::IniObject* ini)
{
    UpdateSettings s;
    if (ini == nullptr)
        return s;
    auto sect = ini->GetSection(SECTION);
    if (!sect.Exists())
        return s;
    const auto str = [&](std::string_view key, size_t maxLen) -> std::string {
        const auto v = sect.GetValue(key).AsStringView();
        if (!v.has_value() || v->size() > maxLen)
            return {};
        return std::string(*v);
    };
    s.autoCheck          = sect.GetValue("UpdateCheck").ToBool(true);
    s.includePreReleases = sect.GetValue("UpdateIncludePreReleases").ToBool(true);
    auto feed            = str("UpdateFeedUrl", 2048);
    if (!feed.empty() && IsAllowedUrl(feed))
        s.feedUrl = std::move(feed);
    s.checkIntervalHours = std::clamp<uint32>(sect.GetValue("UpdateCheckIntervalHours").ToUInt32(24), 1, 24 * 30);
    s.remindAfterDays    = std::min<uint32>(sect.GetValue("UpdateRemindAfterDays").ToUInt32(7), 365);
    s.proxy              = str("UpdateProxy", 512);
    s.lastCheck          = sect.GetValue("UpdateLastCheck").ToUInt64(0);
    s.remindAt           = sect.GetValue("UpdateRemindAt").ToUInt64(0);
    const auto version   = [&](std::string_view key) -> std::string {
        auto v = str(key, 32);
        return Version::Parse(v).has_value() ? v : std::string();
    };
    s.lastSeenVersion   = version("UpdateLastSeenVersion");
    s.skippedVersion    = version("UpdateSkippedVersion");
    s.cachedFeedVersion = version("UpdateCachedFeedVersion");
    s.etag              = HexDecode(str("UpdateETag", 512));
    if (!IsSafeHeaderValue(s.etag))
        s.etag.clear();
    return s;
}

void UpdateSettings::SaveState(AppCUI::Utils::IniObject* ini) const
{
    if (ini == nullptr)
        return;
    auto sect                       = (*ini)[SECTION];
    sect["UpdateLastCheck"]         = lastCheck;
    sect["UpdateLastSeenVersion"]   = std::string_view(lastSeenVersion);
    sect["UpdateRemindAt"]          = remindAt;
    sect["UpdateSkippedVersion"]    = std::string_view(skippedVersion);
    const auto etagHex              = HexEncode(etag);
    sect["UpdateETag"]              = std::string_view(etagHex);
    sect["UpdateCachedFeedVersion"] = std::string_view(cachedFeedVersion);
}

void UpdateSettings::WriteDefaults(AppCUI::Utils::IniObject& ini)
{
    const UpdateSettings d;
    auto sect                        = ini[SECTION];
    sect["UpdateCheck"]              = d.autoCheck;
    sect["UpdateIncludePreReleases"] = d.includePreReleases;
    sect["UpdateFeedUrl"]            = std::string_view(d.feedUrl);
    sect["UpdateCheckIntervalHours"] = d.checkIntervalHours;
    sect["UpdateRemindAfterDays"]    = d.remindAfterDays;
    sect["UpdateProxy"]              = std::string_view(d.proxy);
    d.SaveState(&ini);
}

bool UpdateSettings::ShouldCheckNow(uint64 now) const noexcept
{
    if (!autoCheck)
        return false;
    if (lastCheck == 0 || now < lastCheck) // never checked, or the clock went backwards
        return true;
    return now - lastCheck >= static_cast<uint64>(checkIntervalHours) * 3600ull;
}

bool UpdateSettings::ShouldNotify(const Version& found, const Version& current, uint64 now) const
{
    if (!(found > current))
        return false;
    const auto text = found.ToString();
    if (text == skippedVersion)
        return false;
    if (text != lastSeenVersion)
        return true; // first time this version is seen
    return now >= remindAt;
}

void UpdateSettings::OnNotified(const Version& found, uint64 now)
{
    lastSeenVersion = found.ToString();
    OnRemindLater(found, now);
}

void UpdateSettings::OnRemindLater(const Version& found, uint64 now)
{
    lastSeenVersion = found.ToString();
    if (remindAfterDays == 0)
        remindAt = std::numeric_limits<uint64>::max();
    else
        remindAt = now + static_cast<uint64>(remindAfterDays) * 86400ull;
}

void UpdateSettings::OnSkip(const Version& found)
{
    skippedVersion  = found.ToString();
    lastSeenVersion = skippedVersion;
}
} // namespace GView::Update
