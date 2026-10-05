#include "LearningProtocol.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace GView::Security::Learning
{
using json = nlohmann::json;

namespace
{
    constexpr size_t MAX_CONNECTION_STRING_LENGTH = 16 * 1024;
    constexpr size_t MAX_URL_LENGTH               = 512;
    constexpr size_t MAX_LINK_URL_LENGTH          = 2048;
    constexpr size_t MIN_TOKEN_LENGTH             = 16;
    constexpr size_t MAX_TOKEN_LENGTH             = 256;
    constexpr size_t MAX_WEEKS                    = 512;
    constexpr size_t MAX_ITEMS_PER_WEEK           = 1024;
    constexpr size_t MAX_CA_PEM_LENGTH            = 64 * 1024;

    char ToLowerAscii(char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    bool EqualsNoCase(std::string_view a, std::string_view b) noexcept
    {
        if (a.size() != b.size())
            return false;
        for (size_t i = 0; i < a.size(); i++)
        {
            if (ToLowerAscii(a[i]) != ToLowerAscii(b[i]))
                return false;
        }
        return true;
    }

    bool StartsWithNoCase(std::string_view s, std::string_view prefix) noexcept
    {
        return s.size() >= prefix.size() && EqualsNoCase(s.substr(0, prefix.size()), prefix);
    }

    bool IsHexLower(std::string_view s) noexcept
    {
        for (char c : s)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        }
        return true;
    }

    int Base64Value(char c) noexcept
    {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '+')
            return 62;
        if (c == '/')
            return 63;
        return -1;
    }

    // --- tolerant accessors for display data (wrong type => default) ---
    std::string GetText(const json& j, const char* key, size_t maxLen, bool multiline)
    {
        auto it = j.find(key);
        if (it == j.end() || !it->is_string())
            return {};
        return SanitizeDisplayText(it->get_ref<const std::string&>(), maxLen, multiline);
    }

    int64 GetInt(const json& j, const char* key, int64 def = 0)
    {
        auto it = j.find(key);
        if (it == j.end())
            return def;
        if (it->is_number_integer())
            return it->get<int64>();
        if (it->is_number_unsigned())
        {
            const auto v = it->get<uint64>();
            return v > static_cast<uint64>(INT64_MAX) ? INT64_MAX : static_cast<int64>(v);
        }
        return def;
    }

    uint64 GetUInt(const json& j, const char* key)
    {
        const int64 v = GetInt(j, key, 0);
        return v < 0 ? 0 : static_cast<uint64>(v);
    }

    bool GetBool(const json& j, const char* key, bool def = false)
    {
        auto it = j.find(key);
        if (it == j.end() || !it->is_boolean())
            return def;
        return it->get<bool>();
    }

    std::optional<json> ParseJson(BufferView body)
    {
        if (body.GetLength() == 0 || body.GetData() == nullptr)
            return std::nullopt;
        auto j = json::parse(body.GetData(), body.GetData() + body.GetLength(), nullptr, false);
        if (j.is_discarded())
            return std::nullopt;
        return j;
    }

    bool ParseDeliveryModeValue(std::string_view v, DeliveryMode& out) noexcept
    {
        if (EqualsNoCase(v, "memory"))
        {
            out = DeliveryMode::Memory;
            return true;
        }
        if (EqualsNoCase(v, "file"))
        {
            out = DeliveryMode::File;
            return true;
        }
        return false;
    }

    bool IsValidLinkUrl(std::string_view url) noexcept
    {
        if (url.empty() || url.size() > MAX_LINK_URL_LENGTH)
            return false;
        if (!StartsWithNoCase(url, "https://") && !StartsWithNoCase(url, "http://"))
            return false;
        for (unsigned char c : url)
        {
            if (c <= 0x20 || c >= 0x7F)
                return false;
        }
        return true;
    }

    // returns false if the item must be dropped
    bool ParseItem(const json& j, bool problem, CatalogueItem& item)
    {
        if (!j.is_object())
            return false;
        if (auto en = j.find("enabled"); en != j.end() && en->is_boolean() && !en->get<bool>())
            return false; // defensive: disabled items must never be shown
        auto nameIt = j.find("name");
        if (nameIt == j.end() || !nameIt->is_string() || !IsValidItemName(nameIt->get_ref<const std::string&>()))
            return false;
        item.name        = nameIt->get<std::string>();
        item.title       = GetText(j, "title", MAX_TITLE_LENGTH, false);
        item.description = GetText(j, "description", MAX_DESCRIPTION_LENGTH, true);
        item.order       = GetInt(j, "order");
        if (item.title.empty())
            item.title = item.name;

        item.deliveryMode = DeliveryMode::File;
        if (auto dm = j.find("deliveryMode"); dm != j.end())
        {
            if (!dm->is_string() || !ParseDeliveryModeValue(dm->get_ref<const std::string&>(), item.deliveryMode))
                return false;
        }
        item.fileName = SanitizeFileName(GetText(j, "fileName", 255, false));
        item.mimeType = GetText(j, "mimeType", 128, false);
        item.size     = GetUInt(j, "size");
        if (auto sh = j.find("sha256"); sh != j.end() && sh->is_string())
        {
            std::string v = sh->get<std::string>();
            std::transform(v.begin(), v.end(), v.begin(), [](char c) { return ToLowerAscii(c); });
            if (v.size() == 64 && IsHexLower(v))
                item.sha256 = std::move(v);
        }

        if (problem)
        {
            item.kind          = ItemKind::Problem;
            item.pointsMax     = GetInt(j, "pointsMax");
            item.pointsCurrent = GetInt(j, "pointsCurrent", item.pointsMax);
            item.pointsMin     = GetInt(j, "pointsMin");
            if (auto sub = j.find("submission"); sub != j.end() && sub->is_object())
                item.requireExplanation = GetBool(*sub, "requireExplanation");
            if (auto me = j.find("me"); me != j.end() && me->is_object())
            {
                item.hasMe               = true;
                item.me.solved           = GetBool(*me, "solved");
                const int64 attempts     = GetInt(*me, "attempts");
                item.me.attempts         = attempts < 0 ? 0 : static_cast<uint32>(std::min<int64>(attempts, UINT32_MAX));
                item.me.pointsAwarded    = GetInt(*me, "pointsAwarded");
                item.me.firstDeliveredAt = GetUInt(*me, "firstDeliveredAt");
            }
        }
        else
        {
            auto kindIt = j.find("kind");
            if (kindIt == j.end() || !kindIt->is_string())
                return false;
            const auto& kind = kindIt->get_ref<const std::string&>();
            if (kind == "file")
                item.kind = ItemKind::ResourceFile;
            else if (kind == "text")
                item.kind = ItemKind::ResourceText;
            else if (kind == "link")
            {
                item.kind = ItemKind::ResourceLink;
                auto urlIt = j.find("url");
                if (urlIt == j.end() || !urlIt->is_string() || !IsValidLinkUrl(urlIt->get_ref<const std::string&>()))
                    return false;
                item.url = urlIt->get<std::string>();
            }
            else
                return false;
        }
        return true;
    }

    template <typename T>
    void SortByOrder(std::vector<T>& v)
    {
        std::stable_sort(v.begin(), v.end(), [](const T& a, const T& b) {
            if (a.order != b.order)
                return a.order < b.order;
            return a.name < b.name;
        });
    }

    void AppendJsonString(SecureString& out, std::string_view s)
    {
        static constexpr char HEX[] = "0123456789abcdef";
        out.push_back('"');
        for (unsigned char c : s)
        {
            switch (c)
            {
            case '"':
                out.append("\\\"");
                break;
            case '\\':
                out.append("\\\\");
                break;
            case '\n':
                out.append("\\n");
                break;
            case '\r':
                out.append("\\r");
                break;
            case '\t':
                out.append("\\t");
                break;
            default:
                if (c < 0x20)
                {
                    out.append("\\u00");
                    out.push_back(HEX[c >> 4]);
                    out.push_back(HEX[c & 0xF]);
                }
                else
                    out.push_back(static_cast<char>(c));
            }
        }
        out.push_back('"');
    }
} // namespace

// ============================================================================ general helpers
std::string_view FindHeader(const HeaderMap& headers, std::string_view lowerName) noexcept
{
    for (const auto& [k, v] : headers)
    {
        if (k == lowerName)
            return v;
    }
    return {};
}

std::string ClientVersion()
{
    return GVIEW_VERSION;
}

uint64 NowUnix() noexcept
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto s   = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    return s < 0 ? 0 : static_cast<uint64>(s);
}

std::string ToHex(BufferView data)
{
    static constexpr char HEX[] = "0123456789abcdef";
    std::string r;
    r.resize(data.GetLength() * 2);
    for (size_t i = 0; i < data.GetLength(); i++)
    {
        r[i * 2]     = HEX[data[i] >> 4];
        r[i * 2 + 1] = HEX[data[i] & 0x0F];
    }
    return r;
}

bool FromHex(std::string_view hex, std::vector<uint8>& out)
{
    if (hex.size() % 2 != 0)
        return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8> r;
    r.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        r.push_back(static_cast<uint8>((hi << 4) | lo));
    }
    out = std::move(r);
    return true;
}

std::string Base64Encode(BufferView data)
{
    static constexpr char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string r;
    r.reserve(((data.GetLength() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= data.GetLength(); i += 3)
    {
        const uint32 v = (static_cast<uint32>(data[i]) << 16) | (static_cast<uint32>(data[i + 1]) << 8) | data[i + 2];
        r.push_back(ALPHABET[(v >> 18) & 0x3F]);
        r.push_back(ALPHABET[(v >> 12) & 0x3F]);
        r.push_back(ALPHABET[(v >> 6) & 0x3F]);
        r.push_back(ALPHABET[v & 0x3F]);
    }
    const size_t rem = data.GetLength() - i;
    if (rem == 1)
    {
        const uint32 v = static_cast<uint32>(data[i]) << 16;
        r.push_back(ALPHABET[(v >> 18) & 0x3F]);
        r.push_back(ALPHABET[(v >> 12) & 0x3F]);
        r.append("==");
    }
    else if (rem == 2)
    {
        const uint32 v = (static_cast<uint32>(data[i]) << 16) | (static_cast<uint32>(data[i + 1]) << 8);
        r.push_back(ALPHABET[(v >> 18) & 0x3F]);
        r.push_back(ALPHABET[(v >> 12) & 0x3F]);
        r.push_back(ALPHABET[(v >> 6) & 0x3F]);
        r.push_back('=');
    }
    return r;
}

bool Base64Decode(std::string_view text, SecureBytes& out, size_t maxDecodedSize)
{
    out.clear();
    size_t len = text.size();
    size_t pad = 0;
    while (len > 0 && text[len - 1] == '=' && pad < 2)
    {
        len--;
        pad++;
    }
    if (pad > 0 && text.size() % 4 != 0)
        return false; // padding only allowed on a complete final quantum
    if (len % 4 == 1)
        return false; // impossible length
    const size_t decoded = (len / 4) * 3 + ((len % 4) ? (len % 4) - 1 : 0);
    if (decoded > maxDecodedSize)
        return false;
    out.reserve(decoded);
    uint32 acc  = 0;
    int bits    = 0;
    for (size_t i = 0; i < len; i++)
    {
        const int v = Base64Value(text[i]);
        if (v < 0)
        {
            out.clear();
            return false;
        }
        acc = (acc << 6) | static_cast<uint32>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<uint8>((acc >> bits) & 0xFF));
        }
    }
    // non-canonical encodings (non-zero trailing bits) are rejected
    if (bits > 0 && (acc & ((1u << bits) - 1)) != 0)
    {
        out.clear();
        return false;
    }
    return true;
}

std::optional<std::string> NewUuid4()
{
    uint8 b[16];
    if (!Crypto::Internal::GenerateRandomBytes(b, sizeof(b)).ok)
        return std::nullopt;
    b[6] = static_cast<uint8>((b[6] & 0x0F) | 0x40); // version 4
    b[8] = static_cast<uint8>((b[8] & 0x3F) | 0x80); // RFC 4122 variant
    const std::string hex = ToHex(BufferView(b, sizeof(b)));
    std::string r;
    r.reserve(36);
    r.append(hex, 0, 8).push_back('-');
    r.append(hex, 8, 4).push_back('-');
    r.append(hex, 12, 4).push_back('-');
    r.append(hex, 16, 4).push_back('-');
    r.append(hex, 20, 12);
    return r;
}

bool IsUuid4(std::string_view s) noexcept
{
    if (s.size() != 36)
        return false;
    for (size_t i = 0; i < s.size(); i++)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (s[i] != '-')
                return false;
        }
        else if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    }
    return s[14] == '4' && (s[19] == '8' || s[19] == '9' || s[19] == 'a' || s[19] == 'b');
}

// ============================================================================ connection string
Utils::GStatus ValidateServerUrl(std::string_view url, bool allowPlainHttpLocalhost, std::string& normalized)
{
    if (url.empty() || url.size() > MAX_URL_LENGTH)
        return Utils::GStatus::Error("server URL is empty or too long");
    for (unsigned char c : url)
    {
        if (c <= 0x20 || c >= 0x7F)
            return Utils::GStatus::Error("server URL contains invalid characters");
    }
    bool https = false;
    size_t rest;
    if (StartsWithNoCase(url, "https://"))
    {
        https = true;
        rest  = 8;
    }
    else if (StartsWithNoCase(url, "http://"))
        rest = 7;
    else
        return Utils::GStatus::Error("server URL must start with https://");

    std::string_view remainder = url.substr(rest);
    if (remainder.find_first_of("?#") != std::string_view::npos)
        return Utils::GStatus::Error("server URL must not contain a query or fragment");
    const size_t slash         = remainder.find('/');
    std::string_view authority = remainder.substr(0, slash);
    std::string_view path      = slash == std::string_view::npos ? std::string_view{} : remainder.substr(slash);
    if (authority.empty() || authority.find('@') != std::string_view::npos)
        return Utils::GStatus::Error("server URL has an invalid host");

    std::string_view host = authority, port;
    if (authority.front() == '[')
    {
        const size_t close = authority.find(']');
        if (close == std::string_view::npos)
            return Utils::GStatus::Error("server URL has an invalid IPv6 host");
        host = authority.substr(0, close + 1);
        if (close + 1 < authority.size())
        {
            if (authority[close + 1] != ':')
                return Utils::GStatus::Error("server URL has an invalid port");
            port = authority.substr(close + 2);
        }
        for (char c : host.substr(1, host.size() - 2))
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.'))
                return Utils::GStatus::Error("server URL has an invalid IPv6 host");
        }
    }
    else
    {
        const size_t colon = authority.find(':');
        if (colon != std::string_view::npos)
        {
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        }
        if (host.empty())
            return Utils::GStatus::Error("server URL has an empty host");
        for (char c : host)
        {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-'))
                return Utils::GStatus::Error("server URL has an invalid host");
        }
    }
    if (authority.find(':') != std::string_view::npos && authority.front() != '[' && port.empty())
        return Utils::GStatus::Error("server URL has an empty port");
    if (!port.empty())
    {
        if (port.size() > 5)
            return Utils::GStatus::Error("server URL has an invalid port");
        uint32 p = 0;
        for (char c : port)
        {
            if (c < '0' || c > '9')
                return Utils::GStatus::Error("server URL has an invalid port");
            p = p * 10 + static_cast<uint32>(c - '0');
        }
        if (p == 0 || p > 65535)
            return Utils::GStatus::Error("server URL has an invalid port");
    }
    for (char c : path)
    {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '-' || c == '_' || c == '.' ||
              c == '~'))
            return Utils::GStatus::Error("server URL has an invalid path");
    }
    if (!https)
    {
        const bool local = EqualsNoCase(host, "localhost") || host == "127.0.0.1" || host == "[::1]";
        if (!local || !allowPlainHttpLocalhost)
            return Utils::GStatus::Error(
                  "plain http:// is only allowed for localhost/127.0.0.1 when [GView] LearningAllowPlainHttpLocalhost=true");
    }

    std::string r;
    r.reserve(url.size());
    r.append(https ? "https://" : "http://");
    for (char c : authority)
        r.push_back(ToLowerAscii(c));
    r.append(path);
    while (!r.empty() && r.back() == '/')
        r.pop_back();
    normalized = std::move(r);
    return Utils::GStatus::Ok();
}

Utils::GStatus ParseConnectionString(std::string_view cs, bool allowPlainHttpLocalhost, ConnectionInfo& out)
{
    // tolerate surrounding whitespace from copy/paste, nothing else
    while (!cs.empty() && (cs.front() == ' ' || cs.front() == '\t' || cs.front() == '\r' || cs.front() == '\n'))
        cs.remove_prefix(1);
    while (!cs.empty() && (cs.back() == ' ' || cs.back() == '\t' || cs.back() == '\r' || cs.back() == '\n'))
        cs.remove_suffix(1);
    if (cs.empty())
        return Utils::GStatus::Error("connection string is empty");
    if (cs.size() > MAX_CONNECTION_STRING_LENGTH)
        return Utils::GStatus::Error("connection string is too long");

    SecureBytes outer;
    if (!Base64Decode(cs, outer, MAX_CONNECTION_STRING_LENGTH))
        return Utils::GStatus::Error("connection string is not valid base64");
    std::string_view decoded(reinterpret_cast<const char*>(outer.data()), outer.size());

    std::vector<std::string_view> parts;
    size_t start = 0;
    while (true)
    {
        const size_t pos = decoded.find('#', start);
        parts.push_back(decoded.substr(start, pos == std::string_view::npos ? std::string_view::npos : pos - start));
        if (pos == std::string_view::npos)
            break;
        start = pos + 1;
        if (parts.size() > 4)
            return Utils::GStatus::Error("connection string has too many parts");
    }
    if (parts.size() < 2)
        return Utils::GStatus::Error("connection string must contain token#server");
    if (parts.size() > 4)
        return Utils::GStatus::Error("connection string has too many parts");

    ConnectionInfo info;
    info.version = parts.size() >= 3 ? 2 : 1;

    SecureBytes tmp;
    if (!Base64Decode(parts[0], tmp, MAX_TOKEN_LENGTH))
        return Utils::GStatus::Error("access token part is not valid base64");
    if (tmp.size() < MIN_TOKEN_LENGTH || tmp.size() > MAX_TOKEN_LENGTH)
        return Utils::GStatus::Error("access token has an invalid length");
    for (uint8 c : tmp)
    {
        // the token travels in an HTTP header: printable ASCII only (prevents header injection)
        if (c < 0x21 || c > 0x7E)
            return Utils::GStatus::Error("access token contains invalid characters");
    }
    info.token.assign(reinterpret_cast<const char*>(tmp.data()), tmp.size());

    if (!Base64Decode(parts[1], tmp, MAX_URL_LENGTH))
        return Utils::GStatus::Error("server part is not valid base64");
    const std::string url(reinterpret_cast<const char*>(tmp.data()), tmp.size());
    auto st = ValidateServerUrl(url, allowPlainHttpLocalhost, info.serverUrl);
    if (!st.ok)
        return st;

    if (parts.size() >= 3)
    {
        if (!Base64Decode(parts[2], tmp, 128))
            return Utils::GStatus::Error("public key part is not valid base64");
        const std::string_view hex(reinterpret_cast<const char*>(tmp.data()), tmp.size());
        if (hex.size() != 64 || !FromHex(hex, info.publicKey))
            return Utils::GStatus::Error("public key must be 64 hex characters (32-byte Ed25519 key)");
    }
    if (parts.size() == 4)
    {
        if (!Base64Decode(parts[3], tmp, MAX_CA_PEM_LENGTH * 2))
            return Utils::GStatus::Error("extra part is not valid base64");
        auto j = ParseJson(ToView(tmp));
        if (!j.has_value() || !j->is_object())
            return Utils::GStatus::Error("extra part must be a JSON object");
        if (auto label = j->find("label"); label != j->end())
        {
            if (!label->is_string())
                return Utils::GStatus::Error("extra.label must be a string");
            info.label = SanitizeDisplayText(label->get_ref<const std::string&>(), 128, false);
        }
        if (auto ca = j->find("caPem"); ca != j->end())
        {
            if (!ca->is_string())
                return Utils::GStatus::Error("extra.caPem must be a string");
            SecureBytes pem;
            if (!Base64Decode(ca->get_ref<const std::string&>(), pem, MAX_CA_PEM_LENGTH))
                return Utils::GStatus::Error("extra.caPem is not valid base64");
            info.caPem.assign(reinterpret_cast<const char*>(pem.data()), pem.size());
            if (info.caPem.find("-----BEGIN CERTIFICATE-----") == std::string::npos)
                return Utils::GStatus::Error("extra.caPem does not contain a PEM certificate");
        }
    }
    out = std::move(info);
    return Utils::GStatus::Ok();
}

std::string BuildConnectionString(std::string_view token, std::string_view serverUrl, std::string_view publicKeyHex, std::string_view extraJson)
{
    std::string inner = Base64Encode(BufferView(token));
    inner.push_back('#');
    inner.append(Base64Encode(BufferView(serverUrl)));
    if (!publicKeyHex.empty())
    {
        inner.push_back('#');
        inner.append(Base64Encode(BufferView(publicKeyHex)));
        if (!extraJson.empty())
        {
            inner.push_back('#');
            inner.append(Base64Encode(BufferView(extraJson)));
        }
    }
    return Base64Encode(BufferView(inner));
}

std::string SubjectForToken(const SecureString& token)
{
    uint8 hash[32];
    if (!Crypto::Internal::ComputeSHA256(ToView(token), hash).ok)
        return {};
    return ToHex(BufferView(hash, 8)); // 8 bytes = 16 hex characters
}

bool IsValidItemName(std::string_view name) noexcept
{
    if (name.empty() || name.size() > MAX_ITEM_NAME_LENGTH)
        return false;
    for (char c : name)
    {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    return true;
}

std::string SanitizeFileName(std::string_view name)
{
    const size_t sep = name.find_last_of("/\\");
    if (sep != std::string_view::npos)
        name = name.substr(sep + 1);
    std::string r;
    r.reserve(std::min<size_t>(name.size(), 128));
    for (unsigned char c : name)
    {
        if (r.size() >= 128)
            break;
        if (c < 0x20 || c == 0x7F || c == '<' || c == '>' || c == ':' || c == '"' || c == '|' || c == '?' || c == '*')
            r.push_back('_');
        else
            r.push_back(static_cast<char>(c));
    }
    while (!r.empty() && (r.front() == '.' || r.front() == ' '))
        r.erase(r.begin());
    while (!r.empty() && (r.back() == '.' || r.back() == ' '))
        r.pop_back();
    if (r.empty())
        return "task.bin";
    // Windows reserved device names (checked on the part before the first dot)
    std::string base = r.substr(0, r.find('.'));
    std::transform(base.begin(), base.end(), base.begin(), [](char c) { return ToLowerAscii(c); });
    static constexpr std::string_view RESERVED[] = { "con", "prn", "aux", "nul" };
    bool reserved = std::find(std::begin(RESERVED), std::end(RESERVED), base) != std::end(RESERVED);
    if (!reserved && base.size() == 4 && (base.starts_with("com") || base.starts_with("lpt")) && base[3] >= '0' && base[3] <= '9')
        reserved = true;
    if (reserved)
        r.insert(r.begin(), '_');
    return r;
}

std::string SanitizeDisplayText(std::string_view text, size_t maxLen, bool multiline)
{
    std::string r;
    r.reserve(std::min(text.size(), maxLen));
    for (unsigned char c : text)
    {
        if (r.size() >= maxLen)
            break;
        if (c == '\n' || c == '\t')
            r.push_back(multiline ? static_cast<char>(c) : ' ');
        else if (c == '\r')
            continue;
        else if (c < 0x20 || c == 0x7F)
            r.push_back(' ');
        else
            r.push_back(static_cast<char>(c));
    }
    return r;
}

// ============================================================================ errors
std::string_view ErrorCodeName(ErrorCode code) noexcept
{
    switch (code)
    {
    case ErrorCode::None:
        return "NONE";
    case ErrorCode::BadRequest:
        return "BAD_REQUEST";
    case ErrorCode::Unauthorized:
        return "UNAUTHORIZED";
    case ErrorCode::Forbidden:
        return "FORBIDDEN";
    case ErrorCode::NotFound:
        return "NOT_FOUND";
    case ErrorCode::RateLimited:
        return "RATE_LIMITED";
    case ErrorCode::PolicyExpired:
        return "POLICY_EXPIRED";
    case ErrorCode::PolicyNotStarted:
        return "POLICY_NOT_STARTED";
    case ErrorCode::AlreadySolved:
        return "ALREADY_SOLVED";
    case ErrorCode::ItemDisabled:
        return "ITEM_DISABLED";
    case ErrorCode::UnsupportedClient:
        return "UNSUPPORTED_CLIENT";
    case ErrorCode::ServerError:
        return "SERVER_ERROR";
    case ErrorCode::Transport:
        return "TRANSPORT_ERROR";
    case ErrorCode::Protocol:
        return "PROTOCOL_ERROR";
    }
    return "UNKNOWN";
}

ServerError ParseErrorEnvelope(long httpStatus, BufferView body, std::string_view retryAfterHeader)
{
    ServerError e;
    e.httpStatus = httpStatus;
    // defaults derived from the HTTP status (spec §1 mapping)
    switch (httpStatus)
    {
    case 400:
        e.code = ErrorCode::BadRequest;
        break;
    case 401:
        e.code = ErrorCode::Unauthorized;
        break;
    case 403:
        e.code = ErrorCode::Forbidden;
        break;
    case 404:
        e.code = ErrorCode::NotFound;
        break;
    case 409:
        e.code = ErrorCode::AlreadySolved;
        break;
    case 426:
        e.code = ErrorCode::UnsupportedClient;
        break;
    case 429:
        e.code      = ErrorCode::RateLimited;
        e.retryable = true;
        break;
    default:
        e.code      = httpStatus >= 500 ? ErrorCode::ServerError : ErrorCode::Protocol;
        e.retryable = httpStatus >= 500;
        break;
    }
    try
    {
        if (auto j = ParseJson(body); j.has_value() && j->is_object())
        {
            e.details = GetText(*j, "details", 512, false);
            if (auto c = j->find("code"); c != j->end() && c->is_string())
            {
                static constexpr std::pair<std::string_view, ErrorCode> CODES[] = {
                    { "BAD_REQUEST", ErrorCode::BadRequest },
                    { "UNAUTHORIZED", ErrorCode::Unauthorized },
                    { "FORBIDDEN", ErrorCode::Forbidden },
                    { "NOT_FOUND", ErrorCode::NotFound },
                    { "RATE_LIMITED", ErrorCode::RateLimited },
                    { "POLICY_EXPIRED", ErrorCode::PolicyExpired },
                    { "POLICY_NOT_STARTED", ErrorCode::PolicyNotStarted },
                    { "ALREADY_SOLVED", ErrorCode::AlreadySolved },
                    { "ITEM_DISABLED", ErrorCode::ItemDisabled },
                    { "UNSUPPORTED_CLIENT", ErrorCode::UnsupportedClient },
                    { "SERVER_ERROR", ErrorCode::ServerError },
                };
                const auto& code = c->get_ref<const std::string&>();
                for (const auto& [name, value] : CODES)
                {
                    if (name == code)
                    {
                        e.code = value;
                        break;
                    }
                }
            }
            if (auto r = j->find("retryable"); r != j->end() && r->is_boolean())
                e.retryable = r->get<bool>();
        }
    }
    catch (...)
    {
    }
    if (!retryAfterHeader.empty() && retryAfterHeader.size() <= 6)
    {
        uint32 v = 0;
        bool ok  = true;
        for (char c : retryAfterHeader)
        {
            if (c < '0' || c > '9')
            {
                ok = false;
                break;
            }
            v = v * 10 + static_cast<uint32>(c - '0');
        }
        if (ok)
            e.retryAfterSeconds = std::min<uint32>(v, 3600);
    }
    return e;
}

std::string DescribeError(const ServerError& err)
{
    std::string msg;
    switch (err.code)
    {
    case ErrorCode::Unauthorized:
        msg = "The server rejected the access token (revoked, expired or unknown).";
        break;
    case ErrorCode::PolicyExpired:
        msg = "The course policy has expired. Reconnect to obtain a new one.";
        break;
    case ErrorCode::PolicyNotStarted:
        msg = "The course policy is not active yet.";
        break;
    case ErrorCode::NotFound:
    case ErrorCode::ItemDisabled:
        msg = "The item is not available (unknown, disabled or not visible yet).";
        break;
    case ErrorCode::RateLimited:
        msg = "Too many requests. Please wait";
        if (err.retryAfterSeconds > 0)
            msg += " " + std::to_string(err.retryAfterSeconds) + " s";
        msg += " and retry.";
        break;
    case ErrorCode::AlreadySolved:
        msg = "This problem is already solved.";
        break;
    case ErrorCode::UnsupportedClient:
        msg = "The server requires a newer GView version.";
        break;
    case ErrorCode::ServerError:
        msg = "The server encountered an error.";
        break;
    case ErrorCode::Transport:
        msg = "Could not reach the server.";
        break;
    case ErrorCode::Protocol:
        msg = "The server response does not follow the Learning Mode protocol.";
        break;
    default:
        msg = "Request failed.";
        break;
    }
    msg += " [";
    msg += ErrorCodeName(err.code);
    if (err.httpStatus > 0)
        msg += ", HTTP " + std::to_string(err.httpStatus);
    msg += "]";
    if (!err.details.empty())
        msg += " " + err.details;
    return msg;
}

// ============================================================================ connect
Utils::GStatus ParseConnectResponse(BufferView body, ConnectResponse& out)
{
    try
    {
        ConnectResponse r;
        bool onlyWhitespace = true;
        for (size_t i = 0; i < body.GetLength(); i++)
        {
            const uint8 c = body[i];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            {
                onlyWhitespace = false;
                break;
            }
        }
        if (onlyWhitespace)
        {
            r.legacy = true;
            out      = std::move(r);
            return Utils::GStatus::Ok();
        }
        auto j = ParseJson(body);
        if (!j.has_value() || !j->is_object())
        {
            r.legacy = true; // pre-v2 servers answer "/GView/" with arbitrary text
            out      = std::move(r);
            return Utils::GStatus::Ok();
        }
        const bool hasPolicy   = j->contains("policy");
        const int64 protoVer   = GetInt(*j, "protocolVersion", 0);
        if (!hasPolicy && protoVer < 2)
        {
            r.legacy = true;
            out      = std::move(r);
            return Utils::GStatus::Ok();
        }
        if (auto st = j->find("status"); st != j->end() && (!st->is_string() || st->get_ref<const std::string&>() != "ok"))
            return Utils::GStatus::Error("connect response status is not 'ok'");
        r.protocolVersion = protoVer < 0 ? 0 : static_cast<uint32>(std::min<int64>(protoVer, UINT32_MAX));
        r.serverVersion   = GetText(*j, "serverVersion", 32, false);
        r.serverTime      = GetUInt(*j, "serverTime");
        auto pol          = j->find("policy");
        auto sig          = j->find("policySignature");
        if (pol == j->end() || !pol->is_string() || sig == j->end() || !sig->is_string())
            return Utils::GStatus::Error("connect response lacks policy/policySignature");
        SecureBytes tmp;
        if (!Base64Decode(pol->get_ref<const std::string&>(), tmp, MAX_POLICY_BYTES) || tmp.empty())
            return Utils::GStatus::Error("policy is not valid base64 or exceeds 64 KiB");
        r.policyBytes.assign(tmp.begin(), tmp.end());
        if (!Base64Decode(sig->get_ref<const std::string&>(), tmp, 64) || tmp.size() != 64)
            return Utils::GStatus::Error("policySignature must be a base64 64-byte Ed25519 signature");
        r.signature.assign(tmp.begin(), tmp.end());
        if (auto user = j->find("user"); user != j->end() && user->is_object())
        {
            r.displayName = GetText(*user, "displayName", 128, false);
            r.score       = GetInt(*user, "score");
        }
        out = std::move(r);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed connect response");
    }
}

// ============================================================================ catalogue
const CatalogueItem* Catalogue::Find(std::string_view name, bool problem) const noexcept
{
    for (const auto& w : weeks)
    {
        for (const auto& it : problem ? w.problems : w.resources)
        {
            if (it.name == name)
                return &it;
        }
    }
    return nullptr;
}

const Week* Catalogue::FindWeekOf(std::string_view name) const noexcept
{
    for (const auto& w : weeks)
    {
        for (const auto* list : { &w.problems, &w.resources })
        {
            for (const auto& it : *list)
            {
                if (it.name == name)
                    return &w;
            }
        }
    }
    return nullptr;
}

Utils::GStatus ParseWeeks(BufferView body, Catalogue& out)
{
    try
    {
        auto j = ParseJson(body);
        if (!j.has_value() || !j->is_object())
            return Utils::GStatus::Error("GetWeeks response is not a JSON object");
        if (auto st = j->find("status"); st != j->end() && st->is_string() && st->get_ref<const std::string&>() != "ok")
            return Utils::GStatus::Error("GetWeeks status is not 'ok'");
        auto weeksIt = j->find("weeks");
        if (weeksIt == j->end() || !weeksIt->is_array())
            return Utils::GStatus::Error("GetWeeks response lacks a 'weeks' array");

        Catalogue cat;
        std::vector<std::string> seen;
        auto isDuplicate = [&](const std::string& name) {
            if (std::find(seen.begin(), seen.end(), name) != seen.end())
                return true;
            seen.push_back(name);
            return false;
        };
        for (const auto& wj : *weeksIt)
        {
            if (cat.weeks.size() >= MAX_WEEKS)
            {
                cat.rejectedItems++;
                continue;
            }
            if (!wj.is_object())
            {
                cat.rejectedItems++;
                continue;
            }
            if (auto en = wj.find("enabled"); en != wj.end() && en->is_boolean() && !en->get<bool>())
            {
                cat.rejectedItems++;
                continue;
            }
            Week w;
            w.id           = GetInt(wj, "id");
            w.name         = GetText(wj, "name", MAX_TITLE_LENGTH, false);
            w.title        = GetText(wj, "title", MAX_TITLE_LENGTH, false);
            w.description  = GetText(wj, "description", MAX_DESCRIPTION_LENGTH, true);
            w.order        = GetInt(wj, "order");
            w.visibleFrom  = GetUInt(wj, "visibleFrom");
            w.visibleUntil = GetUInt(wj, "visibleUntil");
            if (w.name.empty())
                w.name = "Week " + std::to_string(w.id);
            for (const bool problem : { true, false })
            {
                auto listIt = wj.find(problem ? "problems" : "resources");
                if (listIt == wj.end() || !listIt->is_array())
                    continue;
                auto& target = problem ? w.problems : w.resources;
                for (const auto& ij : *listIt)
                {
                    CatalogueItem item;
                    if (target.size() >= MAX_ITEMS_PER_WEEK || !ParseItem(ij, problem, item) || isDuplicate(item.name))
                    {
                        cat.rejectedItems++;
                        continue;
                    }
                    target.push_back(std::move(item));
                }
                SortByOrder(target);
            }
            cat.weeks.push_back(std::move(w));
        }
        std::stable_sort(cat.weeks.begin(), cat.weeks.end(), [](const Week& a, const Week& b) {
            if (a.order != b.order)
                return a.order < b.order;
            return a.id < b.id;
        });
        out = std::move(cat);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed GetWeeks response");
    }
}

Utils::GStatus ParseLegacyProblems(BufferView body, Catalogue& out)
{
    try
    {
        auto j = ParseJson(body);
        if (!j.has_value() || !j->is_array())
            return Utils::GStatus::Error("GetProblems response is not a JSON array");
        Catalogue cat;
        cat.legacy = true;
        Week w;
        w.name  = "Problems";
        w.title = "Legacy server (no weeks)";
        std::vector<std::string> seen;
        for (const auto& pj : *j)
        {
            CatalogueItem item;
            if (w.problems.size() >= MAX_ITEMS_PER_WEEK || !ParseItem(pj, true, item) ||
                std::find(seen.begin(), seen.end(), item.name) != seen.end())
            {
                cat.rejectedItems++;
                continue;
            }
            seen.push_back(item.name);
            w.problems.push_back(std::move(item));
        }
        cat.weeks.push_back(std::move(w));
        out = std::move(cat);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed GetProblems response");
    }
}

// ============================================================================ delivery
Utils::GStatus ParseDeliveryHeaders(const HeaderMap& headers, bool requireV2, DeliveryHeaders& out)
{
    DeliveryHeaders d;
    if (auto v = FindHeader(headers, "x-gview-delivery"); !v.empty())
    {
        if (!ParseDeliveryModeValue(v, d.mode))
            return Utils::GStatus::Error("invalid X-GView-Delivery header");
        d.hasMode = true;
    }
    else if (requireV2)
        return Utils::GStatus::Error("missing X-GView-Delivery header");

    if (auto v = FindHeader(headers, "x-gview-encrypted"); !v.empty())
    {
        if (v == "1")
            d.encrypted = true;
        else if (v != "0")
            return Utils::GStatus::Error("invalid X-GView-Encrypted header");
    }
    if (auto v = FindHeader(headers, "x-gview-sha256"); !v.empty())
    {
        std::string h(v);
        std::transform(h.begin(), h.end(), h.begin(), [](char c) { return ToLowerAscii(c); });
        if (h.size() != 64 || !IsHexLower(h))
            return Utils::GStatus::Error("invalid X-GView-SHA256 header");
        d.sha256 = std::move(h);
    }
    else if (requireV2)
        return Utils::GStatus::Error("missing X-GView-SHA256 header");

    if (auto v = FindHeader(headers, "x-gview-filename"); !v.empty())
        d.fileName = SanitizeFileName(v);
    if (auto v = FindHeader(headers, "x-gview-item-version"); !v.empty())
    {
        if (v.size() > 9)
            return Utils::GStatus::Error("invalid X-GView-Item-Version header");
        uint32 n = 0;
        for (char c : v)
        {
            if (c < '0' || c > '9')
                return Utils::GStatus::Error("invalid X-GView-Item-Version header");
            n = n * 10 + static_cast<uint32>(c - '0');
        }
        d.itemVersion = n;
    }
    out = std::move(d);
    return Utils::GStatus::Ok();
}

// ============================================================================ submissions
SecureString BuildSubmitBody(const SubmitRequest& req)
{
    SecureString body;
    body.reserve(256 + req.flag.size() + req.explanation.size() * 2);
    body.append("{\"problem\":");
    AppendJsonString(body, req.problem);
    body.append(",\"flag\":");
    AppendJsonString(body, std::string_view(req.flag.data(), req.flag.size()));
    body.append(",\"explanation\":");
    AppendJsonString(body, std::string_view(req.explanation.data(), req.explanation.size()));
    body.append(",\"clientSubmissionId\":");
    AppendJsonString(body, req.clientSubmissionId);
    body.append(",\"policyId\":");
    AppendJsonString(body, req.policyId);
    body.append(",\"policyDigest\":");
    AppendJsonString(body, req.policyDigest);
    body.append(",\"clientVersion\":");
    AppendJsonString(body, req.clientVersion);
    body.append(",\"clientTime\":");
    const std::string t = std::to_string(req.clientTime);
    body.append(t.data(), t.size());
    body.push_back('}');
    return body;
}

Utils::GStatus ParseSubmitResponse(long httpStatus, BufferView body, SubmitResult& out, ServerError& err)
{
    err = ServerError{};
    if (httpStatus == 409)
    {
        err = ParseErrorEnvelope(httpStatus, body, {});
        if (err.code == ErrorCode::AlreadySolved)
        {
            SubmitResult r;
            r.alreadySolved = true;
            r.details       = err.details.empty() ? "Problem already solved." : err.details;
            out             = std::move(r);
            err             = ServerError{};
            return Utils::GStatus::Ok();
        }
        return Utils::GStatus::Error(DescribeError(err));
    }
    if (httpStatus < 200 || httpStatus >= 300)
    {
        err = ParseErrorEnvelope(httpStatus, body, {});
        return Utils::GStatus::Error(DescribeError(err));
    }
    try
    {
        auto j = ParseJson(body);
        if (!j.has_value() || !j->is_object())
        {
            err.code       = ErrorCode::Protocol;
            err.httpStatus = httpStatus;
            return Utils::GStatus::Error("SubmitFlag response is not a JSON object");
        }
        SubmitResult r;
        std::string status = GetText(*j, "status", 32, false);
        r.details          = GetText(*j, "details", 1024, false);
        if (auto c = j->find("correct"); c != j->end() && c->is_boolean())
        {
            r.correct = c->get<bool>();
        }
        else
        {
            // legacy server: verdict carried by status (spec §4)
            r.legacy  = true;
            r.correct = status == "ok";
        }
        r.points        = GetInt(*j, "points");
        const int64 att = GetInt(*j, "attempts");
        r.attempts      = att < 0 ? 0 : static_cast<uint32>(std::min<int64>(att, UINT32_MAX));
        r.alreadySolved = GetBool(*j, "alreadySolved");
        r.duplicate     = GetBool(*j, "duplicate");
        if (j->contains("totalScore"))
        {
            r.hasTotalScore = true;
            r.totalScore    = GetInt(*j, "totalScore");
        }
        out = std::move(r);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        err.code = ErrorCode::Protocol;
        return Utils::GStatus::Error("malformed SubmitFlag response");
    }
}
} // namespace GView::Security::Learning
