#include "CatalogueView.hpp"

#include <charconv>
#include <iterator>

namespace GView::Security::Learning
{
namespace
{
    constexpr size_t WEEK_HASH_HEX_CHARS = 16;

    // length-prefixed, so two different weeks never serialize to the same bytes ("ab"+"c" vs "a"+"bc")
    void AddField(std::string& out, std::string_view value)
    {
        out += std::to_string(value.size());
        out.push_back(':');
        out.append(value);
        out.push_back(';');
    }
    void AddField(std::string& out, int64 value)
    {
        AddField(out, std::string_view(std::to_string(value)));
    }
    void AddField(std::string& out, uint64 value)
    {
        AddField(out, std::string_view(std::to_string(value)));
    }
    void AddField(std::string& out, bool value)
    {
        AddField(out, std::string_view(value ? "1" : "0"));
    }

    void AddItem(std::string& out, const CatalogueItem& it)
    {
        AddField(out, static_cast<int64>(it.kind));
        AddField(out, it.name);
        AddField(out, it.title);
        AddField(out, it.description);
        AddField(out, it.order);
        AddField(out, it.fileName);
        AddField(out, it.sha256);
        AddField(out, it.url);
        AddField(out, it.size);
        AddField(out, it.pointsMax);
        AddField(out, it.pointsMin);
        AddField(out, it.requireExplanation);
        AddField(out, it.solutionAvailable);
        AddField(out, it.solutionHasReplay);
    }

    bool IsWeekHash(std::string_view s) noexcept
    {
        if (s.size() != WEEK_HASH_HEX_CHARS)
            return false;
        for (char c : s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        return true;
    }

    bool ParseInt64(std::string_view s, int64& out) noexcept
    {
        if (s.empty())
            return false;
        const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
        return r.ec == std::errc() && r.ptr == s.data() + s.size();
    }

    std::string_view Trim(std::string_view s) noexcept
    {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
            s.remove_prefix(1);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
            s.remove_suffix(1);
        return s;
    }
} // namespace

std::string WeekContentHash(const Week& week)
{
    std::string text;
    AddField(text, std::string_view("GView-Week-v1"));
    AddField(text, week.name);
    AddField(text, week.title);
    AddField(text, week.description);
    AddField(text, static_cast<uint64>(week.problems.size()));
    for (const auto& it : week.problems)
        AddItem(text, it);
    AddField(text, static_cast<uint64>(week.resources.size()));
    for (const auto& it : week.resources)
        AddItem(text, it);

    uint8 hash[32];
    if (!Crypto::Internal::ComputeSHA256(BufferView(reinterpret_cast<const uint8*>(text.data()), text.size()), hash).ok)
        return {};
    return ToHex(BufferView(hash, WEEK_HASH_HEX_CHARS / 2));
}

std::string_view WeekOrderName(WeekOrder order) noexcept
{
    return order == WeekOrder::OldestFirst ? "oldest" : "newest";
}

WeekOrder ParseWeekOrder(std::string_view text) noexcept
{
    return Trim(text) == "oldest" ? WeekOrder::OldestFirst : WeekOrder::NewestFirst;
}

std::string SerializeFoldedWeeks(const std::map<int64, std::string>& folded)
{
    std::string r;
    size_t count = 0;
    for (const auto& [id, hash] : folded)
    {
        if (!IsWeekHash(hash))
            continue;
        if (count++ == MAX_REMEMBERED_FOLDED_WEEKS)
            break;
        if (!r.empty())
            r.push_back(',');
        r += std::to_string(id);
        r.push_back(':');
        r += hash;
    }
    return r;
}

std::map<int64, std::string> ParseFoldedWeeks(std::string_view text)
{
    std::map<int64, std::string> r;
    while (!text.empty() && r.size() < MAX_REMEMBERED_FOLDED_WEEKS)
    {
        const size_t comma     = text.find(',');
        const std::string_view entry = Trim(text.substr(0, comma));
        text                   = comma == std::string_view::npos ? std::string_view() : text.substr(comma + 1);
        const size_t colon     = entry.find(':');
        if (colon == std::string_view::npos)
            continue;
        int64 id = 0;
        const auto hash = Trim(entry.substr(colon + 1));
        if (!ParseInt64(Trim(entry.substr(0, colon)), id) || !IsWeekHash(hash))
            continue;
        r[id] = std::string(hash);
    }
    return r;
}

std::vector<size_t> WeekDisplayOrder(const Catalogue& catalogue, WeekOrder order)
{
    std::vector<size_t> r(catalogue.weeks.size());
    for (size_t i = 0; i < r.size(); i++)
        r[i] = order == WeekOrder::NewestFirst ? r.size() - 1 - i : i;
    return r;
}

std::string ViewStateKey(const SecureString& token)
{
    if (token.empty())
        return {};
    SecureString input = "GView-Learning-View-v1";
    input.push_back('\0');
    input.append(token);
    uint8 hash[32];
    if (!Crypto::Internal::ComputeSHA256(ToView(input), hash).ok)
        return {};
    return ToHex(BufferView(hash, 8));
}

std::string WeekViewSection(std::string_view serverUrl, std::string_view viewStateKey)
{
    if (viewStateKey.empty())
        return {};
    std::string r = "LearningCourse.";
    r += ServerFolderName(serverUrl);
    r.push_back('.');
    r.append(viewStateKey);
    for (auto& c : r)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.'))
            c = '_';
    return r;
}

bool ApplyFoldChange(WeekViewState& state, int64 weekId, std::string_view shownHash, bool folded)
{
    const auto it = state.folded.find(weekId);
    if (!folded)
    {
        if (it == state.folded.end())
            return false;
        state.folded.erase(it);
        return true;
    }
    if (it != state.folded.end() || !IsWeekHash(shownHash))
        return false;
    state.folded.emplace(weekId, std::string(shownHash));
    // over the cap: the smallest ids go first, never the week just folded
    for (auto e = state.folded.begin(); state.folded.size() > MAX_REMEMBERED_FOLDED_WEEKS && e != state.folded.end();)
        e = e->first == weekId ? std::next(e) : state.folded.erase(e);
    return true;
}

bool FoldedWeekChanged(const WeekViewState& state, int64 weekId, std::string_view currentHash)
{
    const auto it = state.folded.find(weekId);
    return it != state.folded.end() && !currentHash.empty() && it->second != currentHash;
}
} // namespace GView::Security::Learning
