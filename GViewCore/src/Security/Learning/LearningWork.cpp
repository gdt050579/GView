#include "LearningWork.hpp"
#include "LearningNotes.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <set>

namespace GView::Security::Learning
{
using json = nlohmann::json;

namespace
{
    // a work document nests ~6 levels (zones / entries / replay events); the answers add 2: anything deeper is hostile
    // (nlohmann::json destroys and dumps values recursively)
    constexpr size_t MAX_WORK_JSON_DEPTH = 64;

    // false when the text nests arrays/objects deeper than maxDepth (strings are skipped, escapes honoured)
    bool NestingWithin(std::string_view text, size_t maxDepth) noexcept
    {
        size_t depth  = 0;
        bool inString = false;
        for (size_t i = 0; i < text.size(); i++)
        {
            const char c = text[i];
            if (inString)
            {
                if (c == '\\')
                    i++;
                else if (c == '"')
                    inString = false;
                continue;
            }
            if (c == '"')
                inString = true;
            else if (c == '{' || c == '[')
            {
                if (++depth > maxDepth)
                    return false;
            }
            else if ((c == '}' || c == ']') && depth > 0)
                depth--;
        }
        return true;
    }

    std::optional<json> ParseJsonObject(std::string_view text)
    {
        if (text.empty() || !NestingWithin(text, MAX_WORK_JSON_DEPTH))
            return std::nullopt;
        auto j = json::parse(text.begin(), text.end(), nullptr, false);
        if (j.is_discarded() || !j.is_object())
            return std::nullopt;
        return j;
    }

    std::optional<json> ParseJsonObject(BufferView body)
    {
        if (body.GetLength() == 0 || body.GetData() == nullptr)
            return std::nullopt;
        return ParseJsonObject(std::string_view(reinterpret_cast<const char*>(body.GetData()), body.GetLength()));
    }

    bool StatusIsOk(const json& j)
    {
        auto st = j.find("status");
        return st == j.end() || (st->is_string() && st->get_ref<const std::string&>() == "ok");
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

    bool GetBool(const json& j, const char* key, bool def)
    {
        auto it = j.find(key);
        return it != j.end() && it->is_boolean() ? it->get<bool>() : def;
    }

    // an integer >= 1 (ids, revisions); 0 otherwise (a float, a string, a negative value)
    int64 GetPositiveId(const json& j, const char* key)
    {
        auto it = j.find(key);
        if (it == j.end() || !it->is_number_integer())
            return 0;
        const int64 v = GetInt(j, key, 0);
        return v > 0 ? v : 0;
    }

    uint32 GetSteps(const json& j)
    {
        return static_cast<uint32>(std::clamp<int64>(GetInt(j, "replaySteps", 0), 0, UINT32_MAX));
    }

    bool HasNul(const json& j)
    {
        switch (j.type())
        {
        case json::value_t::string:
            return j.get_ref<const std::string&>().find('\0') != std::string::npos;
        case json::value_t::array:
            for (const auto& v : j)
                if (HasNul(v))
                    return true;
            return false;
        case json::value_t::object:
            for (const auto& [k, v] : j.items())
                if (k.find('\0') != std::string::npos || HasNul(v))
                    return true;
            return false;
        default:
            return false;
        }
    }

    // the checks of ValidateWorkDocumentText on a parsed value; canonical = compact dump (keys sorted by nlohmann)
    Utils::GStatus CanonicalDocument(const json& doc, size_t maxBytes, std::string& canonical)
    {
        if (!doc.is_object())
            return Utils::GStatus::Error("the work document is not a JSON object");
        auto format = doc.find("format");
        if (format == doc.end() || !format->is_string() || format->get_ref<const std::string&>() != WORK_DOCUMENT_FORMAT)
            return Utils::GStatus::Error("the work document is not a GView disassembly annotations document");
        auto version = doc.find("version");
        if (version == doc.end() || !version->is_number_integer())
            return Utils::GStatus::Error("the work document has no integer version");
        const int64 v = GetInt(doc, "version", 0);
        if (v < 1)
            return Utils::GStatus::Error("the work document has an invalid version");
        if (v > WORK_DOCUMENT_MAX_VERSION)
            return Utils::GStatus::Error("the work document was written by a newer GView (version " + std::to_string(v) + ")");
        if (HasNul(doc))
            return Utils::GStatus::Error("the work document contains NUL characters");
        std::string text = doc.dump(-1, ' ', false, json::error_handler_t::replace);
        if (text.size() > maxBytes)
            return Utils::GStatus::Error(
                  "the work document is too large (" + std::to_string(text.size()) + " bytes, at most " + std::to_string(maxBytes) + ")");
        canonical = std::move(text);
        return Utils::GStatus::Ok();
    }

    // returns false when the entry must be dropped
    bool ParseSolutionInfo(const json& j, WorkSolutionInfo& info)
    {
        if (!j.is_object())
            return false;
        info.id       = GetPositiveId(j, "id");
        info.revision = GetPositiveId(j, "revision");
        if (info.id == 0 || info.revision == 0)
            return false; // without them the solution could never be fetched / republished (compare-and-set)
        auto a = j.find("audience");
        if (a == j.end() || !a->is_string())
            return false;
        const auto audience = ParseNoteAudience(a->get_ref<const std::string&>());
        if (!audience.has_value())
            return false;
        info.audience = *audience;
        if (auto en = j.find("enabled"); en != j.end() && !en->is_boolean())
            return false;
        info.enabled     = GetBool(j, "enabled", true);
        info.updatedAt   = GetUInt(j, "updatedAt");
        info.hasReplay   = GetBool(j, "hasReplay", false);
        info.replaySteps = info.hasReplay ? GetSteps(j) : 0;
        return true;
    }

    std::vector<NoteAudience> ParseAudiences(const json& arr, uint32& rejected)
    {
        std::vector<NoteAudience> r{ NoteAudience::All };
        if (!arr.is_array())
        {
            rejected++;
            return r;
        }
        size_t seen = 0;
        for (const auto& a : arr)
        {
            if (++seen > 64)
            {
                rejected++;
                break;
            }
            const auto v = a.is_string() ? ParseNoteAudience(a.get_ref<const std::string&>()) : std::nullopt;
            if (!v.has_value())
            {
                rejected++;
                continue;
            }
            if (std::find(r.begin(), r.end(), *v) == r.end())
                r.push_back(*v);
        }
        return r;
    }

    void AppendInt(SecureString& out, int64 v)
    {
        const std::string t = std::to_string(v);
        out.append(t.data(), t.size());
    }

    void AppendDocument(SecureString& out, std::string_view canonical)
    {
        if (canonical.empty())
            out.append("null"); // never sent: the Perform* functions validate the document first
        else
            out.append(canonical.data(), canonical.size());
    }
} // namespace

// ============================================================================ document
Utils::GStatus ValidateWorkDocumentText(std::string_view text, size_t maxBytes, std::string& canonical)
{
    try
    {
        if (text.find('\0') != std::string_view::npos)
            return Utils::GStatus::Error("the work document contains NUL characters");
        // a pretty-printed document may be larger than its canonical form, within reason
        if (text.size() > maxBytes * 4 + 4096)
            return Utils::GStatus::Error("the work document is too large");
        auto j = ParseJsonObject(text);
        if (!j.has_value())
            return Utils::GStatus::Error("the work document is not a JSON object");
        return CanonicalDocument(*j, maxBytes, canonical);
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed work document");
    }
}

// ============================================================================ answers
Utils::GStatus ParseWorkResponse(BufferView body, WorkResponse& out)
{
    try
    {
        auto j = ParseJsonObject(body);
        if (!j.has_value())
            return Utils::GStatus::Error("GetWork response is not a JSON object");
        if (!StatusIsOk(*j))
            return Utils::GStatus::Error("GetWork status is not 'ok'");
        WorkResponse r;
        r.serverTime = GetUInt(*j, "serverTime");
        if (j->contains("maxBytes"))
            r.maxBytes = static_cast<uint32>(
                  std::clamp<int64>(GetInt(*j, "maxBytes", MAX_WORK_DOCUMENT_BYTES), WORK_MIN_MAX_BYTES, WORK_MAX_MAX_BYTES));
        r.canPublishSolutions = GetBool(*j, "canPublishSolutions", false);
        if (auto a = j->find("audiences"); a != j->end() && !a->is_null())
            r.audiences = ParseAudiences(*a, r.rejected);

        if (auto w = j->find("work"); w != j->end() && !w->is_null())
        {
            if (!w->is_object())
                return Utils::GStatus::Error("GetWork 'work' is not an object");
            r.revision = GetPositiveId(*w, "revision");
            if (r.revision == 0)
                return Utils::GStatus::Error("GetWork 'work' lacks a valid revision");
            auto doc = w->find("document");
            if (doc == w->end())
                return Utils::GStatus::Error("GetWork 'work' lacks its document");
            if (auto st = CanonicalDocument(*doc, MAX_WORK_DOCUMENT_BYTES, r.document); !st.ok)
            {
                // the own document is unusable (written by a newer GView, oversize): the rest of the answer (the solutions, the
                // capability) is still good; the UI says why the work can not be loaded
                r.document.clear();
                r.workError = st.message;
                r.rejected++;
            }
            r.hasWork   = true;
            r.updatedAt = GetUInt(*w, "updatedAt");
            if (auto cv = w->find("clientVersion"); cv != w->end() && cv->is_string())
                r.clientVersion = SanitizeDisplayText(cv->get_ref<const std::string&>(), WORK_CLIENT_VERSION_MAX, false);
            r.hasReplay   = GetBool(*w, "hasReplay", false);
            r.replaySteps = r.hasReplay ? GetSteps(*w) : 0;
        }

        if (auto sols = j->find("solutions"); sols != j->end() && !sols->is_null())
        {
            if (!sols->is_array())
                return Utils::GStatus::Error("GetWork 'solutions' is not an array");
            std::set<int64> seen;
            for (const auto& sj : *sols)
            {
                WorkSolutionInfo info;
                if (r.solutions.size() >= MAX_SOLUTIONS_LISTED || !ParseSolutionInfo(sj, info) || !seen.insert(info.id).second)
                {
                    r.rejected++;
                    continue;
                }
                r.solutions.push_back(info);
            }
        }
        out = std::move(r);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed GetWork response");
    }
}

Utils::GStatus ParseSaveWorkResponse(BufferView body, SaveWorkResponse& out)
{
    try
    {
        auto j = ParseJsonObject(body);
        if (!j.has_value())
            return Utils::GStatus::Error("SaveWork answer is not a JSON object");
        if (!StatusIsOk(*j))
            return Utils::GStatus::Error("SaveWork answer status is not 'ok'");
        SaveWorkResponse r;
        r.revision = GetPositiveId(*j, "revision");
        if (r.revision == 0)
            return Utils::GStatus::Error("SaveWork answer lacks a valid revision");
        r.updatedAt = GetUInt(*j, "updatedAt");
        r.created   = GetBool(*j, "created", false);
        out         = r;
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed SaveWork answer");
    }
}

Utils::GStatus ParseSolutionResponse(BufferView body, SolutionResponse& out)
{
    try
    {
        auto j = ParseJsonObject(body);
        if (!j.has_value())
            return Utils::GStatus::Error("GetSolution response is not a JSON object");
        if (!StatusIsOk(*j))
            return Utils::GStatus::Error("GetSolution status is not 'ok'");
        auto s = j->find("solution");
        if (s == j->end() || !s->is_object())
            return Utils::GStatus::Error("GetSolution response lacks the solution");
        SolutionResponse r;
        if (!ParseSolutionInfo(*s, r.info))
            return Utils::GStatus::Error("GetSolution: the solution lacks a valid id, revision or audience");
        auto doc = s->find("document");
        if (doc == s->end())
            return Utils::GStatus::Error("GetSolution: the solution lacks its document");
        if (auto st = CanonicalDocument(*doc, MAX_WORK_DOCUMENT_BYTES, r.document); !st.ok)
            return Utils::GStatus::Error("GetSolution: " + st.message);
        out = std::move(r);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed GetSolution response");
    }
}

Utils::GStatus ParsePublishSolutionResponse(BufferView body, PublishSolutionResponse& out)
{
    try
    {
        auto j = ParseJsonObject(body);
        if (!j.has_value())
            return Utils::GStatus::Error("PublishSolution answer is not a JSON object");
        if (!StatusIsOk(*j))
            return Utils::GStatus::Error("PublishSolution answer status is not 'ok'");
        PublishSolutionResponse r;
        r.id       = GetPositiveId(*j, "id");
        r.revision = GetPositiveId(*j, "revision");
        if (r.id == 0 || r.revision == 0)
            return Utils::GStatus::Error("PublishSolution answer lacks a valid id or revision");
        r.updatedAt = GetUInt(*j, "updatedAt");
        r.created   = GetBool(*j, "created", false);
        out         = r;
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed PublishSolution answer");
    }
}

// ============================================================================ request bodies
SecureString BuildGetWorkBody(std::string_view problem)
{
    SecureString body;
    body.append("{\"problem\":");
    AppendJsonString(body, problem);
    body.push_back('}');
    return body;
}

SecureString BuildSaveWorkBody(const SaveWorkRequest& req)
{
    SecureString body;
    body.reserve(128 + req.problem.size() + req.document.size());
    body.append("{\"problem\":");
    AppendJsonString(body, req.problem);
    body.append(",\"document\":");
    AppendDocument(body, req.document);
    body.append(req.hasReplay ? ",\"hasReplay\":true" : ",\"hasReplay\":false");
    body.append(",\"replaySteps\":");
    AppendInt(body, req.replaySteps);
    if (req.revision.has_value())
    {
        body.append(",\"revision\":");
        AppendInt(body, *req.revision);
    }
    body.push_back('}');
    return body;
}

SecureString BuildGetSolutionBody(std::string_view problem, std::optional<int64> id)
{
    SecureString body;
    body.append("{\"problem\":");
    AppendJsonString(body, problem);
    if (id.has_value())
    {
        body.append(",\"id\":");
        AppendInt(body, *id);
    }
    body.push_back('}');
    return body;
}

SecureString BuildPublishSolutionBody(const PublishSolutionRequest& req)
{
    SecureString body;
    body.reserve(192 + req.problem.size() + req.document.size());
    body.append("{\"problem\":");
    AppendJsonString(body, req.problem);
    if (req.id.has_value())
    {
        body.append(",\"id\":");
        AppendInt(body, *req.id);
    }
    body.append(",\"audience\":");
    AppendJsonString(body, NoteAudienceName(req.audience));
    body.append(",\"document\":");
    AppendDocument(body, req.document);
    body.append(req.hasReplay ? ",\"hasReplay\":true" : ",\"hasReplay\":false");
    body.append(",\"replaySteps\":");
    AppendInt(body, req.replaySteps);
    body.append(req.enabled ? ",\"enabled\":true" : ",\"enabled\":false");
    if (req.revision.has_value())
    {
        body.append(",\"revision\":");
        AppendInt(body, *req.revision);
    }
    body.push_back('}');
    return body;
}

SecureString BuildDeleteSolutionBody(int64 id)
{
    SecureString body;
    body.append("{\"id\":");
    AppendInt(body, id);
    body.push_back('}');
    return body;
}

// ============================================================================ errors
WorkServerError WorkErrorFromResponse(const HttpResponse& resp)
{
    WorkServerError e;
    static_cast<ServerError&>(e) = NoteErrorFromResponse(resp);
    if (resp.transportOk && !resp.tooLarge && resp.status == 409)
    {
        try
        {
            if (auto j = ParseJsonObject(ToView(resp.body)); j.has_value())
            {
                if (const int64 id = GetPositiveId(*j, "id"); id > 0)
                    e.existingId = id;
                if (const int64 rev = GetPositiveId(*j, "revision"); rev > 0)
                    e.existingRevision = rev;
            }
        }
        catch (...)
        {
        }
    }
    return e;
}
} // namespace GView::Security::Learning
