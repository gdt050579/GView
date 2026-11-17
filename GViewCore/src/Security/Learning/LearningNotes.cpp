#include "LearningNotes.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <set>

namespace GView::Security::Learning
{
using json = nlohmann::json;

namespace
{
    // Decodes one UTF-8 sequence at s[i]; returns its length (0 = invalid). Overlong forms, surrogates and code
    // points above U+10FFFF are invalid.
    size_t Utf8SequenceLength(std::string_view s, size_t i) noexcept
    {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80)
            return 1;
        size_t len;
        uint32 cp;
        if ((c & 0xE0) == 0xC0)
        {
            len = 2;
            cp  = c & 0x1F;
        }
        else if ((c & 0xF0) == 0xE0)
        {
            len = 3;
            cp  = c & 0x0F;
        }
        else if ((c & 0xF8) == 0xF0)
        {
            len = 4;
            cp  = c & 0x07;
        }
        else
            return 0;
        if (i + len > s.size())
            return 0;
        for (size_t k = 1; k < len; k++)
        {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80)
                return 0;
            cp = (cp << 6) | (cc & 0x3F);
        }
        static constexpr uint32 MIN_CP[] = { 0, 0, 0x80, 0x800, 0x10000 };
        if (cp < MIN_CP[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return 0;
        return len;
    }

    // Text received from the server: valid UTF-8 only (invalid bytes => '?'), control characters removed (\n and \t
    // kept when multiline, \r dropped), at most maxCodePoints characters.
    std::string SanitizeNoteText(std::string_view s, size_t maxCodePoints, bool multiline)
    {
        std::string r;
        r.reserve(std::min<size_t>(s.size(), maxCodePoints * 4));
        size_t count = 0;
        for (size_t i = 0; i < s.size() && count < maxCodePoints;)
        {
            const auto c   = static_cast<unsigned char>(s[i]);
            const size_t n = Utf8SequenceLength(s, i);
            if (n == 0)
            {
                r.push_back('?');
                i++;
            }
            else if (n == 1)
            {
                if (c == '\r')
                {
                    i++;
                    continue;
                }
                if (c == '\n' || c == '\t')
                    r.push_back(multiline ? static_cast<char>(c) : ' ');
                else if (c < 0x20 || c == 0x7F)
                    r.push_back(' ');
                else
                    r.push_back(static_cast<char>(c));
                i++;
            }
            else
            {
                r.append(s.substr(i, n));
                i += n;
            }
            count++;
        }
        return r;
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

    std::string GetNoteText(const json& j, const char* key, size_t maxCodePoints, bool multiline)
    {
        auto it = j.find(key);
        if (it == j.end() || !it->is_string())
            return {};
        return SanitizeNoteText(it->get_ref<const std::string&>(), maxCodePoints, multiline);
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

    // missing / null / unknown => general (spec §10.11: missing scope = general)
    NoteScope ParseScope(const json& j)
    {
        NoteScope s;
        auto it = j.find("scope");
        if (it == j.end() || !it->is_object())
            return s;
        auto kind = it->find("kind");
        auto name = it->find("name");
        if (kind == it->end() || !kind->is_string() || name == it->end() || !name->is_string())
            return s;
        const auto& k = kind->get_ref<const std::string&>();
        NoteScope candidate;
        if (k == "week")
            candidate.kind = NoteScopeKind::Week;
        else if (k == "problem")
            candidate.kind = NoteScopeKind::Problem;
        else if (k == "resource")
            candidate.kind = NoteScopeKind::Resource;
        else
            return s;
        candidate.name = name->get<std::string>();
        return IsValidNoteScope(candidate) ? candidate : s;
    }

    json ScopeToJson(const NoteScope& s)
    {
        json j;
        j["kind"] = std::string(NoteScopeKindName(s.kind));
        if (!s.IsGeneral())
            j["name"] = s.name;
        return j;
    }

    SecureString ToSecureBody(const json& j)
    {
        std::string text = j.dump(-1, ' ', false, json::error_handler_t::replace);
        SecureString r(text.data(), text.size());
        WipeString(text);
        return r;
    }

    std::optional<json> ParseJsonObject(BufferView body)
    {
        if (body.GetLength() == 0 || body.GetData() == nullptr)
            return std::nullopt;
        auto j = json::parse(body.GetData(), body.GetData() + body.GetLength(), nullptr, false);
        if (j.is_discarded() || !j.is_object())
            return std::nullopt;
        return j;
    }

    bool StatusIsOk(const json& j)
    {
        auto st = j.find("status");
        return st == j.end() || (st->is_string() && st->get_ref<const std::string&>() == "ok");
    }

    void WipeNote(LocalNote& n) noexcept
    {
        WipeString(n.title);
        WipeString(n.body);
        if (n.outstanding.has_value())
        {
            WipeString(n.outstanding->title);
            WipeString(n.outstanding->body);
        }
    }

    LocalNote FromServer(const StudentNote& s)
    {
        LocalNote n;
        n.id         = s.id;
        n.title      = s.title;
        n.body       = s.body;
        n.scope      = s.scope;
        n.revision   = s.revision;
        n.createdAt  = s.createdAt;
        n.updatedAt  = s.updatedAt;
        n.createSent = true;
        return n;
    }

    bool HasLocalChanges(const LocalNote& n) noexcept
    {
        return n.dirty || n.outstanding.has_value() || n.inFlight || n.deleted || n.conflictPending;
    }
} // namespace

// ============================================================================ text helpers
size_t Utf8Length(std::string_view s) noexcept
{
    size_t n = 0;
    for (unsigned char c : s)
        n += (c & 0xC0) != 0x80;
    return n;
}

std::string TruncateUtf8(std::string_view s, size_t maxCodePoints)
{
    size_t count = 0;
    for (size_t i = 0; i < s.size(); i++)
    {
        if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80)
        {
            if (count == maxCodePoints)
                return std::string(s.substr(0, i));
            count++;
        }
    }
    return std::string(s);
}

std::string NormalizeNoteBody(std::string_view s)
{
    std::string r;
    r.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++)
    {
        const char c = s[i];
        if (c == '\0')
            continue;
        if (c == '\r')
        {
            r.push_back('\n');
            if (i + 1 < s.size() && s[i + 1] == '\n')
                i++;
            continue;
        }
        r.push_back(c);
    }
    return r;
}

std::string NormalizeNoteTitle(std::string_view s)
{
    std::string r;
    r.reserve(s.size());
    for (unsigned char c : s)
        r.push_back((c < 0x20 || c == 0x7F) ? ' ' : static_cast<char>(c));
    return TruncateUtf8(r, NOTE_TITLE_MAX_CHARS);
}

// ============================================================================ data model
std::string_view NoteScopeKindName(NoteScopeKind kind) noexcept
{
    switch (kind)
    {
    case NoteScopeKind::General:
        return "general";
    case NoteScopeKind::Week:
        return "week";
    case NoteScopeKind::Problem:
        return "problem";
    case NoteScopeKind::Resource:
        return "resource";
    }
    return "general";
}

bool IsValidNoteScope(const NoteScope& scope) noexcept
{
    switch (scope.kind)
    {
    case NoteScopeKind::General:
        return scope.name.empty();
    case NoteScopeKind::Week:
        return !scope.name.empty() && Utf8Length(scope.name) <= NOTE_WEEK_NAME_MAX_CHARS && !HasControlCharacters(scope.name);
    case NoteScopeKind::Problem:
    case NoteScopeKind::Resource:
        return IsValidItemName(scope.name);
    }
    return false;
}

std::string DescribeNoteScope(const NoteScope& scope)
{
    switch (scope.kind)
    {
    case NoteScopeKind::General:
        return "General";
    case NoteScopeKind::Week:
        return "Week: " + scope.name;
    case NoteScopeKind::Problem:
        return "Problem: " + scope.name;
    case NoteScopeKind::Resource:
        return "Resource: " + scope.name;
    }
    return "General";
}

bool IsValidNoteId(std::string_view id) noexcept
{
    if (id.empty() || id.size() > NOTE_ID_MAX_LENGTH)
        return false;
    for (char c : id)
    {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    return true;
}

// ============================================================================ wire format
Utils::GStatus ParseNotesResponse(BufferView body, NotesSnapshot& out)
{
    try
    {
        auto j = ParseJsonObject(body);
        if (!j.has_value())
            return Utils::GStatus::Error("GetNotes response is not a JSON object");
        if (!StatusIsOk(*j))
            return Utils::GStatus::Error("GetNotes status is not 'ok'");
        NotesSnapshot snap;
        if (j->contains("maxChars"))
        {
            const int64 v = GetInt(*j, "maxChars", NOTES_DEFAULT_MAX_CHARS);
            snap.maxChars = static_cast<uint32>(std::clamp<int64>(v, NOTES_MIN_MAX_CHARS, NOTES_MAX_MAX_CHARS));
        }
        snap.serverTime = GetUInt(*j, "serverTime");
        if (auto c = j->find("canEditTeacherNotes"); c != j->end() && c->is_boolean())
            snap.canEditTeacherNotes = c->get<bool>();

        if (auto mine = j->find("mine"); mine != j->end() && !mine->is_null())
        {
            if (!mine->is_array())
                return Utils::GStatus::Error("GetNotes 'mine' is not an array");
            std::set<std::string> seen;
            for (const auto& nj : *mine)
            {
                if (snap.mine.size() >= MAX_NOTES_LISTED || !nj.is_object())
                {
                    snap.rejected++;
                    continue;
                }
                auto id = nj.find("id");
                if (id == nj.end() || !id->is_string() || !IsValidNoteId(id->get_ref<const std::string&>()) ||
                    !seen.insert(id->get<std::string>()).second)
                {
                    snap.rejected++;
                    continue;
                }
                StudentNote n;
                n.id       = id->get<std::string>();
                n.revision = GetInt(nj, "revision", 0);
                if (n.revision < 1)
                {
                    snap.rejected++; // without a revision the note could never be updated (compare-and-set)
                    continue;
                }
                n.title     = GetNoteText(nj, "title", NOTE_TITLE_MAX_CHARS, false);
                n.body      = GetNoteText(nj, "body", NOTES_MAX_MAX_CHARS, true);
                n.scope     = ParseScope(nj);
                n.createdAt = GetUInt(nj, "createdAt");
                n.updatedAt = GetUInt(nj, "updatedAt");
                snap.mine.push_back(std::move(n));
            }
        }
        if (auto teacher = j->find("teacher"); teacher != j->end() && !teacher->is_null())
        {
            if (!teacher->is_array())
                return Utils::GStatus::Error("GetNotes 'teacher' is not an array");
            std::set<int64> seen;
            for (const auto& nj : *teacher)
            {
                if (snap.teacher.size() >= MAX_NOTES_LISTED || !nj.is_object())
                {
                    snap.rejected++;
                    continue;
                }
                TeacherNote n;
                n.id = GetInt(nj, "id", 0);
                auto idIt = nj.find("id");
                if (idIt == nj.end() || !idIt->is_number_integer() || n.id < 1 || !seen.insert(n.id).second)
                {
                    snap.rejected++;
                    continue;
                }
                n.title = GetNoteText(nj, "title", NOTE_TITLE_MAX_CHARS, false);
                n.body  = GetNoteText(nj, "body", NOTES_MAX_MAX_CHARS, true);
                n.scope = ParseScope(nj);
                if (auto a = nj.find("audience"); a != nj.end() && a->is_string())
                {
                    const auto& v = a->get_ref<const std::string&>();
                    n.audience    = v == "G1" ? NoteAudience::G1 : (v == "G2" ? NoteAudience::G2 : NoteAudience::All);
                }
                if (auto en = nj.find("enabled"); en != nj.end() && en->is_boolean())
                    n.enabled = en->get<bool>();
                n.order     = GetInt(nj, "order", 0);
                n.revision  = GetInt(nj, "revision", 0);
                n.createdAt = GetUInt(nj, "createdAt");
                n.updatedAt = GetUInt(nj, "updatedAt");
                snap.teacher.push_back(std::move(n));
            }
        }
        out = std::move(snap);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed GetNotes response");
    }
}

SecureString BuildSaveNoteBody(const SaveNoteRequest& req)
{
    json j;
    j["id"]    = req.id;
    j["title"] = req.title;
    j["body"]  = req.body;
    j["scope"] = ScopeToJson(req.scope);
    if (req.revision.has_value())
        j["revision"] = *req.revision;
    return ToSecureBody(j);
}

SecureString BuildDeleteNoteBody(std::string_view id)
{
    json j;
    j["id"] = std::string(id);
    return ToSecureBody(j);
}

SecureString BuildSaveTeacherNoteBody(const SaveTeacherNoteRequest& req)
{
    json j;
    if (req.id.has_value())
        j["id"] = *req.id;
    j["title"] = req.title;
    j["body"]  = req.body;
    if (req.scope.has_value())
        j["scope"] = ScopeToJson(*req.scope);
    if (req.audience.has_value())
        j["audience"] = std::string(NoteAudienceName(*req.audience));
    if (req.enabled.has_value())
        j["enabled"] = *req.enabled;
    if (req.order.has_value())
        j["order"] = *req.order;
    if (req.revision.has_value())
        j["revision"] = *req.revision;
    return ToSecureBody(j);
}

SecureString BuildDeleteTeacherNoteBody(int64 id)
{
    json j;
    j["id"] = id;
    return ToSecureBody(j);
}

Utils::GStatus ParseSaveNoteResponse(BufferView body, bool teacher, SaveNoteResult& out)
{
    try
    {
        auto j = ParseJsonObject(body);
        if (!j.has_value())
            return Utils::GStatus::Error("note answer is not a JSON object");
        if (!StatusIsOk(*j))
            return Utils::GStatus::Error("note answer status is not 'ok'");
        SaveNoteResult r;
        r.revision = GetInt(*j, "revision", 0);
        if (r.revision < 1)
            return Utils::GStatus::Error("note answer lacks a valid revision");
        auto id = j->find("id");
        if (teacher)
        {
            if (id == j->end() || !id->is_number_integer() || id->get<int64>() < 1)
                return Utils::GStatus::Error("teacher note answer lacks a valid id");
            r.teacherId = id->get<int64>();
        }
        else
        {
            if (id == j->end() || !id->is_string() || !IsValidNoteId(id->get_ref<const std::string&>()))
                return Utils::GStatus::Error("note answer lacks a valid id");
            r.id = id->get<std::string>();
        }
        r.updatedAt = GetUInt(*j, "updatedAt");
        if (auto c = j->find("created"); c != j->end() && c->is_boolean())
            r.created = c->get<bool>();
        out = std::move(r);
        return Utils::GStatus::Ok();
    }
    catch (...)
    {
        return Utils::GStatus::Error("malformed note answer");
    }
}

ServerError NoteErrorFromResponse(const HttpResponse& resp)
{
    ServerError e = resp.ToError();
    if (resp.transportOk && !resp.tooLarge)
    {
        if (resp.status == 409)
        {
            e.code      = ErrorCode::Conflict;
            e.retryable = false;
        }
        else if (resp.status == 413)
            e.code = ErrorCode::PayloadTooLarge;
    }
    return e;
}

NoteFailure ClassifyNoteError(const ServerError& err) noexcept
{
    switch (err.code)
    {
    case ErrorCode::None:
        return NoteFailure::None;
    case ErrorCode::Transport:
    case ErrorCode::Protocol:
    case ErrorCode::RateLimited:
    case ErrorCode::ServerError:
        return NoteFailure::Retry;
    case ErrorCode::Conflict:
        return NoteFailure::Conflict;
    case ErrorCode::NotFound:
    case ErrorCode::ItemDisabled:
        return NoteFailure::NotFound;
    case ErrorCode::Forbidden:
        return NoteFailure::Disabled;
    case ErrorCode::PolicyExpired:
        return NoteFailure::Expired;
    default:
        break;
    }
    if (err.httpStatus == 408 || err.httpStatus >= 500)
        return NoteFailure::Retry;
    return NoteFailure::Refused;
}

// ============================================================================ NotesSync
LocalNote* NotesSync::FindMutable(std::string_view id) noexcept
{
    for (auto& n : notes)
    {
        if (n.id == id)
            return &n;
    }
    return nullptr;
}

const LocalNote* NotesSync::Find(std::string_view id) const noexcept
{
    for (const auto& n : notes)
    {
        if (n.id == id)
            return &n;
    }
    return nullptr;
}

void NotesSync::SetMaxChars(uint32 value) noexcept
{
    const uint32 v = std::clamp(value, NOTES_MIN_MAX_CHARS, NOTES_MAX_MAX_CHARS);
    if (v != maxChars)
    {
        maxChars = v;
        Touch();
    }
}

uint64 NotesSync::BackoffMs(uint32 retries, uint32 retryAfterSeconds) noexcept
{
    if (retryAfterSeconds > 0)
        return std::max<uint64>(static_cast<uint64>(retryAfterSeconds) * 1000, 1000);
    const uint32 shift = std::min<uint32>(retries > 0 ? retries - 1 : 0, 5);
    return std::min<uint64>(2000ull << shift, NOTES_RETRY_MAX_MS);
}

NoteSyncState NotesSync::StateOf(const LocalNote& n) const noexcept
{
    if (!n.error.empty() && !n.outstanding.has_value())
        return NoteSyncState::Error;
    if (n.outstanding.has_value())
        return n.retries > 0 ? NoteSyncState::Retrying : NoteSyncState::Saving;
    if (n.dirty || n.conflictPending)
        return NoteSyncState::Unsaved;
    return NoteSyncState::Saved;
}

bool NotesSync::HasUnsavedChanges() const noexcept
{
    for (const auto& n : notes)
    {
        const bool emptyDraft = !n.revision.has_value() && !n.createSent && n.title.empty() && n.body.empty();
        if ((n.dirty && !emptyDraft) || n.outstanding.has_value() || n.conflictPending || (n.deleted && (n.createSent || n.revision.has_value())))
            return true;
    }
    return false;
}

std::vector<std::string> NotesSync::TakeNotices()
{
    std::vector<std::string> r;
    r.swap(notices);
    return r;
}

void NotesSync::ApplySnapshot(const NotesSnapshot& snapshot, uint64 nowMs)
{
    SetMaxChars(snapshot.maxChars);
    std::vector<LocalNote> copies, localOnly, fromServer;
    std::set<std::string> serverIds;

    for (const auto& s : snapshot.mine)
    {
        serverIds.insert(s.id);
        LocalNote* l = FindMutable(s.id);
        if (l != nullptr && l->conflictPending)
        {
            // 409: the server copy wins, the local text is kept as a new note (never overwritten silently)
            if (NormalizeNoteTitle(l->title) != s.title || NormalizeNoteBody(l->body) != s.body || l->scope != s.scope)
            {
                LocalNote copy;
                if (auto id = NewUuid4(); id.has_value())
                {
                    copy.id         = *id;
                    const size_t room = NOTE_TITLE_MAX_CHARS - Utf8Length(NOTE_LOCAL_COPY_SUFFIX);
                    copy.title      = l->title.empty() ? std::string("Untitled") + std::string(NOTE_LOCAL_COPY_SUFFIX)
                                                       : TruncateUtf8(l->title, room) + std::string(NOTE_LOCAL_COPY_SUFFIX);
                    copy.body       = l->body;
                    copy.scope      = l->scope;
                    copy.dirty      = true;
                    copy.lastEditMs = nowMs > NOTES_AUTOSAVE_DEBOUNCE_MS ? nowMs - NOTES_AUTOSAVE_DEBOUNCE_MS : 0; // save right away
                    notices.push_back(
                          "The note \"" + (s.title.empty() ? std::string("Untitled") : s.title) +
                          "\" was changed elsewhere. The server copy was kept; your text was saved as \"" + copy.title + "\".");
                    copies.push_back(std::move(copy));
                }
                else
                {
                    // no id for a copy: keep the local text in place, it will be retried against the new revision
                    l->conflictPending = false;
                    l->revision        = s.revision;
                    l->outstanding.reset();
                    l->dirty = true;
                    continue;
                }
            }
            WipeNote(*l);
            fromServer.push_back(FromServer(s));
            continue;
        }
        if (l != nullptr && HasLocalChanges(*l))
        {
            continue; // kept below, in its current place; the next save meets the server's revision check
        }
        if (l != nullptr)
            WipeNote(*l);
        fromServer.push_back(FromServer(s));
    }

    for (auto& l : notes)
    {
        const bool onServer = serverIds.count(l.id) > 0;
        if (onServer)
        {
            if (!l.conflictPending && HasLocalChanges(l))
                fromServer.push_back(std::move(l)); // local changes win until they are saved (or conflict)
            continue;
        }
        if (l.conflictPending)
        {
            // conflict, then the note disappeared from the server: keep the text, create it again
            l.conflictPending = false;
            l.revision.reset();
            l.outstanding.reset();
            l.dirty = true;
            localOnly.push_back(std::move(l));
            continue;
        }
        if (l.deleted && !l.inFlight)
        {
            WipeNote(l);
            continue; // already gone on the server
        }
        if (l.revision.has_value() && !HasLocalChanges(l))
        {
            WipeNote(l);
            continue; // deleted elsewhere
        }
        if (l.revision.has_value() && !l.inFlight)
        {
            // removed on the server while edited here: the text is kept and the note is created again (also after a
            // 404 of an update: the create that follows either succeeds or is refused for its scope, then waits)
            l.revision.reset();
            l.outstanding.reset();
            l.dirty   = true;
            l.blocked = false;
            l.error.clear();
        }
        localOnly.push_back(std::move(l));
    }

    // order: conflict copies, notes not on the server yet, then the server's order (newest first)
    std::vector<LocalNote> merged;
    merged.reserve(copies.size() + localOnly.size() + fromServer.size());
    for (auto& n : copies)
        merged.push_back(std::move(n));
    for (auto& n : localOnly)
        merged.push_back(std::move(n));
    // fromServer holds the server copies in server order, followed by the kept local versions; restore server order
    std::vector<LocalNote> ordered;
    for (const auto& s : snapshot.mine)
    {
        for (auto& n : fromServer)
        {
            if (!n.id.empty() && n.id == s.id)
            {
                ordered.push_back(std::move(n));
                n.id.clear();
                break;
            }
        }
    }
    for (auto& n : ordered)
        merged.push_back(std::move(n));
    notes = std::move(merged);
    Touch();
}

std::string NotesSync::Create(std::string_view title, std::string_view body, const NoteScope& scope, uint64 nowMs)
{
    auto id = NewUuid4();
    if (!id.has_value())
        return {};
    LocalNote n;
    n.id         = *id;
    n.title      = std::string(title);
    n.body       = std::string(body);
    n.scope      = IsValidNoteScope(scope) ? scope : NoteScope{};
    n.dirty      = true;
    n.lastEditMs = nowMs;
    notes.insert(notes.begin(), std::move(n));
    Touch();
    return *id;
}

bool NotesSync::Edit(std::string_view id, std::string_view title, std::string_view body, const NoteScope& scope, uint64 nowMs)
{
    auto* n = FindMutable(id);
    if (n == nullptr || n->deleted)
        return false;
    const NoteScope s = IsValidNoteScope(scope) ? scope : NoteScope{};
    if (n->title == title && n->body == body && n->scope == s)
        return false;
    n->title      = std::string(title);
    n->body       = std::string(body);
    n->scope      = s;
    n->dirty      = true;
    n->lastEditMs = nowMs;
    n->blocked    = false;
    n->error.clear();
    Touch();
    return true;
}

void NotesSync::Delete(std::string_view id)
{
    auto* n = FindMutable(id);
    if (n == nullptr)
        return;
    if (!n->createSent && !n->revision.has_value() && !n->inFlight && !n->outstanding.has_value())
    {
        // never reached the server: nothing to delete there
        WipeNote(*n);
        notes.erase(notes.begin() + (n - notes.data()));
        Touch();
        return;
    }
    n->deleted         = true;
    n->dirty           = false;
    n->conflictPending = false; // a pending conflict must not bring the note back
    n->blocked         = false;
    n->retries  = 0;
    n->retryAtMs = 0;
    n->error.clear();
    Touch();
}

std::vector<NotesSync::Action> NotesSync::NextActions(uint64 nowMs, bool flushAll)
{
    std::vector<Action> actions;
    for (auto& n : notes)
    {
        if (n.inFlight || n.conflictPending)
            continue;
        const bool retryDue = flushAll || nowMs >= n.retryAtMs;
        if (n.deleted)
        {
            if (retryDue)
            {
                n.inFlight = true;
                actions.push_back(Action{ Action::Kind::Delete, n.id, {} });
            }
            continue;
        }
        if (n.outstanding.has_value())
        {
            if (retryDue)
            {
                n.inFlight = true;
                actions.push_back(Action{ Action::Kind::Save, n.id, *n.outstanding });
            }
            continue;
        }
        if (!n.dirty || n.blocked)
            continue;
        if (!n.revision.has_value() && !n.createSent && n.title.empty() && n.body.empty())
            continue; // a new note nobody typed into yet: created on the server with its first text
        if (!flushAll && nowMs >= n.lastEditMs && nowMs - n.lastEditMs < NOTES_AUTOSAVE_DEBOUNCE_MS)
            continue;
        SaveNoteRequest req;
        req.id       = n.id;
        req.title    = NormalizeNoteTitle(n.title);
        req.body     = NormalizeNoteBody(n.body);
        req.scope    = n.scope;
        req.revision = n.revision;
        if (Utf8Length(req.body) > maxChars)
        {
            const std::string msg = "Not saved: the note is longer than " + std::to_string(maxChars) + " characters.";
            if (n.error != msg)
            {
                n.error = msg;
                Touch();
            }
            continue; // waits for the student to shorten it (Edit clears the error)
        }
        if (BuildSaveNoteBody(req).size() > MAX_NOTE_REQUEST_BYTES)
        {
            const std::string msg = "Not saved: the note is larger than the 256 KiB the server accepts per request.";
            if (n.error != msg)
            {
                n.error = msg;
                Touch();
            }
            continue;
        }
        n.error.clear();
        n.dirty    = false;
        n.retries  = 0;
        n.inFlight = true;
        if (!req.revision.has_value())
            n.createSent = true;
        n.outstanding = req;
        actions.push_back(Action{ Action::Kind::Save, n.id, std::move(req) });
    }
    if (!actions.empty())
        Touch();
    return actions;
}

NoteFailure NotesSync::OnSaveResult(const Action& action, const NoteOpOutcome& outcome, uint64 nowMs)
{
    auto* n = FindMutable(action.id);
    if (n == nullptr)
        return NoteFailure::None;
    n->inFlight = false;
    if (outcome.status.ok)
    {
        if (n->outstanding.has_value() && *n->outstanding == action.request)
            n->outstanding.reset();
        n->revision   = outcome.result.revision;
        n->createSent = true;
        if (outcome.result.updatedAt > 0)
            n->updatedAt = outcome.result.updatedAt;
        if (n->createdAt == 0 && outcome.result.created)
            n->createdAt = outcome.result.updatedAt;
        n->retries   = 0;
        n->retryAtMs = 0;
        n->error.clear();
        Touch();
        return NoteFailure::None;
    }
    const NoteFailure failure = ClassifyNoteError(outcome.error);
    switch (failure)
    {
    case NoteFailure::Retry:
    case NoteFailure::Disabled:
    case NoteFailure::Expired:
        // the very same request is sent again later (creates and updates are idempotent on the server)
        n->retries++;
        n->retryAtMs = nowMs + BackoffMs(n->retries, outcome.error.retryAfterSeconds);
        break;
    case NoteFailure::Conflict:
        n->outstanding.reset();
        n->conflictPending = true;
        refetchNeeded      = true;
        break;
    case NoteFailure::NotFound:
        n->outstanding.reset();
        n->dirty   = true;
        n->blocked = true;
        n->error   = "Not saved: the server does not know this note, or its week/problem/resource is not available (404). "
                     "Edit the note or change its scope to save it again.";
        refetchNeeded = true; // tells whether the note still exists (if not, the next save creates it again)
        break;
    default:
        n->outstanding.reset();
        n->dirty   = true;
        n->blocked = true;
        n->error   = "Not saved: " + DescribeError(outcome.error);
        break;
    }
    Touch();
    return failure;
}

NoteFailure NotesSync::OnDeleteResult(const Action& action, const NoteOpOutcome& outcome, uint64 nowMs)
{
    auto* n = FindMutable(action.id);
    if (n == nullptr)
        return NoteFailure::None;
    n->inFlight               = false;
    const NoteFailure failure = outcome.status.ok ? NoteFailure::None : ClassifyNoteError(outcome.error);
    switch (failure)
    {
    case NoteFailure::Retry:
    case NoteFailure::Disabled:
    case NoteFailure::Expired:
        n->retries++;
        n->retryAtMs = nowMs + BackoffMs(n->retries, outcome.error.retryAfterSeconds);
        Touch();
        return failure;
    case NoteFailure::Refused:
    case NoteFailure::Conflict:
        notices.push_back("The server refused to delete a note: " + DescribeError(outcome.error));
        break;
    default:
        break; // ok, or 404 = already gone
    }
    WipeNote(*n);
    notes.erase(notes.begin() + (n - notes.data()));
    Touch();
    return failure == NoteFailure::NotFound ? NoteFailure::None : failure;
}

void NotesSync::OnActionAborted(const Action& action) noexcept
{
    if (auto* n = FindMutable(action.id); n != nullptr)
        n->inFlight = false;
}

void NotesSync::AbortAllInFlight() noexcept
{
    for (auto& n : notes)
        n.inFlight = false;
}

void NotesSync::PrepareFinalFlush()
{
    std::vector<LocalNote> copies;
    for (auto& n : notes)
    {
        if (n.deleted)
            continue;
        if (n.conflictPending)
        {
            // the server copy stays as it is; the local text is created as a new note
            n.conflictPending = false;
            if (auto id = NewUuid4(); id.has_value())
            {
                LocalNote copy;
                copy.id           = *id;
                const size_t room = NOTE_TITLE_MAX_CHARS - Utf8Length(NOTE_LOCAL_COPY_SUFFIX);
                copy.title        = (n.title.empty() ? std::string("Untitled") : TruncateUtf8(n.title, room)) + std::string(NOTE_LOCAL_COPY_SUFFIX);
                copy.body         = n.body;
                copy.scope        = n.scope;
                copy.dirty        = true;
                copies.push_back(std::move(copy));
            }
            n.dirty = false;
            n.outstanding.reset();
            continue;
        }
        if (n.blocked)
        {
            n.blocked = false; // refused before (404 / 400): one more try with the current text
            n.dirty   = true;
        }
    }
    for (auto& c : copies)
        notes.insert(notes.begin(), std::move(c));
    Touch();
}

void NotesSync::DropEmptyDrafts() noexcept
{
    const auto before = notes.size();
    std::erase_if(notes, [](const LocalNote& n) {
        return !n.revision.has_value() && !n.createSent && !n.inFlight && !n.outstanding.has_value() && n.title.empty() && n.body.empty();
    });
    if (notes.size() != before)
        Touch();
}

void NotesSync::Clear() noexcept
{
    for (auto& n : notes)
        WipeNote(n);
    notes.clear();
    notices.clear();
    refetchNeeded = false;
    maxChars      = NOTES_DEFAULT_MAX_CHARS;
    Touch();
}
} // namespace GView::Security::Learning
