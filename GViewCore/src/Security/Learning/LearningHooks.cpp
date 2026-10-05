// UI-thread facade between GView windows/viewers and the learning session (declared in Internal.hpp).

#include "LearningSession.hpp"

#include <chrono>
#include <cstdio>

using namespace GView::Security;
using namespace GView::Security::Learning;
using RestrictedMode::Feature;

namespace
{
constexpr uint64 BLOCK_NOTICE_INTERVAL_MS = 5000;

uint64 MonoMs() noexcept
{
    return static_cast<uint64>(
          std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

EventType ToEventType(Learning::Hooks::SimpleEvent ev) noexcept
{
    using SE = Learning::Hooks::SimpleEvent;
    switch (ev)
    {
    case SE::JumpBack:
        return EventType::JumpBack;
    case SE::JumpForward:
        return EventType::JumpForward;
    case SE::GotoEntrypoint:
        return EventType::GotoEntrypoint;
    case SE::GotoDialog:
        return EventType::GotoDialog;
    case SE::CommentAdd:
        return EventType::CommentAdd;
    case SE::CommentEdit:
        return EventType::CommentEdit;
    case SE::CommentRemove:
        return EventType::CommentRemove;
    case SE::LabelRename:
        return EventType::LabelRename;
    case SE::NoteAdd:
        return EventType::NoteAdd;
    }
    return EventType::Count;
}

std::string HexAddress(uint64 v)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

// keep only a plausible mnemonic (lowercase letters/digits/dots, <= 15 chars): never arbitrary text
std::string SanitizeMnemonic(std::string_view m)
{
    std::string r;
    for (char c : m)
    {
        if (r.size() >= 15)
            break;
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.')
            r.push_back(c);
        else if (c >= 'A' && c <= 'Z')
            r.push_back(static_cast<char>(c - 'A' + 'a'));
        else
            break;
    }
    return r;
}
} // namespace

namespace GView::Security::Learning::Hooks
{
bool IsSessionActive() noexcept
{
    return GetSession().HasSession();
}

void OnSimpleEvent(const GView::Object* obj, SimpleEvent ev) noexcept
{
    try
    {
        auto& s = GetSession();
        if (!s.HasSession())
            return;
        const auto type = ToEventType(ev);
        if (type != EventType::Count)
            s.Record(obj, type);
    }
    catch (...)
    {
    }
}

void OnJumpFollow(const GView::Object* obj, uint64 from, uint64 to, std::string_view mnemonic) noexcept
{
    try
    {
        auto& s = GetSession();
        if (!s.HasSession())
            return;
        s.Record(
              obj,
              EventType::JumpFollow,
              { FieldValue{ Field::From, HexAddress(from) }, FieldValue{ Field::To, HexAddress(to) }, FieldValue{ Field::Kind, SanitizeMnemonic(mnemonic) } });
    }
    catch (...)
    {
    }
}

void OnFileWindowCreated(const GView::Object* obj) noexcept
{
    try
    {
        GetSession().OnObjectCreated(obj);
    }
    catch (...)
    {
    }
}

void OnFileWindowClosed(const GView::Object* obj) noexcept
{
    try
    {
        GetSession().OnObjectClosed(obj);
    }
    catch (...)
    {
    }
}

void OnFileWindowFrame(const GView::Object* obj, std::string_view viewerKind, bool focused) noexcept
{
    try
    {
        GetSession().OnFrame(obj, viewerKind, focused);
    }
    catch (...)
    {
    }
}

void NoteUserActivity() noexcept
{
    GetSession().NoteActivity();
}

bool IsMemoryOnlyObject(const GView::Object* obj) noexcept
{
    const auto* b = GetSession().FindBinding(obj);
    if (b != nullptr && b->mode == DeliveryMode::Memory)
        return true;
    // defence in depth: under a memory-mode policy nothing derived from any analysed object is persisted
    const auto& pol = GetSession().GetPolicy();
    return pol.has_value() && pol->storageMode == RestrictedMode::StorageMode::Memory && RestrictedMode::IsActive();
}

bool IsLearningProblem(const GView::Object* obj) noexcept
{
    const auto* b = GetSession().FindBinding(obj);
    return b != nullptr && b->problem;
}

void ReportClientError(std::string_view constantMessage, bool fatal) noexcept
{
    try
    {
        GetSession().RecordClientError(constantMessage, fatal);
    }
    catch (...)
    {
    }
}

void Shutdown() noexcept
{
    GetSession().Shutdown();
}
} // namespace GView::Security::Learning::Hooks

namespace GView::App
{
bool CORE_EXPORT IsFeatureRestricted(Security::RestrictedMode::Feature feature) noexcept
{
    if (Security::RestrictedMode::IsFeatureDisabled(feature))
        return true;
    if (feature != Feature::Export && feature != Feature::SaveAs)
        return false;
    // memory-only storage: nothing derived from task content may be written to disk
    if (!Security::RestrictedMode::IsActive())
        return false;
    const auto& pol = GetSession().GetPolicy();
    return pol.has_value() && pol->storageMode == RestrictedMode::StorageMode::Memory;
}

static void NotifyBlocked(Security::RestrictedMode::Feature feature, std::string_view what) noexcept
{
    try
    {
        GetSession().RecordFeatureBlocked(feature);
        static uint64 lastNotice[32] = {};
        const auto bits              = static_cast<uint32>(feature);
        uint32 idx                   = 0;
        while (idx < 31 && ((bits >> idx) & 1u) == 0)
            idx++;
        const uint64 now = MonoMs();
        if (lastNotice[idx] == 0 || now - lastNotice[idx] >= BLOCK_NOTICE_INTERVAL_MS)
        {
            lastNotice[idx] = now;
            LocalString<256> msg;
            msg.SetFormat(
                  "Blocked by course policy: %.*s\n(restricted by Learning and Evaluation Mode: %.*s)",
                  static_cast<int>(std::min<size_t>(what.size(), 120)),
                  what.data(),
                  static_cast<int>(Security::RestrictedMode::FeatureToString(feature).size()),
                  Security::RestrictedMode::FeatureToString(feature).data());
            AppCUI::Dialogs::MessageBox::ShowWarning("Learning and Evaluation Mode", msg);
        }
    }
    catch (...)
    {
    }
}

bool CORE_EXPORT IsBlockedByPolicy(Security::RestrictedMode::Feature feature, std::string_view what)
{
    if (!IsFeatureRestricted(feature))
        return false;
    NotifyBlocked(feature, what);
    return true;
}

bool CORE_EXPORT IsExportBlockedFor(Reference<GView::Object> object, std::string_view what)
{
    if (IsFeatureRestricted(Feature::Export) || Learning::Hooks::IsMemoryOnlyObject(object))
    {
        NotifyBlocked(Feature::Export, what);
        return true;
    }
    return false;
}

bool CORE_EXPORT IsLearningMemoryOnly(Reference<GView::Object> object) noexcept
{
    return Learning::Hooks::IsMemoryOnlyObject(object);
}

bool CORE_EXPORT SetClipboardText(const ConstString& text, bool isSelectionCopy)
{
    if (IsBlockedByPolicy(Security::RestrictedMode::Feature::Clipboard, "writing to the clipboard"))
        return false;
    if (isSelectionCopy && IsBlockedByPolicy(Security::RestrictedMode::Feature::Copy, "copying the selection"))
        return false;
    return AppCUI::OS::Clipboard::SetText(text);
}
} // namespace GView::App
