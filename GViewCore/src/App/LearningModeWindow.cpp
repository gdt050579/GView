// Learning and Evaluation Mode window (formerly "Restricted Mode").
// All network work runs on the learning session's worker; results are applied in OnFrameUpdate.

#include "Internal.hpp"
#include "Learning/LearningSession.hpp"
#include "Learning/TaskFiles.hpp"

#include <cstdio>
#include <optional>

#undef MessageBox // Windows header conflict with AppCUI

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;
using namespace AppCUI::Graphics;
namespace Learning = GView::Security::Learning;
using GView::Security::RestrictedMode::Feature;
using GView::Security::RestrictedMode::StorageMode;

namespace
{
constexpr int BTN_CONNECT = 1;
constexpr int BTN_END     = 2;
constexpr int BTN_OPEN    = 3;
constexpr int BTN_DETAILS = 4;
constexpr int BTN_SUBMIT  = 5;
constexpr int BTN_REFRESH = 6;
constexpr int BTN_CLOSE   = 7;
constexpr int BTN_NOTES   = 8;

constexpr uint64 ROW_NONE = 0xFFFFFFFFFFFFFFFFull;

// shown instead of the connection string once connected: it contains the access token
constexpr std::string_view MASKED_CONNECTION_STRING = "************";

std::u8string_view AsU8(std::string_view utf8)
{
    return std::u8string_view(reinterpret_cast<const char8_t*>(utf8.data()), utf8.size());
}

// number of terminal cells of a UTF-8 string (one per code point; good enough for names and descriptions)
size_t Utf8Cells(std::string_view s)
{
    size_t n = 0;
    for (unsigned char c : s)
        if ((c & 0xC0) != 0x80)
            n++;
    return n;
}

// at most maxCells code points of s, never cutting a UTF-8 sequence
std::string_view Utf8Head(std::string_view s, size_t maxCells)
{
    size_t cells = 0;
    for (size_t i = 0; i < s.size(); i++)
    {
        if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80)
        {
            if (cells == maxCells)
                return s.substr(0, i);
            cells++;
        }
    }
    return s;
}

// first non-empty line of a (multi-line) description, whitespace collapsed at both ends
std::string FirstLine(std::string_view text)
{
    while (!text.empty())
    {
        const size_t eol = text.find('\n');
        std::string_view line = text.substr(0, eol);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t' || line.front() == '\r'))
            line.remove_prefix(1);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
            line.remove_suffix(1);
        if (!line.empty())
        {
            std::string r(line);
            for (auto& c : r)
                if (c == '\t')
                    c = ' ';
            return r;
        }
        if (eol == std::string_view::npos)
            break;
        text.remove_prefix(eol + 1);
    }
    return {};
}

bool IsLightTheme()
{
    auto cfg = AppCUI::Application::GetAppConfig();
    return cfg != nullptr && cfg->Text.Normal.Foreground == Color::Black;
}

ColorPair NormalTextColor()
{
    auto cfg = AppCUI::Application::GetAppConfig();
    return cfg ? cfg->Text.Normal : ColorPair{ Color::Silver, Color::Transparent };
}

// values of a connected session (yellow on the dark themes, olive on the light one)
ColorPair ValueTextColor()
{
    auto cfg = AppCUI::Application::GetAppConfig();
    return cfg ? cfg->Text.Highlighted : ColorPair{ Color::Yellow, Color::Transparent };
}

ColorPair GoodStateColor()
{
    return ColorPair{ IsLightTheme() ? Color::DarkGreen : Color::Green, Color::Transparent };
}

ColorPair BadStateColor()
{
    auto cfg = AppCUI::Application::GetAppConfig();
    return cfg ? cfg->Text.Error : ColorPair{ Color::Red, Color::Transparent };
}

// ---------------------------------------------------------------- one line of text in several colors
// AppCUI labels have a single color; this paints segments one after another and ends with "..." when they do not fit.
class ColoredLine : public UserControl
{
    struct Segment {
        std::string text; // UTF-8
        ColorPair color;
    };
    std::vector<Segment> segments;

  public:
    explicit ColoredLine(std::string_view layout) : UserControl(layout)
    {
        SetEnabled(false); // display only: keeps it out of the Tab order
    }
    void Clear()
    {
        segments.clear();
    }
    ColoredLine& Add(std::string_view text, ColorPair color)
    {
        if (!text.empty())
            segments.push_back(Segment{ std::string(text), color });
        return *this;
    }
    void Paint(Renderer& renderer) override
    {
        const size_t width = GetWidth() > 0 ? static_cast<size_t>(GetWidth()) : 0;
        size_t total       = 0;
        for (const auto& s : segments)
            total += Utf8Cells(s.text);
        const bool overflow = total > width;
        const size_t room   = overflow ? (width > 3 ? width - 3 : 0) : width;
        size_t x            = 0;
        for (const auto& s : segments)
        {
            if (x >= room)
                break;
            const auto part = Utf8Head(s.text, room - x);
            renderer.WriteSingleLineText(static_cast<int>(x), 0, AsU8(part), s.color);
            x += Utf8Cells(part);
        }
        if (overflow && width >= 3)
            renderer.WriteSingleLineText(static_cast<int>(x), 0, "...", NormalTextColor());
    }
};

Learning::LearningSettings LoadLearningSettings()
{
    Learning::LearningSettings s;
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return s;
    auto sect = ini->GetSection("GView");
    if (!sect.Exists())
        return s;
    s.allowPlainHttpLocalhost = sect.GetValue("LearningAllowPlainHttpLocalhost").ToBool(false);
    if (auto key = sect.GetValue("PolicyPublicKey").AsStringView(); key.has_value() && key->size() == 64)
    {
        std::vector<uint8> bytes;
        if (Learning::FromHex(*key, bytes) && bytes.size() == 32)
            s.fallbackPublicKey = std::move(bytes);
    }
    if (auto folder = sect.GetValue("LearningDownloadFolder").AsStringView(); folder.has_value())
        s.downloadFolder = std::string(*folder);
    return s;
}

// Whether AppCUI will deliver OnFrameUpdate on this frontend (FPS mode is enabled by Instance::Init). On Windows both
// frontends (console and SDL) honour FPS mode; on Linux/macOS only SDL does (ncurses never delivers frame updates).
bool FrontendDeliversFrameUpdates()
{
#if defined(BUILD_FOR_WINDOWS) || defined(BUILD_FOR_WASM)
    return true; // the browser frontend runs the AppCUI loop from the frames of the page
#else
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return false;
    auto sect = ini->GetSection("AppCUI");
    if (!sect.Exists())
        return false;
    auto frontend = sect.GetValue("Frontend").AsStringView();
    if (!frontend.has_value() || frontend->size() != 3)
        return false;
    const auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
    return lower((*frontend)[0]) == 's' && lower((*frontend)[1]) == 'd' && lower((*frontend)[2]) == 'l';
#endif
}

// Web build: the connection string (it contains the access token) is kept encrypted by the page
// (Browser::Secrets), never in GView.ini - the page mirrors GView.ini in clear into its localStorage.
std::string LoadSavedConnectionString()
{
#ifdef BUILD_FOR_WASM
    if (auto ini = AppCUI::Application::GetAppSettings(); ini)
    {
        // migrate a value saved in GView.ini by an older web build
        auto sect = ini->GetSection("GView");
        if (sect.Exists())
        {
            if (auto v = sect.GetValue("ServerConnectionString").AsStringView(); v.has_value() && !v->empty())
            {
                GView::App::Browser::Secrets::Set(GView::App::Browser::Secrets::LEARNING_CONNECTION, *v);
                (*ini)["GView"]["ServerConnectionString"] = "";
                AppCUI::Application::SaveAppSettings();
            }
        }
    }
    return GView::App::Browser::Secrets::Get(GView::App::Browser::Secrets::LEARNING_CONNECTION).value_or(std::string());
#else
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return {};
    auto sect = ini->GetSection("GView");
    if (!sect.Exists())
        return {};
    auto v = sect.GetValue("ServerConnectionString").AsStringView();
    return v.has_value() ? std::string(*v) : std::string();
#endif
}

void SaveConnectionString(const std::string& cs)
{
#ifdef BUILD_FOR_WASM
    if (!cs.empty() && LoadSavedConnectionString() != cs)
        GView::App::Browser::Secrets::Set(GView::App::Browser::Secrets::LEARNING_CONNECTION, cs);
#else
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini || cs.empty())
        return;
    if (LoadSavedConnectionString() == cs)
        return;
    (*ini)["GView"]["ServerConnectionString"] = cs;
    AppCUI::Application::SaveAppSettings();
#endif
}

std::string FormatRemaining(uint64 endsAt, uint64 now)
{
    if (endsAt == 0)
        return "no limit";
    if (now >= endsAt)
        return "expired, reconnect";
    uint64 left        = endsAt - now;
    const uint64 days  = left / 86400;
    left %= 86400;
    char buf[64];
    if (days > 0)
        snprintf(buf, sizeof(buf), "%llud %02llu:%02llu", (unsigned long long) days, (unsigned long long) (left / 3600), (unsigned long long) ((left % 3600) / 60));
    else
        snprintf(buf, sizeof(buf), "%02llu:%02llu:%02llu", (unsigned long long) (left / 3600), (unsigned long long) ((left % 3600) / 60), (unsigned long long) (left % 60));
    return buf;
}

std::string FormatSize(uint64 size)
{
    char buf[32];
    if (size >= 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f MiB", static_cast<double>(size) / (1024.0 * 1024.0));
    else if (size >= 1024)
        snprintf(buf, sizeof(buf), "%.1f KiB", static_cast<double>(size) / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long) size);
    return buf;
}

std::string FeatureList(const std::vector<Feature>& features)
{
    if (features.empty())
        return "none";
    std::string r;
    for (auto f : features)
    {
        if (!r.empty())
            r += ", ";
        r += GView::Security::RestrictedMode::FeatureToString(f);
    }
    return r;
}

std::string KindLabel(const Learning::CatalogueItem& item)
{
    switch (item.kind)
    {
    case Learning::ItemKind::Problem:
        return "problem";
    case Learning::ItemKind::ResourceFile:
        return "file";
    case Learning::ItemKind::ResourceText:
        return "text";
    case Learning::ItemKind::ResourceLink:
        return "link";
    }
    return "";
}

// ---------------------------------------------------------------- read-only text dialog
class TextDialog : public Window
{
  public:
    TextDialog(std::string_view title, std::string_view text) : Window(title, "d:c,w:90,h:24", WindowFlags::Sizeable)
    {
        // DisableAutoSelectOnFocus: AppCUI selects the whole text when a text area gets the focus
        Factory::TextArea::Create(
              this,
              AsU8(text),
              "l:1,t:1,r:1,b:3",
              TextAreaFlags::Readonly | TextAreaFlags::ScrollBars | TextAreaFlags::Border | TextAreaFlags::DisableAutoSelectOnFocus);
        Factory::Button::Create(this, "&Close", "r:1,b:0,w:12", 1, ButtonFlags::Flat);
    }
    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::ButtonClicked || eventType == Event::WindowClose || eventType == Event::WindowAccept)
        {
            Exit(Dialogs::Result::Ok);
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }
};

// ---------------------------------------------------------------- link resource dialog
class LinkDialog : public Window
{
    std::string url;

  public:
    LinkDialog(std::string_view title, std::string_view link) : Window(title, "d:c,w:90,h:8", WindowFlags::None), url(link)
    {
        Factory::Label::Create(this, "Link:", "l:1,t:1,w:6");
        Factory::TextField::Create(this, link, "l:8,t:1,r:1", TextFieldFlags::Readonly);
        auto copy = Factory::Button::Create(this, "&Copy", "l:1,b:0,w:12", 1, ButtonFlags::Flat);
        // a disabled Clipboard feature leaves the link read-only (spec §3.1)
        copy->SetEnabled(!GView::Security::RestrictedMode::IsFeatureDisabled(Feature::Clipboard));
        Factory::Button::Create(this, "C&lose", "r:1,b:0,w:12", 2, ButtonFlags::Flat);
    }
    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::ButtonClicked && id == 1)
        {
            if (GView::App::SetClipboardText(url, false))
                Dialogs::MessageBox::ShowNotification("Link", "The link was copied to the clipboard.");
            return true;
        }
        if (eventType == Event::ButtonClicked || eventType == Event::WindowClose || eventType == Event::WindowAccept)
        {
            Exit(Dialogs::Result::Ok);
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }
};

#ifdef BUILD_FOR_WASM
// ---------------------------------------------------------------- launch link of the web build
// [GView] LearningTrustedLaunchOrigins: the course servers this browser connected to through a launch link (not secret)
constexpr std::string_view TRUSTED_LAUNCH_ORIGINS_KEY = "LearningTrustedLaunchOrigins";

std::string TrustedLaunchOrigins()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return {};
    auto sect = ini->GetSection("GView");
    if (!sect.Exists())
        return {};
    auto v = sect.GetValue(TRUSTED_LAUNCH_ORIGINS_KEY).AsStringView();
    return v.has_value() ? std::string(*v) : std::string();
}

void TrustLaunchOrigin(std::string_view origin)
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return;
    (*ini)["GView"][TRUSTED_LAUNCH_ORIGINS_KEY] = Learning::OriginListAdd(TrustedLaunchOrigins(), origin);
    AppCUI::Application::SaveAppSettings(); // mirrored into the localStorage of the page by BrowserHost.cpp
}

void ForgetSavedConnectionString()
{
    GView::App::Browser::Secrets::Remove(GView::App::Browser::Secrets::LEARNING_CONNECTION);
}

// "Connect to the course server <host>?" - asked once per server origin and browser: a crafted link
// (#launch=x&server=https://attacker) must not silently point GView at another server
class LaunchTrustDialog : public Window
{
  public:
    explicit LaunchTrustDialog(std::string_view host) : Window("Course server", "d:c,w:76,h:9", WindowFlags::None)
    {
        const std::string question = "Connect to the course server " + std::string(host) + "?";
        Factory::Label::Create(this, question, "l:2,t:1,r:2,h:1");
        Factory::Label::Create(this, "Only continue if you opened GView from your course page.", "l:2,t:3,r:2,h:1");
        auto connect = Factory::Button::Create(this, "&Connect", "l:22,b:0,w:14", 1);
        Factory::Button::Create(this, "C&ancel", "l:39,b:0,w:14", 2);
        connect->SetFocus();
    }
    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::ButtonClicked)
        {
            Exit(id == 1 ? Dialogs::Result::Ok : Dialogs::Result::Cancel);
            return true;
        }
        if (eventType == Event::WindowClose)
        {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }
};
#endif

// ---------------------------------------------------------------- main window
class LearningModeWindow : public Window,
                           public Handlers::OnTreeViewItemPressedInterface,
                           public Handlers::OnTreeViewCurrentItemChangedInterface
{
    enum class RowKind : uint8 { Week, Problem, Resource };
    struct RowRef {
        size_t week;
        RowKind kind;
        size_t index; // problem / resource index (unused for a week row)
    };

    Reference<TextField> connectionField;
    Reference<Label> lbMaskedConnection;
    Reference<Button> connectButton, reconnectButton, endButton, openButton, detailsButton, submitButton, refreshButton, notesButton;
    Reference<ColoredLine> statusLine, previewLine;
    Reference<Label> lbPolicy, lbBlocked, lbMessage, lbHint;
    Reference<TreeView> tree;
    std::vector<RowRef> rows;

    std::string launchNotice; // web launch link: why nothing was connected (shown until the student connects)
    bool autoConnect;
    bool opened{ false };
    uint64 lastStatusSecond{ 0 };
    bool needsRefresh{ true };
    bool treeFocused{ false };
    bool startDeferred{ false };
    bool populating{ false };
    std::shared_ptr<bool> alive = std::make_shared<bool>(true);

    Learning::LearningSession& Session()
    {
        return Learning::GetSession();
    }

  public:
    // useSaved: an empty `prefilled` shows (and connects with) the saved connection string. notice: a failed web launch
    // opens the window with an empty connection field (useSaved = false) and the reason, so the string can be pasted.
    LearningModeWindow(std::string_view prefilled, bool connectNow, bool useSaved = true, std::string_view notice = {})
        : Window("Learning and Evaluation Mode", "d:c,w:98%,h:96%", WindowFlags::Sizeable), launchNotice(notice), autoConnect(connectNow)
    {
        std::string initial = (prefilled.empty() && useSaved) ? LoadSavedConnectionString() : std::string(prefilled);
        if (prefilled.empty() && !initial.empty() && !Session().HasSession())
            autoConnect = true; // previously verified connection string

        // disconnected: an editable field + Connect; connected: the string is masked (it holds the access token) and
        // Reconnect / End session follow it. Reconnect uses the (hidden) field; End session shows the field again.
        Factory::Label::Create(this, "Connection string:", "l:1,t:0,w:19");
        connectionField    = Factory::TextField::Create(this, initial, "l:21,t:0,r:16");
        connectButton      = Factory::Button::Create(this, "&Connect", "r:1,t:0,w:13", BTN_CONNECT, ButtonFlags::Flat);
        lbMaskedConnection = Factory::Label::Create(this, MASKED_CONNECTION_STRING, "l:21,t:0,w:12");
        reconnectButton    = Factory::Button::Create(this, "Re&connect", "l:35,t:0,w:13", BTN_CONNECT, ButtonFlags::Flat);
        endButton          = Factory::Button::Create(this, "&End session", "l:50,t:0,w:15", BTN_END, ButtonFlags::Flat);

        statusLine = this->CreateChildControl<ColoredLine>("l:1,t:2,r:1,h:1");
        lbPolicy   = Factory::Label::Create(this, "", "l:1,t:3,r:1,h:1");
        lbBlocked  = Factory::Label::Create(this, "", "l:1,t:4,r:1,h:1");
        lbMessage  = Factory::Label::Create(this, "", "l:1,t:5,r:1,h:2");
        lbHint     = Factory::Label::Create(
              this, "Click an item to preview its description below the list; press Details for the full explanation.", "l:1,t:7,r:1,h:1");

        tree = Factory::TreeView::Create(
              this, "l:1,t:8,r:1,b:3", { "n:Week / item,w:44", "n:Kind,w:9", "n:Points,w:10", "n:Status,w:34" }, TreeViewFlags::Searchable);
        tree->Handlers()->OnItemPressed        = this;
        tree->Handlers()->OnCurrentItemChanged = this;
        previewLine                            = this->CreateChildControl<ColoredLine>("l:1,b:2,r:1,h:1");

        openButton    = Factory::Button::Create(this, "&Open", "l:1,b:0,w:12", BTN_OPEN, ButtonFlags::Flat);
        detailsButton = Factory::Button::Create(this, "&Details", "l:14,b:0,w:12", BTN_DETAILS, ButtonFlags::Flat);
        submitButton  = Factory::Button::Create(this, "&Submit flag", "l:27,b:0,w:15", BTN_SUBMIT, ButtonFlags::Flat);
        refreshButton = Factory::Button::Create(this, "&Refresh", "l:43,b:0,w:12", BTN_REFRESH, ButtonFlags::Flat);
        notesButton   = Factory::Button::Create(this, "&Notes", "l:56,b:0,w:11", BTN_NOTES, ButtonFlags::Flat);
        Factory::Button::Create(this, "C&lose", "r:1,b:0,w:12", BTN_CLOSE, ButtonFlags::Flat);

        UpdateStatus();
        PopulateTree();
    }
    ~LearningModeWindow() override
    {
        *alive = false;
    }

    void OnStart() override
    {
        // OnStart runs before the first frame: a job started here would not yet know that frame updates (and thus the
        // background worker) are available and would block the UI inline. Defer it to the first frame when one will come.
        if (FrontendDeliversFrameUpdates())
            startDeferred = true;
        else
            RunStartActions();
    }

    bool OnFrameUpdate() override
    {
        auto& s = Session();
        s.NotifyFrameUpdatesAvailable();
        if (startDeferred)
        {
            startDeferred = false;
            RunStartActions();
        }
        bool repaint = s.DrainCompletions() > 0;
        s.Tick();
        const uint64 now = Learning::NowUnix();
        if (now != lastStatusSecond || repaint || needsRefresh)
        {
            lastStatusSecond = now;
            UpdateStatus();
            repaint = true;
        }
        if (needsRefresh)
        {
            PopulateTree();
            needsRefresh = false;
        }
        return repaint;
    }

    void OnTreeViewItemPressed(Reference<TreeView>, TreeViewItem&) override
    {
        OpenSelected();
    }

    void OnTreeViewCurrentItemChanged(Reference<TreeView>, TreeViewItem&) override
    {
        if (!populating) // the tree reports changes while it is rebuilt, before the rows are complete
            UpdatePreview();
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::ButtonClicked)
        {
            switch (id)
            {
            case BTN_CONNECT:
                StartConnect();
                return true;
            case BTN_END:
                EndSession();
                return true;
            case BTN_OPEN:
                OpenSelected();
                return true;
            case BTN_DETAILS:
                ShowDetails();
                return true;
            case BTN_SUBMIT:
                SubmitSelected();
                return true;
            case BTN_REFRESH:
                StartRefresh();
                return true;
            case BTN_NOTES:
                ShowNotes();
                return true;
            case BTN_CLOSE:
                Exit(opened ? Dialogs::Result::Ok : Dialogs::Result::Cancel);
                return true;
            }
        }
        if (eventType == Event::WindowClose)
        {
            Exit(opened ? Dialogs::Result::Ok : Dialogs::Result::Cancel);
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }

  private:
    template <typename F>
    auto Guarded(F&& f)
    {
        std::weak_ptr<bool> weak = alive;
        return [weak, f = std::forward<F>(f)](auto&&... args) {
            if (auto a = weak.lock(); a && *a)
                f(std::forward<decltype(args)>(args)...);
        };
    }

    // completions run on the UI thread (from OnFrameUpdate, or inline on frontends without frame updates)
    void RefreshNow()
    {
        UpdateStatus();
        PopulateTree();
        needsRefresh = false;
    }

    void UpdateStatus()
    {
        const auto st  = Session().GetStatus();
        const auto now = Learning::NowUnix();
        LocalString<512> tmp;

        // State (green when Active, red otherwise), then who is connected where
        const bool active    = st.state == Learning::SessionState::Active;
        const bool connected = active || st.state == Learning::SessionState::Legacy || st.state == Learning::SessionState::Expired;
        const auto normal    = NormalTextColor();
        const auto value     = connected ? ValueTextColor() : normal;
        statusLine->Clear();
        statusLine->Add("State: ", normal).Add(Learning::SessionStateName(st.state), active ? GoodStateColor() : BadStateColor());
        if (st.busy)
            statusLine->Add("  (working...)", normal);
        if (st.state != Learning::SessionState::Disconnected)
        {
            const std::string score = std::to_string(st.score);
            statusLine->Add("   User: ", normal).Add(st.displayName.empty() ? std::string_view("-") : std::string_view(st.displayName), value);
            statusLine->Add("   Score: ", normal).Add(score, value);
            statusLine->Add("   Server: ", normal).Add(st.serverUrl.empty() ? std::string_view("-") : std::string_view(st.serverUrl), value);
        }
        if (!st.label.empty())
            statusLine->Add("   Course: ", normal).Add(st.label, value);

        // the policy id means nothing to a student; the end of the policy is when they have to reconnect
        if (st.hasPolicy)
            tmp.SetFormat(
                  "Policy: %s   Policy valid for: %s   Storage: %s   Telemetry: %s",
                  st.purpose.empty() ? "-" : st.purpose.c_str(),
                  FormatRemaining(st.endsAt, now).c_str(),
                  st.storageMode == StorageMode::Memory ? "memory only" : "files",
                  st.telemetryEnabled ? "on" : "off");
        else if (st.state == Learning::SessionState::Legacy)
            tmp.Set("Policy: none (legacy server) - restrictions are NOT active");
        else
            tmp.Set("Policy: -");
        lbPolicy->SetText(AsU8(std::string_view(tmp.GetText(), tmp.Len())));

        if (st.hasPolicy)
            tmp.SetFormat("Blocked features: %s", FeatureList(st.disabledFeatures).c_str());
        else
            tmp.Set("Blocked features: none");
        if (st.notes == Learning::NotesAvailability::DisabledByPolicy || st.notes == Learning::NotesAvailability::DisabledByServer)
            tmp.Add("   Course notes are disabled by your teacher");
        lbBlocked->SetText(tmp);
        if (st.state != Learning::SessionState::Disconnected)
            launchNotice.clear(); // a launch error only explains why nothing is connected
        if (!launchNotice.empty())
            lbMessage->SetText(AsU8(launchNotice));
        else // a normal Active session needs no extra message: the State already says it (errors and warnings still show)
            lbMessage->SetText(AsU8(active && st.message == Learning::ACTIVE_STATUS_MESSAGE ? std::string_view() : std::string_view(st.message)));

        const bool connecting = st.state == Learning::SessionState::Connecting;
        // stays masked while (re)connecting: the field holds the token and must not flash on screen
        const bool masked = Session().HasSession() || connecting;
        // AppCUI keeps the focus on a control that becomes hidden (keys then go nowhere): move it first
        // (a Reconnect button disabled while connecting counts too)
        const bool focusOnHidden =
              masked ? (connectionField->HasFocus() || connectButton->HasFocus() || (connecting && reconnectButton->HasFocus()))
                     : (reconnectButton->HasFocus() || endButton->HasFocus());
        connectionField->SetVisible(!masked);
        connectButton->SetVisible(!masked);
        lbMaskedConnection->SetVisible(masked);
        reconnectButton->SetVisible(masked);
        endButton->SetVisible(masked);
        if (focusOnHidden)
        {
            if (masked)
                tree->SetFocus();
            else
                connectionField->SetFocus();
        }
        connectButton->SetEnabled(!connecting);
        reconnectButton->SetEnabled(!connecting);
        endButton->SetEnabled(Session().HasSession() && !connecting);
        refreshButton->SetEnabled(Session().HasSession() && !connecting && st.state != Learning::SessionState::Expired);
        openButton->SetEnabled(Session().CanOpenItems() && !st.busy);
        submitButton->SetEnabled(Session().CanSubmit() && !st.busy);
        detailsButton->SetEnabled(Session().IsCatalogueLoaded());
        // the Notes UI exists only while notes are on (absent object or 403 => hidden, spec §10.11)
        notesButton->SetVisible(st.notes == Learning::NotesAvailability::Available);
    }

    void ShowNotes()
    {
        const auto* item = SelectedItem(); // nullptr on a week row or an empty tree (guarded by CurrentRowIndex)
        GView::App::ShowLearningNotesWindow(item != nullptr ? std::string_view(item->name) : std::string_view(), item != nullptr && item->IsProblem(), nullptr, false);
        RefreshNow();
    }

    // index in rows of the current tree row, or ROW_NONE. AppCUI reports a "valid" current item even when the tree is
    // empty, and TreeViewItem::GetData throws (std::map::at) for a handle it does not know: check first, then guard.
    uint64 CurrentRowIndex()
    {
        if (rows.empty() || tree->GetItemsCount() == 0)
            return ROW_NONE;
        auto cur = tree->GetCurrentItem();
        if (!cur.IsValid())
            return ROW_NONE;
        try
        {
            const uint64 idx = cur.GetData(ROW_NONE);
            return idx < rows.size() ? idx : ROW_NONE;
        }
        catch (...)
        {
            return ROW_NONE;
        }
    }

    // identifies the current row across a rebuild of the tree ("w:<week index>" or "i:<item name>")
    std::string CurrentRowKey()
    {
        const uint64 idx = CurrentRowIndex();
        if (idx == ROW_NONE)
            return {};
        if (rows[idx].kind == RowKind::Week)
            return "w:" + std::to_string(rows[idx].week);
        const auto* item = ItemOf(rows[idx]);
        return item ? "i:" + item->name : std::string();
    }

    void PopulateTree()
    {
        const std::string previous = CurrentRowKey();
        populating                 = true;
        tree->ClearItems();
        rows.clear();
        const auto& cat = Session().GetCatalogue();
        if (!Session().IsCatalogueLoaded())
        {
            populating = false;
            UpdatePreview();
            return;
        }
        const bool memoryPolicy = Session().GetPolicy().has_value() && Session().GetPolicy()->storageMode == StorageMode::Memory;
        std::optional<TreeViewItem> restore;
        for (size_t w = 0; w < cat.weeks.size(); w++)
        {
            const auto& week = cat.weeks[w];
            std::string title = week.name;
            if (!week.title.empty())
                title += " - " + week.title;
            auto weekItem = tree->AddItem(title, true);
            weekItem.SetType(TreeViewItem::Type::Category);
            rows.push_back(RowRef{ w, RowKind::Week, 0 });
            weekItem.SetData(static_cast<uint64>(rows.size() - 1));
            if (previous == "w:" + std::to_string(w))
                restore = weekItem;
            auto addItem = [&](const Learning::CatalogueItem& it, bool problem, size_t idx) {
                auto node = weekItem.AddChild(it.title);
                node.SetText(1, KindLabel(it));
                LocalString<64> pts;
                if (problem)
                {
                    pts.SetFormat("%lld/%lld", (long long) it.pointsCurrent, (long long) it.pointsMax);
                    node.SetText(2, pts);
                }
                std::string status;
                if (problem && it.hasMe)
                {
                    status = it.me.solved ? "SOLVED" : "open";
                    status += " - " + std::to_string(it.me.attempts) + " attempt(s)";
                }
                if (it.kind != Learning::ItemKind::ResourceLink)
                {
                    const bool mem = memoryPolicy || it.deliveryMode == Learning::DeliveryMode::Memory;
                    if (!status.empty())
                        status += ", ";
                    status += mem ? "memory" : "file";
                    if (it.size > 0)
                        status += ", " + FormatSize(it.size);
                }
                node.SetText(3, status);
                if (problem && it.hasMe && it.me.solved)
                    node.SetType(TreeViewItem::Type::Emphasized_1);
                rows.push_back(RowRef{ w, problem ? RowKind::Problem : RowKind::Resource, idx });
                node.SetData(static_cast<uint64>(rows.size() - 1));
                if (previous == "i:" + it.name)
                    restore = node;
            };
            for (size_t i = 0; i < week.problems.size(); i++)
                addItem(week.problems[i], true, i);
            for (size_t i = 0; i < week.resources.size(); i++)
                addItem(week.resources[i], false, i);
            weekItem.Unfold();
        }
        if (!rows.empty() && !treeFocused)
        {
            tree->SetFocus(); // keyboard users land on the catalogue once it is available
            treeFocused = true;
        }
        if (cat.rejectedItems > 0)
        {
            LocalString<128> msg;
            msg.SetFormat("%u malformed or disabled catalogue entr%s hidden", cat.rejectedItems, cat.rejectedItems == 1 ? "y was" : "ies were");
            auto info = tree->AddItem(msg);
            info.SetType(TreeViewItem::Type::GrayedOut);
            info.SetData(ROW_NONE);
        }
        if (restore.has_value())
            restore->SetCurrent(); // a refresh (or a submission) keeps the student on the same row
        populating = false;
        UpdatePreview();
    }

    const Learning::CatalogueItem* ItemOf(const RowRef& r)
    {
        const auto& cat = Session().GetCatalogue();
        if (r.kind == RowKind::Week || r.week >= cat.weeks.size())
            return nullptr;
        const auto& week = cat.weeks[r.week];
        const auto& list = r.kind == RowKind::Problem ? week.problems : week.resources;
        return r.index < list.size() ? &list[r.index] : nullptr;
    }

    const RowRef* CurrentRow()
    {
        const uint64 idx = CurrentRowIndex();
        return idx == ROW_NONE ? nullptr : &rows[idx];
    }

    // the week of the current row (a week row or one of its items)
    const Learning::Week* SelectedWeek()
    {
        const auto* r   = CurrentRow();
        const auto& cat = Session().GetCatalogue();
        if (r == nullptr || r->week >= cat.weeks.size())
            return nullptr;
        return &cat.weeks[r->week];
    }

    // the item of the current row (nullptr on a week row)
    const Learning::CatalogueItem* SelectedItem(std::string* weekName = nullptr)
    {
        const auto* r = CurrentRow();
        if (r == nullptr)
            return nullptr;
        const auto* item = ItemOf(*r);
        if (item != nullptr && weekName != nullptr)
            *weekName = Session().GetCatalogue().weeks[r->week].name;
        return item;
    }

    // one line under the list: the title and the beginning of the description of the current week or item
    void UpdatePreview()
    {
        previewLine->Clear();
        const auto* r = CurrentRow();
        if (r == nullptr)
            return;
        const auto normal = NormalTextColor();
        std::string title, description;
        if (const auto* item = ItemOf(*r); item != nullptr)
        {
            title       = item->title == item->name ? item->name : item->name + " - " + item->title;
            description = FirstLine(item->description);
        }
        else if (const auto* week = SelectedWeek(); week != nullptr)
        {
            title       = week->title.empty() ? week->name : week->name + " - " + week->title;
            description = FirstLine(week->description);
        }
        else
            return;
        previewLine->Add(title, ValueTextColor()).Add(": ", normal);
        previewLine->Add(description.empty() ? std::string_view("(no description)") : std::string_view(description), normal);
    }

    void RunStartActions()
    {
        if (!launchNotice.empty())
            Dialogs::MessageBox::ShowError("Learning and Evaluation Mode", launchNotice);
        if (autoConnect && !Session().HasSession())
            StartConnect();
        else if (Session().HasSession() && !Session().IsCatalogueLoaded())
            StartRefresh();
    }

    void StartConnect()
    {
        std::string cs;
        if (!connectionField->GetText().ToString(cs) || cs.empty())
        {
            Dialogs::MessageBox::ShowError("Learning and Evaluation Mode", "Please paste the connection string provided by your teacher.");
            return;
        }
        launchNotice.clear();
        auto st = Session().Connect(cs, LoadLearningSettings(), Guarded([this, cs](const GView::Utils::GStatus& result) {
            if (result.ok)
            {
                // persisted only after a successful, verified connect
                SaveConnectionString(cs);
                GView::App::RefreshAllFileWindowTitles();
                StartRefresh();
            }
            else
            {
                Dialogs::MessageBox::ShowError("Connection failed", result.message);
            }
            RefreshNow();
        }));
        Learning::WipeString(cs);
        if (!st.ok)
            Dialogs::MessageBox::ShowError("Learning and Evaluation Mode", st.message);
        RefreshNow();
    }

    void StartRefresh()
    {
        auto st = Session().RefreshCatalogue(Guarded([this](const GView::Utils::GStatus& result) {
            if (!result.ok)
                Dialogs::MessageBox::ShowError("Catalogue", result.message);
            RefreshNow();
        }));
        if (!st.ok)
            Dialogs::MessageBox::ShowError("Catalogue", st.message);
        UpdateStatus();
    }

    void EndSession()
    {
        std::string question = "End the learning session? Restrictions will be removed and secrets erased.";
        if (Session().Notes().HasUnsavedChanges())
            question += "\n\nSome note changes are not on the course server yet. GView tries to send them once more; what cannot be "
                        "sent now is erased with the session.";
        if (Dialogs::MessageBox::ShowOkCancel("End session", question) != Dialogs::Result::Ok)
            return;
        auto st = Session().EndSession("user");
        if (!st.ok)
            Dialogs::MessageBox::ShowError("End session", st.message);
        GView::App::RefreshAllFileWindowTitles();
        RefreshNow();
    }

    void ShowDetails()
    {
        std::string weekName;
        const auto* item = SelectedItem(&weekName);
        if (item == nullptr)
        {
            // week row: show the week description
            if (const auto* w = SelectedWeek(); w != nullptr)
            {
                std::string text = w->title.empty() ? w->name : w->name + " - " + w->title;
                text += "\n\n";
                text += w->description.empty() ? "(no description)" : w->description;
                TextDialog dlg(w->name, text);
                dlg.Show();
            }
            return;
        }
        std::string text = item->title + "\n\n";
        text += item->description.empty() ? "(no description)" : item->description;
        text += "\n\n----\nWeek: " + weekName + "\nKind: " + KindLabel(*item);
        if (item->IsProblem())
        {
            text += "\nPoints: " + std::to_string(item->pointsCurrent) + " (max " + std::to_string(item->pointsMax) + ", min " +
                    std::to_string(item->pointsMin) + ")";
            if (item->hasMe)
                text += std::string("\nSolved: ") + (item->me.solved ? "yes" : "no") + ", attempts: " + std::to_string(item->me.attempts);
            if (item->requireExplanation)
                text += "\nAn explanation is required with the flag.";
        }
        if (!item->fileName.empty())
            text += "\nFile: " + item->fileName;
        if (!item->sha256.empty())
            text += "\nSHA-256: " + item->sha256;
        if (DeliveredAsFile(*item))
        {
            const Learning::TaskFileStore store(TaskFolderOf(weekName));
            if (const auto local = store.KnownFile(item->name); local.has_value())
                text += "\nSaved on disk: " + Learning::PathToUtf8(*local);
            else
                text += "\nWill be saved in: " + Learning::PathToUtf8(store.Folder());
        }
        TextDialog dlg(item->name, text);
        dlg.Show();
    }

    void SubmitSelected()
    {
        const auto* item = SelectedItem();
        if (item == nullptr || !item->IsProblem())
        {
            Dialogs::MessageBox::ShowError("Submit flag", "Select a problem first.");
            return;
        }
        GView::App::ShowLearningSubmitDialog(item->name);
        RefreshNow();
    }

    // <download folder>/<server>/<week>: file-mode content is kept there, no Save dialog (TaskFiles.hpp)
    std::filesystem::path TaskFolderOf(std::string_view weekName)
    {
        return Learning::TaskFolder(Session().GetSettings().downloadFolder, Session().GetStatus().serverUrl, weekName);
    }

    // whether the course delivers this item as a file (the server can still force memory mode when it sends it)
    bool DeliveredAsFile(const Learning::CatalogueItem& item)
    {
        const auto& policy = Session().GetPolicy();
        return policy.has_value() && policy->storageMode == StorageMode::File && item.deliveryMode == Learning::DeliveryMode::File &&
               item.kind != Learning::ItemKind::ResourceLink;
    }

    void OpenTaskFile(const std::filesystem::path& path, const Learning::CatalogueItem& item, uint32 version)
    {
        Learning::ItemBinding binding;
        binding.item    = item.name;
        binding.problem = item.IsProblem();
        binding.mode    = Learning::DeliveryMode::File;
        binding.version = version;
        Session().SetPendingBinding(binding);
        GView::App::OpenFile(path, GView::App::OpenMethod::BestMatch, "", nullptr, "Learning mode task");
        Session().ClearPendingBinding();
        Session().RecordItemOpened(item, Learning::DeliveryMode::File, version);
    }

    // The copy saved by an earlier open is used as it is (no download) while it still matches the catalogue checksum.
    bool OpenLocalCopy(const Learning::CatalogueItem& item, const std::string& weekName)
    {
        if (!DeliveredAsFile(item) || item.sha256.empty() || !Session().CanOpenItems())
            return false;
        Learning::TaskFileStore store(TaskFolderOf(weekName));
        const auto path = store.FindUpToDate(item.name, item.sha256);
        if (!path.has_value())
            return false;
        OpenTaskFile(*path, item, store.RecordedVersion(item.name));
        return true;
    }

    void OpenSelected()
    {
        std::string weekName;
        const auto* selected = SelectedItem(&weekName);
        if (selected == nullptr)
            return;
        const Learning::CatalogueItem item = *selected;
        if (item.kind == Learning::ItemKind::ResourceLink)
        {
            LinkDialog dlg(item.title, item.url);
            dlg.Show();
            Session().RecordItemOpened(item, Learning::DeliveryMode::File, 0);
            return;
        }
        if (OpenLocalCopy(item, weekName))
        {
            opened = true;
            Exit(Dialogs::Result::Ok); // show the task
            return;
        }
        auto st = Session().Download(item, Guarded([this, weekName](Learning::DownloadResult& result) {
            if (!result.status.ok)
            {
                Dialogs::MessageBox::ShowError("Download failed", result.status.message);
                return;
            }
            if (OpenDelivered(result, weekName))
            {
                opened = true;
                Exit(Dialogs::Result::Ok); // show the task
            }
        }));
        if (!st.ok)
            Dialogs::MessageBox::ShowError("Open", st.message);
        UpdateStatus();
    }

    bool OpenDelivered(Learning::DownloadResult& result, const std::string& weekName)
    {
        auto& session = Session();
        const auto& item = result.item;
        auto& content    = result.content;

        const std::string fileName = content.fileName.empty() ? Learning::SanitizeFileName(item.name) : content.fileName;

        if (content.mode == Learning::DeliveryMode::Memory)
        {
            Learning::ItemBinding binding;
            binding.item    = item.name;
            binding.problem = item.IsProblem();
            binding.mode    = content.mode;
            binding.version = content.itemVersion;

            // memory mode: no file is created; the viewer reads from locked memory that is wiped on close
            const auto u8name = AsU8(fileName);
            auto dataObject   = std::make_unique<Learning::LockedMemoryDataObject>(std::move(content.data));
            session.SetPendingBinding(binding);
            const bool ok = GView::App::OpenDataObject(
                  std::move(dataObject), u8name, u8name, GView::App::OpenMethod::BestMatch, "", nullptr, "Learning mode task");
            session.ClearPendingBinding();
            if (!ok)
            {
                Dialogs::MessageBox::ShowError("Open", "GView could not open the delivered content.");
                return false;
            }
            session.RecordItemOpened(item, content.mode, content.itemVersion);
            return true;
        }

        // file mode: <download folder>/<server>/<week>/<file>; a copy from an earlier open is reused or replaced
        Learning::TaskFileStore store(TaskFolderOf(weekName));
        const auto plan        = store.PlanFor(item.name, fileName, content.sha256);
        std::filesystem::path path = plan.path;
        uint32 version             = content.itemVersion;
        bool write                 = plan.state == Learning::TaskFileStore::LocalState::Missing ||
                     plan.state == Learning::TaskFileStore::LocalState::Outdated; // unchanged by the student: just update it
        if (plan.state == Learning::TaskFileStore::LocalState::Modified)
        {
            LocalString<512> msg;
            msg.SetFormat(
                  "Your file on disk (%s) has been changed since it was downloaded.\n\nReplace it with the version from the server?\n"
                  "Yes - replace it, No - open your file as it is",
                  plan.file.c_str());
            const auto answer = Dialogs::MessageBox::ShowYesNoCancel("Task file changed", AsU8(std::string_view(msg.GetText(), msg.Len())));
            if (answer == Dialogs::Result::Yes)
                write = true;
            else if (answer == Dialogs::Result::No)
            {
                // the student keeps working on the version they had (0 = unknown: not a file GView recorded)
                version = store.RecordedVersion(item.name);
                store.Keep(plan, item.name, content.sha256, content.itemVersion);
            }
            else
                return false; // the LockedBuffer is wiped when result goes out of scope
        }
        else if (plan.state == Learning::TaskFileStore::LocalState::SameAsServer)
        {
            store.Keep(plan, item.name, content.sha256, content.itemVersion);
        }
        if (write)
        {
            // the file on disk is verified against the SHA-256 of the (already verified) delivered bytes
            auto st = store.Store(plan, item.name, content.data.View(), content.sha256, content.itemVersion, path);
            if (!st.ok && plan.state == Learning::TaskFileStore::LocalState::Missing)
            {
                Dialogs::MessageBox::ShowError("Save failed", st.message);
                return false;
            }
            if (!st.ok)
            {
                // typically the old copy is open in another window (Windows cannot replace an open file)
                LocalString<1024> msg;
                msg.SetFormat(
                      "The file on disk could not be replaced: %s\n\nIf it is open in another window, close it and try again.\n"
                      "Open the copy on disk as it is?",
                      st.message.c_str());
                if (Dialogs::MessageBox::ShowOkCancel("Save failed", AsU8(std::string_view(msg.GetText(), msg.Len()))) != Dialogs::Result::Ok)
                    return false;
                path    = plan.path;
                version = store.RecordedVersion(item.name);
            }
        }
        content.data.Wipe();
        OpenTaskFile(path, item, version);
        return true;
    }
};
} // namespace

void GView::App::ShowLearningModeWindow(std::string_view prefilledConnectionString, bool autoConnect)
{
    LearningModeWindow dlg(prefilledConnectionString, autoConnect);
    dlg.Show();
}

#ifdef BUILD_FOR_WASM
void GView::App::RunLearningLaunch(const Browser::LearningLaunch& launch)
{
    // any failure: the window opens with the reason and an empty connection field (the string can still be pasted);
    // a connection string already stored is left as it is
    const auto failed = [](std::string_view message) {
        LearningModeWindow dlg("", false, false, message);
        dlg.Show();
    };
#ifndef GVIEW_HAS_LEARNING_NETWORK
    failed("Learning and Evaluation Mode is not available in this build of GView.");
#else
    if (!launch.error.empty() || launch.connectionString.empty())
    {
        failed(launch.error.empty() ? std::string_view("The launch link could not be opened. Open GView again from the course page.")
                                    : std::string_view(launch.error));
        return;
    }
    // the same parser and checks as a pasted string, plus: version 2 with the policy key, and the server the code was
    // redeemed at
    const auto settings = LoadLearningSettings();
    Learning::ConnectionInfo info;
    if (auto st = Learning::ValidateLaunchConnectionString(launch.connectionString, launch.serverOrigin, settings.allowPlainHttpLocalhost, info);
        !st.ok)
    {
        failed("Nothing was connected: " + st.message + ".");
        return;
    }
    const std::string origin = Learning::ServerOrigin(launch.serverOrigin);
    const std::string host   = origin.substr(origin.find("://") + 3);

    if (!Learning::OriginListContains(TrustedLaunchOrigins(), origin))
    {
        LaunchTrustDialog ask(host);
        if (ask.Show() != Dialogs::Result::Ok)
        {
            failed("Not connected to " + host + ". You can still paste the connection string here.");
            return;
        }
        TrustLaunchOrigin(origin);
    }

    // another connection (another student on a lab computer, another course): ended first, as End session does - its
    // pending telemetry is sent with its own token - and its connection string is forgotten
    auto& session = Learning::GetSession();
    if (session.HasSession() && !session.UsesConnection(info))
    {
        if (auto st = session.EndSession("user"); !st.ok)
        {
            failed("The current course session could not be ended: " + st.message);
            return;
        }
        GView::App::RefreshAllFileWindowTitles();
    }
    std::string saved = LoadSavedConnectionString();
    if (!saved.empty() && saved != launch.connectionString)
        ForgetSavedConnectionString();
    Learning::WipeString(saved);

    // exactly as if the string had been pasted: connect, then store it once the connection is verified
    LearningModeWindow dlg(launch.connectionString, true);
    dlg.Show();
#endif
}
#endif

void Instance::ShowRestrictedModeWindow()
{
    GView::App::ShowLearningModeWindow("", false);
}

void GView::App::RefreshAllFileWindowTitles()
{
    auto dsk = AppCUI::Application::GetDesktop();
    if (!dsk.IsValid())
        return;
    for (uint32 i = 0; i < dsk->GetChildrenCount(); i++)
    {
        Control* child = dsk->GetChild(i).operator->();
        if (auto* fw = dynamic_cast<FileWindow*>(child); fw != nullptr)
            fw->RefreshTitle();
    }
}
