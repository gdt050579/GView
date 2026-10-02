// Learning and Evaluation Mode window (formerly "Restricted Mode").
// All network work runs on the learning session's worker; results are applied in OnFrameUpdate.

#include "Internal.hpp"
#include "Learning/LearningSession.hpp"

#include <cstdio>

#undef MessageBox // Windows header conflict with AppCUI

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;
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

constexpr uint64 ROW_NONE = 0xFFFFFFFFFFFFFFFFull;

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

std::string LoadSavedConnectionString()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return {};
    auto sect = ini->GetSection("GView");
    if (!sect.Exists())
        return {};
    auto v = sect.GetValue("ServerConnectionString").AsStringView();
    return v.has_value() ? std::string(*v) : std::string();
}

void SaveConnectionString(const std::string& cs)
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini || cs.empty())
        return;
    if (LoadSavedConnectionString() == cs)
        return;
    (*ini)["GView"]["ServerConnectionString"] = cs;
    AppCUI::Application::SaveAppSettings();
}

std::string FormatRemaining(uint64 endsAt, uint64 now)
{
    if (endsAt == 0)
        return "no end";
    if (now >= endsAt)
        return "expired";
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
        Factory::TextArea::Create(this, text, "l:1,t:1,r:1,b:3", TextAreaFlags::Readonly | TextAreaFlags::ScrollBars | TextAreaFlags::Border);
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

// ---------------------------------------------------------------- main window
class LearningModeWindow : public Window, public Handlers::OnTreeViewItemPressedInterface
{
    struct RowRef {
        size_t week;
        bool problem;
        size_t index;
    };

    Reference<TextField> connectionField;
    Reference<Button> connectButton, endButton, openButton, detailsButton, submitButton, refreshButton;
    Reference<Label> lbState, lbUser, lbPolicy, lbProtection, lbBlocked, lbMessage;
    Reference<TreeView> tree;
    std::vector<RowRef> rows;

    std::string pendingConnectionString;
    bool autoConnect;
    bool opened{ false };
    uint64 lastStatusSecond{ 0 };
    bool needsRefresh{ true };
    bool treeFocused{ false };
    std::shared_ptr<bool> alive = std::make_shared<bool>(true);

    Learning::LearningSession& Session()
    {
        return Learning::GetSession();
    }

  public:
    LearningModeWindow(std::string_view prefilled, bool connectNow)
        : Window("Learning and Evaluation Mode", "d:c,w:98%,h:96%", WindowFlags::Sizeable), autoConnect(connectNow)
    {
        std::string initial = prefilled.empty() ? LoadSavedConnectionString() : std::string(prefilled);
        if (prefilled.empty() && !initial.empty() && !Session().HasSession())
            autoConnect = true; // previously verified connection string

        Factory::Label::Create(this, "Connection string:", "l:1,t:0,w:19");
        connectionField = Factory::TextField::Create(this, initial, "l:21,t:0,r:30");
        connectButton   = Factory::Button::Create(this, "&Connect", "r:15,t:0,w:13", BTN_CONNECT, ButtonFlags::Flat);
        endButton       = Factory::Button::Create(this, "&End session", "r:1,t:0,w:13", BTN_END, ButtonFlags::Flat);

        lbState      = Factory::Label::Create(this, "", "l:1,t:2,r:1,h:1");
        lbUser       = Factory::Label::Create(this, "", "l:1,t:3,r:1,h:1");
        lbPolicy     = Factory::Label::Create(this, "", "l:1,t:4,r:1,h:1");
        lbProtection = Factory::Label::Create(this, "", "l:1,t:5,r:1,h:1");
        lbBlocked    = Factory::Label::Create(this, "", "l:1,t:6,r:1,h:1");
        lbMessage    = Factory::Label::Create(this, "", "l:1,t:7,r:1,h:2");

        tree = Factory::TreeView::Create(
              this, "l:1,t:10,r:1,b:3", { "n:Week / item,w:44", "n:Kind,w:9", "n:Points,w:10", "n:Status,w:34" }, TreeViewFlags::Searchable);
        tree->Handlers()->OnItemPressed = this;

        openButton    = Factory::Button::Create(this, "&Open", "l:1,b:0,w:12", BTN_OPEN, ButtonFlags::Flat);
        detailsButton = Factory::Button::Create(this, "&Details", "l:14,b:0,w:12", BTN_DETAILS, ButtonFlags::Flat);
        submitButton  = Factory::Button::Create(this, "&Submit flag", "l:27,b:0,w:15", BTN_SUBMIT, ButtonFlags::Flat);
        refreshButton = Factory::Button::Create(this, "&Refresh", "l:43,b:0,w:12", BTN_REFRESH, ButtonFlags::Flat);
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
        if (autoConnect && !Session().HasSession())
            StartConnect();
        else if (Session().HasSession() && !Session().IsCatalogueLoaded())
            StartRefresh();
    }

    bool OnFrameUpdate() override
    {
        auto& s = Session();
        s.NotifyFrameUpdatesAvailable();
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

        tmp.SetFormat("State: %s%s", std::string(Learning::SessionStateName(st.state)).c_str(), st.busy ? "  (working...)" : "");
        if (!st.label.empty())
            tmp.AddFormat("   Course: %s", st.label.c_str());
        lbState->SetText(tmp);

        if (st.state == Learning::SessionState::Disconnected)
            tmp.Set("User: -");
        else
            tmp.SetFormat("User: %s   Score: %lld   Server: %s", st.displayName.empty() ? "-" : st.displayName.c_str(), (long long) st.score, st.serverUrl.c_str());
        lbUser->SetText(tmp);

        if (st.hasPolicy)
            tmp.SetFormat(
                  "Policy: %s [%s]   Time left: %s   Storage: %s   Telemetry: %s",
                  st.purpose.empty() ? "-" : st.purpose.c_str(),
                  st.policyId.c_str(),
                  FormatRemaining(st.endsAt, now).c_str(),
                  st.storageMode == StorageMode::Memory ? "memory only" : "files",
                  st.telemetryEnabled ? "on" : "off");
        else if (st.state == Learning::SessionState::Legacy)
            tmp.Set("Policy: none (legacy server) - restrictions are NOT active");
        else
            tmp.Set("Policy: -");
        lbPolicy->SetText(tmp);

        if (st.hasPolicy)
            tmp.SetFormat(
                  "Screen protection: %s%s - %s",
                  !st.screenProtectRequested ? "not requested" : (st.screenProtectApplied ? "applied" : "NOT available"),
                  st.screenRequirementUnmet ? " (required by the course!)" : "",
                  st.screenNote.c_str());
        else
            tmp.Set("Screen protection: -");
        lbProtection->SetText(tmp);

        if (st.hasPolicy)
            tmp.SetFormat("Blocked features: %s", FeatureList(st.disabledFeatures).c_str());
        else
            tmp.Set("Blocked features: none");
        lbBlocked->SetText(tmp);
        lbMessage->SetText(st.message);

        const bool connecting = st.state == Learning::SessionState::Connecting;
        connectButton->SetText(Session().HasSession() && !connecting ? "Re&connect" : "&Connect");
        connectButton->SetEnabled(!connecting);
        endButton->SetEnabled(Session().HasSession() && !connecting);
        refreshButton->SetEnabled(Session().HasSession() && !connecting && st.state != Learning::SessionState::Expired);
        openButton->SetEnabled(Session().CanOpenItems() && !st.busy);
        submitButton->SetEnabled(Session().CanSubmit() && !st.busy);
        detailsButton->SetEnabled(Session().IsCatalogueLoaded());
    }

    void PopulateTree()
    {
        tree->ClearItems();
        rows.clear();
        const auto& cat = Session().GetCatalogue();
        if (!Session().IsCatalogueLoaded())
            return;
        const bool memoryPolicy = Session().GetPolicy().has_value() && Session().GetPolicy()->storageMode == StorageMode::Memory;
        for (size_t w = 0; w < cat.weeks.size(); w++)
        {
            const auto& week = cat.weeks[w];
            std::string title = week.name;
            if (!week.title.empty())
                title += " - " + week.title;
            auto weekItem = tree->AddItem(title, true);
            weekItem.SetType(TreeViewItem::Type::Category);
            weekItem.SetData(ROW_NONE);
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
                rows.push_back(RowRef{ w, problem, idx });
                node.SetData(static_cast<uint64>(rows.size() - 1));
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
    }

    const Learning::CatalogueItem* SelectedItem(std::string* weekName = nullptr)
    {
        auto cur = tree->GetCurrentItem();
        if (!cur.IsValid())
            return nullptr;
        const uint64 idx = cur.GetData(ROW_NONE);
        if (idx == ROW_NONE || idx >= rows.size())
            return nullptr;
        const auto& r   = rows[idx];
        const auto& cat = Session().GetCatalogue();
        if (r.week >= cat.weeks.size())
            return nullptr;
        const auto& week = cat.weeks[r.week];
        const auto& list = r.problem ? week.problems : week.resources;
        if (r.index >= list.size())
            return nullptr;
        if (weekName)
            *weekName = week.name;
        return &list[r.index];
    }

    void StartConnect()
    {
        std::string cs;
        if (!connectionField->GetText().ToString(cs) || cs.empty())
        {
            Dialogs::MessageBox::ShowError("Learning and Evaluation Mode", "Please paste the connection string provided by your teacher.");
            return;
        }
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
        if (Dialogs::MessageBox::ShowOkCancel("End session", "End the learning session? Restrictions will be removed and secrets erased.") !=
            Dialogs::Result::Ok)
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
            auto cur = tree->GetCurrentItem();
            if (cur.IsValid())
            {
                for (const auto& w : Session().GetCatalogue().weeks)
                {
                    std::string title = w.name;
                    if (!w.title.empty())
                        title += " - " + w.title;
                    std::string shown;
                    cur.GetText().ToString(shown);
                    if (shown == title)
                    {
                        TextDialog dlg(w.name, w.description.empty() ? std::string_view("(no description)") : std::string_view(w.description));
                        dlg.Show();
                        return;
                    }
                }
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

        Learning::ItemBinding binding;
        binding.item    = item.name;
        binding.problem = item.IsProblem();
        binding.mode    = content.mode;
        binding.version = content.itemVersion;

        const std::string fileName = content.fileName.empty() ? Learning::SanitizeFileName(item.name) : content.fileName;
        const std::u8string_view u8name(reinterpret_cast<const char8_t*>(fileName.data()), fileName.size());

        if (content.mode == Learning::DeliveryMode::Memory)
        {
            // memory mode: no file is created; the viewer reads from locked memory that is wiped on close
            auto dataObject = std::make_unique<Learning::LockedMemoryDataObject>(std::move(content.data));
            session.SetPendingBinding(binding);
            const bool ok = GView::App::OpenDataObject(
                  std::move(dataObject), u8name, u8name, GView::App::OpenMethod::BestMatch, "", nullptr, "Learning mode task");
            session.ClearPendingBinding();
            if (!ok)
            {
                Dialogs::MessageBox::ShowError("Open", "GView could not open the delivered content.");
                return false;
            }
        }
        else
        {
            const auto folder = Learning::DefaultDownloadFolder(session.GetSettings().downloadFolder, weekName);
            std::error_code ec;
            std::filesystem::create_directories(folder, ec);
            auto chosen = Dialogs::FileDialog::ShowSaveFileWindow(u8name, "", folder);
            if (!chosen.has_value())
                return false; // the LockedBuffer is wiped when result goes out of scope
            std::filesystem::path written;
            // the file on disk is verified against the SHA-256 of the (already verified) delivered bytes
            auto st = Learning::WriteFileAtomic(chosen->parent_path(), Learning::PathToUtf8(chosen->filename()), content.data.View(), content.sha256, written);
            if (!st.ok)
            {
                Dialogs::MessageBox::ShowError("Save failed", st.message);
                return false;
            }
            content.data.Wipe();
            session.SetPendingBinding(binding);
            GView::App::OpenFile(written, GView::App::OpenMethod::BestMatch, "", nullptr, "Learning mode task");
            session.ClearPendingBinding();
        }
        session.RecordItemOpened(item, content.mode, content.itemVersion);
        return true;
    }
};
} // namespace

void GView::App::ShowLearningModeWindow(std::string_view prefilledConnectionString, bool autoConnect)
{
    LearningModeWindow dlg(prefilledConnectionString, autoConnect);
    dlg.Show();
}

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
