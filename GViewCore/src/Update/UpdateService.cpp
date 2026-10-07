#include "Internal.hpp"
#include "UpdateService.hpp"
#include "HttpClient.hpp"
#include "Installer.hpp"
#include "Stager.hpp"
#include "Learning/BackgroundWorker.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace GView::Update
{
namespace fs = std::filesystem;
using namespace AppCUI;
using namespace AppCUI::Graphics;

namespace
{
    struct FetchParams {
        std::string feedUrl;
        std::string etag; // empty = unconditional request
        std::string proxy;
        bool includePreReleases{ true };
        bool refetchWhenNotModified{ false }; // a 304 hides a release the user must still be told about
    };

    struct FetchOutcome {
        bool ok{ false };
        bool notModified{ false };
        bool cancelled{ false };
        std::optional<ReleaseInfo> release;
        std::string etag;
        std::string error;
    };

    struct State {
        bool enabled{ false };
        bool started{ false };
        bool busy{ false }; // a dialog / modal progress of the updater is on screen
        Security::Learning::BackgroundWorker worker;
        std::atomic<bool> cancel{ false };
        std::optional<ReleaseInfo> pending; // found by the background check, waiting for a quiet moment
    };

    // intentionally never destroyed: the worker is stopped explicitly by Shutdown() (no thread join during DLL unload)
    State& S()
    {
        static State* state = new State();
        return *state;
    }

    struct BusyGuard {
        bool previous;
        BusyGuard() : previous(S().busy)
        {
            S().busy = true;
        }
        ~BusyGuard()
        {
            S().busy = previous;
        }
    };

    uint64 Now()
    {
        const auto t = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        return t > 0 ? static_cast<uint64>(t) : 0;
    }

    bool UpdatesBlocked() noexcept
    {
        return Security::RestrictedMode::IsActive() || Security::Learning::Hooks::IsSessionActive();
    }

#ifdef DISSASM_DEV
    // development builds only: GVIEW_UPDATE_TEST_AUTOACCEPT=1 answers "Install update" and the confirmation automatically
    // so that the whole install / restart flow can be exercised end to end without a keyboard (docs/source/updates.rst)
    bool AutoAcceptForTests()
    {
#    ifdef _MSC_VER
        char* value = nullptr;
        size_t len  = 0;
        const bool on = _dupenv_s(&value, &len, "GVIEW_UPDATE_TEST_AUTOACCEPT") == 0 && value != nullptr && std::string_view(value) == "1";
        free(value);
        return on;
#    else
        const char* value = std::getenv("GVIEW_UPDATE_TEST_AUTOACCEPT");
        return value != nullptr && std::string_view(value) == "1";
#    endif
    }
#else
    constexpr bool AutoAcceptForTests()
    {
        return false;
    }
#endif

    fs::path GViewExecutable()
    {
        return AppCUI::OS::GetCurrentApplicationPath();
    }

    std::string FormatMB(uint64 bytes)
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
        return buf;
    }

    // ---------------------------------------------------------------- network (worker / helper thread)
    FetchOutcome Fetch(const FetchParams& params, const std::atomic<bool>* cancel)
    {
        FetchOutcome outcome;
        for (int attempt = 0; attempt < 2; attempt++) {
            const bool conditional = attempt == 0 && !params.etag.empty();
            HttpGetRequest req;
            req.url             = params.feedUrl;
            req.headers         = { "Accept: application/vnd.github+json", "X-GitHub-Api-Version: 2022-11-28" };
            req.maxBytes        = MAX_FEED_BYTES;
            req.followRedirects = true; // renamed repositories answer 301 (https only)
            req.proxy           = params.proxy;
            req.cancel          = cancel;
            if (conditional)
                req.headers.push_back("If-None-Match: " + params.etag);
            const auto resp = HttpGetToMemory(req);
            if (resp.cancelled) {
                outcome.cancelled = true;
                return outcome;
            }
            if (conditional && resp.transportOk && resp.status == 304) {
                if (params.refetchWhenNotModified)
                    continue; // the release details are needed: ask again without the ETag
                outcome.ok          = true;
                outcome.notModified = true;
                return outcome;
            }
            if (!resp.IsSuccess()) {
                outcome.error = resp.Describe();
                return outcome;
            }
            auto feed = ParseReleaseFeed(resp.body, params.includePreReleases, Platform::Current());
            if (!feed.ok) {
                outcome.error = feed.error;
                return outcome;
            }
            outcome.ok      = true;
            outcome.release = std::move(feed.release);
            if (IsSafeHeaderValue(resp.etag))
                outcome.etag = resp.etag;
            return outcome;
        }
        outcome.error = "unexpected answer from the update server";
        return outcome;
    }

    FetchParams ParamsFrom(const UpdateSettings& settings, bool conditional, uint64 now)
    {
        FetchParams p;
        p.feedUrl            = settings.feedUrl;
        p.proxy              = settings.proxy;
        p.includePreReleases = settings.includePreReleases;
        if (conditional) {
            p.etag          = settings.etag;
            const auto prev = Version::Parse(settings.cachedFeedVersion);
            p.refetchWhenNotModified = prev.has_value() && settings.ShouldNotify(*prev, CurrentVersion(), now);
        }
        return p;
    }

    // UI thread: records the result of a completed check (automatic or manual)
    void RecordCheck(UpdateSettings& settings, const FetchOutcome& outcome, uint64 now)
    {
        settings.lastCheck = now;
        if (outcome.ok && !outcome.notModified) {
            settings.etag              = outcome.etag;
            settings.cachedFeedVersion = outcome.release.has_value() ? outcome.release->version.ToString() : std::string();
        }
    }

    void SaveSettings(const UpdateSettings& settings)
    {
        auto ini = AppCUI::Application::GetAppSettings();
        if (ini == nullptr)
            return;
        settings.SaveState(ini);
        if (!AppCUI::Application::SaveAppSettings()) {
            LOG_WARNING("Unable to save the update state in GView.ini");
        }
    }

    void OnAutomaticCheckDone(const FetchOutcome& outcome)
    {
        if (outcome.cancelled)
            return;
        const auto now = Now();
        auto settings  = UpdateSettings::Load(AppCUI::Application::GetAppSettings());
        RecordCheck(settings, outcome, now);
        if (!outcome.ok) {
            LOG_WARNING("Automatic update check failed: %s", outcome.error.c_str());
        } else if (outcome.release.has_value() && settings.ShouldNotify(outcome.release->version, CurrentVersion(), now)) {
            S().pending = outcome.release;
        }
        SaveSettings(settings);
    }

    void StartAutomaticCheck()
    {
        if (UpdatesBlocked())
            return;
        const auto now      = Now();
        const auto settings = UpdateSettings::Load(AppCUI::Application::GetAppSettings());
        if (!settings.ShouldCheckNow(now))
            return;
        auto& s = S();
        s.worker.Start();
        const auto params = ParamsFrom(settings, true, now);
        s.worker.Post([params, cancel = &s.cancel]() -> Security::Learning::BackgroundWorker::Completion {
            auto outcome = Fetch(params, cancel);
            return [outcome = std::move(outcome)]() { OnAutomaticCheckDone(outcome); };
        });
    }

    // ---------------------------------------------------------------- download + hand over to the installer
    void InstallRelease(const ReleaseInfo& release)
    {
        if (UpdatesBlocked()) {
            Dialogs::MessageBox::ShowNotification("Update", "Finish the Learning and Evaluation Mode session before updating GView.");
            return;
        }
        const auto gviewExe   = GViewExecutable();
        const auto installDir = gviewExe.parent_path();
        const auto settings   = UpdateSettings::Load(AppCUI::Application::GetAppSettings());

        StageProgress progress;
        std::atomic<bool> cancel{ false };
        std::atomic<bool> finished{ false };
        StageResult result;
        std::thread worker([&]() {
            try {
                result = StageRelease(release, installDir, settings, progress, cancel);
            } catch (...) {
                result       = StageResult{};
                result.error = "unexpected error while preparing the update";
            }
            finished.store(true, std::memory_order_release);
        });

        const auto title = "Updating GView to " + release.version.ToString();
        ProgressStatus::Init(title, 1000, ProgressStatus::Flags::DisableDelayedActivation | ProgressStatus::Flags::AlwaysUpdate);
        std::string text;
        while (!finished.load(std::memory_order_acquire)) {
            const uint64 done  = progress.done.load(std::memory_order_relaxed);
            const uint64 total = std::max<uint64>(progress.total.load(std::memory_order_relaxed), 1);
            uint64 value       = 0;
            switch (progress.phase.load()) {
            case StagePhase::Preparing:
                text = "Preparing ...";
                break;
            case StagePhase::Downloading:
                text  = "Downloading " + FormatMB(done) + " of " + FormatMB(total);
                value = std::min<uint64>(done, total) * 800 / total;
                break;
            case StagePhase::Verifying:
                text  = "Verifying the download ...";
                value = 800;
                break;
            case StagePhase::Extracting:
            case StagePhase::Done:
                text  = "Extracting files ...";
                value = 850 + std::min<uint64>(done, total) * 150 / total;
                break;
            }
            if (!cancel.load() && ProgressStatus::Update(value, text))
                cancel.store(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        worker.join();

        if (!result.ok) {
            if (!result.cancelled && !cancel.load())
                Dialogs::MessageBox::ShowError("Update", "The update could not be prepared: " + result.error);
            return;
        }
        const auto question = "GView " + release.version.ToString() +
                              " is ready to be installed.\nGView will close, replace its files and restart with the same command line.\n\nContinue?";
        if (!AutoAcceptForTests() && Dialogs::MessageBox::ShowOkCancel("Install update", question) != Dialogs::Result::Ok) {
            std::error_code ec;
            fs::remove_all(result.stagingDir, ec);
            return;
        }
        Installer::SetPending({ release.version, installDir, result.stagingDir, gviewExe });
        AppCUI::Application::Close();
    }

    // shows the dialog and applies the user's choice
    void PresentRelease(const ReleaseInfo& release, bool manual)
    {
        BusyGuard busy;
        const auto now = Now();
        auto settings  = UpdateSettings::Load(AppCUI::Application::GetAppSettings());
        if (!manual) {
            // recorded before the dialog: closing it (or GView) counts as "remind me later"
            settings.OnNotified(release.version, now);
            SaveSettings(settings);
        }
        const bool canInstall = CanWriteInstallDir(GViewExecutable().parent_path());
        const auto choice = (AutoAcceptForTests() && canInstall) ? DialogChoice::Install : ShowUpdateDialog(release, canInstall, !manual);
        switch (choice) {
        case DialogChoice::Install:
            settings.OnNotified(release.version, now);
            SaveSettings(settings);
            InstallRelease(release);
            break;
        case DialogChoice::Skip:
            settings.OnSkip(release.version);
            SaveSettings(settings);
            break;
        case DialogChoice::RemindLater:
            settings.OnRemindLater(release.version, now);
            SaveSettings(settings);
            break;
        }
    }
} // namespace

namespace Service
{
    void Enable() noexcept
    {
        S().enabled = true;
    }

    bool OnFrame(bool desktopHasFocus)
    {
        auto& s = S();
        if (!s.enabled || s.busy)
            return false;
        if (!s.started) {
            // the first frame proves that this frontend delivers frame updates, i.e. completions will be applied
            s.started = true;
            StartAutomaticCheck();
        }
        bool repaint = s.worker.DrainCompletions() > 0;
        // only when no modal window (tutorial, dialogs, ...) is open and Learning mode is not active
        if (s.pending.has_value() && desktopHasFocus && !UpdatesBlocked()) {
            const auto release = std::move(*s.pending);
            s.pending.reset();
            PresentRelease(release, false);
            repaint = true;
        }
        return repaint;
    }

    void CheckInteractive()
    {
        auto& s = S();
        if (!s.enabled || s.busy)
            return;
        if (UpdatesBlocked()) {
            Dialogs::MessageBox::ShowNotification("Check for updates", "Updates are not available during a Learning and Evaluation Mode session.");
            return;
        }
        BusyGuard busy;
        const auto now = Now();
        auto settings  = UpdateSettings::Load(AppCUI::Application::GetAppSettings());
        const auto params = ParamsFrom(settings, false, now);

        FetchOutcome outcome;
        std::atomic<bool> cancel{ false };
        std::atomic<bool> finished{ false };
        std::thread worker([&]() {
            try {
                outcome = Fetch(params, &cancel);
            } catch (...) {
                outcome       = FetchOutcome{};
                outcome.error = "unexpected error";
            }
            finished.store(true, std::memory_order_release);
        });
        ProgressStatus::Init("Check for updates");
        while (!finished.load(std::memory_order_acquire)) {
            if (!cancel.load() && ProgressStatus::Update(0, "Contacting the update server ..."))
                cancel.store(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        worker.join();
        if (outcome.cancelled || cancel.load())
            return;

        RecordCheck(settings, outcome, now);
        SaveSettings(settings);
        if (!outcome.ok) {
            Dialogs::MessageBox::ShowError("Check for updates", "Unable to check for updates: " + outcome.error);
            return;
        }
        if (!outcome.release.has_value() || !(outcome.release->version > CurrentVersion())) {
            Dialogs::MessageBox::ShowNotification("Check for updates", "You are running the latest version of GView (" GVIEW_VERSION ").");
            return;
        }
        PresentRelease(*outcome.release, true);
    }

    void Shutdown() noexcept
    {
        auto& s = S();
        s.enabled = false;
        s.cancel.store(true);
        s.worker.Stop();
        s.pending.reset();
    }
} // namespace Service
} // namespace GView::Update
