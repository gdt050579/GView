#include "Internal.hpp"
#include "../Update/UpdateService.hpp"

#include <chrono>
#include <cstdio>

using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

namespace GView::Update
{
namespace
{
    constexpr int BUTTON_INSTALL = 1;
    constexpr int BUTTON_REMIND  = 2;
    constexpr int BUTTON_SKIP    = 3;
    constexpr int BUTTON_COPY    = 4;
    // an unsolicited prompt appears while the user may be typing in a viewer: ignore the buttons for a moment so that a
    // keystroke meant for the viewer cannot answer it (same idea as the "security delay" of browser permission prompts)
    constexpr auto INPUT_GUARD = std::chrono::milliseconds(1000);

    std::u8string_view AsUtf8(std::string_view s)
    {
        return { reinterpret_cast<const char8_t*>(s.data()), s.size() };
    }

    std::string FormatSize(uint64 bytes)
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
        return buf;
    }

    class UpdateDialog : public Window
    {
        const ReleaseInfo& release;
        bool canInstall;
        DialogChoice choice{ DialogChoice::RemindLater };
        Reference<Button> install, remind, skip;
        bool guarded;
        std::chrono::steady_clock::time_point shownAt;

        void EnableButtons(bool enabled)
        {
            install->SetEnabled(enabled && canInstall);
            remind->SetEnabled(enabled);
            skip->SetEnabled(enabled);
        }

      public:
        UpdateDialog(const ReleaseInfo& r, bool installAllowed, bool unsolicited)
            : Window("Update available", "d:c,w:96,h:26", WindowFlags::Sizeable), release(r), canInstall(installAllowed), guarded(unsolicited),
              shownAt(std::chrono::steady_clock::now())
        {
            Factory::Label::Create(this, "A new version of GView is available.", "l:1,t:1,r:1");

            std::string details = "Installed: " GVIEW_VERSION "    Available: " + release.version.ToString();
            details += release.prerelease ? " (pre-release" : " (";
            if (!release.publishedAt.empty())
                details += (release.prerelease ? ", published " : "published ") + release.publishedAt;
            details += (release.prerelease || !release.publishedAt.empty()) ? ", " : "";
            details += FormatSize(release.assetSize) + ")";
            Factory::Label::Create(this, details, "l:1,t:2,r:1");

            if (!canInstall)
                Factory::Label::Create(
                      this,
                      "GView cannot write to its installation folder: download the new version manually (use 'Copy link').",
                      "l:1,t:3,r:1");

            const std::string_view notes = release.notes.empty() ? std::string_view("No release notes were published.") : release.notes;
            Factory::TextArea::Create(this, AsUtf8(notes), "l:1,t:5,r:1,b:3", TextAreaFlags::Readonly | TextAreaFlags::ScrollBars | TextAreaFlags::Border);

            install = Factory::Button::Create(this, "&Install update", "l:1,b:0,w:19", BUTTON_INSTALL);
            remind  = Factory::Button::Create(this, "&Remind me later", "l:22,b:0,w:20", BUTTON_REMIND);
            skip    = Factory::Button::Create(this, "&Skip this version", "l:44,b:0,w:22", BUTTON_SKIP);
            auto copy = Factory::Button::Create(this, "Copy &link", "r:1,b:0,w:14", BUTTON_COPY, ButtonFlags::Flat);
            copy->SetEnabled(!GView::Security::RestrictedMode::IsFeatureDisabled(GView::Security::RestrictedMode::Feature::Clipboard));
            EnableButtons(!guarded);
            // the safe choice has the focus: Enter never installs by accident
            if (!guarded)
                remind->SetFocus();
        }

        bool OnFrameUpdate() override
        {
            if (!guarded || std::chrono::steady_clock::now() - shownAt < INPUT_GUARD)
                return false;
            guarded = false;
            EnableButtons(true);
            remind->SetFocus();
            return true;
        }

        DialogChoice Choice() const
        {
            return choice;
        }

        bool OnEvent(Reference<Control> c, Event eventType, int id) override
        {
            if (eventType == Event::ButtonClicked) {
                switch (id) {
                case BUTTON_INSTALL:
                    if (!canInstall)
                        return true;
                    choice = DialogChoice::Install;
                    Exit(Dialogs::Result::Ok);
                    return true;
                case BUTTON_REMIND:
                    choice = DialogChoice::RemindLater;
                    Exit(Dialogs::Result::Cancel);
                    return true;
                case BUTTON_SKIP:
                    choice = DialogChoice::Skip;
                    Exit(Dialogs::Result::No);
                    return true;
                case BUTTON_COPY: {
                    const auto& url = release.htmlUrl.empty() ? release.assetUrl : release.htmlUrl;
                    if (GView::App::SetClipboardText(url, false))
                        Dialogs::MessageBox::ShowNotification("Link", "The link to the release was copied to the clipboard.");
                    return true;
                }
                }
            }
            if (eventType == Event::WindowAccept)
                return true; // Enter outside a button: no implicit choice
            if (eventType == Event::WindowClose) {
                choice = DialogChoice::RemindLater;
                Exit(Dialogs::Result::Cancel);
                return true;
            }
            return Window::OnEvent(c, eventType, id);
        }
    };
} // namespace

DialogChoice ShowUpdateDialog(const ReleaseInfo& release, bool canInstall, bool unsolicited)
{
    UpdateDialog dlg(release, canInstall, unsolicited);
    dlg.Show();
    return dlg.Choice();
}
} // namespace GView::Update
