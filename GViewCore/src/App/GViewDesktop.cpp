#include "Internal.hpp"
#include "../Update/UpdateService.hpp"

#undef MessageBox // Windows header conflict with AppCUI

namespace GView::App
{
namespace
{
    // The desktop is the root of the control tree: AppCUI calls its OnFrameUpdate before walking (and caching) the
    // children, so opening a modal window (or a file window) from here is safe. HasFocus() is false while any modal
    // window is on top.
    class GViewDesktop : public AppCUI::Controls::Desktop
    {
      public:
        bool OnFrameUpdate() override
        {
            bool repaint = GView::Update::Service::OnFrame(HasFocus());
            // the learning session's timers and completions (note autosave, retries) also while no learning window is open
            repaint |= GView::Security::Learning::Hooks::OnDesktopFrame();
#ifdef BUILD_FOR_WASM
            repaint |= GView::App::Browser::OnFrame(HasFocus());
#endif
            // AppCUI rebuilds the command bar on a focus change or a command, not when the last window is deleted or a course session
            // starts / ends: without this the bar keeps the commands of the closed window (and no SeeServerWindow)
            const DesktopBarState state{ GetChildrenCount() == 0, IsLearningModeActive() };
            if (state != barState) {
                barState = state;
                if (state.empty && HasFocus())
                    SetFocus(); // the desktop has no parent: only asks for the command bar update and a repaint
                repaint = true;
            }
            return repaint;
        }
        // no window opened: the command bar is the desktop's. The Course key opens the window of the course server (connection,
        // catalogue) - the same window as Course -> Problem list - also before connecting: that window connects with the saved
        // connection string (after GView was closed or the page reloaded) or asks for one
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override
        {
#ifdef GVIEW_HAS_LEARNING_NETWORK
            // a desktop child without its own commands (e.g. a remote window) sends the update here too
            if (GetChildrenCount() == 0)
                commandBar.SetCommand(
                      InstanceCommands::INSTANCE_LEARNING_COURSE.Key,
                      IsLearningModeActive() ? "SeeServerWindow" : "LearningMode",
                      MenuCommands::OPEN_RESTRICTED_MODE);
#endif
            return true;
        }

        // AppCUI closes GView when an Escape reaches the desktop. In Learning and Evaluation Mode that ends the course session,
        // and in a web page GView only comes back by reloading the page: one Escape too many asks first (a second Escape
        // answers Cancel). File -> Exit (Shift+Esc) still closes without asking.
        bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 unicodeChar) override
        {
            if (keyCode == AppCUI::Input::Key::Escape)
            {
                const bool learning = IsLearningModeActive();
#ifdef BUILD_FOR_WASM
                const bool ask = true;
#else
                const bool ask = learning;
#endif
                if (ask)
                {
                    std::string question;
                    if (learning)
                    {
                        question = "Close GView? This ends your course session.\nTo see the problem list, ";
                        AppCUI::Utils::LocalString<32> key; // the Course key is configurable, and may be unassigned
                        const auto courseKey = InstanceCommands::INSTANCE_LEARNING_COURSE.Key;
                        if (courseKey != AppCUI::Input::Key::None && AppCUI::Utils::KeyUtils::ToString(courseKey, key) && key.Len() > 0)
                        {
                            question += "press ";
                            question.append(key.GetText(), key.Len());
                            question += " instead.";
                        }
                        else
                            question += "use Course -> Problem list.";
                    }
                    else
                        question = "Close GView? In the browser, it starts again only when the page is reloaded.";
                    if (AppCUI::Dialogs::MessageBox::ShowOkCancel("Close GView", question) == AppCUI::Dialogs::Result::Ok)
                        AppCUI::Application::Close();
                    return true;
                }
            }
            return Desktop::OnKeyEvent(keyCode, unicodeChar);
        }

      private:
        struct DesktopBarState {
            bool empty                                    = false; // no window opened
            bool learning                                 = false; // a course session or the restrictions of a course policy
            bool operator==(const DesktopBarState&) const = default;
        };
        DesktopBarState barState;

        static bool IsLearningModeActive()
        {
#ifdef GVIEW_HAS_LEARNING_NETWORK
            return GView::Security::Learning::Hooks::IsSessionActive() || GView::Security::RestrictedMode::IsActive();
#else
            return false;
#endif
        }
    };
} // namespace

AppCUI::Controls::Desktop* CreateDesktop()
{
    return new GViewDesktop();
}
} // namespace GView::App
