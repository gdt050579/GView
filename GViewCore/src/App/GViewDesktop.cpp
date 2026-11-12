#include "Internal.hpp"
#include "../Update/UpdateService.hpp"

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
        // no window opened: the command bar is the desktop's. In Learning and Evaluation Mode the Course key opens the window
        // of the course server (connection, catalogue) - the same window as Options -> Learning and Evaluation Mode
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override
        {
            // a desktop child without its own commands (e.g. a remote window) sends the update here too
            if (GetChildrenCount() == 0 && IsLearningModeActive())
                commandBar.SetCommand(InstanceCommands::INSTANCE_LEARNING_COURSE.Key, "SeeServerWindow", MenuCommands::OPEN_RESTRICTED_MODE);
            return true;
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
