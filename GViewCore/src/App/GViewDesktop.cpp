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
#ifdef BUILD_FOR_WASM
            repaint |= GView::App::Browser::OnFrame(HasFocus());
#endif
            return repaint;
        }
    };
} // namespace

AppCUI::Controls::Desktop* CreateDesktop()
{
    return new GViewDesktop();
}
} // namespace GView::App
