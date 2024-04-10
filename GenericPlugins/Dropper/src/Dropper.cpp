#include "Dropper.hpp"

#include <array>
#include <regex>
#include <charconv>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

namespace GView::GenericPlugins::Droppper
{
extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "Dropper") {
        auto instance = Instance();
        if (!instance.Process(object)) {
            Dialogs::MessageBox::ShowError("Dropper", "Failed extracting objects!");
        }
        Dialogs::MessageBox::ShowNotification("Dropper", "Objects extracted.");
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["command.Dropper"] = Input::Key::F10;
}
}
} // namespace GView::GenericPlugins::Droppper
