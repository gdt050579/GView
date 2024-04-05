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
        CHECK(instance.Init(), false, "");
        CHECK(instance.Process(), false, "");
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["command.Dropper"] = Input::Key::Alt | Input::Key::F10;
}
}
} // namespace GView::GenericPlugins::Droppper
