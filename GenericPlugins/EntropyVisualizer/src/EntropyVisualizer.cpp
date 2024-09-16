#include "EntropyVisualizer.hpp"

namespace GView::GenericPlugins::EntropyVisualizer
{
extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "EntropyVisualizer") {
        auto p = Plugin(object);
        p.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.EntropyVisualizer"] = Input::Key::F12;
}
}
} // namespace GView::GenericPlugins::EntropyVisualizer
