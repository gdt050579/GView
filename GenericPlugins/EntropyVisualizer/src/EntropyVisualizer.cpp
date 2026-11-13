#include "EntropyVisualizer.hpp"

using namespace GView::GenericPlugins::EntropyVisualizer;

GVIEW_PLUGIN_ENTRY_POINTS {
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
    // was F12 (an older GView.ini keeps it: Instance::Init (MoveRetiredPluginKeys) moves it to the new default)
    sect["Command.EntropyVisualizer"] = Input::Key::Alt | Input::Key::F12;
}
}
