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

PLUGIN_EXPORT void RegisterPlugin([[maybe_unused]] Reference<GView::PluginRegistry> registry)
{
    // static metadata of the plugin: no HDF vocabulary yet (see docs/source/hdf.rst)
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.EntropyVisualizer"] = Input::Key::F12;
}
}
