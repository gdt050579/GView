#include "json.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

GVIEW_PLUGIN_ENTRY_POINTS
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        // all good
        return true;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new JSON::JSONFile();
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto json = win->GetObject()->GetContentType<JSON::JSONFile>();

        LexicalViewer::Settings settings;
        settings.SetParser(json.ToObjectRef<LexicalViewer::ParseInterface>());
        settings.AddPlugin(&json->upper_case_plugin);

        win->CreateViewer(settings);

        win->CreateViewer<TextViewer::Settings>("Text View");

        GView::View::BufferViewer::Settings s{};
        json->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(s);

        // add panels
        win->AddPanel(Pointer<TabPage>(new JSON::Panels::Information(json)), true);

        return true;
    }
    PLUGIN_EXPORT void RegisterPlugin([[maybe_unused]] Reference<GView::PluginRegistry> registry)
    {
        // static metadata of the plugin: no HDF vocabulary yet (see docs/source/hdf.rst)
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = "json";
        sect["Priority"]    = 1;
        sect["Description"] = "JavaScript Object Notation file format (*.json)";
    }
}
