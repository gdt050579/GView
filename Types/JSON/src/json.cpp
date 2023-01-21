#include "json.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

extern "C"
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

        win->CreateViewer("Lexical", settings);

        win->CreateViewer<TextViewer::Settings>("Text View");

        GView::View::BufferViewer::Settings s{};
        json->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation("Buffer View", s);

        // add panels
        win->AddPanel(Pointer<TabPage>(new JSON::Panels::Information(json)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = "json";
        sect["Priority"]    = 1;
        sect["Description"] = "JavaScript Object Notation file format (*.json)";
    }
}

int main()
{
    return 0;
}
