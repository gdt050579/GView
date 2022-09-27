#include "ini.hpp"

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
        return new INI::INIFile();
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto ini = win->GetObject()->GetContentType<INI::INIFile>();
        ini->Update();

        LexicalViewer::Settings settings;
        settings.SetParser(ini.ToObjectRef<LexicalViewer::ParseInterface>());
        settings.AddPlugin(&ini->plugins.removeComments);
        settings.AddPlugin(&ini->plugins.casing);
        settings.AddPlugin(&ini->plugins.valueToString);
        win->CreateViewer("Lexical", settings);

        win->CreateViewer<TextViewer::Settings>("Text View");
        win->CreateViewer<BufferViewer::Settings>("Buffer View");

        // add panels
        win->AddPanel(Pointer<TabPage>(new INI::Panels::Information(ini)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = { "ini", "toml" };
        sect["Priority"]    = 1;
        sect["Description"] = "Initialization file (*.ini, *.toml)";
    }
}

int main()
{
    return 0;
}
