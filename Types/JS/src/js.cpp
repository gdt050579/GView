#include "js.hpp"

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
        return new JS::JSFile();
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto js = win->GetObject()->GetContentType<JS::JSFile>();
        js->Update();

        LexicalViewer::Settings settings;
        settings.SetParser(js.ToObjectRef<LexicalViewer::ParseInterface>());

        settings.SetMaxTokenSize({ 30u, 5u });

        settings.AddPlugin(&js->plugins.simplify);
        settings.AddPlugin(&js->plugins.foldConstants);
        settings.AddPlugin(&js->plugins.constPropagation);
        settings.AddPlugin(&js->plugins.removeDeadCode);
        settings.AddPlugin(&js->plugins.removeDummyCode);
        settings.AddPlugin(&js->plugins.contextAwareRename);
        settings.AddPlugin(&js->plugins.emulate);
        settings.AddPlugin(&js->plugins.inlineFunctions);
        settings.AddPlugin(&js->plugins.hoistFunctions);
        settings.AddPlugin(&js->plugins.removeComments);
        settings.AddPlugin(&js->plugins.markAlwaysTrue);
        settings.AddPlugin(&js->plugins.unrollLoop);
        settings.AddPlugin(&js->plugins.dumpAST);
        settings.AddPlugin(&js->plugins.addStrings);
        settings.AddPlugin(&js->plugins.reverseStrings);
        settings.AddPlugin(&js->plugins.replaceConstants);

        win->CreateViewer(settings);

        win->CreateViewer<TextViewer::Settings>("Text View");
        win->CreateViewer<BufferViewer::Settings>("Buffer View");

        // add panels
        win->AddPanel(Pointer<TabPage>(new JS::Panels::Information(js)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = "js";
        sect["Priority"]    = 1;
        sect["Description"] = "JavaScript / ECMAScript language file (*.js)";
    }
}

int main()
{
    return 0;
}
