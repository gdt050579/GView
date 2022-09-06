#include "vba.hpp"

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
        return new VBA::VBAFile();
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto vba = win->GetObject()->GetContentType<VBA::VBAFile>();
        // ini->Update();

        LexicalViewer::Settings settings;
        settings.SetParser(vba.ToObjectRef<LexicalViewer::ParseInterface>());

        win->CreateViewer("Lexical", settings);

        win->CreateViewer<TextViewer::Settings>("Text View");
        win->CreateViewer<BufferViewer::Settings>("Buffer View");

        // add panels
        win->AddPanel(Pointer<TabPage>(new VBA::Panels::Information(vba)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"] = { "vba", "vbs" };
        sect["Priority"]  = 1;
    }
}

int main()
{
    return 0;
}
