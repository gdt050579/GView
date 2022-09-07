#include "cpp.hpp"

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
        return new CPP::CPPFile();
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto cpp = win->GetObject()->GetContentType<CPP::CPPFile>();
        cpp->Update();

        LexicalViewer::Settings settings;
        settings.SetParser(cpp.ToObjectRef<LexicalViewer::ParseInterface>());
        settings.AddPlugin(&cpp->plugins.removeComments);
        win->CreateViewer("Lexical", settings);

        win->CreateViewer<TextViewer::Settings>("Text View");
        win->CreateViewer<BufferViewer::Settings>("Buffer View");

        // add panels
        win->AddPanel(Pointer<TabPage>(new CPP::Panels::Information(cpp)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"] = { "cpp", "c", "h", "hpp" };
        sect["Priority"]  = 1;
    }
}

int main()
{
    return 0;
}
