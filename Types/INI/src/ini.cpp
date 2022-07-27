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
    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto ini = win->GetObject()->GetContentType<INI::INIFile>();
        ini->Update();

        win->CreateViewer<TextViewer::Settings>("TextView");
        win->CreateViewer<BufferViewer::Settings>("BufferView");

        // add panels
        win->AddPanel(Pointer<TabPage>(new INI::Panels::Information(ini)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]  = "BM";
        sect["Priority"] = 1;
    }
}

int main()
{
    return 0;
}
