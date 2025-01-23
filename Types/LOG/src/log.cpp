#include "log.hpp"
#include <iostream>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

extern "C" {
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        // all good
        return true;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new GView::Type::LOG::LogFile();
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto log = win->GetObject()->GetContentType<GView::Type::LOG::LogFile>();

        LexicalViewer::Settings settings;
        settings.SetParser(log.ToObjectRef<LexicalViewer::ParseInterface>());

        win->CreateViewer(settings);

        win->CreateViewer<TextViewer::Settings>("Text View");

        GView::View::BufferViewer::Settings s{};
        log->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(s);

        win->AddPanel(Pointer<TabPage>(new GView::Type::LOG::Panels::Information(log)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = "log";
        sect["Priority"]    = 1;
        sect["Description"] = "LOG file format (*.log)";
    }
}

int main()
{
    return 0;
}
