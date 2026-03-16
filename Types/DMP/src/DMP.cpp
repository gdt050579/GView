#include "dmp.hpp"

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
        if (buf.GetLength() < 500)
            return false;
        auto dmpHeader = buf.GetObject<DMP::Header>();
        
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new DMP::DMPFile();
    }
    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<DMP::DMPFile> dmp)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, sizeof(DMP::Header), ColorPair{ Color::Black, Color::DarkBlue }, "Header");

        //settings.AddZone(sizeof(DMP::Header), sizeof(DMP::), ColorPair{ Color::Olive, Color::DarkBlue }, "Image entries");

        dmp->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);

    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto dmp = win->GetObject()->GetContentType<DMP::DMPFile>();
        dmp->Update();
        
      
        GView::View::DumpViewer::Settings settings;
        settings.SetLeftColumnName((String)"Thread");
        settings.SetRightColumnName((String) "Module");
        settings.AddLeftColumnInfo(dmp->GetThreadInfo());
        settings.AddRightColumnInfo(dmp->GetModuleInfo());
        settings.AddHighlightedInfoLeft(dmp->GetHighlightedInfoLeft());
        settings.AddHighlightedInfoRight(dmp->GetHighlightedInfoRight());
        //add viewer
        win->CreateViewer(settings);
        CreateBufferView(win, dmp);

        // add panels
        win->AddPanel(Pointer<TabPage>(new DMP::Panels::Information(dmp)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = {"dmp"};
        sect["Pattern"] = {"magic:4D 44 4D 50"};
        sect["Priority"]    = 1;
        sect["Description"] = "DMP files(.dmp)";
    }
}

int main()
{
    return 0;
}
