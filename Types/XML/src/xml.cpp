#include "xml.hpp"

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
        return new XML::XMLFile();
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto xml = win->GetObject()->GetContentType<XML::XMLFile>();
        xml->Update();

        LexicalViewer::Settings settings;
        settings.SetParser(xml.ToObjectRef<LexicalViewer::ParseInterface>());
        settings.AddPlugin(&xml->plugins.extractContent);
        win->CreateViewer(settings);

        win->CreateViewer<TextViewer::Settings>();

        View::BufferViewer::Settings s{};
        xml->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(s);

        // add panels
        //win->AddPanel(Pointer<TabPage>(new CPP::Panels::Information(cpp)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = { "xml" };
        sect["Priority"]    = 1;
        sect["Pattern"]     = { "linestartswith:<?xml version=\""};
        sect["Description"] = "XML files (*.xml)";
    }
}