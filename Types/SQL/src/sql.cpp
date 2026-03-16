#include "sql.hpp"

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
        return new SQL::SQLFile();
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto sql = win->GetObject()->GetContentType<SQL::SQLFile>();
        sql->Update();

        LexicalViewer::Settings settings;
        settings.SetParser(sql.ToObjectRef<LexicalViewer::ParseInterface>());
        settings.AddPlugin(&sql->plugins.removeComments);
        win->CreateViewer(settings);

        win->CreateViewer<TextViewer::Settings>();

        View::BufferViewer::Settings s{};
        sql->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(s);

        // add panels
        win->AddPanel(Pointer<TabPage>(new SQL::Panels::Information(sql)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = { "sql" };
        sect["Priority"]    = 1;
        sect["Description"] = "SQL language file (*.sql)";
    }
}

int main()
{
    return 0;
}