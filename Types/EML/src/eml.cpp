#include "eml.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<EML::EMLFile> eml)
{
    ContainerViewer::Settings settings;

    //settings.SetIcon(ISO_ICON);
    settings.SetColumns({
          "n:&Identifier,a:l,w:30",
          "n:&Content-Type,a:c,w:40",
          "n:&Size,a:c,w:15",
          "n:&OffsetInFile,a:c,w:15",
    });

    settings.SetEnumerateCallback(win->GetObject()->GetContentType<EML::EMLFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(win->GetObject()->GetContentType<EML::EMLFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

    win->CreateViewer(settings);
}

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        // no validation atm
        return true;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new EML::EMLFile();
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto eml = win->GetObject()->GetContentType<EML::EMLFile>();

        CreateContainerView(win, eml);
        win->AddPanel(Pointer<TabPage>(new EML::Panels::Information(eml)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = { "eml" };
        sect["Priority"]    = 1;
        sect["Description"] = "Electronic Mail Format (*.eml)";
    }
}

int main()
{
    return 0;
}
