#include "doc.hpp"
#include <string>
#include <locale>
#include <codecvt>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

                                 
constexpr string_view DOC_ICON = "1111111111111111" // 5
                                 "1wwwwwwwww111111"  // 6
                                 "1w11111111w11111"  // 7
                                 "1w111111111w1111"  // 8
                                 "1w1111111111w111"  // 9
                                 "1w11111111111w11"  // 9
                                 "1w111111111111w1"  // 9
                                 "1w1www1www1111w1"  // 9
                                 "1w111111111111w1"  // 10
                                 "1w1wwwww1wwww1w1"  // 11
                                 "1w111111111111w1"  // 12
                                 "1w1wwwwwwwww11w1"  // 12
                                 "1w111111111111w1"  // 13
                                 "1w111111111111w1"  // 14
                                 "1wwwwwwwwwwwwww1"  // 15
                                 "1111111111111111"; // 16

void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<DOC::DOCFile> doc)
{
    ContainerViewer::Settings settings;

    settings.SetIcon(DOC_ICON);
    settings.SetColumns({
          "n:&Index,a:r,w:50",
    });

    settings.SetEnumerateCallback(win->GetObject()->GetContentType<DOC::DOCFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(win->GetObject()->GetContentType<DOC::DOCFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

    win->CreateViewer(settings);
}

extern "C" {
PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    return true;
}
PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new DOC::DOCFile();
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto doc = win->GetObject()->GetContentType<DOC::DOCFile>();

    // TODO: check return value
    doc->ProcessData();

    CreateContainerView(win, doc);
    win->AddPanel(Pointer<TabPage>(new DOC::Panels::Information(doc)), true);

    return true;
}
PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Pattern"]     = "magic:D0 CF 11 E0 A1 B1 1A E1";

    // TODO: not quite right
    sect["Extension"]   = { "doc" };
    sect["Priority"]    = 1;
    sect["Description"] = "Document (*.doc)";
}
}

int main()
{
    return 0;
}
