#include "msi.hpp"

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
    // Check for OLE Signature: D0 CF 11 E0 A1 B1 1A E1
    if (buf.GetLength() < 8)
        return false;
    uint64 sig = *(uint64*) buf.GetData();
    if (sig != MSI::OLE_SIGNATURE)
        return false;

    // Optionally check extension for strict MSI handling,
    // though OLE signature covers MST/MSP/DOC/XLS too.
    // GView priority settings usually handle the disambiguation.
    return true;
}

PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new MSI::MSIFile();
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto msi = win->GetObject()->GetContentType<MSI::MSIFile>();

    if (!msi->Update()) {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Failed to parse MSI file structure.");
        return false;
    }

    // 1. Create Container View (Tree view of streams)
    ContainerViewer::Settings settings;
    settings.SetIcon(
          "16,16,00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"); // Placeholder
                                                                                                                                                     // icon
    settings.SetColumns({ "n:&Name,a:l,w:40", "n:&Type,a:l,w:10", "n:&Size,a:r,w:15" });

    settings.SetEnumerateCallback(msi.ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(msi.ToObjectRef<ContainerViewer::OpenItemInterface>());
    win->CreateViewer(settings);

    // 2. Add Information Panel
    win->AddPanel(Pointer<TabPage>(new MSI::Panels::Information(msi)), true);

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Pattern"]     = "magic:D0 CF 11 E0 A1 B1 1A E1";
    sect["Priority"]    = 1;
    sect["Description"] = "Windows Installer Database (*.msi)";
}
}

int main()
{
    return 0;
}