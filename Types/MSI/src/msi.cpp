#include "msi.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

// 1 = Transparent/Background
// w = White/Foreground
constexpr std::string_view MSI_ICON = "1111111111111111"
                                      "1111111111111111"
                                      "wwwwwwwwwwwwwwww"
                                      "1111111111111111"
                                      "1111111111111111"
                                      "w1111w1wwwww1www"
                                      "ww11ww1w111111w1"
                                      "w1ww1w1www1111w1"
                                      "w1111w111www11w1"
                                      "w1111w11111w11w1"
                                      "w1111w1wwwww1www" 
                                      "1111111111111111"
                                      "1111111111111111"
                                      "wwwwwwwwwwwwwwww"
                                      "1111111111111111"
                                      "1111111111111111";

extern "C" {
PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    // 1. Basic Header Size Check
    if (buf.GetLength() < sizeof(MSI::OLEHeader))
        return false;

    // 2. Signature Check
    auto h = buf.GetObject<MSI::OLEHeader>(0);
    if (h->signature != MSI::OLE_SIGNATURE)
        return false;

    // 3. Strict Size Calculation
    // Calculate the minimum required size based on the header fields
    uint32 sectorSize = 1 << h->sectorShift;

    // Sanity check for sector size (usually 512 or 4096)
    if (sectorSize < 512 || sectorSize > 4096)
        return false;

    uint64 minFileSize = 512; // Header is always 512 bytes
    minFileSize += (uint64) h->numFatSectors * sectorSize;
    minFileSize += (uint64) h->numDirSectors * sectorSize; // Can be 0 in v3
    minFileSize += (uint64) h->numMiniFatSectors * sectorSize;
    // Note: We don't check DIFAT sectors count here to keep it simple,
    // but this is already a much stronger check.

    if (buf.GetLength() < minFileSize)
        return false;

    return true;
}

PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new MSI::MSIFile();
}

void CreateBufferView(Reference<WindowInterface> win, Reference<MSI::MSIFile> msi)
{
    BufferViewer::Settings settings;

    // Delegate zone creation to the class logic
    msi->UpdateBufferViewZones(settings);

    win->CreateViewer(settings);
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto msi = win->GetObject()->GetContentType<MSI::MSIFile>();

    if (!msi->Update()) {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Failed to parse MSI file structure.");
        return false;
    }

    // 1. Create Container View
    ContainerViewer::Settings settings;
    settings.SetIcon(MSI_ICON);
    settings.SetColumns(
          { "n:&Name,a:l,w:60", // Increased width for better name visibility
            "n:&Type,a:l,w:10",
            "n:&Size,a:r,w:15" });
    
    settings.SetEnumerateCallback(msi.ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(msi.ToObjectRef<ContainerViewer::OpenItemInterface>());
    win->CreateViewer(settings);

    // 2. Create Buffer View (NEW)
    CreateBufferView(win, msi);

    // 3. Add Information Panel
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
