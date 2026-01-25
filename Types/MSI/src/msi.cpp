// msi.cpp
// GView plugin exports for MSI type (Validate, CreateInstance, PopulateWindow, UpdateSettings)

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
    // Small helper to create a buffer view (header + body zones) and assign selection interface
    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MSI::MSIFile> msi)
    {
        BufferViewer::Settings settings;
        // CFB header (first 512 bytes)
        settings.AddZone(0, 512, ColorPair{ Color::Magenta, Color::DarkBlue }, "CFB Header");

        msi->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        // quick size check
        if (buf.GetLength() < 512)
            return false;

        const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.GetData());

        // check CFB signature
        if (!MSI::CFBHelper::HasCFBSignature(data, buf.GetLength()))
            return false;

        // quick heuristic: presence of SummaryInformation or Property streams
        MSI::CFBHelper helper(data, buf.GetLength());
        std::string summary;
        summary.push_back(char(0x05));
        summary += "SummaryInformation";

        if (helper.ContainsNameASCII("Property") || helper.ContainsNameASCII(summary) || helper.ContainsNameUTF16("Property"))
            return true;

        // fallback: extension hint
        if (!extension.empty()) {
            std::string ext(extension);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".msi")
                return true;
        }

        return false;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new GView::Type::MSI::MSIFile();
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto msi = win->GetObject()->GetContentType<MSI::MSIFile>();
        // msi->Update();

        // add viewer
        CreateBufferView(win, msi);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"] = {
            "magic:D0 CF 11 E0 A1 B1 1A E1", // CFB signature
        };
        sect["Priority"]    = 1;
        sect["Description"] = "MSI Installer Package (*.msi) - Compound File Binary (CFB/OLE)";
    }
}

int main()
{
    return 0;
}
