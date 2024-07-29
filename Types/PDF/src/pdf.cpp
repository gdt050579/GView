#include "pdf.hpp"

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
        if (buf.GetLength() < sizeof(PDF::Header)) {
            return false;
        }
        auto header = buf.GetObject<PDF::Header>();
        if (std::memcmp(header->identifier, PDF::PDF_MAGIC, 5) != 0) {
            return false;
        }
        if (header->version_1 != '1' || header->point != '.' || (header->version_N < '0' || header->version_N > '7'))
        {
            return false;
        }
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new PDF::PDFFile;
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<PDF::PDFFile> pdf)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, sizeof(PDF::Header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");

        pdf->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto pdf = win->GetObject()->GetContentType<PDF::PDFFile>();
        pdf->Update();

        // viewers
        CreateBufferView(win, pdf);
        //win->CreateViewer<TextViewer::Settings>();

        win->AddPanel(Pointer<TabPage>(new PDF::Panels::Information(pdf)), true);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = { "pdf" };
        sect["Priority"]    = 1;
        sect["Pattern"]     = "magic:25 50 44 46 2D";
        sect["Description"] = "Portable Document Format (*.pdf)";
    }
 }

int main()
{
    return 0;
}
