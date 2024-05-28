#include "csv.hpp"

using namespace AppCUI;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::Buffer& buf, const std::string_view& extension)
    {
        CHECK(extension == ".tsv" || extension == ".csv", false, "Wrong extension: [%.*s]!", extension.length(), extension.data());
        if (extension == ".tsv")
        {
            for (auto i = 0U; i < buf.GetLength(); i++)
            {
                if (buf[i] == '\t')
                {
                    return true;
                }
            }
        }
        else if (extension == ".csv")
        {
            for (auto i = 0U; i < buf.GetLength(); i++)
            {
                if (buf[i] == ',')
                {
                    return true;
                }
            }
        }

        return false;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new CSV::CSVFile();
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto csv = win->GetObject()->GetContentType<CSV::CSVFile>();
        csv->Update(win->GetObject());

        GView::View::GridViewer::Settings gridSettings;
        csv->UpdateGrid(gridSettings);
        win->CreateViewer(gridSettings);

        GView::View::BufferViewer::Settings bufferSettings;
        csv->UpdateBufferViewZones(bufferSettings);
        csv->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(bufferSettings);

        // panels
        if (csv->HasPanel(CSV::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new CSV::Panels::Information(csv)), true);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = { "csv", "tsv" };
        sect["Priority"]    = 1;
        sect["Description"] = "Comma or Tab separated values (*.csv, *.tsv)";
    }
}

int main()
{
    return 0;
}
