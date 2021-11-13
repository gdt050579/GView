#include "csv.hpp"

using namespace AppCUI;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const GView::Utils::Buffer& buf, const std::string_view& extension)
    {
        CHECK(extension == ".tsv" || extension == ".csv", false, "Wrong extension: [%.*s]!", extension.length(), extension.data());
        if (extension == ".tsv")
        {
            for (auto i = 0U; i < buf.length; i++)
            {
                if (buf[i] == '\t')
                {
                    return true;
                }
            }
        }
        else if (extension == ".csv")
        {
            for (auto i = 0U; i < buf.length; i++)
            {
                if (buf[i] == ',')
                {
                    return true;
                }
            }
        }

        return false;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new CSV::CSVFile(file);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto csv = reinterpret_cast<CSV::CSVFile*>(win->GetObject()->type);
        csv->Update();

        // auto b = win->AddBufferView("Buffer View");
       // csv->UpdateBufferViewZones(b);

        if (csv->HasPanel(CSV::Panels::IDs::Information))
            win->AddPanel(Pointer<TabPage>(new CSV::Panels::Information(csv)), true);

        return true;
    }
}

int main()
{
    return 0;
}
