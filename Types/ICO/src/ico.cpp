#include "ico.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        if (buf.GetLength() < sizeof(ICO::Header) + sizeof(ICO::IconDirectoryEntry))
            return false;
        auto ic = buf.GetObject<ICO::Header>();
        if ((ic->magic != ICO::MAGIC_FORMAT_ICO) && (ic->magic != ICO::MAGIC_FORMAT_CUR))
            return false;
        if (ic->count == 0)
            return false; // at least one component needs to be present
        // all good
        return true;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new ICO::ICOFile(file);
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto ico = win->GetObject()->type->To<ICO::ICOFile>();
        ico->Update();

        auto b = win->AddBufferViewer("Buffer View");
        ico->UpdateBufferViewZones(b);

        // add panels
        win->AddPanel(Pointer<TabPage>(new ICO::Panels::Information(ico)), true);
        win->AddPanel(Pointer<TabPage>(new ICO::Panels::Directories(ico, win)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"] = {
            "hex:'00 00 01 00'",
            "hex:'00 00 02 00'",
        };
        sect["Priority"] = 1;
    }
}

int main()
{
    return 0;
}
