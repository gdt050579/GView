#include "LNK.hpp"

using namespace AppCUI;
using namespace AppCUI::OS;
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
        struct Sig
        {
            uint32 sig;
        };
        auto signature = buf.GetObject<Sig>(0);
        CHECK(signature.IsValid(), false, "");
        CHECK(signature->sig == MAM::SIGNATURE, false, "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new LNK::LNKFile();
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<LNK::LNKFile> lnk)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, 4, ColorPair{ Color::Pink, Color::DarkBlue }, "Signature");
        settings.AddZone(4, 4, ColorPair{ Color::Magenta, Color::DarkBlue }, "Size Uncompressed");
        settings.AddZone(8, win->GetObject()->GetData().GetSize() - 8, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Content");

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto lnk = win->GetObject()->GetContentType<LNK::LNKFile>();
        lnk->Update();

        // add views
        CreateBufferView(win, lnk);

        // add panels
        win->AddPanel(Pointer<TabPage>(new LNK::Panels::Information(win->GetObject(), lnk)), true);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]   = "hex:'4D 41 4D 04'";
        sect["Extension"] = "pf";
        sect["Priority"]  = 1;
    }
}
