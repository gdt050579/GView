#include "prefetch.hpp"

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
        CHECK(buf.GetLength() > sizeof(uint32), false, "");
        const auto sig = *(uint32*) buf.GetData();

        CHECK(sig == static_cast<uint32>(Prefetch::Magic::WIN_XP_2003) || sig == static_cast<uint32>(Prefetch::Magic::WIN_VISTA_7) ||
                    sig == static_cast<uint32>(Prefetch::Magic::WIN_8) || sig == static_cast<uint32>(Prefetch::Magic::WIN_10) ||
                    sig == static_cast<uint32>(Prefetch::Magic::WIN_10_MAM),
              false,
              "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new Prefetch::PrefetchFile();
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<Prefetch::PrefetchFile> prefetch)
    {
        BufferViewer::Settings settings;

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto iso = win->GetObject()->GetContentType<Prefetch::PrefetchFile>();
        iso->Update();

        // add views
        CreateBufferView(win, iso);

        // add panels
        win->AddPanel(Pointer<TabPage>(new Prefetch::Panels::Information(win->GetObject(), iso)), true);
        win->AddPanel(Pointer<TabPage>(new Prefetch::Panels::Objects(iso, win)), false);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const std::initializer_list<std::string> patterns = {
            "hex:'" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_XP_2003, sizeof(Prefetch::Magic::WIN_XP_2003)) + "'",
            "hex:'" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_VISTA_7, sizeof(Prefetch::Magic::WIN_VISTA_7)) + "'",
            "hex:'" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_8, sizeof(Prefetch::Magic::WIN_8)) + "'",
            "hex:'" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_10, sizeof(Prefetch::Magic::WIN_10)) + "'",
            "hex:'" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_10, sizeof(Prefetch::Magic::WIN_10)) + "'",
        };

        sect["Pattern"]   = patterns;
        sect["Extension"] = "pf";
        sect["Priority"]  = 1;
    }
}
