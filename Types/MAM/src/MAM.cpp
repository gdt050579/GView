#include "MAM.hpp"

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
        return new MAM::MAMFile();
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MAM::MAMFile> mam)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, 4, ColorPair{ Color::Pink, Color::DarkBlue }, "Signature");
        settings.AddZone(4, 4, ColorPair{ Color::Magenta, Color::DarkBlue }, "Size Uncompressed");
        settings.AddZone(8, win->GetObject()->GetData().GetSize() - 8, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Content");

        mam->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto mam = win->GetObject()->GetContentType<MAM::MAMFile>();
        mam->Update();

        // add views
        CreateBufferView(win, mam);

        // add panels
        win->AddPanel(Pointer<TabPage>(new MAM::Panels::Information(win->GetObject(), mam)), true);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]            = "magic:4D 41 4D 04";
        sect["Extension"]          = "pf";
        sect["Priority"]           = 1;
        sect["Description"]        = "PF file format (*.pf)";

        LocalString<128> buffer;
        for (const auto& command : MAM::MAM_COMMANDS) {
            buffer.SetFormat("Command.%s", command.Caption);
            sect[buffer.GetText()] = command.Key;
        }
    }
}
