#include "iso.hpp"

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
        CHECK(buf.GetLength() >= ISO::SYSTEM_AREA_SIZE + sizeof(ISO::VolumeDescriptor), false, "");

        auto vdh = buf.GetObject<ISO::VolumeDescriptorHeader>(ISO::SYSTEM_AREA_SIZE);
        CHECK(ISO::identifiers.find(std::string_view{ vdh->identifier, sizeof(vdh->identifier) }) != ISO::identifiers.end(), false, "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new ISO::ISOFile(file);
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<ISO::ISOFile> bmp)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, ISO::SYSTEM_AREA_SIZE, ColorPair{ Color::Silver, Color::DarkBlue }, "SystemArea");
        settings.AddZone(
              ISO::SYSTEM_AREA_SIZE,
              sizeof(ISO::PrimaryVolumeDescriptor),
              ColorPair{ Color::Magenta, Color::DarkBlue },
              "PrimaryVolumeDescriptor");

        // settings.AddZone(
        //       ISO::SYSTEM_AREA_SIZE + sizeof(ISO::BootRecord),
        //       sizeof(ISO::PrimaryVolumeDescriptor),
        //       ColorPair{ Color::DarkGreen, Color::DarkBlue },
        //       "PrimaryVolumeDescriptor");
        //
        settings.AddBookmark(0, ISO::SYSTEM_AREA_SIZE);
        // settings.AddBookmark(1, ISO::SYSTEM_AREA_SIZE + sizeof(ISO::BootRecord));

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto iso = win->GetObject()->type->To<ISO::ISOFile>();
        iso->Update();

        // add views
        CreateBufferView(win, iso);

        // add panels
        win->AddPanel(Pointer<TabPage>(new ISO::Panels::Information(iso)), true);
        win->AddPanel(Pointer<TabPage>(new ISO::Panels::Objects(iso, win)), false);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]   = "hex:'00 00 00 00 00 00 00 00'";
        sect["Extension"] = "iso";
        sect["Priority"]  = 1;
    }
}
