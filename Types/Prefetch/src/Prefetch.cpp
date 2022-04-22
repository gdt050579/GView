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
        CHECK(buf.GetLength() > sizeof(Prefetch::Header), false, "");
        auto header = buf.GetObject<Prefetch::Header>(0);
        CHECK(header.IsValid(), false, "");

        CHECK(header->version == Prefetch::Magic::WIN_XP_2003 || header->version == Prefetch::Magic::WIN_VISTA_7 ||
                    header->version == Prefetch::Magic::WIN_8 || header->version == Prefetch::Magic::WIN_10 ||
                    header->version == Prefetch::Magic::WIN_10_MAM,
              false,
              "");
        CHECK(header->signature == Prefetch::SIGNATURE, false, "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new Prefetch::PrefetchFile();
    }

    void CreateBufferView_17(
          Reference<GView::View::WindowInterface> win, Reference<Prefetch::PrefetchFile> prefetch, BufferViewer::Settings& settings)
    {
        settings.AddZone(0, sizeof(Prefetch::Header), ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Header");
        settings.AddZone(
              sizeof(Prefetch::Header),
              sizeof(Prefetch::FileInformation_17),
              ColorPair{ Color::DarkRed, Color::DarkBlue },
              "FileInformation(17)");

        Prefetch::FileInformation_17 fileInformation{};
        if (win->GetObject()->GetData().Copy<Prefetch::FileInformation_17>(sizeof(Prefetch::Header), fileInformation))
        {
            settings.AddZone(
                  fileInformation.sectionA.offset,
                  fileInformation.sectionA.entries * sizeof(Prefetch::FileMetricsEntryRecord_17),
                  ColorPair{ Color::DarkGreen, Color::DarkBlue },
                  "Section A");

            settings.AddZone(
                  fileInformation.sectionB.offset,
                  fileInformation.sectionB.entries * sizeof(Prefetch::TraceChainEntry_17_23_26),
                  ColorPair{ Color::DarkRed, Color::DarkBlue },
                  "Section B");

            settings.AddZone(
                  fileInformation.sectionC.offset,
                  fileInformation.sectionC.length,
                  ColorPair{ Color::DarkGreen, Color::DarkBlue },
                  "Section C");

            settings.AddZone(
                  fileInformation.sectionD.offset,
                  fileInformation.sectionD.size,
                  ColorPair{ Color::DarkRed, Color::DarkBlue },
                  "Section D");
        }
    }

    void CreateBufferView_23(
          Reference<GView::View::WindowInterface> win, Reference<Prefetch::PrefetchFile> prefetch, BufferViewer::Settings& settings)
    {
        settings.AddZone(0, sizeof(Prefetch::Header), ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Header");
        settings.AddZone(
              sizeof(Prefetch::Header),
              sizeof(Prefetch::FileInformation_23),
              ColorPair{ Color::DarkRed, Color::DarkBlue },
              "FileInformation(17)");

        Prefetch::FileInformation_23 fileInformation{};
        if (win->GetObject()->GetData().Copy<Prefetch::FileInformation_23>(sizeof(Prefetch::Header), fileInformation))
        {
            settings.AddZone(
                  fileInformation.sectionA.offset,
                  fileInformation.sectionA.entries * sizeof(Prefetch::FileMetricsEntryRecord_23),
                  ColorPair{ Color::DarkGreen, Color::DarkBlue },
                  "Section A");

            settings.AddZone(
                  fileInformation.sectionB.offset,
                  fileInformation.sectionB.entries * sizeof(Prefetch::TraceChainEntry_17_23_26),
                  ColorPair{ Color::DarkRed, Color::DarkBlue },
                  "Section B");

            settings.AddZone(
                  fileInformation.sectionC.offset,
                  fileInformation.sectionC.length,
                  ColorPair{ Color::DarkGreen, Color::DarkBlue },
                  "Section C");

            settings.AddZone(
                  fileInformation.sectionD.offset,
                  fileInformation.sectionD.size,
                  ColorPair{ Color::DarkRed, Color::DarkBlue },
                  "Section D");
        }
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<Prefetch::PrefetchFile> prefetch)
    {
        BufferViewer::Settings settings;

        switch (prefetch->header.version)
        {
        case Prefetch::Magic::WIN_XP_2003:
            CreateBufferView_17(win, prefetch, settings);
            break;
        case Prefetch::Magic::WIN_VISTA_7:
            CreateBufferView_23(win, prefetch, settings);
            break;
        case Prefetch::Magic::WIN_8:
        case Prefetch::Magic::WIN_10:
        default:
            break;
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto prefetch = win->GetObject()->GetContentType<Prefetch::PrefetchFile>();
        prefetch->Update();

        // add views
        CreateBufferView(win, prefetch);

        // add panels
        win->AddPanel(Pointer<TabPage>(new Prefetch::Panels::Information(win->GetObject(), prefetch)), true);
        win->AddPanel(Pointer<TabPage>(new Prefetch::Panels::FileInformationEntry(prefetch, win)), false);
        win->AddPanel(Pointer<TabPage>(new Prefetch::Panels::TraceChains(prefetch, win)), false);
        win->AddPanel(Pointer<TabPage>(new Prefetch::Panels::VolumeInformation(prefetch, win)), false);
        win->AddPanel(Pointer<TabPage>(new Prefetch::Panels::VolumeDirectories(prefetch, win)), false);
        win->AddPanel(Pointer<TabPage>(new Prefetch::Panels::VolumeFiles(prefetch, win)), false);

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
