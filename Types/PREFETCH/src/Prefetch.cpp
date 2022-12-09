#include "Prefetch.hpp"

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

    ColorPair header{ Color::DarkGreen, Color::DarkBlue };
    ColorPair fileInformation{ Color::DarkRed, Color::DarkBlue };
    ColorPair sectionA{ Color::DarkGreen, Color::DarkBlue };
    ColorPair sectionB{ Color::DarkRed, Color::DarkBlue };
    ColorPair sectionC{ Color::DarkGreen, Color::DarkBlue };
    ColorPair sectionD{ Color::DarkRed, Color::DarkBlue };
    ColorPair exe{ Color::Red, Color::DarkBlue };

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<Prefetch::PrefetchFile> prefetch)
    {
        BufferViewer::Settings settings;

        const auto& magic = prefetch->header.version;
        const auto& area  = prefetch->area;

        settings.AddZone(0, sizeof(Prefetch::Header), header, "Header");
        settings.AddZone(sizeof(Prefetch::Header), Prefetch::FileInformationSizes.at(magic), fileInformation, "FileInformation");
        settings.AddZone(area.sectionA.offset, area.sectionA.entries * Prefetch::FileMetricsSizes.at(magic), sectionA, "Section A");
        settings.AddZone(area.sectionB.offset, area.sectionB.entries * Prefetch::TraceChainEntrySizes.at(magic), sectionB, "Section B");
        settings.AddZone(area.sectionC.offset, area.sectionC.length, sectionC, "Section C");
        settings.AddZone(area.sectionD.offset, area.sectionD.size, sectionD, "Section D");

        if (magic == Prefetch::Magic::WIN_10)
        {
            if (prefetch->win10Version == Prefetch::Win10Version::V2)
            {
                Prefetch::FileInformation_30v2 fi{};
                if (win->GetObject()->GetData().Copy<Prefetch::FileInformation_30v2>(sizeof(Prefetch::Header), fi))
                {
                    settings.AddZone(fi.executablePathOffset, fi.executablePathSize, exe, "EXECUTABLE");
                }
            }
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
            "magic:" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_XP_2003, sizeof(Prefetch::Magic::WIN_XP_2003)),
            "magic:" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_VISTA_7, sizeof(Prefetch::Magic::WIN_VISTA_7)),
            "magic:" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_8, sizeof(Prefetch::Magic::WIN_8)),
            "magic:" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_10, sizeof(Prefetch::Magic::WIN_10)),
            "magic:" + Prefetch::BinaryToHexString(Prefetch::Magic::WIN_10, sizeof(Prefetch::Magic::WIN_10)),
        };

        sect["Pattern"]     = patterns;
        sect["Extension"]   = "pf";
        sect["Priority"]    = 1;
        sect["Description"] = "Prefetch file format for Windows OS";
    }
}
