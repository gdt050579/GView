#include "iso.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

// clang-format off
static const std::map<std::string_view, ISO::Identifier> identifiers
{
    { "CD001", ISO::Identifier::ECMA_119 },
    { "NSR02", ISO::Identifier::ECMA_167_PREVIOUS },
    { "NSR03", ISO::Identifier::ECMA_167 },
    { "BEA01", ISO::Identifier::ECMA_167_EXTENDED },
    { "BOOT2", ISO::Identifier::ECMA_167_BOOT },
    { "TEA01", ISO::Identifier::ECMO_167_TERMINATOR },
    { "CDW02", ISO::Identifier::ECMA_168 }
};
// clang-format on

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        CHECK(buf.GetLength() >= ISO::ECMA_119_SYSTEM_AREA_SIZE + sizeof(ISO::ECMA_119_VolumeDescriptor), false, "");
        auto vdh = buf.GetObject<ISO::ECMA_119_VolumeDescriptorHeader>(ISO::ECMA_119_SYSTEM_AREA_SIZE);

        const auto identifier = identifiers.find(std::string_view{ vdh->identifier, sizeof(vdh->identifier) });
        if (identifier != identifiers.end())
        {
            CHECK(identifier->second == ISO::Identifier::ECMA_119, false, "We are supporting only ECMA_119 for now.")
        }
        else
        {
            RETURNERROR(false, "Unknown ISO format/standard!");
        }

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new ISO::ISOFile();
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<ISO::ISOFile> iso)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, ISO::ECMA_119_SYSTEM_AREA_SIZE, ColorPair{ Color::Silver, Color::DarkBlue }, "SystemArea");

        auto i     = 0;
        auto brvdi = 0;
        auto pvdi1 = 0;
        auto pvdi2 = 0;
        auto svdi  = 0;
        auto stvdi = 0;
        LocalString<128> ls;
        for (const auto& entry : iso->headers)
        {
            const auto offset = ISO::ECMA_119_SYSTEM_AREA_SIZE + ISO::ECMA_119_SECTOR_SIZE * i;

            if (entry.header.type == ISO::SectorType::BootRecord)
            {
                settings.AddZone(
                      offset,
                      ISO::ECMA_119_SECTOR_SIZE,
                      ColorPair{ Color::Magenta, Color::DarkBlue },
                      ls.Format("#%d_BootRecordVolumeDescriptor", brvdi));
                brvdi++;
            }
            else if (entry.header.type == ISO::SectorType::Partition)
            {
                settings.AddZone(
                      offset,
                      ISO::ECMA_119_SECTOR_SIZE,
                      ColorPair{ Color::Magenta, Color::DarkBlue },
                      ls.Format("#%d_PartitionVolumeDescriptor", pvdi1));
                pvdi1++;
            }
            else if (entry.header.type == ISO::SectorType::Primary)
            {
                settings.AddZone(
                      offset,
                      ISO::ECMA_119_SECTOR_SIZE,
                      ColorPair{ Color::Magenta, Color::DarkBlue },
                      ls.Format("#%d_PrimaryVolumeDescriptor", pvdi2));
                pvdi2++;
            }
            else if (entry.header.type == ISO::SectorType::Supplementary)
            {
                settings.AddZone(
                      offset,
                      ISO::ECMA_119_SECTOR_SIZE,
                      ColorPair{ Color::Magenta, Color::DarkBlue },
                      ls.Format("#%d_SupplementaryVolumeDescriptor", svdi));
                svdi++;
            }
            else if (entry.header.type == ISO::SectorType::SetTerminator)
            {
                settings.AddZone(
                      offset,
                      ISO::ECMA_119_SECTOR_SIZE,
                      ColorPair{ Color::Magenta, Color::DarkBlue },
                      ls.Format("#%d_SetTerminatorVolumeDescriptor", stvdi));
                stvdi++;
            }

            i++;
        }

        settings.AddBookmark(0, ISO::ECMA_119_SYSTEM_AREA_SIZE);

        for (const auto& entry : iso->headers)
        {
            if (entry.header.type != ISO::SectorType::Primary)
            {
                continue;
            }

            ISO::ECMA_119_PrimaryVolumeDescriptor pvd{};
            CHECKBK(iso->obj->GetData().Copy<ISO::ECMA_119_PrimaryVolumeDescriptor>(entry.offsetInFile, pvd), "");
            const auto blockSize   = pvd.vdd.logicalBlockSize.LSB;
            const auto ptrLocation = pvd.vdd.locationOfTypeLPathTable * blockSize;
            const auto ptrSize     = pvd.vdd.pathTableSize.LSB;
            settings.AddZone(ptrLocation, ptrSize, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "PathTableRecord");

            settings.AddBookmark(1, ptrLocation);

            break;
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto iso = win->GetObject()->GetContentType<ISO::ISOFile>();
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
