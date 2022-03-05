#include "MachOFB.hpp"

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
        auto header = buf.GetObject<MachOFB::MAC::fat_header>();
        CHECK(header != nullptr, false, "");
        CHECK(header->magic == MachOFB::MAC::FAT_MAGIC || header->magic == MachOFB::MAC::FAT_CIGAM ||
                    header->magic == MachOFB::MAC::FAT_MAGIC_64 || header->magic == MachOFB::MAC::FAT_CIGAM_64,
              false,
              "Magic is [%u]!",
              header->magic);
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new MachOFB::MachOFBFile(file);
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MachOFB::MachOFBFile> macho)
    {
        BufferViewer::Settings settings;
        uint64_t offsetHeaders = 0;

        settings.AddZone(offsetHeaders, sizeof(macho->header), macho->colors.header, "Header");
        offsetHeaders += sizeof(macho->header);

        uint32_t objectCount = 0;
        LocalString<128> temp;

        for (const auto& vArch : macho->archs)
        {
            uint64_t structSize = 0;
            uint64_t offset     = 0;
            uint64_t size       = 0;

            switch (vArch.index())
            {
            case 0:
            {
                const auto& arch = std::get<0>(vArch);
                structSize       = sizeof(arch);
                offset           = arch.offset;
                size             = arch.size;
            }
            break;
            case 1:
            {
                const auto& arch = std::get<1>(vArch);
                structSize       = sizeof(arch);
                offset           = arch.offset;
                size             = arch.size;
            }
            break;
            default:
                break;
            }

            temp.Format("Arch #%u", objectCount);
            settings.AddZone(offsetHeaders, structSize, macho->colors.arch, temp);
            offsetHeaders += structSize;

            const auto& ai = macho->archsInfo[objectCount];
            temp.Format("#%u %s", objectCount, ai.name.c_str());
            settings.AddZone(offset, size, macho->colors.object, temp);

            objectCount++;
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto mach = reinterpret_cast<MachOFB::MachOFBFile*>(win->GetObject()->type);
        mach->Update();

        CreateBufferView(win, mach);

        if (mach->HasPanel(MachOFB::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new MachOFB::Panels::Information(mach)), true);
        }

        if (mach->HasPanel(MachOFB::Panels::IDs::Objects))
        {
            win->AddPanel(Pointer<TabPage>(new MachOFB::Panels::Objects(mach, win)), false);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const std::initializer_list<std::string> patterns = {
            "hex:'" + MachOFB::Utils::BinaryToHexString(MachOFB::MAC::FAT_MAGIC, sizeof(MachOFB::MAC::FAT_MAGIC)) + "'",
            "hex:'" + MachOFB::Utils::BinaryToHexString(MachOFB::MAC::FAT_CIGAM, sizeof(MachOFB::MAC::FAT_CIGAM)) + "'",
            "hex:'" + MachOFB::Utils::BinaryToHexString(MachOFB::MAC::FAT_MAGIC_64, sizeof(MachOFB::MAC::FAT_MAGIC_64)) + "'",
            "hex:'" + MachOFB::Utils::BinaryToHexString(MachOFB::MAC::FAT_CIGAM_64, sizeof(MachOFB::MAC::FAT_CIGAM_64)) + "'"
        };

        sect["Pattern"]  = patterns;
        sect["Priority"] = 1;
    }
}

int main()
{
    return 0;
}
