#include "UniversalMachO.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;
using namespace UniversalMachO;
using namespace UniversalMachO::MAC;
using namespace UniversalMachO::Utils;
using namespace UniversalMachO::Panels;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const BufferView& buf, const std::string_view& extension)
    {
        auto header = buf.GetObject<fat_header>();
        CHECK(header != nullptr, false, "");
        const auto magic = header->magic;
        CHECK(magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64, false, "Magic is [%u]!", magic);

        if (magic == FAT_MAGIC || magic == FAT_CIGAM)
        {
            auto maybeArchCount = header->nfat_arch;

            if (magic == FAT_CIGAM)
            {
                maybeArchCount = SwapEndian(maybeArchCount);
            }

            CHECK(maybeArchCount < 0x2D, false, "This is probably a JAR class file!");
        }

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<FileCache> file)
    {
        return new UniversalMachOFile(file);
    }

    void CreateBufferView(Reference<WindowInterface> win, Reference<UniversalMachOFile> macho)
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

    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto mach = reinterpret_cast<UniversalMachOFile*>(win->GetObject()->type);
        mach->Update();

        CreateBufferView(win, mach);

        if (mach->HasPanel(IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new Information(mach)), true);
        }

        if (mach->HasPanel(IDs::Objects))
        {
            win->AddPanel(Pointer<TabPage>(new Objects(mach, win)), false);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const auto patterns = { "hex:'" + BinaryToHexString(FAT_MAGIC, sizeof(FAT_MAGIC)) + "'",
                                       "hex:'" + BinaryToHexString(FAT_CIGAM, sizeof(FAT_CIGAM)) + "'",
                                       "hex:'" + BinaryToHexString(FAT_MAGIC_64, sizeof(FAT_MAGIC_64)) + "'",
                                       "hex:'" + BinaryToHexString(FAT_CIGAM_64, sizeof(FAT_CIGAM_64)) + "'" };
        sect["Pattern"]            = patterns;
        sect["Priority"]           = 1;
    }
}

int main()
{
    return 0;
}
