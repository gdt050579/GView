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
using namespace UniversalMachO::Panels;
using namespace MAC;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const BufferView& buf, const std::string_view& extension)
    {
        auto header = buf.GetObject<fat_header>();
        CHECK(header.IsValid(), false, "");
        const auto magic = header->magic;
        CHECK(header->magic == FAT_MAGIC || header->magic == FAT_CIGAM || header->magic == FAT_MAGIC_64 || header->magic == FAT_CIGAM_64,
              false,
              "Magic is [%u]!",
              header->magic);

        auto fh = *reinterpret_cast<const fat_header*>(buf.GetData());
        if (header->magic == FAT_CIGAM || header->magic == FAT_CIGAM_64)
        {
            Swap(fh);
        }

        CHECK(fh.nfat_arch < 0x2D, false, "This is probably a JAR class file!");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new UniversalMachOFile();
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
            temp.Format("Arch #%u", objectCount);

            const auto structSize = macho->is64 ? sizeof(fat_arch64) : sizeof(fat_arch);
            settings.AddZone(offsetHeaders, structSize, macho->colors.arch, temp);
            offsetHeaders += structSize;

            const auto& ai = macho->archs[objectCount].info;
            temp.Format("#%u %s", objectCount, ai.name.c_str());
            settings.AddZone(macho->archs[objectCount].offset, macho->archs[objectCount].size, macho->colors.object, temp);

            objectCount++;
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto mach = win->GetObject()->GetContentType<UniversalMachOFile>();
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
