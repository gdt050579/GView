#include "MachO.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;
using namespace GView::Type::MachO;
using namespace MAC;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const BufferView& buf, const std::string_view& extension)
    {
        auto dword = buf.GetObject<uint32_t>();
        CHECK(dword != nullptr, false, "");
        const uint32_t magic = dword;
        const bool isMacho   = magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
        const bool isFat     = magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
        CHECK(isMacho || isFat, false, "Magic is [%u]!", magic);

        if (isFat)
        {
            auto fh = *reinterpret_cast<const fat_header*>(buf.GetData());
            if (magic == FAT_CIGAM || magic == FAT_CIGAM_64)
            {
                Swap(fh);
            }

            CHECK(fh.nfat_arch < 0x2D, false, "This is probably a JAR class file!");
        }

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<DataCache> file)
    {
        return new MachOFile(file);
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MachOFile> machO)
    {
        BufferViewer::Settings settings;

        if (machO->isMacho)
        {
            const auto headerSize = sizeof(mach_header) + machO->is64 ? sizeof(mach_header::reserved) : 0;
            settings.AddZone(0, headerSize, machO->colors.header, "Header");

            LocalString<128> tmp;
            {
                auto i = 0ULL;
                for (const auto& lc : machO->loadCommands)
                {
                    settings.AddZone(lc.offset, lc.value.cmdsize, machO->colors.loadCommand, tmp.Format("(#%u)LC", i));
                    i++;
                }
            }

            for (const auto& segment : machO->segments)
            {
                for (const auto& s : segment.sections)
                {
                    settings.AddZone(
                          s.offset != 0 ? s.offset : s.addr /* handling __bss section */, s.size, machO->colors.section, s.sectname);
                }
            }

            if (machO->main.has_value())
            {
                settings.SetEntryPointOffset(machO->main->entryoff);
            }

            if (machO->dySymTab.has_value())
            {
                settings.AddZone(
                      machO->dySymTab->sc.symoff,
                      machO->dySymTab->sc.nsyms * (machO->is64 ? sizeof(MAC::nlist_64) : sizeof(MAC::nlist)),
                      machO->colors.section,
                      "Symbol_Table");
                settings.AddZone(machO->dySymTab->sc.stroff, machO->dySymTab->sc.strsize, machO->colors.section, "Symbol_Strings");
            }

            {
                auto i = 0ULL;
                for (const auto& linkEdit : machO->linkEditDatas)
                {
                    settings.AddZone(linkEdit.dataoff, linkEdit.datasize, machO->colors.linkEdit, tmp.Format("(#%u)Link_Edit", i));
                    i++;
                }
            }
        }
        else if (machO->isFat)
        {
            // TODO:
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto machO = win->GetObject()->GetContentType<MachO::MachOFile>();
        machO->Update();

        CreateBufferView(win, machO);

        if (machO->HasPanel(MachO::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::Information(win->GetObject(), machO)), true);
        }

        if (machO->isMacho)
        {
            if (machO->HasPanel(MachO::Panels::IDs::LoadCommands))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::LoadCommands(machO, win)), false);
            }

            if (machO->HasPanel(MachO::Panels::IDs::Segments))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::Segments(machO, win)), false);
            }

            if (machO->HasPanel(MachO::Panels::IDs::Sections))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::Sections(machO, win)), false);
            }

            if (machO->HasPanel(MachO::Panels::IDs::DyldInfo))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::DyldInfo(machO)), true);
            }

            if (machO->HasPanel(MachO::Panels::IDs::Dylib))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::Dylib(machO, win)), false);
            }

            if (machO->HasPanel(MachO::Panels::IDs::DySymTab))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::SymTab(machO, win)), false);
            }

            if (machO->HasPanel(MachO::Panels::IDs::CodeSign))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::CodeSignMagic(machO, win)), true);
            }
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const std::initializer_list<std::string> patterns = {
            "hex:'" + BinaryToHexString(MAC::MH_MAGIC, sizeof(MAC::MH_MAGIC)) + "'",
            "hex:'" + BinaryToHexString(MAC::MH_CIGAM, sizeof(MAC::MH_CIGAM)) + "'",
            "hex:'" + BinaryToHexString(MAC::MH_MAGIC_64, sizeof(MAC::MH_MAGIC_64)) + "'",
            "hex:'" + BinaryToHexString(MAC::MH_CIGAM_64, sizeof(MAC::MH_CIGAM_64)) + "'",
            /* Universal/Fat */
            "hex:'" + BinaryToHexString(FAT_MAGIC, sizeof(FAT_MAGIC)) + "'",
            "hex:'" + BinaryToHexString(FAT_CIGAM, sizeof(FAT_CIGAM)) + "'",
            "hex:'" + BinaryToHexString(FAT_MAGIC_64, sizeof(FAT_MAGIC_64)) + "'",
            "hex:'" + BinaryToHexString(FAT_CIGAM_64, sizeof(FAT_CIGAM_64)) + "'"
        };

        sect["Pattern"]  = patterns;
        sect["Priority"] = 1;
    }
}
