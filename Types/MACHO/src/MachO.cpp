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

constexpr string_view FAT_ICON = "................"  // 1
                                 "................"  // 2
                                 "................"  // 3
                                 "................"  // 4
                                 "WWWW.WWWWW.WWWWW"  // 5
                                 "W....W...W...W.."  // 6
                                 "W....W...W...W.."  // 7
                                 "WWWW.WWWWW...W.."  // 8
                                 "W....W...W...W.."  // 9
                                 "W....W...W...W.."  // 10
                                 "W....W...W...W.."  // 11
                                 "................"  // 12
                                 "................"  // 13
                                 "................"  // 14
                                 "................"  // 15
                                 "................"; // 16

extern "C"
{
    PLUGIN_EXPORT bool Validate(const BufferView& buf, const std::string_view&)
    {
        auto dword = buf.GetObject<uint32>();
        CHECK(dword != nullptr, false, "");
        const uint32 magic = dword;
        const bool isMacho = magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
        const bool isFat   = magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
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
            const auto headerSize = sizeof(mach_header) + (machO->is64 ? sizeof(mach_header::reserved) : 0);
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

            // set specific color for opcodes
            switch (machO->header.cputype)
            {
            case MAC::CPU_TYPE_I386:
            case MAC::CPU_TYPE_X86_64:
                settings.SetPositionToColorCallback(machO.ToBase<GView::View::BufferViewer::PositionToColorInterface>());
            default:
                break;
            }
        }
        else if (machO->isFat)
        {
            uint64_t offsetHeaders = 0;

            settings.AddZone(offsetHeaders, sizeof(machO->fatHeader), machO->colors.header, "Header");
            offsetHeaders += sizeof(machO->header);

            uint32_t objectCount = 0;
            LocalString<128> temp;

            for (const auto& vArch : machO->archs)
            {
                temp.Format("Arch #%u", objectCount);

                const auto structSize = machO->is64 ? sizeof(fat_arch64) : sizeof(fat_arch);
                settings.AddZone(offsetHeaders, structSize, machO->colors.arch, temp);
                offsetHeaders += structSize;

                const auto& ai = machO->archs[objectCount].info;
                temp.Format("#%u %s", objectCount, ai.name.c_str());
                settings.AddZone(machO->archs[objectCount].offset, machO->archs[objectCount].size, machO->colors.object, temp);

                objectCount++;
            }
        }

        machO->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<MachOFile>)
    {
        ContainerViewer::Settings settings;

        settings.SetIcon(FAT_ICON);
        settings.SetColumns({
              "n:CPU type,a:r,w:25",
              "n:CPU subtype,a:r,w:25",
              "n:File type,w:80",
              "n:Offset,a:r,w:12",
              "n:Size,a:r,w:12",
              "n:Align,a:r,w:12",
              "n:Real Align,a:r,w:12",
        });

        settings.SetEnumerateCallback(
              win->GetObject()->GetContentType<MachO::MachOFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
        settings.SetOpenItemCallback(
              win->GetObject()->GetContentType<MachO::MachOFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

        win->CreateViewer(settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto machO = win->GetObject()->GetContentType<MachO::MachOFile>();
        machO->Update();

        if (machO->isFat)
        {
            CreateContainerView(win, machO);
        }

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

            if (machO->HasPanel(MachO::Panels::IDs::GoInformation))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::GoInformation(win->GetObject(), machO)), true);
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::GoFiles(win->GetObject(), machO)), true);
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::GoFunctions(machO, win)), false);
            }

            if (machO->HasPanel(MachO::Panels::IDs::OpCodes))
            {
                win->AddPanel(Pointer<TabPage>(new MachO::Panels::OpCodes(win->GetObject(), machO)), true);
            }
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const std::initializer_list<std::string> patterns = {
            "magic:" + BinaryToHexString(MAC::MH_MAGIC, sizeof(MAC::MH_MAGIC)),
            "magic:" + BinaryToHexString(MAC::MH_CIGAM, sizeof(MAC::MH_CIGAM)),
            "magic:" + BinaryToHexString(MAC::MH_MAGIC_64, sizeof(MAC::MH_MAGIC_64)),
            "magic:" + BinaryToHexString(MAC::MH_CIGAM_64, sizeof(MAC::MH_CIGAM_64)),
            /* Universal/Fat */
            "magic:" + BinaryToHexString(FAT_MAGIC, sizeof(FAT_MAGIC)),
            "magic:" + BinaryToHexString(FAT_CIGAM, sizeof(FAT_CIGAM)),
            "magic:" + BinaryToHexString(FAT_MAGIC_64, sizeof(FAT_MAGIC_64)),
            "magic:" + BinaryToHexString(FAT_CIGAM_64, sizeof(FAT_CIGAM_64))
        };

        sect["Pattern"]                  = patterns;
        sect["Priority"]                 = 1;
        sect["Description"]              = "Mach file executable object (Mach-O) for OSX based systems (including MachO Fat)";
        sect["OpCodes.Mask"]             = (uint32) GView::Dissasembly::Opcodes::All;

        LocalString<128> buffer;
        for (const auto& command : MachO::Commands::MACHO_COMMANDS) {
            buffer.SetFormat("Command.%s", command.Caption);
            sect[buffer.GetText()] = command.Key;
        }
    }
}
