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

GVIEW_PLUGIN_ENTRY_POINTS
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

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new MachOFile(nullptr);
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

                const auto& ai = vArch.info;
                temp.Format("#%u %s", objectCount, ai.name.c_str());
                settings.AddZone(vArch.offset, vArch.size, machO->colors.object, temp);

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

    // the sections of machine code (__text, __stubs, __stub_helper)
    bool IsInstructionsSection(const MachOFile::Section& section)
    {
        constexpr uint32 PURE_INSTRUCTIONS = static_cast<uint32>(MAC::SectionAttributtes::PURE_INSTRUCTIONS);
        constexpr uint32 SOME_INSTRUCTIONS = static_cast<uint32>(MAC::SectionAttributtes::SOME_INSTRUCTIONS);
        return (section.flags & (PURE_INSTRUCTIONS | SOME_INSTRUCTIONS)) != 0 && section.offset != 0 && section.size > 0;
    }

    // The imports of the code: the lazy / non-lazy symbol pointers (__la_symbol_ptr, __got) named through the indirect symbol table
    // (LC_DYSYMTAB); the __stubs jump through them. The memory mappings of the disassembly are keyed by the RVA of the slot
    void AddDissasmImports(DissasmViewer::Settings& settings, Reference<MachOFile> machO, Reference<GView::Object> obj)
    {
        struct DySymTabCommand // dysymtab_command
        {
            uint32 cmd, cmdsize;
            uint32 ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym;
            uint32 tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms;
            uint32 indirectsymoff, nindirectsyms;
            uint32 extreloff, nextrel, locreloff, nlocrel;
        };
        if (!machO->dySymTab.has_value())
            return;
        DySymTabCommand command{};
        bool found = false;
        for (const auto& loadCommand : machO->loadCommands)
            if (loadCommand.value.cmd == MAC::LoadCommandType::DYSYMTAB && obj->GetData().Copy<DySymTabCommand>(loadCommand.offset, command))
                found = true;
        constexpr uint32 MAX_INDIRECT_SYMBOLS = 0x100000;
        if (!found || command.nindirectsyms == 0 || command.nindirectsyms > MAX_INDIRECT_SYMBOLS)
            return;
        const auto indirectSymbols = obj->GetData().CopyToBuffer(command.indirectsymoff, command.nindirectsyms * sizeof(uint32));
        if (indirectSymbols.GetLength() < command.nindirectsyms * sizeof(uint32))
            return;
        const auto symbols      = reinterpret_cast<const uint32*>(indirectSymbols.GetData());
        const auto& names       = machO->dySymTab->objects;
        const uint64 imageBase  = machO->dissasmTranslation.GetImageBase();
        const uint32 pointerSize = machO->is64 ? 8 : 4;
        constexpr uint32 LAZY_POINTERS     = static_cast<uint32>(MAC::SectionType::LAZY_SYMBOL_POINTERS);
        constexpr uint32 NON_LAZY_POINTERS = static_cast<uint32>(MAC::SectionType::NON_LAZY_SYMBOL_POINTERS);
        constexpr uint32 INDIRECT_SYMBOL_LOCAL = 0x80000000; // a pointer to a local symbol / an absolute value: not an import
        constexpr uint32 INDIRECT_SYMBOL_ABS   = 0x40000000;
        for (const auto& segment : machO->segments)
        {
            for (const auto& section : segment.sections)
            {
                const uint32 type = section.flags & MAC::SECTION_TYPE;
                if (type != LAZY_POINTERS && type != NON_LAZY_POINTERS)
                    continue;
                // reserved1: the index of the first pointer in the indirect symbol table
                for (uint64 slot = 0; slot < section.size / pointerSize; slot++)
                {
                    const uint64 index = section.reserved1 + slot;
                    if (index >= command.nindirectsyms)
                        break;
                    const uint32 symbol = symbols[index];
                    if ((symbol & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) != 0 || symbol >= names.size() || names[symbol].symbolNameDemangled.empty())
                        continue;
                    const uint64 address = section.addr + slot * pointerSize;
                    if (address >= imageBase)
                        settings.AddMemoryMapping(address - imageBase, names[symbol].symbolNameDemangled, DissasmViewer::MemoryMappingType::FunctionMapping);
                }
            }
        }
    }

    // The functions: the symbols of the instructions sections (the external ones are exports) and LC_FUNCTION_STARTS (every function
    // start, without names: it is kept in stripped files)
    void AddDissasmFunctionEntries(DissasmViewer::Settings& settings, Reference<MachOFile> machO, Reference<GView::Object> obj)
    {
        auto& translation = machO->dissasmTranslation;
        constexpr uint32 VA = 2;
        if (machO->dySymTab.has_value())
        {
            // the sections are numbered from 1, in the order of the segments
            std::vector<bool> isCode{ false };
            for (const auto& segment : machO->segments)
                for (const auto& section : segment.sections)
                    isCode.push_back(IsInstructionsSection(section));
            constexpr uint8 STAB         = static_cast<uint8>(MAC::N_TYPE::STAB);
            constexpr uint8 TYPE         = static_cast<uint8>(MAC::N_TYPE::TYPE);
            constexpr uint8 EXT          = static_cast<uint8>(MAC::N_TYPE::EXT);
            constexpr uint8 SECT         = static_cast<uint8>(MAC::N_TYPE_BITS::SECT);
            for (const auto& symbol : machO->dySymTab->objects)
            {
                if ((symbol.n_type & STAB) != 0 || (symbol.n_type & TYPE) != SECT || symbol.n_sect >= isCode.size() || !isCode[symbol.n_sect] ||
                    symbol.symbolNameDemangled.empty())
                    continue;
                const uint64 offset = translation.TranslateToFileOffset(symbol.n_value, VA);
                if (offset != static_cast<uint64>(-1))
                    settings.AddFunctionEntry(
                          offset,
                          symbol.symbolNameDemangled,
                          (symbol.n_type & EXT) != 0 ? DissasmViewer::FunctionEntryType::Export : DissasmViewer::FunctionEntryType::Symbol);
            }
        }
        // LC_FUNCTION_STARTS: ULEB128 distances, the first one from the start of the __TEXT segment
        constexpr uint32 MAX_FUNCTION_STARTS_SIZE = 0x1000000;
        for (const auto& data : machO->linkEditDatas)
        {
            if (data.cmd != MAC::LoadCommandType::FUNCTION_STARTS || data.datasize == 0 || data.datasize > MAX_FUNCTION_STARTS_SIZE)
                continue;
            const auto buffer = obj->GetData().CopyToBuffer(data.dataoff, data.datasize);
            uint64 address    = translation.GetImageBase();
            size_t position   = 0;
            while (position < buffer.GetLength())
            {
                uint64 delta = 0;
                uint32 shift = 0;
                uint8 byte   = 0;
                do
                {
                    byte = buffer.GetData()[position++];
                    if (shift < 64)
                        delta |= static_cast<uint64>(byte & 0x7F) << shift;
                    shift += 7;
                } while ((byte & 0x80) != 0 && position < buffer.GetLength());
                if (delta == 0)
                    break; // the end of the list
                address += delta;
                const uint64 offset = translation.TranslateToFileOffset(address, VA);
                if (offset != static_cast<uint64>(-1))
                    settings.AddFunctionEntry(offset, {}, DissasmViewer::FunctionEntryType::Symbol);
            }
        }
    }

    // The disassembly of the x86 / x64 code: one zone from the first to the last instructions section (__text, __stubs, __stub_helper),
    // the entry point of LC_MAIN
    void CreateDissasmView(Reference<GView::View::WindowInterface> win, Reference<MachOFile> machO)
    {
        if (!machO->isMacho || machO->shouldSwapEndianess)
            return;
        DissasmViewer::DisassemblyLanguage language;
        if (machO->header.cputype == MAC::CPU_TYPE_X86_64)
            language = DissasmViewer::DisassemblyLanguage::x64;
        else if (machO->header.cputype == MAC::CPU_TYPE_I386)
            language = DissasmViewer::DisassemblyLanguage::x86;
        else
            return; // the disassembly view decodes only x86 / x64

        uint64 start = UINT64_MAX, end = 0;
        std::vector<uint64> sectionStarts; // the padding between two sections never hides the start of the next one
        for (const auto& segment : machO->segments)
            for (const auto& section : segment.sections)
                if (IsInstructionsSection(section))
                {
                    sectionStarts.push_back(section.offset);
                    start = std::min<uint64>(start, section.offset);
                    end   = std::max<uint64>(end, static_cast<uint64>(section.offset) + section.size);
                }
        end = std::min<uint64>(end, win->GetObject()->GetData().GetSize());
        if (start >= end)
            return;
        // LC_MAIN: the offset of the entry point from the start of the __TEXT segment (its file offset); a library starts at the code
        uint64 entryPoint = machO->main.has_value() ? machO->main->entryoff : start;
        if (entryPoint < start || entryPoint >= end)
            entryPoint = start;

        DissasmViewer::Settings settings;
        settings.AddDisassemblyZone(start, end - start, entryPoint, language);
        for (const uint64 sectionStart : sectionStarts)
            settings.AddInstructionBoundary(sectionStart);
        settings.SetOffsetTranslationList({ "RVA", "VA" }, &machO->dissasmTranslation);
        AddDissasmImports(settings, machO, win->GetObject());
        AddDissasmFunctionEntries(settings, machO, win->GetObject());
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
        CreateDissasmView(win, machO);

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
            sect[buffer.GetText()] = command.DefaultKey;
        }
    }
}
