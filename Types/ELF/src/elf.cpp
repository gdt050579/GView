#include "elf.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

GVIEW_PLUGIN_ENTRY_POINTS
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        CHECK(buf.GetLength() > sizeof(uint32), false, "");
        uint32 magic;
        memcpy(&magic, buf.GetData(), sizeof(magic));
        CHECK(magic == GView::Type::ELF::MAGIC, false, "");
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new ELF::ELFFile();
    }

    static const auto HEADER_COLOR      = ColorPair{ Color::Olive, Color::Transparent };
    static const auto PHT_COLOR         = ColorPair{ Color::Magenta, Color::Transparent };
    static const auto SHT_COLOR         = ColorPair{ Color::DarkRed, Color::Transparent };
    static const auto SHT_CONTENT_COLOR = ColorPair{ Color::Silver, Color::Transparent };

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<ELF::ELFFile> elf)
    {
        BufferViewer::Settings settings;

        uint64 offset = 0;
        if (elf->is64)
        {
            settings.AddZone(offset, sizeof(ELF::Elf64_Ehdr), HEADER_COLOR, "Header64");

            offset    = elf->header64.e_phoff;
            auto size = elf->header64.e_phnum * elf->header64.e_phentsize;
            settings.AddZone(offset, size, PHT_COLOR, "PHT64");

            offset = elf->header64.e_shoff;
            size   = elf->header64.e_shnum * elf->header64.e_shentsize;
            settings.AddZone(offset, size, SHT_COLOR, "SHT64");

            size_t i = 0;
            for (const auto& section : elf->sections64)
            {
                if (i >= elf->sectionNames.size()) // truncated binaries
                {
                    break;
                }
                const auto& name = elf->sectionNames.at(i++);
                settings.AddZone(section.sh_offset, section.sh_size, SHT_CONTENT_COLOR, name.c_str());
            }

            uint64 epFA = 0;
            for (const auto& segment : elf->segments64)
            {
                if (segment.p_vaddr <= elf->header64.e_entry && elf->header64.e_entry < segment.p_vaddr + segment.p_memsz)
                {
                    epFA = elf->header64.e_entry - segment.p_vaddr + segment.p_offset;
                    break;
                }
            }

            settings.SetEntryPointOffset(epFA);
        }
        else
        {
            settings.AddZone(offset, sizeof(ELF::Elf32_Ehdr), HEADER_COLOR, "Header32");

            offset    = elf->header32.e_phoff;
            auto size = elf->header32.e_phnum * elf->header32.e_phentsize;
            settings.AddZone(offset, size, PHT_COLOR, "PHT32");

            offset = elf->header32.e_shoff;
            size   = elf->header32.e_shnum * elf->header32.e_shentsize;
            settings.AddZone(offset, size, SHT_COLOR, "SHT32");

            size_t i = 0;
            for (const auto& section : elf->sections32)
            {
                if (i >= elf->sectionNames.size()) // truncated binaries
                {
                    break;
                }
                const auto& name = elf->sectionNames.at(i++);
                settings.AddZone(section.sh_offset, section.sh_size, SHT_CONTENT_COLOR, name.c_str());
            }

            uint64 epFA = 0;
            for (const auto& segment : elf->segments32)
            {
                if (segment.p_vaddr <= elf->header32.e_entry && elf->header32.e_entry < segment.p_vaddr + segment.p_memsz)
                {
                    epFA = (uint64) elf->header32.e_entry - segment.p_vaddr + segment.p_offset;
                    break;
                }
            }

            settings.SetEntryPointOffset(epFA);
        }

        // translation
        settings.SetOffsetTranslationList({ "VA" }, elf.ToBase<GView::View::BufferViewer::OffsetTranslateInterface>());

        // set specific color for opcodes
        const auto machine = elf->is64 ? elf->header64.e_machine : elf->header32.e_machine;
        switch (machine)
        {
        case ELF::EM_386:
        case ELF::EM_486:
        case ELF::EM_860:
        case ELF::EM_960:
        case ELF::EM_8051:
        case ELF::EM_X86_64:
            settings.SetPositionToColorCallback(elf.ToBase<GView::View::BufferViewer::PositionToColorInterface>());
            break;
        };

        elf->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    // The imports of the code: the GOT slots of the dynamic relocations (the PLT stubs jump through them, -fno-plt calls use them), named
    // after their dynamic symbols; the memory mappings of the disassembly are keyed by the RVA of the slot
    void AddDissasmImports(DissasmViewer::Settings& settings, Reference<ELF::ELFFile> elf, Reference<GView::Object> obj)
    {
        const uint64 imageBase = elf->GetImageBase() == static_cast<uint64>(-1) ? 0 : elf->GetImageBase();
        auto addSlot           = [&](uint64 slot, uint64 symbolIndex, uint64 type) {
            // jump slots (PLT) and global data (GOT) of the same numbers in x86 and x64
            if (type != ELF::R_X86_64_JUMP_SLOT && type != ELF::R_X86_64_GLOB_DAT)
                return;
            if (symbolIndex == 0 || symbolIndex >= elf->dynamicSymbolsNames.size() || elf->dynamicSymbolsNames[symbolIndex].empty() || slot < imageBase)
                return;
            settings.AddMemoryMapping(slot - imageBase, elf->dynamicSymbolsNames[symbolIndex], DissasmViewer::MemoryMappingType::FunctionMapping);
        };
        constexpr uint64 MAX_RELOCATIONS_SIZE = 0x1000000; // 16 MB of relocations
        auto readRelocations                  = [&](uint64 offset, uint64 size, uint32 type) {
            if (size == 0 || size > MAX_RELOCATIONS_SIZE || offset >= obj->GetData().GetSize())
                return;
            const auto buffer = obj->GetData().CopyToBuffer(offset, static_cast<uint32>(size));
            const auto data   = buffer.GetData();
            const auto length = buffer.GetLength();
            if (elf->is64)
            {
                const size_t entrySize = type == ELF::SHT_RELA ? sizeof(ELF::Elf64_Rela) : sizeof(ELF::Elf64_Rel);
                for (size_t position = 0; position + entrySize <= length; position += entrySize)
                {
                    ELF::Elf64_Rel relocation;
                    memcpy(&relocation, data + position, sizeof(relocation)); // r_offset and r_info start both layouts
                    addSlot(relocation.r_offset, ELF64_R_SYM(relocation.r_info), ELF64_R_TYPE(relocation.r_info));
                }
            }
            else
            {
                const size_t entrySize = type == ELF::SHT_RELA ? sizeof(ELF::Elf32_Rela) : sizeof(ELF::Elf32_Rel);
                for (size_t position = 0; position + entrySize <= length; position += entrySize)
                {
                    ELF::Elf32_Rel relocation;
                    memcpy(&relocation, data + position, sizeof(relocation));
                    addSlot(relocation.r_offset, ELF32_R_SYM(relocation.r_info), ELF32_R_TYPE(relocation.r_info));
                }
            }
        };
        if (elf->is64)
        {
            for (const auto& section : elf->sections64)
                if (section.sh_type == ELF::SHT_RELA || section.sh_type == ELF::SHT_REL)
                    readRelocations(section.sh_offset, section.sh_size, section.sh_type);
        }
        else
        {
            for (const auto& section : elf->sections32)
                if (section.sh_type == ELF::SHT_RELA || section.sh_type == ELF::SHT_REL)
                    readRelocations(section.sh_offset, section.sh_size, section.sh_type);
        }
    }

    // The functions of the symbols (the static ones of an unstripped file, the exported ones): named labels with their sizes
    void AddDissasmFunctionEntries(DissasmViewer::Settings& settings, Reference<ELF::ELFFile> elf)
    {
        // a function of both tables gets its exported name (an alias of the static one: malloc, not __libc_malloc)
        auto addSymbols = [&](const auto& symbols, const std::vector<std::string>& names, DissasmViewer::FunctionEntryType type) {
            for (size_t index = 0; index < symbols.size() && index < names.size(); index++)
            {
                const auto& symbol = symbols[index];
                if ((symbol.st_info & 0xF) != ELF::STT_FUNC || symbol.st_shndx == ELF::SHN_UNDEF || symbol.st_value == 0 || names[index].empty())
                    continue;
                const uint64 offset = elf->VAToFileOffset(symbol.st_value);
                if (offset != ELF::ELF_INVALID_ADDRESS)
                    settings.AddFunctionEntry(offset, names[index], type, symbol.st_size);
            }
        };
        if (elf->is64)
        {
            addSymbols(elf->staticSymbols64, elf->staticSymbolsNames, DissasmViewer::FunctionEntryType::Symbol);
            addSymbols(elf->dynamicSymbols64, elf->dynamicSymbolsNames, DissasmViewer::FunctionEntryType::Export);
        }
        else
        {
            addSymbols(elf->staticSymbols32, elf->staticSymbolsNames, DissasmViewer::FunctionEntryType::Symbol);
            addSymbols(elf->dynamicSymbols32, elf->dynamicSymbolsNames, DissasmViewer::FunctionEntryType::Export);
        }
    }

    // The disassembly of the x86 / x64 code: one zone from the first to the last executable section (.init, .plt, .text, .fini), so the
    // calls to the PLT stubs stay inside the zone
    void CreateDissasmView(Reference<GView::View::WindowInterface> win, Reference<ELF::ELFFile> elf)
    {
        const auto machine = elf->is64 ? elf->header64.e_machine : elf->header32.e_machine;
        DissasmViewer::DisassemblyLanguage language;
        if (machine == ELF::EM_X86_64)
            language = DissasmViewer::DisassemblyLanguage::x64;
        else if (machine == ELF::EM_386)
            language = DissasmViewer::DisassemblyLanguage::x86;
        else
            return; // the disassembly view decodes only x86 / x64

        uint64 start = UINT64_MAX, end = 0;
        std::vector<uint64> sectionStarts; // the padding between two sections never hides the start of the next one
        auto addSection = [&](uint64 flags, uint32 type, uint64 offset, uint64 size) {
            if ((flags & ELF::SHF_EXECINSTR) == 0 || type == ELF::SHT_NOBITS || size == 0)
                return;
            start = std::min(start, offset);
            end   = std::max(end, offset + size);
            sectionStarts.push_back(offset);
        };
        if (elf->is64)
        {
            for (const auto& section : elf->sections64)
                addSection(section.sh_flags, section.sh_type, section.sh_offset, section.sh_size);
        }
        else
        {
            for (const auto& section : elf->sections32)
                addSection(section.sh_flags, section.sh_type, section.sh_offset, section.sh_size);
        }
        const uint64 fileSize = win->GetObject()->GetData().GetSize();
        end                   = std::min(end, fileSize);
        if (start >= end)
            return;
        // the entry point; a library (no entry point) starts at the code
        uint64 entryPoint = elf->VAToFileOffset(elf->is64 ? elf->header64.e_entry : elf->header32.e_entry);
        if (entryPoint == ELF::ELF_INVALID_ADDRESS || entryPoint < start || entryPoint >= end)
            entryPoint = start;

        DissasmViewer::Settings settings;
        settings.AddDisassemblyZone(start, end - start, entryPoint, language);
        for (const uint64 sectionStart : sectionStarts)
            settings.AddInstructionBoundary(sectionStart);
        settings.SetOffsetTranslationList({ "RVA", "VA" }, &elf->dissasmTranslation);
        AddDissasmImports(settings, elf, win->GetObject());
        AddDissasmFunctionEntries(settings, elf);
        win->CreateViewer(settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto elf = win->GetObject()->GetContentType<ELF::ELFFile>();
        elf->Update();

        // add viewers
        CreateBufferView(win, elf);
        CreateDissasmView(win, elf);

        // add panels
        if (elf->HasPanel(ELF::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::Information(win->GetObject(), elf)), true);
        }
        if (elf->HasPanel(ELF::Panels::IDs::Segments))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::Segments(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::Sections))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::Sections(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::GoInformation))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::GoInformation(win->GetObject(), elf)), true);
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::GoFiles(win->GetObject(), elf)), true);
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::GoFunctions(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::StaticSymbols))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::StaticSymbols(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::DynamicSymbols))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::DynamicSymbols(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::OpCodes))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::OpCodes(win->GetObject(), elf)), true);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]      = "magic:7F 45 4C 46";
        sect["Priority"]     = 1;
        sect["Description"]  = "Executable and Linkable Format (for UNIX systems)";
        sect["OpCodes.Mask"] = (uint32) GView::Dissasembly::Opcodes::All;
    }
}
