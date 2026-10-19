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
        const auto machine     = elf->is64 ? elf->header64.e_machine : elf->header32.e_machine;
        constexpr unsigned R_ARM_GLOB_DAT  = 21;
        constexpr unsigned R_ARM_JUMP_SLOT = 22;
        // a variable of another module (STT_OBJECT: stdout, environ, the vtables of __cxxabiv1): its slot is a pointer to it, counter_ptr
        // (IDA), its line the variable; a function: an import slot (__imp_puts)
        const auto isVariable = [&](uint64 symbolIndex) {
            const uint8 info = elf->is64 ? (symbolIndex < elf->dynamicSymbols64.size() ? elf->dynamicSymbols64[symbolIndex].st_info : 0)
                                         : (symbolIndex < elf->dynamicSymbols32.size() ? elf->dynamicSymbols32[symbolIndex].st_info : 0);
            return (info & 0xF) == ELF::STT_OBJECT;
        };
        // the pointer at `slot` to the symbol (plus the addend): named after it, its line the symbol
        const auto addImportPointer = [&](uint64 slot, uint64 symbolIndex, int64 addend) {
            const std::string& name = elf->dynamicSymbolsNames[symbolIndex];
            if (isVariable(symbolIndex))
                settings.AddMemoryMapping(slot - imageBase, name + "_ptr", DissasmViewer::MemoryMappingType::TextMapping);
            else
                settings.AddMemoryMapping(slot - imageBase, name, DissasmViewer::MemoryMappingType::FunctionMapping);
            std::string bound = name;
            if (addend != 0)
            {
                char text[32];
                snprintf(text, sizeof(text), addend > 0 ? "+0x%llx" : "-0x%llx", static_cast<unsigned long long>(addend > 0 ? addend : -addend));
                bound += text;
            }
            settings.AddBoundSymbol(slot - imageBase, bound);
        };
        auto addSlot           = [&](uint64 slot, uint64 symbolIndex, uint64 type) {
            // jump slots (PLT) and global data (GOT): the same numbers in x86 and x64, their own in AArch64 and in ARM
            bool isImport = type == ELF::R_X86_64_JUMP_SLOT || type == ELF::R_X86_64_GLOB_DAT;
            if (machine == ELF::EM_AARCH64)
                isImport = type == ELF::R_AARCH64_JUMP_SLOT || type == ELF::R_AARCH64_GLOB_DAT;
            else if (machine == ELF::EM_ARM)
                isImport = type == R_ARM_JUMP_SLOT || type == R_ARM_GLOB_DAT;
            if (!isImport)
                return;
            if (symbolIndex == 0 || symbolIndex >= elf->dynamicSymbolsNames.size() || elf->dynamicSymbolsNames[symbolIndex].empty() || slot < imageBase)
                return;
            addImportPointer(slot, symbolIndex, 0);
        };
        // the pointers the loader writes (RELA: the bytes in the file are 0): R_*_RELATIVE / R_*_IRELATIVE (the image base, 0 here, plus the
        // addend; the resolver of an ifunc), a 64 bit pointer to a symbol of the file (its value plus the addend); a pointer to an import
        // (a vtable entry, a callback of another library) is named after it. REL (32 bit x86 / ARM) keeps the value in the file
        constexpr unsigned R_AARCH64_IRELATIVE = 1032;
        // a copy relocation: the variable of a library copied into the program (stdout, environ, the vtables of __cxxabiv1 that the typeinfo
        // objects of a non PIE program point to), named after its symbol
        constexpr unsigned R_AARCH64_COPY = 1024;
        constexpr unsigned R_ARM_COPY     = 20;
        auto addCopy                      = [&](uint64 slot, uint64 symbolIndex, uint64 type) {
            const bool isCopy = machine == ELF::EM_AARCH64 ? type == R_AARCH64_COPY : (machine == ELF::EM_ARM ? type == R_ARM_COPY : type == ELF::R_X86_64_COPY);
            if (isCopy && symbolIndex != 0 && symbolIndex < elf->dynamicSymbolsNames.size() && !elf->dynamicSymbolsNames[symbolIndex].empty() && slot >= imageBase)
                settings.AddMemoryMapping(slot - imageBase, elf->dynamicSymbolsNames[symbolIndex], DissasmViewer::MemoryMappingType::TextMapping);
        };
        auto addPointer                        = [&](uint64 slot, uint64 symbolIndex, uint64 type, int64 addend) {
            bool isRelative = false, isAbsolute = false;
            if (machine == ELF::EM_X86_64)
            {
                isRelative = type == ELF::R_X86_64_RELATIVE || type == ELF::R_X86_64_IRELATIVE;
                isAbsolute = type == ELF::R_X86_64_64;
            }
            else if (machine == ELF::EM_AARCH64)
            {
                isRelative = type == ELF::R_AARCH64_RELATIVE || type == R_AARCH64_IRELATIVE;
                isAbsolute = type == ELF::R_AARCH64_ABS64;
            }
            if (!isRelative && !isAbsolute)
                return;
            uint64 value = static_cast<uint64>(addend);
            if (isAbsolute)
            {
                if (symbolIndex == 0 || symbolIndex >= elf->dynamicSymbols64.size())
                    return;
                const auto& symbol = elf->dynamicSymbols64[symbolIndex];
                if (symbol.st_shndx == ELF::SHN_UNDEF)
                {
                    // a pointer to an import: named after it; its value (0) is not known
                    if (symbolIndex >= elf->dynamicSymbolsNames.size() || elf->dynamicSymbolsNames[symbolIndex].empty() || slot < imageBase)
                        return;
                    // its line: the symbol and the addend (a typeinfo: vptr = the vtable of __class_type_info + 0x10)
                    addImportPointer(slot, symbolIndex, addend);
                    value = 0;
                }
                else
                    value += symbol.st_value;
            }
            const uint64 offset = elf->VAToFileOffset(slot);
            if (offset != ELF::ELF_INVALID_ADDRESS)
                settings.AddRelocatedPointer(offset, value);
        };
        constexpr uint64 MAX_RELOCATIONS_SIZE = 0x1000000; // 16 MB of relocations
        // 32 bit REL: a pointer to a symbol (R_386_32 / R_ARM_ABS32: a vtable entry, the vptr / the name of a typeinfo); the addend is the
        // value in the file. A symbol of another module: named after it; a symbol of the file (preemptible in a shared object): its value
        constexpr unsigned R_ARM_ABS32 = 2;
        auto addPointer32              = [&](uint64 slot, uint64 symbolIndex, uint64 type) {
            const bool isAbsolute = (machine == ELF::EM_386 && type == ELF::R_386_32) || (machine == ELF::EM_ARM && type == R_ARM_ABS32);
            if (!isAbsolute || symbolIndex == 0 || symbolIndex >= elf->dynamicSymbols32.size() || slot < imageBase)
                return;
            const uint64 offset = elf->VAToFileOffset(slot);
            uint32 addend       = 0;
            if (offset == ELF::ELF_INVALID_ADDRESS || !obj->GetData().Copy<uint32>(offset, addend))
                return;
            const auto& symbol = elf->dynamicSymbols32[symbolIndex];
            if (symbol.st_shndx != ELF::SHN_UNDEF)
            {
                settings.AddRelocatedPointer(offset, static_cast<uint32>(symbol.st_value + addend));
                return;
            }
            if (symbolIndex >= elf->dynamicSymbolsNames.size() || elf->dynamicSymbolsNames[symbolIndex].empty())
                return;
            addImportPointer(slot, symbolIndex, static_cast<int32>(addend));
            settings.AddRelocatedPointer(offset, 0); // its value is not known
        };
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
                    ELF::Elf64_Rela relocation{};
                    memcpy(&relocation, data + position, entrySize); // r_offset and r_info start both layouts (REL: no addend)
                    addSlot(relocation.r_offset, ELF64_R_SYM(relocation.r_info), ELF64_R_TYPE(relocation.r_info));
                    addCopy(relocation.r_offset, ELF64_R_SYM(relocation.r_info), ELF64_R_TYPE(relocation.r_info));
                    if (type == ELF::SHT_RELA)
                        addPointer(relocation.r_offset, ELF64_R_SYM(relocation.r_info), ELF64_R_TYPE(relocation.r_info), relocation.r_addend);
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
                    addCopy(relocation.r_offset, ELF32_R_SYM(relocation.r_info), ELF32_R_TYPE(relocation.r_info));
                    if (type == ELF::SHT_REL)
                        addPointer32(relocation.r_offset, ELF32_R_SYM(relocation.r_info), ELF32_R_TYPE(relocation.r_info));
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

    // ARM: the mode of every executable section: the .plt stubs of glibc are ARM code even in a Thumb file, the others have the mode of the
    // entry point (a stripped file: the function and the mapping symbols are gone)
    void AddDissasmArmModes(DissasmViewer::Settings& settings, Reference<ELF::ELFFile> elf, bool isThumb)
    {
        for (size_t index = 0; index < elf->sections32.size(); index++)
        {
            const auto& section = elf->sections32[index];
            if ((section.sh_flags & ELF::SHF_EXECINSTR) == 0 || section.sh_type == ELF::SHT_NOBITS || section.sh_size == 0)
                continue;
            const bool isPlt = index < elf->sectionNames.size() && elf->sectionNames[index] == ".plt";
            settings.AddArmCodeMode(section.sh_offset, isPlt || !isThumb ? DissasmViewer::ArmCodeMode::Arm : DissasmViewer::ArmCodeMode::Thumb);
        }
    }

    // ARM: the mapping symbols of the assembler ($a: ARM code, $t: Thumb code, $d: data, also $a.N ...) in the static symbols
    void AddDissasmMappingSymbols(DissasmViewer::Settings& settings, Reference<ELF::ELFFile> elf)
    {
        for (size_t index = 0; index < elf->staticSymbols32.size() && index < elf->staticSymbolsNames.size(); index++)
        {
            const auto& name = elf->staticSymbolsNames[index];
            if (name.size() < 2 || name[0] != '$' || (name.size() > 2 && name[2] != '.'))
                continue;
            DissasmViewer::ArmCodeMode mode;
            if (name[1] == 'a')
                mode = DissasmViewer::ArmCodeMode::Arm;
            else if (name[1] == 't')
                mode = DissasmViewer::ArmCodeMode::Thumb;
            else if (name[1] == 'd')
                mode = DissasmViewer::ArmCodeMode::Data;
            else
                continue;
            const auto& symbol = elf->staticSymbols32[index];
            if (symbol.st_shndx == ELF::SHN_UNDEF)
                continue;
            const uint64 offset = elf->VAToFileOffset(symbol.st_value);
            if (offset != ELF::ELF_INVALID_ADDRESS)
                settings.AddArmCodeMode(offset, mode);
        }
    }

    // The functions of the symbols (the static ones of an unstripped file, the exported ones): named labels with their sizes
    void AddDissasmFunctionEntries(DissasmViewer::Settings& settings, Reference<ELF::ELFFile> elf)
    {
        // a function of both tables gets its exported name (an alias of the static one: malloc, not __libc_malloc)
        const bool isArm = !elf->is64 && elf->header32.e_machine == ELF::EM_ARM;
        auto addSymbols  = [&](const auto& symbols, const std::vector<std::string>& names, DissasmViewer::FunctionEntryType type) {
            for (size_t index = 0; index < symbols.size() && index < names.size(); index++)
            {
                const auto& symbol = symbols[index];
                if ((symbol.st_info & 0xF) != ELF::STT_FUNC || symbol.st_shndx == ELF::SHN_UNDEF || symbol.st_value == 0 || names[index].empty())
                    continue;
                // ARM: the bit 0 of a function address is its Thumb mode
                const uint64 value  = isArm ? (symbol.st_value & ~static_cast<uint64>(1)) : symbol.st_value;
                const uint64 offset = elf->VAToFileOffset(value);
                if (offset == ELF::ELF_INVALID_ADDRESS)
                    continue;
                settings.AddFunctionEntry(offset, names[index], type, symbol.st_size);
                if (isArm)
                    settings.AddArmCodeMode(offset, (symbol.st_value & 1) ? DissasmViewer::ArmCodeMode::Thumb : DissasmViewer::ArmCodeMode::Arm);
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

    // The disassembly of the x86 / x64 / AArch64 code: one zone from the first to the last executable section (.init, .plt, .text, .fini),
    // so the calls to the PLT stubs stay inside the zone
    void CreateDissasmView(Reference<GView::View::WindowInterface> win, Reference<ELF::ELFFile> elf)
    {
        const auto machine = elf->is64 ? elf->header64.e_machine : elf->header32.e_machine;
        DissasmViewer::DisassemblyLanguage language;
        if (machine == ELF::EM_X86_64)
            language = DissasmViewer::DisassemblyLanguage::x64;
        else if (machine == ELF::EM_386)
            language = DissasmViewer::DisassemblyLanguage::x86;
        else if (machine == ELF::EM_AARCH64 && elf->is64)
            language = DissasmViewer::DisassemblyLanguage::ARM64;
        else if (machine == ELF::EM_ARM && !elf->is64) // the bit 0 of the entry point: Thumb code
            language = (elf->header32.e_entry & 1) ? DissasmViewer::DisassemblyLanguage::Thumb : DissasmViewer::DisassemblyLanguage::ARM;
        else
            return; // the disassembly view decodes x86 / x64 / AArch64 / ARM
        const bool isArm = machine == ELF::EM_ARM;

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
        // the entry point; a library has none (its functions keep the names of their symbols)
        const uint64 entryVA = elf->is64 ? elf->header64.e_entry : (isArm ? elf->header32.e_entry & ~1u : elf->header32.e_entry);
        uint64 entryPoint    = entryVA != 0 ? elf->VAToFileOffset(entryVA) : ELF::ELF_INVALID_ADDRESS;
        if (entryPoint == ELF::ELF_INVALID_ADDRESS || entryPoint < start || entryPoint >= end)
            entryPoint = DissasmViewer::NO_ENTRY_POINT;

        DissasmViewer::Settings settings;
        settings.AddDisassemblyZone(start, end - start, entryPoint, language);
        for (const uint64 sectionStart : sectionStarts)
            settings.AddInstructionBoundary(sectionStart);
        // the data of the program (.rodata, .data, .data.rel.ro, .got, .init_array, ...): a data zone each; the metadata of the loader
        // (.dynsym, .dynstr, .rela.*, .eh_frame, .note.*, .dynamic, ...) stays in its panels
        const auto addDataSection = [&](size_t index, uint64 flags, uint32 type, uint64 offset, uint64 size) {
            if ((flags & ELF::SHF_ALLOC) == 0 || (flags & ELF::SHF_EXECINSTR) != 0 || type == ELF::SHT_NOBITS || size == 0 || offset >= fileSize)
                return;
            const std::string name = index < elf->sectionNames.size() ? elf->sectionNames[index] : std::string();
            const bool isProgramData = name.starts_with(".rodata") || name.starts_with(".data") || name.starts_with(".got") ||
                                       name.starts_with(".init_array") || name.starts_with(".fini_array") || name.starts_with(".tdata") ||
                                       name.starts_with(".ctors") || name.starts_with(".dtors") || name == ".sdata" || name == ".srodata";
            if (!isProgramData || (offset < end && start < offset + size)) // never inside the code zone
                return;
            settings.AddDataZone(offset, std::min(size, fileSize - offset), language, name);
        };
        if (elf->is64)
        {
            for (size_t index = 0; index < elf->sections64.size(); index++)
            {
                const auto& section = elf->sections64[index];
                addDataSection(index, section.sh_flags, section.sh_type, section.sh_offset, section.sh_size);
            }
        }
        else
        {
            for (size_t index = 0; index < elf->sections32.size(); index++)
            {
                const auto& section = elf->sections32[index];
                addDataSection(index, section.sh_flags, section.sh_type, section.sh_offset, section.sh_size);
            }
        }
        // the uninitialized data (.bss, .sbss, .lbss: no bytes in the file); not the thread local ones (.tbss: their addresses are offsets of
        // the TLS block)
        const auto addUninitializedSection = [&](size_t index, uint64 flags, uint32 type, uint64 address, uint64 size) {
            if (type != ELF::SHT_NOBITS || (flags & ELF::SHF_ALLOC) == 0 || (flags & (ELF::SHF_EXECINSTR | ELF::SHF_TLS)) != 0 || size == 0 || address == 0)
                return;
            const std::string name = index < elf->sectionNames.size() ? elf->sectionNames[index] : std::string(".bss");
            if (name == ".relro_padding") // lld: the page alignment after RELRO, no variables
                return;
            settings.AddUninitializedDataZone(address, size, language, name);
        };
        if (elf->is64)
        {
            for (size_t index = 0; index < elf->sections64.size(); index++)
            {
                const auto& section = elf->sections64[index];
                addUninitializedSection(index, section.sh_flags, section.sh_type, section.sh_addr, section.sh_size);
            }
        }
        else
        {
            for (size_t index = 0; index < elf->sections32.size(); index++)
            {
                const auto& section = elf->sections32[index];
                addUninitializedSection(index, section.sh_flags, section.sh_type, section.sh_addr, section.sh_size);
            }
        }
        // 32 bit x86 position independent code: ebx is the global offset table in the PLT stubs (jmp dword ptr [ebx + 0xc])
        if (machine == ELF::EM_386 && !elf->is64 && elf->header32.e_type == ELF::ET_DYN)
        {
            uint64 gotPlt = 0, got = 0;
            for (size_t index = 0; index < elf->sections32.size() && index < elf->sectionNames.size(); index++)
            {
                if (elf->sectionNames[index] == ".got.plt")
                    gotPlt = elf->sections32[index].sh_addr;
                else if (elf->sectionNames[index] == ".got")
                    got = elf->sections32[index].sh_addr;
            }
            if (gotPlt != 0 || got != 0)
                settings.SetGlobalOffsetTable(gotPlt != 0 ? gotPlt : got);
        }
        settings.SetOffsetTranslationList({ "RVA", "VA" }, &elf->dissasmTranslation);
        AddDissasmImports(settings, elf, win->GetObject());
        if (isArm)
            AddDissasmArmModes(settings, elf, language == DissasmViewer::DisassemblyLanguage::Thumb);
        AddDissasmFunctionEntries(settings, elf); // the Thumb bit of the function symbols
        if (isArm)
            AddDissasmMappingSymbols(settings, elf); // the most precise: the mapping symbols of the assembler
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
