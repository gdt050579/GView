#include "elf.hpp"

using namespace GView::Type::ELF;

ELFFile::ELFFile()
{
}

bool ELFFile::Update()
{
    panelsMask |= (1ULL << (uint8) Panels::IDs::Information);
    panelsMask |= (1ULL << (uint8) Panels::IDs::Segments);
    panelsMask |= (1ULL << (uint8) Panels::IDs::Sections);

    uint64 offset = 0;
    CHECK(obj->GetData().Copy<Elf32_Ehdr>(offset, header32), false, "");
    if (header32.e_ident[EI_CLASS] != ELFCLASS32)
    {
        CHECK(header32.e_ident[EI_CLASS] == ELFCLASS64, false, "");
        CHECK(obj->GetData().Copy<Elf64_Ehdr>(offset, header64), false, "");
        is64 = true;
        offset += sizeof(Elf64_Ehdr);
    }
    else
    {
        offset += sizeof(Elf32_Ehdr);
    }

    if (is64)
    {
        offset = header64.e_phoff;
        for (auto i = 0; i < header64.e_phnum; i++)
        {
            Elf64_Phdr entry{};
            CHECK(obj->GetData().Copy<Elf64_Phdr>(offset, entry), false, "");
            segments64.emplace_back(entry);
            offset += sizeof(entry);
        }
    }
    else
    {
        offset = header32.e_phoff;
        for (auto i = 0; i < header32.e_phnum; i++)
        {
            Elf32_Phdr entry{};
            CHECK(obj->GetData().Copy<Elf32_Phdr>(offset, entry), false, "");
            segments32.emplace_back(entry);
            offset += sizeof(entry);
        }
    }

    if (is64)
    {
        offset = header64.e_shoff;
        for (auto i = 0; i < header64.e_shnum; i++)
        {
            auto& entry = sections64.emplace_back(Elf64_Shdr{});
            CHECK(obj->GetData().Copy<Elf64_Shdr>(offset, entry), false, "");
            offset += sizeof(entry);

            auto& segmentIdx = sectionsToSegments.emplace_back(-1);
            for (auto i = 0; i < segments64.size(); i++)
            {
                const auto& segment = segments64.at(i);
                if (segment.p_vaddr != 0 && entry.sh_addr >= segment.p_vaddr &&
                    entry.sh_addr + entry.sh_size <= segment.p_vaddr + segment.p_filesz)
                {
                    segmentIdx = i;
                    break;
                }
            }
        }

        sectionNames.reserve(header64.e_shnum);

        if (header64.e_shstrndx != SHN_UNDEF && header64.e_shstrndx < SHN_LORESERVE)
        {
            const auto& shstrtab = sections64.at(header64.e_shstrndx);
            auto buffer          = obj->GetData().CopyToBuffer(shstrtab.sh_offset, (uint32) shstrtab.sh_size);
            if (buffer.IsValid())
            {
                for (const auto& section : sections64)
                {
                    const auto name = (char*) (buffer.GetData() + section.sh_name);
                    sectionNames.emplace_back(name);
                }
            }
        }
        else if (header64.e_shstrndx >= SHN_LORESERVE)
        {
            // TODO:
        }
    }
    else
    {
        offset = header32.e_shoff;
        for (auto i = 0; i < header32.e_shnum; i++)
        {
            auto& entry = sections32.emplace_back(Elf32_Shdr{});
            CHECK(obj->GetData().Copy<Elf32_Shdr>(offset, entry), false, "");
            offset += sizeof(entry);

            auto& segmentIdx = sectionsToSegments.emplace_back(-1);
            for (auto i = 0; i < segments32.size(); i++)
            {
                const auto& segment = segments32.at(i);
                if (segment.p_vaddr != 0 && entry.sh_addr >= segment.p_vaddr &&
                    entry.sh_addr + entry.sh_size <= segment.p_vaddr + segment.p_filesz)
                {
                    segmentIdx = i;
                    break;
                }
            }
        }

        sectionNames.reserve(header32.e_shnum);

        if (header32.e_shstrndx != SHN_UNDEF && header32.e_shstrndx < SHN_LORESERVE)
        {
            const auto& shstrtab = sections32.at(header32.e_shstrndx);
            auto buffer          = obj->GetData().CopyToBuffer(shstrtab.sh_offset, shstrtab.sh_size);
            if (buffer.IsValid())
            {
                for (const auto& section : sections32)
                {
                    const auto name = (char*) (buffer.GetData() + section.sh_name);
                    sectionNames.emplace_back(name);
                }
            }
        }
        else if (header32.e_shstrndx >= SHN_LORESERVE)
        {
            // TODO:
        }
    }

    CHECK(ParseGoData(), false, "");
    CHECK(ParseSymbols(), false, "");

    return true;
}

bool ELFFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << ((uint8) id))) != 0;
}

bool ELFFile::ParseGoData()
{
    Buffer noteBuffer;
    if (is64)
    {
        for (const auto& segment : segments64)
        {
            if (segment.p_type == PT_NOTE)
            {
                noteBuffer = obj->GetData().CopyToBuffer(segment.p_offset, (uint32) segment.p_filesz);
            }
        }
    }
    else
    {
        for (const auto& segment : segments32)
        {
            if (segment.p_type == PT_NOTE)
            {
                noteBuffer = obj->GetData().CopyToBuffer(segment.p_offset, segment.p_filesz);
            }
        }
    }

    if (noteBuffer.IsValid() && noteBuffer.GetLength() >= 16)
    {
        nameSize = *(uint32*) noteBuffer.GetData();
        valSize  = *(uint32*) (noteBuffer.GetData() + 4);
        tag      = *(uint32*) (noteBuffer.GetData() + 8);
        noteName = std::string((char*) noteBuffer.GetData() + 12, 4);

        std::string_view noteNameView{ (char*) noteBuffer.GetData() + 12, 4 };
        if (nameSize == 4 && 16ULL + valSize <= noteBuffer.GetLength() && tag == Golang::ELF_GO_BUILD_ID_TAG &&
            noteNameView == Golang::ELF_GO_NOTE)
        {
            pcLnTab.SetBuildId({ (char*) noteBuffer.GetData() + 16, valSize });
        }

        if (nameSize == 4 && 16ULL + valSize <= noteBuffer.GetLength() && tag == Golang::GNU_BUILD_ID_TAG &&
            noteNameView == Golang::ELF_GNU_NOTE)
        {
            gnuString = std::string((char*) noteBuffer.GetData() + 16, valSize);
        }
    }

    // go symbols
    for (auto i = 0U; i < sectionNames.size(); i++)
    {
        auto& name = sectionNames.at(i);
        if (name == ".gopclntab")
        {
            panelsMask |= (1ULL << (uint8) Panels::IDs::GoInformation);

            uint64 bufferOffset       = 0;
            uint64 bufferSize         = 0;
            Golang::Architecture arch = is64 ? Golang::Architecture::x64 : Golang::Architecture::x86;
            if (is64)
            {
                const auto& section = sections64.at(i);
                bufferOffset        = section.sh_offset;
                bufferSize          = section.sh_size;
            }
            else
            {
                const auto& section = sections32.at(i);
                bufferOffset        = section.sh_offset;
                bufferSize          = section.sh_size;
            }

            CHECK(pcLnTab.Process(obj->GetData().CopyToBuffer(bufferOffset, (uint32) bufferSize), arch), false, "");
            break;
        }
    }

    return true;
}

bool ELFFile::ParseSymbols()
{
    if (is64)
    {
        for (auto i = 0; i < sections64.size(); i++)
        {
            const auto& section = sections64.at(i);
            if (section.sh_type == SHT_SYMTAB) /* Static symbol table */
            {
                panelsMask |= (1ULL << (uint8) Panels::IDs::StaticSymbols);

                const auto staticSymbolsBuffer = obj->GetData().CopyToBuffer(section.sh_offset, (uint32) section.sh_size);

                const auto& strtabSection = sections64.at(section.sh_link);
                const auto strtabBuffer   = obj->GetData().CopyToBuffer(strtabSection.sh_offset, (uint32) strtabSection.sh_size);

                auto offset = 0U;
                while (offset < section.sh_size)
                {
                    const auto& sym = staticSymbols64.emplace_back(*(Elf64_Sym*) (staticSymbolsBuffer.GetData() + offset));
                    offset += sizeof(Elf64_Sym);

                    String demangled;
                    const auto str = reinterpret_cast<char*>((char*) (strtabBuffer.GetData() + sym.st_name));
                    if (GView::Utils::Demangle(str, demangled) == false)
                    {
                        demangled = str;
                    }

                    staticSymbolsNames.emplace_back(demangled.GetText());
                }
            }
            else if (section.sh_type == SHT_DYNSYM) /* Dynamic symbol table */
            {
                panelsMask |= (1ULL << (uint8) Panels::IDs::DynamicSymbols);

                const auto dynamicSymbolsBuffer = obj->GetData().CopyToBuffer(section.sh_offset, (uint32) section.sh_size);

                const auto& dstrtabSection = sections64.at(section.sh_link);
                const auto dstrtabBuffer   = obj->GetData().CopyToBuffer(dstrtabSection.sh_offset, (uint32) dstrtabSection.sh_size);

                auto offset = 0U;
                while (offset < section.sh_size)
                {
                    const auto& sym = dynamicSymbols64.emplace_back(*(Elf64_Sym*) (dynamicSymbolsBuffer.GetData() + offset));
                    offset += sizeof(Elf64_Sym);

                    String demangled;
                    const auto str = reinterpret_cast<char*>((char*) (dstrtabBuffer.GetData() + sym.st_name));
                    if (GView::Utils::Demangle(str, demangled) == false)
                    {
                        demangled = str;
                    }

                    dynamicSymbolsNames.emplace_back(demangled.GetText());
                }
            }
        }
    }
    else
    {
        for (auto i = 0; i < sections32.size(); i++)
        {
            const auto& section = sections32.at(i);
            if (section.sh_type == SHT_SYMTAB) /* Static symbol table */
            {
                panelsMask |= (1ULL << (uint8) Panels::IDs::StaticSymbols);

                const auto staticSymbolsBuffer = obj->GetData().CopyToBuffer(section.sh_offset, section.sh_size);

                const auto& strtabSection = sections32.at(section.sh_link);
                const auto strtabBuffer   = obj->GetData().CopyToBuffer(strtabSection.sh_offset, strtabSection.sh_size);

                auto offset = 0U;
                while (offset < section.sh_size)
                {
                    const auto& sym = staticSymbols32.emplace_back(*(Elf32_Sym*) (staticSymbolsBuffer.GetData() + offset));
                    offset += sizeof(Elf32_Sym);

                    String demangled;
                    const auto str = reinterpret_cast<char*>((char*) (strtabBuffer.GetData() + sym.st_name));
                    if (GView::Utils::Demangle(str, demangled) == false)
                    {
                        demangled = str;
                    }

                    staticSymbolsNames.emplace_back(demangled.GetText());
                }
            }
            else if (section.sh_type == SHT_DYNSYM) /* Dynamic symbol table */
            {
                panelsMask |= (1ULL << (uint8) Panels::IDs::DynamicSymbols);

                const auto dynamicSymbolsBuffer = obj->GetData().CopyToBuffer(section.sh_offset, section.sh_size);

                const auto& dstrtabSection = sections32.at(section.sh_link);
                const auto dstrtabBuffer   = obj->GetData().CopyToBuffer(dstrtabSection.sh_offset, dstrtabSection.sh_size);

                auto offset = 0U;
                while (offset < section.sh_size)
                {
                    const auto& sym = dynamicSymbols32.emplace_back(*(Elf32_Sym*) (dynamicSymbolsBuffer.GetData() + offset));
                    offset += sizeof(Elf32_Sym);

                    String demangled;
                    const auto str = reinterpret_cast<char*>((char*) (dstrtabBuffer.GetData() + sym.st_name));
                    if (GView::Utils::Demangle(str, demangled) == false)
                    {
                        demangled = str;
                    }

                    dynamicSymbolsNames.emplace_back(demangled.GetText());
                }
            }
        }
    }

    return true;
}

uint64 ELFFile::TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex)
{
    return ConvertAddress(value, static_cast<AddressType>(fromTranslationIndex), AddressType::FileOffset);
}

uint64 ELFFile::TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex)
{
    return ConvertAddress(value, AddressType::FileOffset, static_cast<AddressType>(toTranslationIndex));
}

uint64 ELFFile::ConvertAddress(uint64 address, AddressType fromAddressType, AddressType toAddressType)
{
    switch (fromAddressType)
    {
    case AddressType::FileOffset:
        switch (toAddressType)
        {
        case AddressType::FileOffset:
            return address;
        case AddressType::VA:
            return FileOffsetToVA(address);
        };
        break;
    case AddressType::VA:
        switch (toAddressType)
        {
        case AddressType::FileOffset:
            return VAToFileOffset(address);
        case AddressType::VA:
            return address;
        };
        break;
    }

    return ELF_INVALID_ADDRESS;
}

uint64 ELFFile::FileOffsetToVA(uint64 fileOffset)
{
    if (is64)
    {
        for (const auto& section : sections64)
        {
            if (section.sh_offset <= fileOffset && fileOffset <= section.sh_offset + section.sh_size)
            {
                auto diff     = fileOffset - section.sh_offset;
                const auto fa = section.sh_addr + diff;
                return fa;
            }
        }
    }
    else
    {
        for (const auto& section : sections32)
        {
            if (section.sh_offset <= fileOffset && fileOffset <= section.sh_offset + section.sh_size)
            {
                auto diff     = fileOffset - section.sh_offset;
                const auto fa = section.sh_addr + diff;
                return fa;
            }
        }
    }

    return ELF_INVALID_ADDRESS;
}

uint64 ELFFile::VAToFileOffset(uint64 virtualAddress)
{
    if (is64)
    {
        for (const auto& section : sections64)
        {
            if (section.sh_addr != 0 && section.sh_addr <= virtualAddress && virtualAddress <= section.sh_addr + section.sh_size)
            {
                auto diff     = virtualAddress - section.sh_addr;
                const auto fa = section.sh_offset + diff;
                return fa;
            }
        }
    }
    else
    {
        for (const auto& section : sections32)
        {
            if (section.sh_addr != 0 && section.sh_addr <= virtualAddress && virtualAddress <= (uint64) section.sh_addr + section.sh_size)
            {
                auto diff     = virtualAddress - section.sh_addr;
                const auto fa = section.sh_offset + diff;
                return fa;
            }
        }
    }

    return ELF_INVALID_ADDRESS;
}

uint64 ELFFile::GetImageBase() const
{
    if (is64)
    {
        for (const auto& segment : segments64)
        {
            if (segment.p_type == PT_LOAD)
            {
                return segment.p_vaddr;
            }
        }
    }
    else
    {
        for (const auto& segment : segments32)
        {
            if (segment.p_type == PT_LOAD)
            {
                return segment.p_vaddr;
            }
        }
    }
    return -1;
}

uint64 ELFFile::GetVirtualSize() const
{
    uint64 vSize = 0;
    if (is64)
    {
        for (const auto& segment : segments64)
        {
            if (segment.p_type == PT_LOAD)
            {
                vSize += segment.p_memsz;
            }
        }
    }
    else
    {
        for (const auto& segment : segments32)
        {
            if (segment.p_type == PT_LOAD)
            {
                vSize += segment.p_memsz;
            }
        }
    }
    return -1;
}

bool ELFFile::GetColorForBuffer(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result)
{
    CHECK(buf.IsValid(), false, "");

    static constexpr auto API_CALL_COLOR       = ColorPair{ Color::White, Color::Silver };
    static constexpr auto API_JUMP_COLOR       = ColorPair{ Color::Yellow, Color::DarkRed };
    static constexpr auto BREAKPOINT_COLOR     = ColorPair{ Color::Magenta, Color::DarkBlue }; // Gray
    static constexpr auto START_FUNCTION_COLOR = ColorPair{ Color::Yellow, Color::Olive };
    static constexpr auto END_FUNCTION_COLOR   = ColorPair{ Color::Black, Color::Olive };
    static constexpr auto EXE_MARKER_COLOR     = ColorPair{ Color::Yellow, Color::DarkRed };

    // maybe add
    // EB (direct jump, signed byte EIP-displacement), E9 (direct jump, signed dword EIP-displacement), E8 (direct call, signed dword
    // EIP-displacement)

    const auto machine = is64 ? header64.e_machine : header32.e_machine;
    auto* p            = buf.begin();
    switch (*p)
    {
    case 0x7F:
        CHECKBK(buf.GetLength() >= 4, "");
        if (*(uint32*) p == 0x464C457F)
        {
            result.start = offset;
            result.end   = offset + 3;
            result.color = EXE_MARKER_COLOR;
            return true;
        }
        break;
    default:
        switch (machine)
        {
        case EM_386:
        case EM_486:
        case EM_860:
        case EM_960:
        case EM_8051:
        case EM_X86_64:
            switch (*p)
            {
            case 0xFF:
                CHECKBK(buf.GetLength() >= 6, "");

                if (p[1] == 0x15) // FF 15 is a CALLN instruction. N stands for near (as opposed to F / FAR) | FF15 (indirect call, absolute
                                  // dword address) | possible call to API
                {
                    auto addr = *(uint32*) (p + 2);
                    if ((addr >= this->memStartOffset) && (addr <= this->memEndOffset))
                    {
                        result.start = offset;
                        result.end   = offset + 5;
                        result.color = API_CALL_COLOR;
                        return true;
                    }
                }
                else if (p[1] == 0x25) // FF25 (indirect jmp, absolute dword address) | possible jump to API
                {
                    auto addr = *(uint32*) (p + 2);
                    if ((addr >= this->memStartOffset) && (addr <= this->memEndOffset))
                    {
                        result.start = offset;
                        result.end   = offset + 5;
                        result.color = API_JUMP_COLOR;
                        return true;
                    }
                }
                break;

            case 0xE8: // not far calls
                CHECKBK(buf.GetLength() >= 6, "");
                {
                    auto addr = *(uint32*) (p + 1);
                    if (p[3] == 0xFF && p[4] == 0xFF)
                    {
                        addr = *(uint16*) (p + 1);
                    }
                    if ((addr >= this->memStartOffset) && (addr <= this->memEndOffset) || addr < obj->GetData().GetSize())
                    {
                        result.start = offset;
                        result.end   = offset + 3;
                        result.color = API_CALL_COLOR;
                        return true;
                    }
                }
                break;
            case 0xE9: // not far jmps
                CHECKBK(buf.GetLength() >= 6, "");
                {
                    auto addr = *(uint32*) (p + 1);
                    if (p[3] == 0xFF && p[4] == 0xFF)
                    {
                        addr = *(uint16*) (p + 1);
                    }
                    if ((addr >= this->memStartOffset) && (addr <= this->memEndOffset) || addr < obj->GetData().GetSize())
                    {
                        result.start = offset;
                        result.end   = offset + 3;
                        result.color = API_JUMP_COLOR;
                        return true;
                    }
                }
                break;

            case 0xCC: // INT 3
                result.start = result.end = offset;
                result.color              = BREAKPOINT_COLOR;
                return true;

            case 0x55: // start of function
                CHECKBK(buf.GetLength() >= 3, "");

                if ((*(uint16*) (p + 1)) == 0xEC8B || // possible `push EBP` followed by MOV ebp, esp
                    (*(uint16*) (p + 1)) == 0xE589    // possible `push EBP` followed by MOV ebp, esp
                )
                {
                    result.start = offset;
                    result.end   = offset + 2;
                    result.color = START_FUNCTION_COLOR;
                    return true;
                }
                break;

            case 0x8B: // end of function
            case 0x89: // end of function
                CHECKBK(buf.GetLength() >= 4, "");

                if (((*(uint16*) (p + 1)) == 0x5DE5 || // possible `MOV esp, EBP` followed by `POP ebp` and `RET`
                     ((*(uint16*) (p + 1)) == 0x5DEC)) &&
                    (p[3] == 0xC3))
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = END_FUNCTION_COLOR;
                    return true;
                }
                break;
            case 0x5D: // end of function => pop ebp | ret
                if (p[1] == 0xC3)
                {
                    result.start = offset;
                    result.end   = offset + 1;
                    result.color = END_FUNCTION_COLOR;
                    return true;
                }
                break;
            }
            break;
        case EM_ARM: // IT WILL NOT COVER ALL THE CASES | TODO: https://github.com/scottt/debugbreak/blob/master/debugbreak.h
        {
            switch (*p)
            {
            case 0x98: //
            case 0xA0: // R3

                if (p[1] == 0x47)
                {
                    result.start = offset;
                    result.end   = offset + 1;
                    result.color = API_CALL_COLOR;
                    return true;
                }
                break;
            case 0xDC: // api call => dc f8 00 f0 ldr.w pc,[r12,#0x0]=>->MSVCRT.DLL::_initterm = 00042f56
                if (p[1] == 0xF8 && p[2] == 0x00 && p[3] == 0xF0)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = API_JUMP_COLOR;
                    return true;
                }
                break;

            case 0x2D: // start of function => 2d e9 00 48 push { r11, lr } | eb 46 mov r11, sp
                if (p[1] == 0xE9 && p[4] == 0xEB && p[5] == 0x46)
                {
                    result.start = offset;
                    result.end   = offset + 5;
                    result.color = START_FUNCTION_COLOR;
                    return true;
                }
                break;

            case 0xBD: // end of function => bd e8 78 88 pop.w { r3, r4, r5, r6, r11, pc }
                if (p[1] == 0xE8)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = END_FUNCTION_COLOR;
                    return true;
                }
                break;

            case 0xFE: // breapoint: UND => FE DE FF E7 in ARM mode
                if (p[1] == 0xDE && p[2] == 0xFF && p[3] == 0xE7)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = BREAKPOINT_COLOR;
                    return true;
                }
                break;
            case 0xBE: // breapoint: BKPT ( BE BE ) in Thumb
                if (p[1] == 0xDE && p[2] == 0xBE)
                {
                    result.start = offset;
                    result.end   = offset + 1;
                    result.color = BREAKPOINT_COLOR;
                    return true;
                }
                break;
            }
        }
        break;
        case EM_AARCH64: // TODO: https://github.com/scottt/debugbreak/blob/master/debugbreak.h
            switch (*p)
            {
                // https://opensource.apple.com/source/xnu/xnu-7195.50.7.100.1/doc/pac.md
                /*
                    - Assembly routines must manually sign the return address with `pacibsp` before
                      pushing it onto the stack, and use an authenticating `retab` instruction in
                      place of `ret`.  xnu provides assembly macros `ARM64_STACK_PROLOG` and
                      `ARM64_STACK_EPILOG` which emit the appropriate instructions for both arm64
                      and arm64e targets.
                */

            case 0x7F: // start of function => 7f 23 03 d5 pacibsp

                if (p[1] == 0x23 && p[2] == 0x03 && p[3] == 0xD5)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = START_FUNCTION_COLOR;
                    return true;
                }
                break;

            case 0xFF: // end of function =>  ff 23 03 d5 autibsp | c0 03 5f d6 ret

                if (p[1] == 0x23 && p[2] == 0x03 && p[3] == 0xD5)
                {
                    result.start = offset;
                    result.end   = offset + 7;
                    result.color = END_FUNCTION_COLOR;
                    return true;
                }
                break;
            case 0xC0: // end of function =>  c0 03 5f d6 ret

                if (p[1] == 0x03 && p[2] == 0x5F && p[3] == 0xD6)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = END_FUNCTION_COLOR;
                    return true;
                }
                break;

            case 0xDE: // __builtin_trap();
                if (p[1] == 0xFF)
                {
                    result.start = offset;
                    result.end   = offset + 1;
                    result.color = BREAKPOINT_COLOR;
                    return true;
                }
                break;
            case 0xFE: // On ARM Linux it's usually an UND opcode (e.g. FE DE FF E7)
                if (p[1] == 0xDE && p[2] == 0xFF && p[3] == 0xE7)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = BREAKPOINT_COLOR;
                    return true;
                }
                break;
            case 0xF7: // raise(SIGTRAP); => blx	104a8 <raise@plt>
                if (p[1] == 0xFF && p[2] == 0xEF && p[3] == 0x8A)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = BREAKPOINT_COLOR;
                    return true;
                }
                break;
            case 0xD4: // __asm__("DCPS1"); / __asm__("DCPS2"); / __asm__("DCPS3");
                if (p[1] == 0xA0 && p[2] == 0x00 && (p[3] == 0x01 || p[3] == 0x02 || p[3] == 0x03))
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = BREAKPOINT_COLOR;
                    return true;
                }
                break;
            case 0x52: // __asm__("DRPS");
                if (p[1] == 0x80 && p[2] == 0x00 && p[3] == 0x00)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = BREAKPOINT_COLOR;
                    return true;
                }
                break;

            default: // api call => 60 02 3f d6 blr x19=>MSVCRT.DLL::_onexit
                if (p[2] == 0x3F && p[3] == 0xD6)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = API_CALL_COLOR;
                    return true;
                }

                /*
                       14002ecfc b0 01 00 d0     adrp       x16,0x140064000
                       14002ed00 10 8a 43 f9     ldr        x16,[x16, #0x710]=>->MSVCRT.DLL::setlocale       = 0006f26c
                       14002ed04 00 02 1f d6     br         x16
                */

                if (buf.GetLength() >= 12)
                {
                    if ((p[3] == 0xD0 || p[3] == 0xB0) && p[7] == 0xF9 && p[11] == 0xD6)
                    {
                        result.start = offset;
                        result.end   = offset + 7;
                        result.color = API_JUMP_COLOR;
                        return true;
                    }
                }
                break;
            }
            break;
        default:
            break;
        }
    }

    return false;
}
