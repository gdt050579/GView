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
    panelsMask |= (1ULL << (uint8) Panels::IDs::OpCodes);

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

bool ELFFile::GetColorForBufferForIntel(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result)
{
    const auto mode = is64 ? GView::Dissasembly::Mode::X64 : GView::Dissasembly::Mode::X32;

    GView::Dissasembly::Instruction ins{ 0 };
    if (is64)
    {
        CHECK(GView::Dissasembly::DissasembleInstructionIntelx64(buf, offset, ins), false, "");
    }
    else
    {
        CHECK(GView::Dissasembly::DissasembleInstructionIntelx86(buf, offset, ins), false, "");
    }

    switch ((GView::Dissasembly::InstructionX86) ins.id)
    {
    case GView::Dissasembly::InstructionX86::CALL:
    {
        CHECKBK(((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::Call) == (uint32) GView::Dissasembly::Opcodes::Call), "");
        result.start = offset;
        result.end   = offset + ins.size;
        result.color = INS_CALL_COLOR;
        return true;
    }
    case GView::Dissasembly::InstructionX86::LCALL:
    {
        CHECKBK(((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::LCall) == (uint32) GView::Dissasembly::Opcodes::LCall), "");
        result.start = offset;
        result.end   = offset + ins.size;
        result.color = INS_LCALL_COLOR;
        return true;
    }
    case GView::Dissasembly::InstructionX86::JMP:
    {
        CHECKBK(((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::Jmp) == (uint32) GView::Dissasembly::Opcodes::Jmp), "");
        result.start = offset;
        result.end   = offset + ins.size;
        result.color = INS_JUMP_COLOR;
        return true;
    }
    case GView::Dissasembly::InstructionX86::LJMP:
    {
        CHECKBK(((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::LJmp) == (uint32) GView::Dissasembly::Opcodes::LJmp), "");
        result.start = offset;
        result.end   = offset + ins.size;
        result.color = INS_LJUMP_COLOR;
        return true;
    }
    case GView::Dissasembly::InstructionX86::INT:
    case GView::Dissasembly::InstructionX86::INT1:
    case GView::Dissasembly::InstructionX86::INT3:
    case GView::Dissasembly::InstructionX86::INTO:
    {
        CHECKBK(
              ((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::Breakpoint) == (uint32) GView::Dissasembly::Opcodes::Breakpoint),
              "");
        result.start = offset;
        result.end   = offset + ins.size;
        result.color = INS_BREAKPOINT_COLOR;
        return true;
    }
    case GView::Dissasembly::InstructionX86::PUSH:
    case GView::Dissasembly::InstructionX86::PUSHAW:
    case GView::Dissasembly::InstructionX86::PUSHAL:
    case GView::Dissasembly::InstructionX86::PUSHF:
    case GView::Dissasembly::InstructionX86::PUSHFD:
    case GView::Dissasembly::InstructionX86::PUSHFQ:
    {
        CHECKBK(
              ((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::FunctionStart) ==
               (uint32) GView::Dissasembly::Opcodes::FunctionStart),
              "");
        result.start = offset;
        result.end   = offset + ins.size;

        bool ok = is64 ? GView::Dissasembly::DissasembleInstructionIntelx64(buf, offset, ins)
                       : GView::Dissasembly::DissasembleInstructionIntelx86(buf, offset, ins);
        if (ok)
        {
            switch ((GView::Dissasembly::InstructionX86) ins.id)
            {
            case GView::Dissasembly::InstructionX86::MOV:
            case GView::Dissasembly::InstructionX86::MOVABS:
            case GView::Dissasembly::InstructionX86::MOVAPD:
            case GView::Dissasembly::InstructionX86::MOVAPS:
            case GView::Dissasembly::InstructionX86::MOVBE:
            case GView::Dissasembly::InstructionX86::MOVDDUP:
            case GView::Dissasembly::InstructionX86::MOVDIR64B:
            case GView::Dissasembly::InstructionX86::MOVDIRI:
            case GView::Dissasembly::InstructionX86::MOVDQA:
            case GView::Dissasembly::InstructionX86::MOVDQU:
            case GView::Dissasembly::InstructionX86::MOVHLPS:
            case GView::Dissasembly::InstructionX86::MOVHPD:
            case GView::Dissasembly::InstructionX86::MOVHPS:
            case GView::Dissasembly::InstructionX86::MOVLHPS:
            case GView::Dissasembly::InstructionX86::MOVLPD:
            case GView::Dissasembly::InstructionX86::MOVLPS:
            case GView::Dissasembly::InstructionX86::MOVMSKPD:
            case GView::Dissasembly::InstructionX86::MOVMSKPS:
            case GView::Dissasembly::InstructionX86::MOVNTDQA:
            case GView::Dissasembly::InstructionX86::MOVNTDQ:
            case GView::Dissasembly::InstructionX86::MOVNTI:
            case GView::Dissasembly::InstructionX86::MOVNTPD:
            case GView::Dissasembly::InstructionX86::MOVNTPS:
            case GView::Dissasembly::InstructionX86::MOVNTSD:
            case GView::Dissasembly::InstructionX86::MOVNTSS:
            case GView::Dissasembly::InstructionX86::MOVSB:
            case GView::Dissasembly::InstructionX86::MOVSD:
            case GView::Dissasembly::InstructionX86::MOVSHDUP:
            case GView::Dissasembly::InstructionX86::MOVSLDUP:
            case GView::Dissasembly::InstructionX86::MOVSQ:
            case GView::Dissasembly::InstructionX86::MOVSS:
            case GView::Dissasembly::InstructionX86::MOVSW:
            case GView::Dissasembly::InstructionX86::MOVSX:
            case GView::Dissasembly::InstructionX86::MOVSXD:
            case GView::Dissasembly::InstructionX86::MOVUPD:
            case GView::Dissasembly::InstructionX86::MOVUPS:
            case GView::Dissasembly::InstructionX86::MOVZX:
            {
                result.end += ins.size;
                result.color = START_FUNCTION_COLOR;
                return true;
            }
            default:
                break;
            }
        }
        return false;
    }
    case GView::Dissasembly::InstructionX86::IRET:
    case GView::Dissasembly::InstructionX86::IRETD:
    case GView::Dissasembly::InstructionX86::IRETQ:
    case GView::Dissasembly::InstructionX86::RET:
    case GView::Dissasembly::InstructionX86::RETF:
    case GView::Dissasembly::InstructionX86::RETFQ:
    case GView::Dissasembly::InstructionX86::SYSRET:
    case GView::Dissasembly::InstructionX86::SYSRETQ:
    {
        CHECKBK(
              ((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::FunctionEnd) == (uint32) GView::Dissasembly::Opcodes::FunctionEnd),
              "");
        result.start = offset;
        result.end   = offset + ins.size;
        result.color = END_FUNCTION_COLOR;
        return true;
    }
    default:
        break;
    }

    return false;
}

bool ELFFile::GetColorForBuffer(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result)
{
    CHECK(buf.IsValid(), false, "");
    result.color = ColorPair{ Color::Transparent, Color::Transparent };
    CHECK(showOpcodesMask != 0, false, "");

    const auto machine = is64 ? header64.e_machine : header32.e_machine;
    auto* p            = buf.begin();
    switch (*p)
    {
    case 0x7F:
        CHECKBK(((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::Header) == (uint32) GView::Dissasembly::Opcodes::Header), "");
        CHECKBK(buf.GetLength() >= 4, "");
        if (*(uint32*) p == 0x464C457F)
        {
            result.start = offset;
            result.end   = offset + 3;
            result.color = EXE_MARKER_COLOR;
            return true;
        } // do not break
    default:
        switch (machine)
        {
        case EM_386:
        case EM_486:
        case EM_860:
        case EM_960:
        case EM_8051:
        case EM_X86_64:
            return GetColorForBufferForIntel(offset, buf, result);
        default:
            break;
        }
    }

    return false;
}
