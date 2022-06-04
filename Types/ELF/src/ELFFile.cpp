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
    // go metadata

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
        if (nameSize == 4 && 16ULL + valSize <= noteBuffer.GetLength() && tag == Go::ELF_GO_BUILD_ID_TAG && noteNameView == Go::ELF_GO_NOTE)
        {
            buildId = std::string((char*) noteBuffer.GetData() + 16, valSize);
        }

        if (nameSize == 4 && 16ULL + valSize <= noteBuffer.GetLength() && tag == Go::GNU_BUILD_ID_TAG && noteNameView == Go::ELF_GNU_NOTE)
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
            panelsMask |= (1ULL << (uint8) Panels::IDs::GoFunctions);

            if (is64)
            {
                const auto& section = sections64.at(i);
                pclntab112.buffer   = obj->GetData().CopyToBuffer(section.sh_offset, (uint32) section.sh_size);
                pclntab112.header   = (Go::GoFunctionHeader*) pclntab112.buffer.GetData();

                pclntab112.nfunctab    = *(uint32*) (pclntab112.buffer.GetData() + sizeof(Go::GoFunctionHeader));
                pclntab112.funcdata    = pclntab112.buffer.GetData();
                pclntab112.funcnametab = pclntab112.buffer.GetData();
                pclntab112.functab     = pclntab112.buffer.GetData() + 8 + pclntab112.header->sizeOfUintptr;
                pclntab112.pctab       = pclntab112.buffer.GetData();
                pclntab112.functabsize =
                      (pclntab112.nfunctab * 2 + 1) * pclntab112.header->sizeOfUintptr; // TODO: version >= 1.18 size is fixed to 4
                pclntab112.fileoff  = *(uint32*) (pclntab112.functab + pclntab112.functabsize);
                pclntab112.filetab  = pclntab112.buffer.GetData() + pclntab112.fileoff;
                pclntab112.nfiletab = *(uint32*) pclntab112.filetab;
                pclntab112.filetab  = pclntab112.filetab + pclntab112.nfiletab * 4;

                uint32 offset         = 0;
                auto currentAddress   = (uint64) pclntab112.filetab;
                const auto endAddress = (uint64) pclntab112.buffer.GetData() + pclntab112.buffer.GetLength();
                for (uint32 i = 0; i < pclntab112.nfiletab - 1 && (uint64) currentAddress <= (uint64) endAddress; i++)
                {
                    auto fname                 = (char*) (pclntab112.filetab + offset);
                    const auto& [pair, result] = pclntab112.files.emplace(std::pair<uint32, std::string_view>{ i, fname });
                    offset += (uint32) pair->second.size() + 2;
                    currentAddress = (uint64) pclntab112.filetab + offset;
                }

                offset         = 0U;
                currentAddress = (uint64) pclntab112.functab;
                auto count     = 0U;
                while (count <= pclntab112.nfunctab && (uint64) currentAddress <= (uint64) endAddress)
                {
                    auto entry64 = *((Go::FstEntry64*) pclntab112.functab + count);
                    entries64.emplace_back(entry64);
                    offset += sizeof(Go::FstEntry64);
                    count++;
                }

                for (const auto& entry : entries64)
                {
                    const auto& func = functions64.emplace_back(*(Go::Func64*) (pclntab112.buffer.GetData() + entry.functionOffset));
                    functionsNames.emplace_back((char*) pclntab112.funcnametab + func.name);
                }

                if (functions64.empty() == false)
                {
                    functions64.pop_back();
                    functionsNames.pop_back();
                }
            }
            else
            {
                const auto& section = sections32.at(i);
                pclntab112.buffer   = obj->GetData().CopyToBuffer(section.sh_offset, section.sh_size);
                pclntab112.header   = (Go::GoFunctionHeader*) pclntab112.buffer.GetData();

                pclntab112.nfunctab    = *(uint32*) (pclntab112.buffer.GetData() + sizeof(Go::GoFunctionHeader));
                pclntab112.funcdata    = pclntab112.buffer.GetData();
                pclntab112.funcnametab = pclntab112.buffer.GetData();
                pclntab112.functab     = pclntab112.buffer.GetData() + 8 + pclntab112.header->sizeOfUintptr;
                pclntab112.pctab       = pclntab112.buffer.GetData();
                pclntab112.functabsize =
                      (pclntab112.nfunctab * 2 + 1) * pclntab112.header->sizeOfUintptr; // TODO: version >= 1.18 size is fixed to 4
                pclntab112.fileoff  = *(uint32*) (pclntab112.functab + pclntab112.functabsize);
                pclntab112.filetab  = pclntab112.buffer.GetData() + pclntab112.fileoff;
                pclntab112.nfiletab = *(uint32*) pclntab112.filetab;
                pclntab112.filetab  = pclntab112.filetab + pclntab112.nfiletab * 4;

                uint32 offset         = 0;
                auto currentAddress   = (uint64) pclntab112.filetab;
                const auto endAddress = (uint64) pclntab112.buffer.GetData() + pclntab112.buffer.GetLength();
                for (uint32 i = 0; i < pclntab112.nfiletab - 1 && (uint64) currentAddress <= (uint64) endAddress; i++)
                {
                    auto fname = (char*) (pclntab112.filetab + offset);
                    const auto& [pair, result] =
                          pclntab112.files.emplace(std::pair<uint32, std::string_view>{ pclntab112.nfiletab - i - 1, fname });
                    offset += (uint32) pair->second.size() + 2;
                    currentAddress = (uint64) pclntab112.filetab + offset;
                }

                offset         = 0U;
                currentAddress = (uint64) pclntab112.functab;
                auto count     = 0U;
                while (count <= pclntab112.nfunctab && (uint64) currentAddress <= (uint64) endAddress)
                {
                    auto entry32 = *((Go::FstEntry32*) pclntab112.functab + count);
                    entries32.emplace_back(entry32);
                    offset += sizeof(Go::FstEntry32);
                    count++;
                }

                for (const auto& entry : entries32)
                {
                    const auto& func = functions32.emplace_back(*(Go::Func32*) (pclntab112.buffer.GetData() + entry.functionOffset));
                    functionsNames.emplace_back((char*) pclntab112.funcnametab + func.name);
                }

                if (functions32.empty() == false)
                {
                    functions32.pop_back();
                    functionsNames.pop_back();
                }
            }

            goPlcntabSectionIndex = i;
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
            if (section.sh_addr <= virtualAddress && virtualAddress <= section.sh_addr + section.sh_size)
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
            if (section.sh_addr <= virtualAddress && virtualAddress <= (uint64) section.sh_addr + section.sh_size)
            {
                auto diff     = virtualAddress - section.sh_addr;
                const auto fa = section.sh_offset + diff;
                return fa;
            }
        }
    }

    return ELF_INVALID_ADDRESS;
}
