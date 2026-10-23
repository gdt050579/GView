#include "elf.hpp"

#include <algorithm>

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

    switch (is64 ? header64.e_machine : header32.e_machine)
    {
    case EM_386:
    case EM_486:
    case EM_860:
    case EM_960:
    case EM_8051:
    case EM_X86_64:
        panelsMask |= (1ULL << (uint8) Panels::IDs::OpCodes);
    default:
        break;
    }

    isLittleEndian = (header32.e_ident[EI_DATA] == ELFDATA2LSB);

    // the program headers: the ones that can be read (a truncated table keeps its first entries)
    const auto readProgramHeaders = [&](auto& segments, auto entry, uint64 tableOffset, uint32 count) {
        for (uint32 index = 0; index < count; index++)
        {
            if (!obj->GetData().Copy(tableOffset + static_cast<uint64>(index) * sizeof(entry), entry))
                break;
            if ((entry.p_flags & PF_X) == PF_X)
                executableZonesFAs.emplace_back(std::pair<uint64, uint64>{ entry.p_offset, entry.p_offset + entry.p_filesz });
            segments.emplace_back(entry);
        }
    };
    if (is64)
        readProgramHeaders(segments64, Elf64_Phdr{}, header64.e_phoff, header64.e_phnum);
    else
        readProgramHeaders(segments32, Elf32_Phdr{}, header32.e_phoff, header32.e_phnum);

    // the section headers: ignored when their table is not in the file: a file stripped of them (sstrip) or whose headers were damaged
    // on purpose is analyzed through its segments (a wrong e_shentsize is ignored: the entries have the size of the class). Every section
    // has a name (empty when the string table is not known), read inside the string table
    const auto readSectionHeaders = [&](auto& sections, const auto& segments, auto entry, uint64 tableOffset, uint32 count, uint32 namesIndex) {
        const uint64 fileSize = obj->GetData().GetSize();
        if (count == 0 || tableOffset == 0 || tableOffset >= fileSize ||
            static_cast<uint64>(count) * sizeof(entry) > fileSize - tableOffset)
            return;
        for (uint32 index = 0; index < count; index++)
        {
            if (!obj->GetData().Copy(tableOffset + static_cast<uint64>(index) * sizeof(entry), entry))
            {
                sections.clear();
                return;
            }
            sections.emplace_back(entry);
        }
        sectionsToSegments.assign(sections.size(), static_cast<uint32>(-1));
        for (size_t index = 0; index < sections.size(); index++)
            for (uint32 segmentIndex = 0; segmentIndex < segments.size(); segmentIndex++)
            {
                const auto& segment = segments[segmentIndex];
                const auto& section = sections[index];
                if (segment.p_vaddr != 0 && section.sh_addr >= segment.p_vaddr && section.sh_addr + section.sh_size <= segment.p_vaddr + segment.p_filesz)
                {
                    sectionsToSegments[index] = segmentIndex;
                    break;
                }
            }
        sectionNames.assign(sections.size(), std::string());
        if (namesIndex == SHN_UNDEF || namesIndex >= sections.size())
            return;
        constexpr uint64 MAX_NAMES_SIZE = 0x1000000;
        const auto& namesSection        = sections[namesIndex];
        if (namesSection.sh_size == 0 || namesSection.sh_size > MAX_NAMES_SIZE)
            return;
        const auto names = obj->GetData().CopyToBuffer(namesSection.sh_offset, static_cast<uint32>(namesSection.sh_size));
        if (!names.IsValid())
            return;
        for (size_t index = 0; index < sections.size(); index++)
            for (uint64 position = sections[index].sh_name; position < names.GetLength() && names.GetData()[position] != 0; position++)
                sectionNames[index].push_back(static_cast<char>(names.GetData()[position]));
    };
    if (is64)
        readSectionHeaders(sections64, segments64, Elf64_Shdr{}, header64.e_shoff, header64.e_shnum, header64.e_shstrndx);
    else
        readSectionHeaders(sections32, segments32, Elf32_Shdr{}, header32.e_shoff, header32.e_shnum, header32.e_shstrndx);

    ParseGoData(); // the Go metadata and the symbols are optional: a malformed table leaves its panel out
    ParseSymbols();
    ParseDynamic(); // a malformed dynamic segment leaves the file as it is

    return true;
}

bool ELFFile::ParseDynamic()
{
    constexpr uint64 MAX_DYNAMIC_ENTRIES = 0x10000;
    constexpr uint64 MAX_SYMBOLS         = 0x100000;
    constexpr uint64 MAX_TABLE_SIZE      = 0x4000000;
    // the entries of PT_DYNAMIC (d_tag, d_val), until DT_NULL
    std::vector<std::pair<int64, uint64>> entries;
    const auto readEntries = [&](uint64 offset, uint64 size) {
        const uint64 entrySize = is64 ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
        for (uint64 position = 0; position + entrySize <= size && entries.size() < MAX_DYNAMIC_ENTRIES; position += entrySize)
        {
            int64 tag    = 0;
            uint64 value = 0;
            if (is64)
            {
                Elf64_Dyn entry{};
                if (!obj->GetData().Copy<Elf64_Dyn>(offset + position, entry))
                    return;
                tag   = static_cast<int64>(entry.d_tag);
                value = entry.d_un.d_val;
            }
            else
            {
                Elf32_Dyn entry{};
                if (!obj->GetData().Copy<Elf32_Dyn>(offset + position, entry))
                    return;
                tag   = static_cast<int32>(entry.d_tag);
                value = entry.d_un.d_val;
            }
            if (tag == DT_NULL)
                return;
            entries.emplace_back(tag, value);
        }
    };
    if (is64)
    {
        for (const auto& segment : segments64)
            if (segment.p_type == PT_DYNAMIC)
                readEntries(segment.p_offset, segment.p_filesz);
    }
    else
    {
        for (const auto& segment : segments32)
            if (segment.p_type == PT_DYNAMIC)
                readEntries(segment.p_offset, segment.p_filesz);
    }
    if (entries.empty())
        return false;
    const auto value = [&entries](int64 tag) -> std::optional<uint64> {
        for (const auto& [entryTag, entryValue] : entries)
            if (entryTag == tag)
                return entryValue;
        return std::nullopt;
    };

    pltGot = value(DT_PLTGOT);

    // the relocation tables
    constexpr int64 DT_ANDROID_REL    = 0x6000000F, DT_ANDROID_RELSZ = 0x60000010;
    constexpr int64 DT_ANDROID_RELA   = 0x60000011, DT_ANDROID_RELASZ = 0x60000012;
    constexpr int64 DT_ANDROID_RELR   = 0x6FFFE000, DT_ANDROID_RELRSZ = 0x6FFFE001;
    constexpr uint32 SHT_ANDROID_REL  = 0x60000001, SHT_ANDROID_RELA = 0x60000002, SHT_ANDROID_RELR = 0x6FFFFF00;
    const auto addTable = [&](int64 addressTag, int64 sizeTag, uint32 type) {
        const auto address = value(addressTag);
        const auto size    = value(sizeTag);
        if (!address.has_value() || !size.has_value() || size.value() == 0 || size.value() > MAX_TABLE_SIZE)
            return;
        const uint64 offset = VAToFileOffset(address.value());
        if (offset != ELF_INVALID_ADDRESS && offset < obj->GetData().GetSize())
            dynamicRelocations.push_back({ offset, size.value(), type });
    };
    addTable(DT_RELA, DT_RELASZ, SHT_RELA);
    addTable(DT_REL, DT_RELSZ, SHT_REL);
    addTable(DT_JMPREL, DT_PLTRELSZ, value(DT_PLTREL).value_or(DT_RELA) == DT_REL ? SHT_REL : SHT_RELA);
    addTable(DT_RELR, DT_RELRSZ, SHT_RELR);
    addTable(DT_ANDROID_REL, DT_ANDROID_RELSZ, SHT_ANDROID_REL);
    addTable(DT_ANDROID_RELA, DT_ANDROID_RELASZ, SHT_ANDROID_RELA);
    addTable(DT_ANDROID_RELR, DT_ANDROID_RELRSZ, SHT_ANDROID_RELR);

    // the dynamic symbols, when no section holds them; their names, when the string table of their section is not known (a damaged
    // sh_link: every name is empty)
    const bool hasNames = std::any_of(dynamicSymbolsNames.begin(), dynamicSymbolsNames.end(), [](const std::string& name) { return !name.empty(); });
    if (!dynamicSymbolsNames.empty() && hasNames)
        return true;
    const auto symbolTable = value(DT_SYMTAB);
    const auto stringTable = value(DT_STRTAB);
    const auto stringSize  = value(DT_STRSZ);
    if (!stringTable.has_value() || !stringSize.has_value() || stringSize.value() > MAX_TABLE_SIZE)
        return false;
    const uint64 stringsOffset = VAToFileOffset(stringTable.value());
    if (stringsOffset == ELF_INVALID_ADDRESS)
        return false;
    const auto strings = obj->GetData().CopyToBuffer(stringsOffset, static_cast<uint32>(stringSize.value()));
    if (!strings.IsValid())
        return false;
    const auto nameAt = [&strings](uint64 offset) {
        std::string name;
        for (uint64 position = offset; position < strings.GetLength() && strings.GetData()[position] != 0; position++)
            name.push_back(static_cast<char>(strings.GetData()[position]));
        String demangled;
        return !name.empty() && GView::Utils::Demangle(name, demangled) ? std::string(demangled.GetText()) : name;
    };
    if (!dynamicSymbolsNames.empty())
    {
        for (size_t index = 0; index < dynamicSymbolsNames.size(); index++)
            dynamicSymbolsNames[index] = nameAt(is64 ? (index < dynamicSymbols64.size() ? dynamicSymbols64[index].st_name : 0)
                                                     : (index < dynamicSymbols32.size() ? dynamicSymbols32[index].st_name : 0));
        return true;
    }
    if (!symbolTable.has_value())
        return false;
    const uint64 symbolSize    = is64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
    const uint64 symbolsOffset = VAToFileOffset(symbolTable.value());
    if (symbolsOffset == ELF_INVALID_ADDRESS)
        return false;
    // the count: the chains of DT_HASH; the last chain of DT_GNU_HASH; else the symbols before the strings
    std::optional<uint64> count;
    if (const auto hash = value(DT_HASH); hash.has_value())
    {
        uint32 header[2] = {};
        const uint64 offset = VAToFileOffset(hash.value());
        if (offset != ELF_INVALID_ADDRESS && obj->GetData().Copy(offset, header))
            count = header[1]; // nchain
    }
    if (!count.has_value())
        if (const auto gnuHash = value(DT_GNU_HASH); gnuHash.has_value())
        {
            const uint64 offset = VAToFileOffset(gnuHash.value());
            uint32 header[4]    = {}; // nbuckets, symoffset, bloom_size, bloom_shift
            if (offset != ELF_INVALID_ADDRESS && obj->GetData().Copy(offset, header) && header[0] < MAX_SYMBOLS && header[2] < MAX_SYMBOLS)
            {
                const uint64 buckets = offset + 16 + static_cast<uint64>(header[2]) * (is64 ? 8 : 4);
                const uint64 chains  = buckets + 4ull * header[0];
                uint32 last          = 0;
                for (uint32 index = 0; index < header[0]; index++)
                {
                    uint32 bucket = 0;
                    if (obj->GetData().Copy<uint32>(buckets + 4ull * index, bucket))
                        last = std::max(last, bucket);
                }
                if (last < header[1])
                    count = header[1];
                else
                {
                    // the end of the chain of the last bucket: the entry with the bit 0 set
                    for (uint32 chain = 0; last < MAX_SYMBOLS && obj->GetData().Copy<uint32>(chains + 4ull * (last - header[1]), chain); last++)
                        if ((chain & 1) != 0)
                            break;
                    count = static_cast<uint64>(last) + 1;
                }
            }
        }
    if (!count.has_value() && stringTable.value() > symbolTable.value())
        count = (stringTable.value() - symbolTable.value()) / symbolSize;
    if (!count.has_value() || count.value() == 0 || count.value() > MAX_SYMBOLS)
        return false;
    const auto symbols = obj->GetData().CopyToBuffer(symbolsOffset, static_cast<uint32>(count.value() * symbolSize));
    if (!symbols.IsValid())
        return false;
    for (uint64 position = 0; position + symbolSize <= symbols.GetLength(); position += symbolSize)
    {
        if (is64)
        {
            Elf64_Sym symbol{};
            memcpy(&symbol, symbols.GetData() + position, sizeof(symbol));
            dynamicSymbols64.push_back(symbol);
            dynamicSymbolsNames.push_back(nameAt(symbol.st_name));
        }
        else
        {
            Elf32_Sym symbol{};
            memcpy(&symbol, symbols.GetData() + position, sizeof(symbol));
            dynamicSymbols32.push_back(symbol);
            dynamicSymbolsNames.push_back(nameAt(symbol.st_name));
        }
    }
    panelsMask |= (1ULL << (uint8) Panels::IDs::DynamicSymbols);
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
        if (nameSize == 4 && 16ULL + valSize <= noteBuffer.GetLength() && tag == Golang::ELF_GO_BUILD_ID_TAG && noteNameView == Golang::ELF_GO_NOTE)
        {
            pcLnTab.SetBuildId({ (char*) noteBuffer.GetData() + 16, valSize });
        }

        if (nameSize == 4 && 16ULL + valSize <= noteBuffer.GetLength() && tag == Golang::GNU_BUILD_ID_TAG && noteNameView == Golang::ELF_GNU_NOTE)
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

            constexpr uint64 MAX_GO_TABLE_SIZE = 0x10000000;
            if (bufferSize > MAX_GO_TABLE_SIZE || !pcLnTab.Process(obj->GetData().CopyToBuffer(bufferOffset, static_cast<uint32>(bufferSize)), arch))
                panelsMask &= ~(1ULL << (uint8) Panels::IDs::GoInformation); // a malformed table: no Go panels
            break;
        }
    }

    return true;
}

bool ELFFile::ParseSymbols()
{
    // the symbol tables (SHT_SYMTAB / SHT_DYNSYM) and their names: the entries that the table holds, the names inside their string table
    // (sh_link); a table or a string table that is not in the file gives no symbols / empty names
    constexpr uint64 MAX_TABLE_SIZE = 0x4000000;
    const auto readTable = [&](const auto& sections, auto symbol, auto& symbols, std::vector<std::string>& names, uint32 tableType, Panels::IDs panel) {
        for (const auto& section : sections)
        {
            if (section.sh_type != tableType || section.sh_size == 0 || section.sh_size > MAX_TABLE_SIZE)
                continue;
            const auto table = obj->GetData().CopyToBuffer(section.sh_offset, static_cast<uint32>(section.sh_size));
            if (!table.IsValid())
                continue;
            Buffer strings;
            if (section.sh_link < sections.size() && sections[section.sh_link].sh_size <= MAX_TABLE_SIZE)
                strings = obj->GetData().CopyToBuffer(sections[section.sh_link].sh_offset, static_cast<uint32>(sections[section.sh_link].sh_size));
            panelsMask |= (1ULL << (uint8) panel);
            for (size_t position = 0; position + sizeof(symbol) <= table.GetLength(); position += sizeof(symbol))
            {
                memcpy(&symbol, table.GetData() + position, sizeof(symbol));
                symbols.emplace_back(symbol);
                std::string name;
                for (uint64 character = symbol.st_name; strings.IsValid() && character < strings.GetLength() && strings.GetData()[character] != 0; character++)
                    name.push_back(static_cast<char>(strings.GetData()[character]));
                String demangled;
                names.emplace_back(!name.empty() && GView::Utils::Demangle(name, demangled) ? std::string(demangled.GetText()) : name);
            }
        }
    };
    if (is64)
    {
        readTable(sections64, Elf64_Sym{}, staticSymbols64, staticSymbolsNames, SHT_SYMTAB, Panels::IDs::StaticSymbols);
        readTable(sections64, Elf64_Sym{}, dynamicSymbols64, dynamicSymbolsNames, SHT_DYNSYM, Panels::IDs::DynamicSymbols);
    }
    else
    {
        readTable(sections32, Elf32_Sym{}, staticSymbols32, staticSymbolsNames, SHT_SYMTAB, Panels::IDs::StaticSymbols);
        readTable(sections32, Elf32_Sym{}, dynamicSymbols32, dynamicSymbolsNames, SHT_DYNSYM, Panels::IDs::DynamicSymbols);
    }
    return true;
}

uint64 DissasmAddressTranslation::TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex)
{
    const uint64 imageBase = elf->GetImageBase() == static_cast<uint64>(-1) ? 0 : elf->GetImageBase();
    switch (fromTranslationIndex)
    {
    case 0: // file offset
        return value;
    case 1: // RVA
        return elf->VAToFileOffset(value + imageBase);
    case 2: // VA
        return elf->VAToFileOffset(value);
    }
    return ELF_INVALID_ADDRESS;
}

uint64 DissasmAddressTranslation::TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex)
{
    if (toTranslationIndex == 0)
        return value;
    const uint64 va = elf->FileOffsetToVA(value);
    if (va == ELF_INVALID_ADDRESS)
        return ELF_INVALID_ADDRESS;
    const uint64 imageBase = elf->GetImageBase() == static_cast<uint64>(-1) ? 0 : elf->GetImageBase();
    if (toTranslationIndex == 1)
        return va >= imageBase ? va - imageBase : ELF_INVALID_ADDRESS;
    return toTranslationIndex == 2 ? va : ELF_INVALID_ADDRESS;
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

namespace
{
// A section that contains the address wins: the end of a section is the start of the next one (lld places .text right after .rodata, at
// another VA). The end of a section matches only when no section contains the address (an address right after the last byte)
// A section whose bytes are not in the file (a damaged header: a huge sh_size) translates nothing.
template <typename Section>
uint64 TranslateBySections(const std::vector<Section>& sections, uint64 value, bool fromFileOffset, uint64 fileSize)
{
    for (int pass = 0; pass < 2; pass++)
    {
        for (const auto& section : sections)
        {
            if (section.sh_type == SHT_NOBITS && pass == 0)
                continue; // no bytes in the file
            if (section.sh_type != SHT_NOBITS && (section.sh_offset > fileSize || section.sh_size > fileSize - section.sh_offset))
                continue; // a damaged header
            const uint64 from = fromFileOffset ? static_cast<uint64>(section.sh_offset) : static_cast<uint64>(section.sh_addr);
            const uint64 to   = fromFileOffset ? static_cast<uint64>(section.sh_addr) : static_cast<uint64>(section.sh_offset);
            if (!fromFileOffset && section.sh_addr == 0)
                continue; // not loaded
            if (fromFileOffset && pass == 0 && (section.sh_flags & SHF_ALLOC) == 0)
                continue; // not loaded: no VA
            const uint64 end = from + section.sh_size;
            if (value >= from && (pass == 0 ? value < end : value <= end))
                return to + (value - from);
        }
    }
    return ELF_INVALID_ADDRESS;
}
} // namespace

// the PT_LOAD segments: the addresses that no (valid) section holds (a file without section headers, a damaged section header, the ELF
// header at the start of the first segment)
template <typename Segment>
uint64 TranslateBySegments(const std::vector<Segment>& segments, uint64 value, bool fromFileOffset)
{
    for (const auto& segment : segments)
    {
        if (segment.p_type != PT_LOAD || segment.p_filesz == 0)
            continue;
        const uint64 from = fromFileOffset ? static_cast<uint64>(segment.p_offset) : static_cast<uint64>(segment.p_vaddr);
        const uint64 to   = fromFileOffset ? static_cast<uint64>(segment.p_vaddr) : static_cast<uint64>(segment.p_offset);
        if (value >= from && value - from < segment.p_filesz)
            return to + (value - from);
    }
    return ELF_INVALID_ADDRESS;
}

uint64 ELFFile::FileOffsetToVA(uint64 fileOffset)
{
    const uint64 fileSize = obj->GetData().GetSize();
    const uint64 va = is64 ? TranslateBySections(sections64, fileOffset, true, fileSize) : TranslateBySections(sections32, fileOffset, true, fileSize);
    if (va != ELF_INVALID_ADDRESS)
        return va;
    return is64 ? TranslateBySegments(segments64, fileOffset, true) : TranslateBySegments(segments32, fileOffset, true);
}

uint64 ELFFile::VAToFileOffset(uint64 virtualAddress)
{
    const uint64 fileSize = obj->GetData().GetSize();
    const uint64 offset   = is64 ? TranslateBySections(sections64, virtualAddress, false, fileSize)
                                 : TranslateBySections(sections32, virtualAddress, false, fileSize);
    if (offset != ELF_INVALID_ADDRESS)
        return offset;
    return is64 ? TranslateBySegments(segments64, virtualAddress, false) : TranslateBySegments(segments32, virtualAddress, false);
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
    return vSize;
}

GView::Utils::JsonBuilderInterface* ELFFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    if (!sectionNames.empty())
        builder->AddStringArray("SectionNames", sectionNames);
    return builder;
}

bool ELFFile::GetColorForBufferIntel(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result)
{
    // const auto imageBase = GetImageBase();
    // const auto vcSize    = GetVirtualSize();

    const auto* p = buf.begin();
    switch (*p)
    {
    case 0xFF:
        if (buf.GetLength() >= 6)
        {
            if (p[1] == 0x15) // possible call to API
            {
                // const uint64 addr = *reinterpret_cast<const uint32_t*>(p + 2);
                // if (addr >= imageBase && addr <= imageBase + vcSize)
                {
                    result.start = offset;
                    result.end   = offset + 5;
                    result.color = INS_CALL_COLOR;
                    return true;
                }
            }
            else if (p[1] == 0x25) // possible jump to API
            {
                // const uint64 addr = *reinterpret_cast<const uint32_t*>(p + 2);
                // if (addr >= imageBase && addr <= imageBase + vcSize)
                {
                    result.start = offset;
                    result.end   = offset + 5;
                    result.color = INS_JUMP_COLOR;
                    return true;
                }
            }
            return false;
        }
        return false;
    case 0xCC: // INT 3
        result.start = result.end = offset;
        result.color              = INS_BREAKPOINT_COLOR;
        return true;
    case 0x55:
        if (buf.GetLength() >= 3)
        {
            if (*reinterpret_cast<const uint16_t*>(p + 1) == 0xEC8B) // possible `push EBP` followed by MOV ebp, sep
            {
                result.start = offset;
                result.end   = offset + 2;
                result.color = START_FUNCTION_COLOR;
                return true;
            }
        }
        return false;
    case 0x8B:
        if (buf.GetLength() >= 4)
        {
            if ((*reinterpret_cast<const uint16_t*>(p + 1) == 0x5DE5) && (p[3] == 0xC3)) // possible `MOV esp, EBP` followed by `POP ebp` and `RET`
            {
                result.start = offset;
                result.end   = offset + 3;
                result.color = END_FUNCTION_COLOR;
                return true;
            }
        }
        return false;
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
        if (((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::Header) == (uint32) GView::Dissasembly::Opcodes::Header))
        {
            if (buf.GetLength() >= 4)
            {
                uint32 magic;
                memcpy(&magic, p, sizeof(magic));
                if (magic == 0x464C457F)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = EXE_MARKER_COLOR;
                    return true;
                } // do not break
            }
        }
        [[fallthrough]];
    default:
        switch (machine)
        {
        case EM_386:
        case EM_486:
        case EM_860:
        case EM_960:
        case EM_8051:
        case EM_X86_64:
            for (const auto& [start, end] : executableZonesFAs)
            {
                if (offset >= start && offset < end)
                {
                    return GetColorForBufferIntel(offset, buf, result);
                }
            }
            break;
        default:
            break;
        }
    }

    return false;
}
