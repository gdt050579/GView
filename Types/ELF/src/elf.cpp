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

    // The exception handling of GCC / clang: the call sites of the LSDA of each FDE of .eh_frame (.gcc_except_table) that have a landing
    // pad (VAs), the types their catches take: the entries of the type table, a typeinfo object or the slot that points to it (DW.ref.*,
    // an indirect entry: the loader fills it, AddDissasmImports reads its relocation into `typeinfoSlots`)
    struct DissasmTypeinfoSlot
    {
        uint64 value = 0; // the VA of the typeinfo (a relative relocation, a symbol of the file)
        std::string name; // the typeinfo of another module (the symbol of an absolute relocation)
    };
    struct DissasmLandingPads
    {
        struct CatchType
        {
            uint64 value;  // the typeinfo, or the slot of an indirect entry; 0: a catch-all
            bool indirect; // `value` is a slot of typeinfoSlots
            bool known;    // the entry was read (its encoding is supported)
        };
        struct CallSite
        {
            uint64 begin, end, pad;
            bool isCleanup;
            std::vector<CatchType> types;
        };
        std::vector<CallSite> callSites;
        std::unordered_map<uint64, DissasmTypeinfoSlot> typeinfoSlots;
        std::vector<std::pair<uint64, uint64>> frameRanges; // every FDE: the start and the length of a function or of a fragment of one (VAs)
    };

    // a value of the exception tables (DW_EH_PE_*): the format of the low 4 bits, absolute or relative to its own address (pcrel: `address`
    // is the VA of data[0]); a raw 0 is a null pointer. The other applications (textrel, datarel, funcrel, aligned) are not read. The
    // indirect bit (0x80) is the caller's
    bool ReadEhValue(const uint8* data, size_t size, size_t& position, uint8 encoding, uint64 address, bool is64, uint64& value)
    {
        const auto readUnsigned = [&](size_t bytes) {
            if (position + bytes > size)
                return false;
            value = 0;
            for (size_t index = 0; index < bytes; index++)
                value |= static_cast<uint64>(data[position + index]) << (8 * index);
            position += bytes;
            return true;
        };
        const auto readSigned = [&](size_t bytes) {
            if (!readUnsigned(bytes))
                return false;
            if (bytes < 8 && (value >> (8 * bytes - 1)) & 1)
                value |= ~static_cast<uint64>(0) << (8 * bytes);
            return true;
        };
        const auto readLeb = [&](bool isSigned) {
            value          = 0;
            uint32 shift   = 0;
            uint8 byte     = 0x80;
            for (; (byte & 0x80) != 0; shift += 7)
            {
                if (position >= size || shift > 63)
                    return false;
                byte = data[position++];
                value |= static_cast<uint64>(byte & 0x7F) << shift;
            }
            if (isSigned && shift < 64 && (byte & 0x40))
                value |= ~static_cast<uint64>(0) << shift;
            return true;
        };
        const uint64 fieldAddress = address + position;
        bool read                 = false;
        switch (encoding & 0x0F)
        {
        case 0x00:
            read = readUnsigned(is64 ? 8 : 4);
            break;
        case 0x01:
            read = readLeb(false);
            break;
        case 0x02:
            read = readUnsigned(2);
            break;
        case 0x03:
            read = readUnsigned(4);
            break;
        case 0x04:
            read = readUnsigned(8);
            break;
        case 0x09:
            read = readLeb(true);
            break;
        case 0x0A:
            read = readSigned(2);
            break;
        case 0x0B:
            read = readSigned(4);
            break;
        case 0x0C:
            read = readSigned(8);
            break;
        default:
            return false;
        }
        if (!read)
            return false;
        const uint8 application = encoding & 0x70;
        if (application == 0x10 && value != 0)
            value += fieldAddress;
        else if (application != 0x00 && application != 0x10)
            return false;
        if (!is64)
            value &= 0xFFFFFFFF;
        return true;
    }

    void ReadDissasmLandingPads(Reference<ELF::ELFFile> elf, Reference<GView::Object> obj, DissasmLandingPads& result)
    {
        constexpr uint64 MAX_TABLE_SIZE      = 0x4000000; // 64 MB of .eh_frame / .gcc_except_table
        constexpr size_t MAX_CALL_SITES      = 0x40000;
        constexpr uint32 MAX_ACTION_RECORDS  = 64; // the catches of one call site
        // the address, the file offset and the size of a section, by its name
        const auto findSection = [&](std::string_view name, uint64& address, uint64& offset, uint64& size) {
            const size_t count = elf->is64 ? elf->sections64.size() : elf->sections32.size();
            for (size_t index = 0; index < count && index < elf->sectionNames.size(); index++)
            {
                if (elf->sectionNames[index] != name)
                    continue;
                address = elf->is64 ? elf->sections64[index].sh_addr : elf->sections32[index].sh_addr;
                offset  = elf->is64 ? elf->sections64[index].sh_offset : elf->sections32[index].sh_offset;
                size    = elf->is64 ? elf->sections64[index].sh_size : elf->sections32[index].sh_size;
                const uint32 type = elf->is64 ? elf->sections64[index].sh_type : elf->sections32[index].sh_type;
                return type != ELF::SHT_NOBITS && size > 0 && size <= MAX_TABLE_SIZE && offset < obj->GetData().GetSize();
            }
            return false;
        };
        constexpr uint64 MAX_FRAME_RANGE  = 0x1000000; // 16 MB of code in one FDE
        constexpr size_t MAX_FRAME_RANGES = 0x100000;
        uint64 frameAddress = 0, frameOffset = 0, frameSize = 0, tableAddress = 0, tableOffset = 0, tableSize = 0;
        if (!findSection(".eh_frame", frameAddress, frameOffset, frameSize))
            return;
        const auto frameBuffer = obj->GetData().CopyToBuffer(frameOffset, static_cast<uint32>(frameSize));
        // without .gcc_except_table (C code): the ranges of the FDEs only
        Buffer tableBuffer;
        if (findSection(".gcc_except_table", tableAddress, tableOffset, tableSize))
            tableBuffer = obj->GetData().CopyToBuffer(tableOffset, static_cast<uint32>(tableSize));
        if (!frameBuffer.IsValid())
            return;
        const uint8* frame     = frameBuffer.GetData();
        const size_t frameEnd  = frameBuffer.GetLength();
        const uint8* table     = tableBuffer.IsValid() ? tableBuffer.GetData() : nullptr;
        const size_t tableEnd  = tableBuffer.IsValid() ? tableBuffer.GetLength() : 0;
        const bool is64        = elf->is64;
        uint64 unused          = 0;

        // the LSDA of the function at `start`: its call sites with a landing pad (a cleanup, the types of the catches of their actions)
        const auto readLsda = [&](uint64 lsda, uint64 start) {
            if (!table || lsda < tableAddress || lsda - tableAddress >= tableEnd)
                return;
            size_t position = static_cast<size_t>(lsda - tableAddress);
            uint64 landingPadBase = start;
            const uint8 landingPadEncoding = table[position++];
            if (landingPadEncoding != 0xFF && !ReadEhValue(table, tableEnd, position, landingPadEncoding, tableAddress, is64, landingPadBase))
                return;
            if (position >= tableEnd)
                return;
            const uint8 typeEncoding = table[position++];
            std::optional<size_t> typeBase; // the type table ends there (its entries are read backwards)
            if (typeEncoding != 0xFF)
            {
                uint64 typeOffset = 0;
                if (!ReadEhValue(table, tableEnd, position, 0x01, tableAddress, is64, typeOffset) || typeOffset > tableEnd - position)
                    return;
                typeBase = position + static_cast<size_t>(typeOffset);
            }
            if (position >= tableEnd)
                return;
            const uint8 callSiteEncoding = table[position++];
            uint64 callSitesLength       = 0;
            if (!ReadEhValue(table, tableEnd, position, 0x01, tableAddress, is64, callSitesLength) || callSitesLength > tableEnd - position)
                return;
            const size_t callSitesEnd = position + static_cast<size_t>(callSitesLength);
            const size_t actionTable  = callSitesEnd;
            // the size of an entry of the type table (the LEB128 formats have none)
            size_t typeSize = 0;
            switch (typeEncoding & 0x0F)
            {
            case 0x00:
                typeSize = is64 ? 8 : 4;
                break;
            case 0x02:
            case 0x0A:
                typeSize = 2;
                break;
            case 0x03:
            case 0x0B:
                typeSize = 4;
                break;
            case 0x04:
            case 0x0C:
                typeSize = 8;
                break;
            }
            while (position < callSitesEnd && result.callSites.size() < MAX_CALL_SITES)
            {
                uint64 siteStart = 0, siteLength = 0, landingPad = 0, action = 0;
                // the start and the length of a call site are offsets from the start of the function, its landing pad from the base
                if (!ReadEhValue(table, callSitesEnd, position, callSiteEncoding & 0x0F, tableAddress, is64, siteStart) ||
                    !ReadEhValue(table, callSitesEnd, position, callSiteEncoding & 0x0F, tableAddress, is64, siteLength) ||
                    !ReadEhValue(table, callSitesEnd, position, callSiteEncoding & 0x0F, tableAddress, is64, landingPad) ||
                    !ReadEhValue(table, callSitesEnd, position, 0x01, tableAddress, is64, action))
                    return;
                if (landingPad == 0 || siteLength == 0)
                    continue; // no landing pad: the unwinding goes on to the caller
                DissasmLandingPads::CallSite site{ start + siteStart, start + siteStart + siteLength, landingPadBase + landingPad, action == 0, {} };
                // the action records (filter, offset of the next one): 0 a cleanup, > 0 the index of a type (catch), < 0 an exception
                // specification
                size_t record = tableEnd;
                if (action != 0 && action - 1 < tableEnd - actionTable)
                    record = actionTable + static_cast<size_t>(action - 1);
                for (uint32 count = 0; count < MAX_ACTION_RECORDS && record < tableEnd; count++)
                {
                    uint64 filter = 0, next = 0;
                    if (!ReadEhValue(table, tableEnd, record, 0x09, tableAddress, is64, filter))
                        break;
                    const size_t nextField = record;
                    if (!ReadEhValue(table, tableEnd, record, 0x09, tableAddress, is64, next))
                        break;
                    const int64 index = static_cast<int64>(filter);
                    if (index == 0)
                        site.isCleanup = true;
                    else if (index > 0)
                    {
                        DissasmLandingPads::CatchType type{ 0, false, false };
                        if (typeBase.has_value() && typeSize != 0 && static_cast<uint64>(index) <= typeBase.value() / typeSize)
                        {
                            size_t entry = typeBase.value() - static_cast<size_t>(index) * typeSize;
                            if (ReadEhValue(table, tableEnd, entry, typeEncoding & 0x7F, tableAddress, is64, type.value))
                            {
                                type.known    = true;
                                type.indirect = (typeEncoding & 0x80) != 0 && type.value != 0;
                                if (type.indirect)
                                    result.typeinfoSlots.emplace(type.value, DissasmTypeinfoSlot{});
                            }
                        }
                        site.types.push_back(type);
                    }
                    const int64 offset = static_cast<int64>(next);
                    if (offset == 0 || (offset < 0 && static_cast<uint64>(-offset) > nextField))
                        break;
                    record = static_cast<size_t>(static_cast<int64>(nextField) + offset);
                }
                result.callSites.push_back(std::move(site));
            }
        };

        // the CIEs (their encodings of the FDE pointers and of the LSDA), by their offset in .eh_frame; their FDEs follow them
        struct CieEncodings
        {
            uint8 pointers;
            uint8 lsda;
            bool hasAugmentationData;
        };
        std::unordered_map<size_t, CieEncodings> cies;
        size_t position = 0;
        while (position + 4 <= frameEnd && result.callSites.size() < MAX_CALL_SITES)
        {
            const size_t recordOffset = position;
            uint64 length             = 0;
            ReadEhValue(frame, frameEnd, position, 0x03, frameAddress, is64, length);
            if (length == 0)
                break; // the terminator
            if (length == 0xFFFFFFFF && !ReadEhValue(frame, frameEnd, position, 0x04, frameAddress, is64, length))
                break;
            if (length > frameEnd - position || length < 4)
                break;
            const size_t recordEnd = position + static_cast<size_t>(length);
            const size_t idField   = position;
            uint64 id              = 0;
            ReadEhValue(frame, recordEnd, position, 0x03, frameAddress, is64, id);
            if (id == 0)
            {
                // a CIE: its version, its augmentation string ("zR", "zPLR"), the alignments, the return register, the augmentation data
                CieEncodings encodings{ 0x00, 0xFF, false };
                const uint8 version = position < recordEnd ? frame[position++] : 0;
                std::string augmentation;
                while (position < recordEnd && frame[position] != 0 && augmentation.size() < 16)
                    augmentation.push_back(static_cast<char>(frame[position++]));
                position++;
                if (version >= 4)
                    position += 2; // the address size, the segment size
                bool valid = position < recordEnd && ReadEhValue(frame, recordEnd, position, 0x01, frameAddress, is64, unused) &&
                             ReadEhValue(frame, recordEnd, position, 0x09, frameAddress, is64, unused);
                if (valid && version == 1)
                    position++;
                else if (valid)
                    valid = ReadEhValue(frame, recordEnd, position, 0x01, frameAddress, is64, unused);
                if (valid && !augmentation.empty() && augmentation[0] == 'z')
                {
                    uint64 dataLength = 0;
                    valid             = ReadEhValue(frame, recordEnd, position, 0x01, frameAddress, is64, dataLength) && dataLength <= recordEnd - position;
                    encodings.hasAugmentationData = true;
                    for (size_t index = 1; valid && index < augmentation.size() && position < recordEnd; index++)
                    {
                        if (augmentation[index] == 'L')
                            encodings.lsda = frame[position++];
                        else if (augmentation[index] == 'R')
                            encodings.pointers = frame[position++];
                        else if (augmentation[index] == 'P')
                        {
                            const uint8 personality = frame[position++];
                            valid                   = ReadEhValue(frame, recordEnd, position, personality & 0x7F, frameAddress, is64, unused);
                        }
                        else if (augmentation[index] != 'S' && augmentation[index] != 'B' && augmentation[index] != 'G')
                            break; // not known: the rest of its data is not read
                    }
                }
                if (valid)
                    cies[recordOffset] = encodings;
            }
            else if (id <= idField)
            {
                // an FDE: its CIE (the offset back from the field), the start of its function, the length, its LSDA
                const auto cie = cies.find(idField - static_cast<size_t>(id));
                uint64 start = 0, range = 0, lsda = 0, dataLength = 0;
                if (cie != cies.end() && ReadEhValue(frame, recordEnd, position, cie->second.pointers & 0x7F, frameAddress, is64, start) &&
                    ReadEhValue(frame, recordEnd, position, cie->second.pointers & 0x0F, frameAddress, is64, range) && start != 0)
                {
                    if (range != 0 && range <= MAX_FRAME_RANGE && result.frameRanges.size() < MAX_FRAME_RANGES)
                        result.frameRanges.emplace_back(start, range);
                    if (cie->second.lsda != 0xFF && (cie->second.lsda & 0x80) == 0 && cie->second.hasAugmentationData &&
                        ReadEhValue(frame, recordEnd, position, 0x01, frameAddress, is64, dataLength) && dataLength <= recordEnd - position &&
                        ReadEhValue(frame, position + static_cast<size_t>(dataLength), position, cie->second.lsda & 0x7F, frameAddress, is64, lsda) && lsda != 0)
                        readLsda(lsda, start);
                }
            }
            position = recordEnd;
        }
    }

    // the ranges of the FDEs (ReadDissasmLandingPads) as file offsets: the code of one function or of one fragment (a stripped file: no
    // start of the prologue rules inside, GCC's frame set up after the early exits); not the ones of the PLT (one FDE for all the stubs)
    void AddDissasmCodeRanges(DissasmViewer::Settings& settings, Reference<ELF::ELFFile> elf, const DissasmLandingPads& tables)
    {
        std::vector<std::pair<uint64, uint64>> plt;
        const size_t count = elf->is64 ? elf->sections64.size() : elf->sections32.size();
        for (size_t index = 0; index < count && index < elf->sectionNames.size(); index++)
            if (elf->sectionNames[index].starts_with(".plt"))
                plt.emplace_back(elf->is64 ? elf->sections64[index].sh_addr : elf->sections32[index].sh_addr,
                                 elf->is64 ? elf->sections64[index].sh_size : elf->sections32[index].sh_size);
        for (const auto& [start, length] : tables.frameRanges)
        {
            if (std::any_of(plt.begin(), plt.end(), [start](const auto& section) { return start >= section.first && start - section.first < section.second; }))
                continue;
            const uint64 first = elf->VAToFileOffset(start);
            const uint64 last  = elf->VAToFileOffset(start + length - 1);
            if (first != ELF::ELF_INVALID_ADDRESS && last != ELF::ELF_INVALID_ADDRESS && last - first == length - 1)
                settings.AddCodeRange(first, length);
        }
    }

    // the call sites of the exception handling (ReadDissasmLandingPads) as file offsets, the names of the types of their catches (the
    // typeinfo objects: "typeinfo for std::runtime_error" -> std::runtime_error)
    void AddDissasmLandingPads(DissasmViewer::Settings& settings, Reference<ELF::ELFFile> elf, const DissasmLandingPads& landingPads)
    {
        if (landingPads.callSites.empty())
            return;
        constexpr std::string_view TYPEINFO = "typeinfo for ";
        std::unordered_map<uint64, std::string_view> typeinfos; // the typeinfo objects of the file, by VA
        const auto addTypeinfos = [&](const auto& symbols, const std::vector<std::string>& names) {
            for (size_t index = 0; index < symbols.size() && index < names.size(); index++)
                if (symbols[index].st_shndx != ELF::SHN_UNDEF && names[index].starts_with(TYPEINFO))
                    typeinfos.emplace(symbols[index].st_value, std::string_view(names[index]).substr(TYPEINFO.size()));
        };
        if (elf->is64)
        {
            addTypeinfos(elf->dynamicSymbols64, elf->dynamicSymbolsNames);
            addTypeinfos(elf->staticSymbols64, elf->staticSymbolsNames);
        }
        else
        {
            addTypeinfos(elf->dynamicSymbols32, elf->dynamicSymbolsNames);
            addTypeinfos(elf->staticSymbols32, elf->staticSymbolsNames);
        }
        const auto typeName = [&](const DissasmLandingPads::CatchType& type) -> std::string {
            if (!type.known)
                return "?";
            if (type.value == 0)
                return "...";
            uint64 value = type.value;
            if (type.indirect)
            {
                const auto slot = landingPads.typeinfoSlots.find(type.value);
                if (slot == landingPads.typeinfoSlots.end())
                    return "?";
                if (!slot->second.name.empty())
                    return slot->second.name.starts_with(TYPEINFO) ? slot->second.name.substr(TYPEINFO.size()) : slot->second.name;
                value = slot->second.value;
            }
            const auto typeinfo = typeinfos.find(value);
            return typeinfo != typeinfos.end() ? std::string(typeinfo->second) : "?";
        };
        std::vector<DissasmViewer::LandingPad> pads;
        pads.reserve(landingPads.callSites.size());
        for (const auto& site : landingPads.callSites)
        {
            const uint64 begin = elf->VAToFileOffset(site.begin);
            const uint64 last  = elf->VAToFileOffset(site.end - 1);
            const uint64 pad   = elf->VAToFileOffset(site.pad);
            if (begin == ELF::ELF_INVALID_ADDRESS || last == ELF::ELF_INVALID_ADDRESS || pad == ELF::ELF_INVALID_ADDRESS || last < begin)
                continue;
            DissasmViewer::LandingPad landingPad{ begin, last + 1, pad, site.isCleanup, {} };
            for (const auto& type : site.types)
                landingPad.catchTypes.push_back(typeName(type));
            pads.push_back(std::move(landingPad));
        }
        settings.AddLandingPads(pads);
    }

    // The imports of the code: the GOT slots of the dynamic relocations (the PLT stubs jump through them, -fno-plt calls use them), named
    // after their dynamic symbols; the memory mappings of the disassembly are keyed by the RVA of the slot. The slots of `typeinfoSlots`
    // (the indirect entries of the type tables of the exception handling) get the typeinfo their relocation points to
    void AddDissasmImports(
          DissasmViewer::Settings& settings, Reference<ELF::ELFFile> elf, Reference<GView::Object> obj, std::unordered_map<uint64, DissasmTypeinfoSlot>& typeinfoSlots)
    {
        // a slot of a type table: the typeinfo its relocation points to (a VA of the file, or the name of an import)
        const auto setTypeinfo = [&](uint64 slot, uint64 value, const std::string* name) {
            if (const auto typeinfo = typeinfoSlots.find(slot); typeinfo != typeinfoSlots.end())
            {
                typeinfo->second.value = value;
                if (name)
                    typeinfo->second.name = *name;
            }
        };
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
        // the functions an ifunc resolves (STT_GNU_IFUNC: memcpy, strlen of glibc), by the address of their resolver: the slot of an IRELATIVE
        // relocation (the internal PLT of libc: its calls of its own memcpy) is named after its function, the PLT stub j_memcpy
        constexpr uint8 STT_GNU_IFUNC = 10;
        std::unordered_map<uint64, std::string> ifuncNames;
        for (const auto* table : { &elf->dynamicSymbols64, &elf->staticSymbols64 })
        {
            const auto& tableNames = table == &elf->dynamicSymbols64 ? elf->dynamicSymbolsNames : elf->staticSymbolsNames;
            for (size_t index = 0; index < table->size() && index < tableNames.size(); index++)
            {
                const auto& symbol = (*table)[index];
                if ((symbol.st_info & 0xF) == STT_GNU_IFUNC && symbol.st_shndx != ELF::SHN_UNDEF && symbol.st_value != 0 && !tableNames[index].empty())
                    ifuncNames.emplace(symbol.st_value, tableNames[index]); // .dynsym first: the exported name (memcpy, not __GI_memcpy)
            }
        }
        auto addPointer = [&](uint64 slot, uint64 symbolIndex, uint64 type, int64 addend) {
            bool isRelative = false, isAbsolute = false, isIfunc = false;
            if (machine == ELF::EM_X86_64)
            {
                isRelative = type == ELF::R_X86_64_RELATIVE || type == ELF::R_X86_64_IRELATIVE;
                isAbsolute = type == ELF::R_X86_64_64;
                isIfunc    = type == ELF::R_X86_64_IRELATIVE;
            }
            else if (machine == ELF::EM_AARCH64)
            {
                isRelative = type == ELF::R_AARCH64_RELATIVE || type == R_AARCH64_IRELATIVE;
                isAbsolute = type == ELF::R_AARCH64_ABS64;
                isIfunc    = type == R_AARCH64_IRELATIVE;
            }
            if (!isRelative && !isAbsolute)
                return;
            if (isIfunc && slot >= imageBase)
                if (const auto ifunc = ifuncNames.find(static_cast<uint64>(addend)); ifunc != ifuncNames.end())
                    settings.AddMemoryMapping(slot - imageBase, ifunc->second, DissasmViewer::MemoryMappingType::FunctionMapping);
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
                    setTypeinfo(slot, 0, &elf->dynamicSymbolsNames[symbolIndex]);
                    value = 0;
                }
                else
                    value += symbol.st_value;
            }
            if (value != 0)
                setTypeinfo(slot, value, nullptr);
            const uint64 offset = elf->VAToFileOffset(slot);
            if (offset != ELF::ELF_INVALID_ADDRESS)
                settings.AddRelocatedPointer(offset, value);
        };
        constexpr uint64 MAX_RELOCATIONS_SIZE = 0x1000000; // 16 MB of relocations
        // 32 bit REL: a pointer to a symbol (R_386_32 / R_ARM_ABS32: a vtable entry, the vptr / the name of a typeinfo); the addend is the
        // value in the file. A symbol of another module: named after it; a symbol of the file (preemptible in a shared object): its value.
        // R_386_RELATIVE / R_ARM_RELATIVE: the value in place is the pointer
        constexpr unsigned R_ARM_ABS32    = 2;
        constexpr unsigned R_ARM_RELATIVE = 23;
        constexpr unsigned R_386_RELATIVE = 8;
        auto addPointer32                 = [&](uint64 slot, uint64 symbolIndex, uint64 type) {
            const bool isAbsolute = (machine == ELF::EM_386 && type == ELF::R_386_32) || (machine == ELF::EM_ARM && type == R_ARM_ABS32);
            const bool isRelative = (machine == ELF::EM_386 && type == R_386_RELATIVE) || (machine == ELF::EM_ARM && type == R_ARM_RELATIVE);
            if ((!isAbsolute && !isRelative) || slot < imageBase)
                return;
            const uint64 offset = elf->VAToFileOffset(slot);
            uint32 addend       = 0;
            if (offset == ELF::ELF_INVALID_ADDRESS || !obj->GetData().Copy<uint32>(offset, addend))
                return;
            if (isRelative) // the image base (0 here) plus the value in place: a pointer of the file (a vtable entry, a callback)
            {
                settings.AddRelocatedPointer(offset, addend);
                setTypeinfo(slot, addend, nullptr);
                return;
            }
            if (symbolIndex == 0 || symbolIndex >= elf->dynamicSymbols32.size())
                return;
            const auto& symbol = elf->dynamicSymbols32[symbolIndex];
            if (symbol.st_shndx != ELF::SHN_UNDEF)
            {
                settings.AddRelocatedPointer(offset, static_cast<uint32>(symbol.st_value + addend));
                setTypeinfo(slot, static_cast<uint32>(symbol.st_value + addend), nullptr);
                return;
            }
            if (symbolIndex >= elf->dynamicSymbolsNames.size() || elf->dynamicSymbolsNames[symbolIndex].empty())
                return;
            addImportPointer(slot, symbolIndex, static_cast<int32>(addend));
            setTypeinfo(slot, 0, &elf->dynamicSymbolsNames[symbolIndex]);
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
        // the packed relocations: RELR (-z pack-relative-relocs: the relative relocations, their addend in place) and Android APS2
        // (--pack-dyn-relocs=android: every relocation, decoded as the ones of the REL / RELA sections)
        constexpr uint32 SHT_ANDROID_REL  = 0x60000001;
        constexpr uint32 SHT_ANDROID_RELA = 0x60000002;
        constexpr uint32 SHT_ANDROID_RELR = 0x6fffff00;
        auto readPackedRelocations        = [&](uint64 offset, uint64 size, uint32 type) {
            if (size == 0 || size > MAX_RELOCATIONS_SIZE || offset >= obj->GetData().GetSize())
                return;
            const auto buffer = obj->GetData().CopyToBuffer(offset, static_cast<uint32>(size));
            if (type == ELF::SHT_RELR || type == SHT_ANDROID_RELR)
            {
                std::vector<uint64> addresses;
                GView::Utils::DecodeElfRelr(buffer, elf->is64, addresses);
                for (const uint64 address : addresses)
                {
                    // R_*_RELATIVE: the image base (0 here) plus the value in place
                    const uint64 fileOffset = elf->VAToFileOffset(address);
                    if (fileOffset == ELF::ELF_INVALID_ADDRESS)
                        continue;
                    uint64 value = 0;
                    uint32 value32 = 0;
                    const bool read = elf->is64 ? obj->GetData().Copy<uint64>(fileOffset, value) : obj->GetData().Copy<uint32>(fileOffset, value32);
                    if (read)
                    {
                        settings.AddRelocatedPointer(fileOffset, elf->is64 ? value : value32);
                        setTypeinfo(address, elf->is64 ? value : value32, nullptr);
                    }
                }
                return;
            }
            const bool isRela = type == SHT_ANDROID_RELA;
            std::vector<GView::Utils::ElfRelocation> relocations;
            GView::Utils::DecodeAndroidPackedRelocations(buffer, isRela, relocations);
            for (const auto& relocation : relocations)
            {
                const uint64 symbol = elf->is64 ? ELF64_R_SYM(relocation.info) : ELF32_R_SYM(static_cast<uint32>(relocation.info));
                const uint64 kind   = elf->is64 ? ELF64_R_TYPE(relocation.info) : ELF32_R_TYPE(static_cast<uint32>(relocation.info));
                addSlot(relocation.offset, symbol, kind);
                addCopy(relocation.offset, symbol, kind);
                if (isRela && elf->is64)
                    addPointer(relocation.offset, symbol, kind, relocation.addend);
                else if (!isRela && !elf->is64)
                    addPointer32(relocation.offset, symbol, kind);
            }
        };
        const auto readSection = [&](uint64 offset, uint64 size, uint32 type) {
            if (type == ELF::SHT_RELA || type == ELF::SHT_REL)
                readRelocations(offset, size, type);
            else if (type == ELF::SHT_RELR || type == SHT_ANDROID_RELR || type == SHT_ANDROID_REL || type == SHT_ANDROID_RELA)
                readPackedRelocations(offset, size, type);
        };
        bool hasRelocationSections = false;
        const auto isRelocationSection = [&](uint32 type) {
            return type == ELF::SHT_RELA || type == ELF::SHT_REL || type == ELF::SHT_RELR || type == SHT_ANDROID_RELR || type == SHT_ANDROID_REL ||
                   type == SHT_ANDROID_RELA;
        };
        if (elf->is64)
        {
            for (const auto& section : elf->sections64)
            {
                hasRelocationSections |= isRelocationSection(section.sh_type);
                readSection(section.sh_offset, section.sh_size, section.sh_type);
            }
        }
        else
        {
            for (const auto& section : elf->sections32)
            {
                hasRelocationSections |= isRelocationSection(section.sh_type);
                readSection(section.sh_offset, section.sh_size, section.sh_type);
            }
        }
        // a file without section headers (sstrip): the tables of the dynamic segment
        if (!hasRelocationSections)
            for (const auto& table : elf->dynamicRelocations)
                readSection(table.fileOffset, table.size, table.type);
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
        // a function of both tables gets its exported name (an alias of the static one: malloc, not __libc_malloc); of the exported names of
        // one function the public one (close, fclose, strdup, not the reserved __close, _IO_fclose, __strdup of glibc: the first export of a
        // function keeps its name, the public ones are added first)
        const bool isArm = !elf->is64 && elf->header32.e_machine == ELF::EM_ARM;
        enum class Names : uint8 { All, Public, Reserved };
        auto addSymbols = [&](const auto& symbols, const std::vector<std::string>& names, DissasmViewer::FunctionEntryType type, Names which) {
            for (size_t index = 0; index < symbols.size() && index < names.size(); index++)
            {
                const auto& symbol = symbols[index];
                if ((symbol.st_info & 0xF) != ELF::STT_FUNC || symbol.st_shndx == ELF::SHN_UNDEF || symbol.st_value == 0 || names[index].empty())
                    continue;
                if (which != Names::All && (names[index][0] == '_') != (which == Names::Reserved))
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
            addSymbols(elf->staticSymbols64, elf->staticSymbolsNames, DissasmViewer::FunctionEntryType::Symbol, Names::All);
            addSymbols(elf->dynamicSymbols64, elf->dynamicSymbolsNames, DissasmViewer::FunctionEntryType::Export, Names::Public);
            addSymbols(elf->dynamicSymbols64, elf->dynamicSymbolsNames, DissasmViewer::FunctionEntryType::Export, Names::Reserved);
        }
        else
        {
            addSymbols(elf->staticSymbols32, elf->staticSymbolsNames, DissasmViewer::FunctionEntryType::Symbol, Names::All);
            addSymbols(elf->dynamicSymbols32, elf->dynamicSymbolsNames, DissasmViewer::FunctionEntryType::Export, Names::Public);
            addSymbols(elf->dynamicSymbols32, elf->dynamicSymbolsNames, DissasmViewer::FunctionEntryType::Export, Names::Reserved);
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
        // a file without section headers (sstrip): the executable PT_LOAD segments
        const bool hasSections = elf->is64 ? !elf->sections64.empty() : !elf->sections32.empty();
        const auto forEachLoad = [&](auto&& callback) {
            if (elf->is64)
            {
                for (const auto& segment : elf->segments64)
                    if (segment.p_type == ELF::PT_LOAD)
                        callback(static_cast<uint32>(segment.p_flags), static_cast<uint64>(segment.p_offset), static_cast<uint64>(segment.p_filesz),
                                 static_cast<uint64>(segment.p_vaddr), static_cast<uint64>(segment.p_memsz));
            }
            else
            {
                for (const auto& segment : elf->segments32)
                    if (segment.p_type == ELF::PT_LOAD)
                        callback(static_cast<uint32>(segment.p_flags), static_cast<uint64>(segment.p_offset), static_cast<uint64>(segment.p_filesz),
                                 static_cast<uint64>(segment.p_vaddr), static_cast<uint64>(segment.p_memsz));
            }
        };
        if (!hasSections)
            forEachLoad([&](uint32 flags, uint64 offset, uint64 size, uint64, uint64) {
                if ((flags & ELF::PF_X) != 0)
                    addSection(ELF::SHF_EXECINSTR, ELF::SHT_PROGBITS, offset, size);
            });
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
        // a file without section headers: the other PT_LOAD segments are the data (LOAD_R / LOAD_RW), the part of a writable one past its
        // bytes the uninitialized data
        if (!hasSections)
            forEachLoad([&](uint32 flags, uint64 offset, uint64 size, uint64 address, uint64 memorySize) {
                if ((flags & ELF::PF_X) != 0)
                    return;
                const std::string name = (flags & ELF::PF_W) != 0 ? "LOAD_RW" : "LOAD_R";
                if (size > 0 && offset < fileSize && !(offset < end && start < offset + size))
                    settings.AddDataZone(offset, std::min(size, fileSize - offset), language, name);
                if ((flags & ELF::PF_W) != 0 && memorySize > size && address != 0)
                    settings.AddUninitializedDataZone(address + size, memorySize - size, language, name + "_bss");
            });
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
            if (gotPlt == 0 && got == 0 && elf->pltGot.has_value())
                gotPlt = elf->pltGot.value(); // a file without section headers: DT_PLTGOT
            if (gotPlt != 0 || got != 0)
                settings.SetGlobalOffsetTable(gotPlt != 0 ? gotPlt : got);
        }
        settings.SetOffsetTranslationList({ "RVA", "VA" }, &elf->dissasmTranslation);
        DissasmLandingPads landingPads; // the slots of their typeinfo objects are relocated
        ReadDissasmLandingPads(elf, win->GetObject(), landingPads);
        AddDissasmImports(settings, elf, win->GetObject(), landingPads.typeinfoSlots);
        AddDissasmLandingPads(settings, elf, landingPads);
        AddDissasmCodeRanges(settings, elf, landingPads);
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
