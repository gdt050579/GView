#include "MachO.hpp"

namespace GView::Type::MachO
{
MachOFile::MachOFile(Reference<GView::Utils::FileCache> file) : header({}), is64(false), shouldSwapEndianess(false), panelsMask(0)
{
    this->file = file;
}

bool MachOFile::Update()
{
    uint64_t offset = 0;

    {
        uint32_t magic = 0;
        CHECK(file->Copy<uint32_t>(offset, magic), false, "");

        is64                = magic == MAC::MH_MAGIC_64 || magic == MAC::MH_CIGAM_64;
        shouldSwapEndianess = magic == MAC::MH_CIGAM || magic == MAC::MH_CIGAM_64;
    }

    CHECK(file->Copy<MachO::MAC::mach_header>(offset, header), false, "");
    offset += sizeof(header);
    if (is64 == false)
    {
        offset -= sizeof(MachO::MAC::mach_header::reserved);
    }

    if (shouldSwapEndianess)
    {
        header.magic      = Utils::SwapEndian(header.magic);
        header.cputype    = Utils::SwapEndian(header.cputype);
        header.cpusubtype = Utils::SwapEndian(header.cpusubtype);
        header.filetype   = Utils::SwapEndian(header.filetype);
        header.ncmds      = Utils::SwapEndian(header.ncmds);
        header.sizeofcmds = Utils::SwapEndian(header.sizeofcmds);
        header.flags      = Utils::SwapEndian(header.flags);
    }

    loadCommands.reserve(header.ncmds);
    const auto commandsStartOffset = offset;

    for (decltype(header.ncmds) i = 0; i < header.ncmds; i++)
    {
        MAC::load_command lc{};
        CHECK(file->Copy<MAC::load_command>(offset, lc), false, "");
        if (shouldSwapEndianess)
        {
            lc.cmd     = Utils::SwapEndian(lc.cmd);
            lc.cmdsize = Utils::SwapEndian(lc.cmdsize);
        }
        loadCommands.push_back({ lc, offset });
        offset += lc.cmdsize;
    }

    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::SEGMENT)
        {
            Segment s{};
            CHECK(file->Copy<MAC::segment_command>(lc.offset, s.x86), false, "");
            if (shouldSwapEndianess)
            {
                s.x86.cmd     = Utils::SwapEndian(s.x86.cmd);
                s.x86.cmdsize = Utils::SwapEndian(s.x86.cmdsize);
                for (auto i = 0U; i < sizeof(s.x86.segname) / sizeof(s.x86.segname[0]); i++)
                {
                    s.x86.segname[i] = Utils::SwapEndian(s.x86.segname[i]);
                }
                s.x86.vmaddr   = Utils::SwapEndian(s.x86.vmaddr);
                s.x86.vmsize   = Utils::SwapEndian(s.x86.vmsize);
                s.x86.fileoff  = Utils::SwapEndian(s.x86.fileoff);
                s.x86.filesize = Utils::SwapEndian(s.x86.filesize);
                s.x86.maxprot  = Utils::SwapEndian(s.x86.maxprot);
                s.x86.initprot = Utils::SwapEndian(s.x86.initprot);
                s.x86.nsects   = Utils::SwapEndian(s.x86.nsects);
                s.x86.flags    = Utils::SwapEndian(s.x86.flags);
            }
            segments.emplace_back(s);
        }
        else if (lc.value.cmd == MAC::LoadCommandType::SEGMENT_64)
        {
            Segment s{};
            CHECK(file->Copy<MAC::segment_command_64>(lc.offset, s.x64), false, "");
            if (shouldSwapEndianess)
            {
                s.x64.cmd     = Utils::SwapEndian(s.x64.cmd);
                s.x64.cmdsize = Utils::SwapEndian(s.x64.cmdsize);
                for (auto i = 0U; i < sizeof(s.x64.segname) / sizeof(s.x64.segname[0]); i++)
                {
                    s.x64.segname[i] = Utils::SwapEndian(s.x64.segname[i]);
                }
                s.x64.vmaddr   = Utils::SwapEndian(s.x64.vmaddr);
                s.x64.vmsize   = Utils::SwapEndian(s.x64.vmsize);
                s.x64.fileoff  = Utils::SwapEndian(s.x64.fileoff);
                s.x64.filesize = Utils::SwapEndian(s.x64.filesize);
                s.x64.maxprot  = Utils::SwapEndian(s.x64.maxprot);
                s.x64.initprot = Utils::SwapEndian(s.x64.initprot);
                s.x64.nsects   = Utils::SwapEndian(s.x64.nsects);
                s.x64.flags    = Utils::SwapEndian(s.x64.flags);
            }
            segments.emplace_back(s);
        }
    }

    offset = commandsStartOffset;
    for (const auto& segment : segments)
    {
        if (is64)
        {
            offset += sizeof(MAC::segment_command_64);
            for (auto i = 0U; i < segment.x64.nsects; i++)
            {
                Section s{};
                CHECK(file->Copy<MAC::section_64>(offset, s.x64), false, "");
                if (shouldSwapEndianess)
                {
                    for (auto i = 0U; i < sizeof(s.x64.sectname) / sizeof(s.x64.sectname[0]); i++)
                    {
                        s.x64.sectname[i] = Utils::SwapEndian(s.x64.sectname[i]);
                    }
                    for (auto i = 0U; i < sizeof(s.x64.segname) / sizeof(s.x64.segname[0]); i++)
                    {
                        s.x64.segname[i] = Utils::SwapEndian(s.x64.segname[i]);
                    }
                    s.x64.addr      = Utils::SwapEndian(s.x64.addr);
                    s.x64.size      = Utils::SwapEndian(s.x64.size);
                    s.x64.offset    = Utils::SwapEndian(s.x64.offset);
                    s.x64.align     = Utils::SwapEndian(s.x64.align);
                    s.x64.reloff    = Utils::SwapEndian(s.x64.reloff);
                    s.x64.nreloc    = Utils::SwapEndian(s.x64.nreloc);
                    s.x64.flags     = Utils::SwapEndian(s.x64.flags);
                    s.x64.reserved1 = Utils::SwapEndian(s.x64.reserved1);
                    s.x64.reserved2 = Utils::SwapEndian(s.x64.reserved2);
                    s.x64.reserved3 = Utils::SwapEndian(s.x64.reserved3);
                }
                sections.emplace_back(s);
                offset += sizeof(MAC::section_64);
            }
        }
        else
        {
            for (auto i = 0U; i < segment.x86.nsects; i++)
            {
                Section s{};
                CHECK(file->Copy<MAC::section>(offset, s.x86), false, "");
                if (shouldSwapEndianess)
                {
                    for (auto i = 0U; i < sizeof(s.x86.sectname) / sizeof(s.x86.sectname[0]); i++)
                    {
                        s.x86.sectname[i] = Utils::SwapEndian(s.x86.sectname[i]);
                    }
                    for (auto i = 0U; i < sizeof(s.x86.segname) / sizeof(s.x86.segname[0]); i++)
                    {
                        s.x86.segname[i] = Utils::SwapEndian(s.x86.segname[i]);
                    }
                    s.x86.addr      = Utils::SwapEndian(s.x86.addr);
                    s.x86.size      = Utils::SwapEndian(s.x86.size);
                    s.x86.offset    = Utils::SwapEndian(s.x86.offset);
                    s.x86.align     = Utils::SwapEndian(s.x86.align);
                    s.x86.reloff    = Utils::SwapEndian(s.x86.reloff);
                    s.x86.nreloc    = Utils::SwapEndian(s.x86.nreloc);
                    s.x86.flags     = Utils::SwapEndian(s.x86.flags);
                    s.x86.reserved1 = Utils::SwapEndian(s.x86.reserved1);
                    s.x86.reserved2 = Utils::SwapEndian(s.x86.reserved2);
                }
                sections.emplace_back(s);
                offset += sizeof(MAC::section_64);
            }
        }
    }

    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Information);
    panelsMask |= (1ULL << (uint8_t) Panels::IDs::LoadCommands);

    if (segments.empty() == false)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::Segments);
    }

    if (sections.empty() == false)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::Sections);
    }

    return true;
}

bool MachOFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << ((uint8_t) id))) != 0;
}

uint64_t MachOFile::TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex)
{
    return value;
}

uint64_t MachOFile::TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex)
{
    return value;
}
} // namespace GView::Type::MachO
