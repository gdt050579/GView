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

    if (is64)
    {
        // for (decltype(header.nfat_arch) i = 0; i < header.nfat_arch; i++)
        //{
        //     fat_arch64 fa64;
        //     CHECK(file->Copy<fat_arch64>(offset, fa64), false, "");
        //     if (shouldSwapEndianess)
        //     {
        //         fa64.cputype    = SwapEndian(fa64.cputype);
        //         fa64.cpusubtype = SwapEndian(fa64.cpusubtype);
        //         fa64.offset     = SwapEndian(fa64.offset);
        //         fa64.size       = SwapEndian(fa64.size);
        //         fa64.align      = SwapEndian(fa64.align);
        //         fa64.reserved   = SwapEndian(fa64.reserved);
        //     }
        //     archs.push_back(fa64);
        //     offset += sizeof(fat_arch64);
        // }
    }
    else
    {
        // for (decltype(header.nfat_arch) i = 0; i < header.nfat_arch; i++)
        //{
        //     fat_arch fa;
        //     CHECK(file->Copy<fat_arch>(offset, fa), false, "");
        //
        //     if (shouldSwapEndianess)
        //     {
        //         fa.cputype    = SwapEndian(fa.cputype);
        //         fa.cpusubtype = SwapEndian(fa.cpusubtype);
        //         fa.offset     = SwapEndian(fa.offset);
        //         fa.size       = SwapEndian(fa.size);
        //         fa.align      = SwapEndian(fa.align);
        //     }
        //     archs.push_back(fa);
        //     offset += sizeof(fat_arch);
        // }
    }

    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Information);
    panelsMask |= (1ULL << (uint8_t) Panels::IDs::LoadCommands);

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
