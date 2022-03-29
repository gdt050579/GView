#include "UniversalMachO.hpp"

namespace GView::Type::UniversalMachO
{
UniversalMachOFile::UniversalMachOFile(Reference<GView::Utils::FileCache> file)
    : header({}), is64(false), shouldSwapEndianess(false), panelsMask(0)
{
    this->file = file;
}

bool UniversalMachOFile::Update()
{
    uint64_t offset = 0;

    CHECK(file->Copy<MAC::fat_header>(offset, header), false, "");
    offset += sizeof(MAC::fat_header);

    is64                = header.magic == MAC::FAT_MAGIC_64 || header.magic == MAC::FAT_CIGAM_64;
    shouldSwapEndianess = header.magic == MAC::FAT_CIGAM || header.magic == MAC::FAT_CIGAM_64;

    if (shouldSwapEndianess)
    {
        Swap(header);
    }

    archs.clear();
    archs.reserve(header.nfat_arch);

    for (decltype(header.nfat_arch) i = 0; i < header.nfat_arch; i++)
    {
        MAC::Arch arch{};
        if (is64)
        {
            MAC::fat_arch64 fa64;
            CHECK(file->Copy<MAC::fat_arch64>(offset, fa64), false, "");
            if (shouldSwapEndianess)
            {
                Swap(fa64);
            }
            offset += sizeof(MAC::fat_arch64);

            arch.cputype    = fa64.cputype;
            arch.cpusubtype = fa64.cpusubtype;
            arch.offset     = fa64.offset;
            arch.size       = fa64.size;
            arch.align      = fa64.align;
            arch.reserved   = fa64.reserved;
        }
        else
        {
            MAC::fat_arch fa;
            CHECK(file->Copy<MAC::fat_arch>(offset, fa), false, "");
            if (shouldSwapEndianess)
            {
                Swap(fa);
            }
            offset += sizeof(MAC::fat_arch);

            arch.cputype    = fa.cputype;
            arch.cpusubtype = fa.cpusubtype;
            arch.offset     = fa.offset;
            arch.size       = fa.size;
            arch.align      = fa.align;
        }

        MAC::mach_header mh{};
        CHECK(file->Copy<MAC::mach_header>(arch.offset, mh), false, "");
        if (mh.magic == MAC::MH_CIGAM || mh.magic == MAC::MH_CIGAM_64)
        {
            Swap(mh);
        }

        arch.filetype = mh.filetype;

        arch.info = MAC::GetArchInfoFromCPUTypeAndSubtype(arch.cputype, arch.cpusubtype);
        archs.emplace_back(arch);
    }

    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Information);
    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Objects);

    return true;
}

bool UniversalMachOFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << (static_cast<uint8_t>(id)))) != 0;
}

uint64_t UniversalMachOFile::TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex)
{
    return value;
}

uint64_t UniversalMachOFile::TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex)
{
    return value;
}
} // namespace GView::Type::UniversalMachO
