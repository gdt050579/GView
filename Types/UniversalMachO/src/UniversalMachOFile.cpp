#include "UniversalMachO.hpp"

namespace GView::Type::UniversalMachO
{
UniversalMachOFile::UniversalMachOFile(Reference<GView::Utils::FileCache> file) : header({}), is64(false), shouldSwapEndianess(false), panelsMask(0)
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
        header.magic     = Utils::SwapEndian(header.magic);
        header.nfat_arch = Utils::SwapEndian(header.nfat_arch);
    }

    archs.clear();
    archs.reserve(header.nfat_arch);

    archsInfo.clear();
    archsInfo.reserve(header.nfat_arch);

    if (is64)
    {
        for (decltype(header.nfat_arch) i = 0; i < header.nfat_arch; i++)
        {
            MAC::fat_arch64 fa64;
            CHECK(file->Copy<MAC::fat_arch64>(offset, fa64), false, "");
            if (shouldSwapEndianess)
            {
                fa64.cputype    = Utils::SwapEndian(fa64.cputype);
                fa64.cpusubtype = Utils::SwapEndian(fa64.cpusubtype);
                fa64.offset     = Utils::SwapEndian(fa64.offset);
                fa64.size       = Utils::SwapEndian(fa64.size);
                fa64.align      = Utils::SwapEndian(fa64.align);
                fa64.reserved   = Utils::SwapEndian(fa64.reserved);
            }
            archs.push_back(fa64);
            offset += sizeof(MAC::fat_arch64);

            auto ai = GetArchInfoFromCPUTypeAndSubtype(fa64.cputype, static_cast<uint32_t>(fa64.cpusubtype));
            archsInfo.emplace_back(std::move(ai));
        }
    }
    else
    {
        for (decltype(header.nfat_arch) i = 0; i < header.nfat_arch; i++)
        {
            MAC::fat_arch fa;
            CHECK(file->Copy<MAC::fat_arch>(offset, fa), false, "");

            if (shouldSwapEndianess)
            {
                fa.cputype    = Utils::SwapEndian(fa.cputype);
                fa.cpusubtype = Utils::SwapEndian(fa.cpusubtype);
                fa.offset     = Utils::SwapEndian(fa.offset);
                fa.size       = Utils::SwapEndian(fa.size);
                fa.align      = Utils::SwapEndian(fa.align);
            }
            archs.push_back(fa);
            offset += sizeof(MAC::fat_arch);

            auto ai = GetArchInfoFromCPUTypeAndSubtype(fa.cputype, static_cast<uint32_t>(fa.cpusubtype));
            archsInfo.emplace_back(std::move(ai));
        }
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
} // namespace GView::Type::MachOFB
