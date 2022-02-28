#include "machofb.hpp"
namespace GView::Type::MachOFB
{
MachOFBFile::MachOFBFile(Reference<GView::Utils::FileCache> file)
{
    this->file = file;
}

template <typename T>
T SwapEndian(T u)
{
    union
    {
        T u;
        unsigned char u8[sizeof(T)];
    } source{ u }, dest{};

    for (size_t k = 0; k < sizeof(T); k++)
        dest.u8[k] = source.u8[sizeof(T) - k - 1];

    return dest.u;
}

bool MachOFBFile::Update()
{
    uint64_t offset = 0;

    CHECK(file->Copy<fat_header>(offset, header), false, "");
    offset += sizeof(fat_header);

    is64                = header.magic == FAT_MAGIC_64 || header.magic == FAT_CIGAM_64;
    shouldSwapEndianess = header.magic == FAT_CIGAM || header.magic == FAT_CIGAM_64;

    if (shouldSwapEndianess)
    {
        header.magic     = SwapEndian(header.magic);
        header.nfat_arch = SwapEndian(header.nfat_arch);
    }

    archs64.reserve(header.nfat_arch);

    if (is64)
    {
        for (decltype(header.nfat_arch) i = 0; i < header.nfat_arch; i++)
        {
            fat_arch64 fa64;
            CHECK(file->Copy<fat_arch64>(offset, fa64), false, "");
            if (shouldSwapEndianess)
            {
                fa64.cputype    = SwapEndian(fa64.cputype);
                fa64.cpusubtype = SwapEndian(fa64.cpusubtype);
                fa64.offset     = SwapEndian(fa64.offset);
                fa64.size       = SwapEndian(fa64.size);
                fa64.align      = SwapEndian(fa64.align);
                fa64.reserved   = SwapEndian(fa64.reserved);
            }
            archs64.push_back(fa64);
            offset += sizeof(fat_arch64);
        }
    }
    else
    {
        for (decltype(header.nfat_arch) i = 0; i < header.nfat_arch; i++)
        {
            fat_arch fa;
            CHECK(file->Copy<fat_arch>(offset, fa), false, "");

            if (shouldSwapEndianess)
            {
                fa.cputype    = SwapEndian(fa.cputype);
                fa.cpusubtype = SwapEndian(fa.cpusubtype);
                fa.offset     = SwapEndian(fa.offset);
                fa.size       = SwapEndian(fa.size);
                fa.align      = SwapEndian(fa.align);
            }
            archs.push_back(fa);
            offset += sizeof(fat_arch);
        }
    }

    return true;
}

uint64_t MachOFBFile::TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex)
{
    return value;
}

uint64_t MachOFBFile::TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex)
{
    return value;
}
} // namespace GView::Type::MachOFB
