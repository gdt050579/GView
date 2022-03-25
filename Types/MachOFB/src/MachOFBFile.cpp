#include "Machofb.hpp"
namespace GView::Type::MachOFB
{
template <typename T>
T SwapEndian(T u)
{
    union
    {
        T object;
        unsigned char bytes[sizeof(T)];
    } source{ u }, dest{};

    for (decltype(sizeof(T)) i = 0; i < sizeof(T); i++)
    {
        dest.bytes[i] = source.bytes[sizeof(T) - i - 1];
    }

    return dest.object;
}

MachOFBFile::MachOFBFile(Reference<GView::Utils::FileCache> file) : header({}), is64(false), shouldSwapEndianess(false), panelsMask(0)
{
    this->file = file;
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

    archs.reserve(header.nfat_arch);

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
            archs.push_back(fa64);
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

    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Information);
    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Objects);

    return true;
}

bool MachOFBFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << ((uint8_t) id))) != 0;
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
