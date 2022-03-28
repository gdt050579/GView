#include "iso.hpp"

using namespace GView::Type::ISO;

ISOFile::ISOFile(Reference<GView::Utils::FileCache> fileCache)
{
    file = fileCache;
}

bool ISOFile::Update()
{
    auto offset = SYSTEM_AREA_SIZE;
    MyVolumeDescriptorHeader vdh{};
    do
    {
        CHECK(file->Copy<VolumeDescriptorHeader>(offset, vdh.header), false, "");
        vdh.offsetInFile = offset;
        headers.emplace_back(vdh);
        offset += SECTOR_SIZE;
    } while (vdh.header.type != SectorType::SetTerminator);

    return true;
}
