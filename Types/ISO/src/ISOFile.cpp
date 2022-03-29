#include "iso.hpp"

using namespace GView::Type::ISO;

ISOFile::ISOFile(Reference<GView::Utils::FileCache> fileCache)
{
    file = fileCache;
}

bool ISOFile::Update()
{
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
    }

    for (const auto& entry : headers)
    {
        if (entry.header.type != SectorType::Primary)
        {
            continue;
        }

        PrimaryVolumeDescriptor pvd{};
        CHECK(file->Copy<PrimaryVolumeDescriptor>(entry.offsetInFile, pvd), false, "");

        const auto blockSize = pvd.vdd.logicalBlockSize.LSB;
        const auto root      = *reinterpret_cast<DirectoryRecord*>(&pvd.vdd.directoryEntryForTheRootDirectory);
        auto fileEntryOffset = root.locationOfExtent.LSB * blockSize;
        DirectoryRecord dr{};
        do
        {
            CHECK(file->Copy<DirectoryRecord>(fileEntryOffset, dr), false, "");
            records.emplace_back(dr);
            fileEntryOffset += dr.lengthOfDirectoryRecord;
        } while ((dr.fileFlags & FileFlags::MultiExtent) || records.size() < 3);

        break;
    }

    return true;
}
