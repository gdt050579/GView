#include "iso.hpp"

#include <queue>

using namespace GView::Type::ISO;

ISOFile::ISOFile(Reference<GView::Utils::DataCache> fileCache)
{
    file = fileCache;
}

bool ISOFile::Update()
{
    {
        auto offset = ECMA_119_SYSTEM_AREA_SIZE;
        MyVolumeDescriptorHeader vdh{};
        do
        {
            CHECK(file->Copy<ECMA_119_VolumeDescriptorHeader>(offset, vdh.header), false, "");
            vdh.offsetInFile = offset;
            headers.emplace_back(vdh);
            offset += ECMA_119_SECTOR_SIZE;
        } while (vdh.header.type != SectorType::SetTerminator);
    }

    for (const auto& entry : headers)
    {
        if (entry.header.type != SectorType::Primary)
        {
            continue;
        }

        ECMA_119_PrimaryVolumeDescriptor pvd{};
        CHECK(file->Copy<ECMA_119_PrimaryVolumeDescriptor>(entry.offsetInFile, pvd), false, "");

        const auto ptrLocation = pvd.vdd.locationOfTypeLPathTable * pvd.vdd.logicalBlockSize.LSB;
        ECMA_119_PathTableRecord ptr{};
        file->Copy<ECMA_119_PathTableRecord>(ptrLocation, ptr);

        /* you can also parse ECMA_119_PathTableRecords

        const auto buffer = file->CopyToBuffer(ptrLocation, pvd.vdd.pathTableSize.LSB);
        auto ptrStart     = buffer.GetData();

        ECMA_119_PathTableRecord* ddr = &ptr;
        do
        {
            ptrStart += sizeof(ECMA_119_PathTableRecord) - sizeof(ECMA_119_PathTableRecord::dirID) + ddr->lengthOfDirectoryIdentifier +
                        (ddr->lengthOfDirectoryIdentifier % 2 == 0 ? 0 : 1);
            ddr = (ECMA_119_PathTableRecord*) (ptrStart);
        } while (ptrStart < buffer.GetData() + buffer.GetLength());

         */

        const auto blockSize = pvd.vdd.logicalBlockSize.LSB;
        const auto root      = *reinterpret_cast<ECMA_119_DirectoryRecord*>(&pvd.vdd.directoryEntryForTheRootDirectory);
        auto fileEntryOffset = root.locationOfExtent.LSB * blockSize;
        auto block           = 0;
        CHECK(fileEntryOffset == ptr.locationOfExtent * blockSize, false, "");

        std::queue<ECMA_119_DirectoryRecord> drs;
        drs.emplace(root);

        do
        {
            auto offset = drs.front().locationOfExtent.LSB * pvd.vdd.logicalBlockSize.LSB;
            drs.pop();

            auto i = 0ULL;
            ECMA_119_DirectoryRecord dr{};
            do
            {
                CHECK(file->Copy<ECMA_119_DirectoryRecord>(offset, dr), false, "");

                if (i > 1) // skip '.' & '..'
                {
                    if (dr.fileFlags & ECMA_119_FileFlags::Directory)
                    {
                        drs.emplace(dr);
                    }
                }

                if (dr.lengthOfDirectoryRecord != 0)
                {
                    if (i > 1) // skip '.' & '..'
                    {
                        records.emplace_back(dr);
                    }
                    offset += dr.lengthOfDirectoryRecord;
                }

                i++;

            } while (dr.lengthOfDirectoryRecord != 0);
        } while (drs.empty() == false);

        break;
    }

    return true;
}
