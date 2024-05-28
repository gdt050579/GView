#include "iso.hpp"

#include <queue>
#include <map>

using namespace GView::Type::ISO;

ISOFile::ISOFile()
{
}

bool ISOFile::Update()
{
    {
        auto offset = ECMA_119_SYSTEM_AREA_SIZE;
        MyVolumeDescriptorHeader vdh{};
        do
        {
            CHECK(obj->GetData().Copy<ECMA_119_VolumeDescriptorHeader>(offset, vdh.header), false, "");
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

        CHECK(obj->GetData().Copy<ECMA_119_PrimaryVolumeDescriptor>(entry.offsetInFile, pvd), false, "");

        const auto ptrLocation = pvd.vdd.locationOfTypeLPathTable * pvd.vdd.logicalBlockSize.LSB;
        ECMA_119_PathTableRecord ptr{};
        obj->GetData().Copy<ECMA_119_PathTableRecord>(ptrLocation, ptr);

        /* you can also parse ECMA_119_PathTableRecords

        const auto buffer = obj->GetData().CopyToBuffer(ptrLocation, pvd.vdd.pathTableSize.LSB);
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
        root                 = *reinterpret_cast<ECMA_119_DirectoryRecord*>(&pvd.vdd.directoryEntryForTheRootDirectory);
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
                CHECK(obj->GetData().Copy<ECMA_119_DirectoryRecord>(offset, dr), false, "");

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

bool ISOFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    objects.clear();
    currentItemIndex = 0;
    ECMA_119_DirectoryRecord current{};

    int64 currentOffset;
    if (parent.GetParent().GetHandle() == InvalidItemHandle)
    {
        currentOffset = (int64) root.locationOfExtent.LSB * pvd.vdd.logicalBlockSize.LSB;
    }
    else
    {
        auto data     = parent.GetData<ECMA_119_DirectoryRecord>();
        currentOffset = (uint64) data->locationOfExtent.LSB * pvd.vdd.logicalBlockSize.LSB;
        CHECK(currentOffset != pvd.vdd.logicalBlockSize.LSB, false, "");
    }

    auto i = 0ULL;
    do
    {
        CHECK(obj->GetData().Copy<ECMA_119_DirectoryRecord>(currentOffset, current), false, "");

        if (i > 1 && current.lengthOfDirectoryRecord != 0) // skip '.' & '..'
        {
            objects.emplace_back(current);
        }

        currentOffset += current.lengthOfDirectoryRecord;

        i++;

    } while (current.lengthOfDirectoryRecord != 0);

    return objects.size() > 0;
}

bool ISOFile::PopulateItem(TreeViewItem item)
{
    NumericFormatter nf;
    const static auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, '.' };
    const static auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    const auto& currentObject = objects.at(currentItemIndex);
    item.SetText(std::string_view{ currentObject.fileIdentifier, currentObject.lengthOfFileIdentifier });

    if (currentObject.fileFlags & ECMA_119_FileFlags::Directory)
    {
        item.SetType(
              (currentObject.fileFlags & ECMA_119_FileFlags::Existence) ? TreeViewItem::Type::ErrorInformation
                                                                        : TreeViewItem::Type::Category);
    }
    else
    {
        item.SetType(
              (currentObject.fileFlags & ECMA_119_FileFlags::Existence) ? TreeViewItem::Type::ErrorInformation
                                                                        : TreeViewItem::Type::Normal);
    }

    item.SetPriority(currentObject.fileFlags & ECMA_119_FileFlags::Directory);
    item.SetExpandable(currentObject.fileFlags & ECMA_119_FileFlags::Directory);

    item.SetText(1, nf.ToString((uint64) currentObject.dataLength.LSB, dec));
    item.SetText(2, RecordingDateAndTimeToString(currentObject.recordingDateAndTime));
    item.SetText(3, nf.ToString((uint64) currentObject.locationOfExtent.LSB * pvd.vdd.logicalBlockSize.LSB, hex));
    item.SetText(4, GetECMA_119_FileFlags(currentObject.fileFlags));

    const auto key = DRCRC64(currentObject);
    const auto it  = itemsCache.find(key);
    if (it == itemsCache.end())
    {
        auto res = itemsCache.emplace(std::pair{ key, currentObject });
        item.SetData<ECMA_119_DirectoryRecord>(&res.first->second);
    }
    else
    {
        item.SetData<ECMA_119_DirectoryRecord>(&it->second);
    }

    currentItemIndex++;

    return currentItemIndex != objects.size();
}

void ISOFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    CHECKRET(item.GetParent().GetHandle() != InvalidItemHandle, "");

    auto data         = item.GetData<ECMA_119_DirectoryRecord>();
    const auto offset = (uint64) data->locationOfExtent.LSB * pvd.vdd.logicalBlockSize.LSB;
    const auto length = (uint32) data->dataLength.LSB;
    const auto buffer = obj->GetData().CopyToBuffer(offset, length);

    LocalString<64> ls;
    ls.Format("_0x%x_0x%x.bin", offset, length);
    auto name = std::string{ data->fileIdentifier, data->lengthOfFileIdentifier };
    name.append("_").append(ls.ToStringView());

    LocalUnicodeStringBuilder<64> lus{ ls };
    auto fullPath = std::u16string{ path.data(), path.size() };
    fullPath.append(lus.ToStringView());

    GView::App::OpenBuffer(buffer, name, fullPath, GView::App::OpenMethod::BestMatch);
}
