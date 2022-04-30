#include "LNK.hpp"

using namespace GView::Type::LNK;

LNKFile::LNKFile()
{
}

bool LNKFile::Update()
{
    auto offset = 0;
    CHECK(obj->GetData().Copy<Header>(offset, header), false, "");
    offset += sizeof(header);

    if (header.linkFlags & (uint32) LNK::LinkFlags::HasTargetIDList)
    {
        CHECK(obj->GetData().Copy<LinkTargetIDList>(offset, linkTargetIDList), false, "");
        offset += sizeof(LinkTargetIDList);
        linkTargetIDListBuffer = obj->GetData().CopyToBuffer(offset, linkTargetIDList.IDListSize);
        CHECK(linkTargetIDListBuffer.IsValid(), false, "");

        auto offset2 = 0;
        while (offset2 < linkTargetIDList.IDListSize - 2) // - terminal
        {
            const auto itemID = itemIDS.emplace_back((ItemID*) &linkTargetIDListBuffer.GetData()[offset2]);
            offset2 += itemID->ItemIDSize;
        }
        offset += offset2 + 2;
    }

    if (header.linkFlags & (uint32) LNK::LinkFlags::HasLinkInfo)
    {
        CHECK(obj->GetData().Copy<LocationInformation>(offset, locationInformation), false, "");
        locationInformationBuffer = obj->GetData().CopyToBuffer(offset, locationInformation.size);
        CHECK(locationInformationBuffer.IsValid(), false, "");
        offset += locationInformation.size;

        if (locationInformation.headerSize > 28)
        {
            unicodeLocalPathOffset                = *(uint32*) (locationInformationBuffer.GetData() + sizeof(LocationInformation));
            const auto unicodeLocalPathOffsetSize = wcslen((wchar_t*) (locationInformationBuffer.GetData() + unicodeLocalPathOffset));
            unicodeLocalPath = { (char16*) (locationInformationBuffer.GetData() + unicodeLocalPathOffset), unicodeLocalPathOffsetSize };

            if (locationInformation.headerSize > 32)
            {
                unicodeCommonPathOffset =
                      *(uint32*) (locationInformationBuffer.GetData() + sizeof(LocationInformation) + sizeof(unicodeLocalPathOffset));
                const auto unicodeCommonPathOffsetSize = wcslen((wchar_t*) (locationInformationBuffer.GetData() + unicodeCommonPathOffset));
                unicodeCommonPath                      = { (char16*) (locationInformationBuffer.GetData() + unicodeCommonPathOffset),
                                      unicodeCommonPathOffsetSize };
            }
        }
        volumeInformation = (VolumeInformation*) (locationInformationBuffer.GetData() + locationInformation.volumeInformationOffset);

        if (locationInformation.networkShareOffset > 0)
        {
            networkShareInformation =
                  (NetworkShareInformation*) (locationInformationBuffer.GetData() + locationInformation.networkShareOffset);
        }
    }

    dataStringsBuffer    = obj->GetData().CopyToBuffer(offset, (uint32) (obj->GetData().GetSize() - offset));
    dataStringsOffset    = (uint32) offset;
    const bool isUnicode = (header.linkFlags & (uint32) LNK::LinkFlags::IsUnicode);

    auto dataStringBufferOffset = 0;
    for (const auto& flag : std::initializer_list{ LNK::LinkFlags::HasName,
                                                   LNK::LinkFlags::HasRelativePath,
                                                   LNK::LinkFlags::HasWorkingDir,
                                                   LNK::LinkFlags::HasArguments,
                                                   LNK::LinkFlags::HasIconLocation })
    {
        if (header.linkFlags & (uint32) flag)
        {
            DataStringTypes dst = DataStringTypes::Description;

            switch (flag)
            {
            case LNK::LinkFlags::HasName:
                dst = DataStringTypes::Description;
                break;
            case LNK::LinkFlags::HasRelativePath:
                dst = DataStringTypes::RelativePath;
                break;
            case LNK::LinkFlags::HasWorkingDir:
                dst = DataStringTypes::WorkingDirectory;
                break;
            case LNK::LinkFlags::HasArguments:
                dst = DataStringTypes::CommandLineArguments;
                break;
            case LNK::LinkFlags::HasIconLocation:
                dst = DataStringTypes::IconLocation;
                break;
            default:
                break;
            }

            const auto ds  = (DataString*) (dataStringsBuffer.GetData() + dataStringBufferOffset);
            const auto buf = ((uint8*) &ds->charsCount + sizeof(DataString));
            if (isUnicode)
            {
                std::u16string_view sv{ (char16*) buf, ds->charsCount };
                dataStrings.emplace(std::pair<DataStringTypes, ConstString>{ dst, ConstString{ sv } });
                dataStringBufferOffset += (ds->charsCount + 1ULL) * sizeof(char16);
            }
            else
            {
                std::string_view sv{ (char*) buf, ds->charsCount };
                dataStrings.emplace(std::pair<DataStringTypes, ConstString>{ dst, ConstString{ sv } });
                dataStringBufferOffset += (ds->charsCount + 1ULL);
            }
        }
    }

    offset += dataStringBufferOffset;
    extraDataBuffer = obj->GetData().CopyToBuffer(offset, (uint32) (obj->GetData().GetSize() - offset));

    auto extraDataBufferOffset = 0;
    while (extraDataBufferOffset < extraDataBuffer.GetLength())
    {
        const auto extra = (ExtraDataBase*) ((uint8*) extraDataBuffer.GetData() + extraDataBufferOffset);
        CHECKBK(extra->size != 0, "");
        extraDataBases.emplace_back(extra);
        extraDataBufferOffset += extra->size;
    }

    return true;
}
