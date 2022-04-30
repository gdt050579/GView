#include "LNK.hpp"

using namespace GView::Type::LNK;

LNKFile::LNKFile()
{
}

bool LNKFile::Update()
{
    CHECK(obj->GetData().Copy<Header>(0, header), false, "");
    if (header.linkFlags & (uint32) LNK::LinkFlags::HasTargetIDList)
    {
        CHECK(obj->GetData().Copy<LinkTargetIDList>(sizeof(header), linkTargetIDList), false, "");
        linkTargetIDListBuffer = obj->GetData().CopyToBuffer(sizeof(Header) + sizeof(LinkTargetIDList), linkTargetIDList.IDListSize);
        CHECK(linkTargetIDListBuffer.IsValid(), false, "");

        auto offset = 0;
        while (offset < linkTargetIDList.IDListSize - 2) // - terminal
        {
            const auto itemID = itemIDS.emplace_back((ItemID*) &linkTargetIDListBuffer.GetData()[offset]);
            offset += itemID->ItemIDSize;
        }
    }

    if (header.linkFlags & (uint32) LNK::LinkFlags::HasLinkInfo)
    {
        auto offset = sizeof(header);
        if (header.linkFlags & (uint32) LNK::LinkFlags::HasTargetIDList)
        {
            offset += sizeof(LinkTargetIDList) + linkTargetIDList.IDListSize;
        }
        CHECK(obj->GetData().Copy<LocationInformation>(offset, locationInformation), false, "");
        locationInformationBuffer =
              obj->GetData().CopyToBuffer(offset, (uint32) obj->GetData().GetSize() - offset); // getting everything left here
        CHECK(locationInformationBuffer.IsValid(), false, "");

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

    return true;
}
