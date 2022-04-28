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
            const auto itemID = (ItemID*) &linkTargetIDListBuffer.GetData()[offset];
            // TODO: actual parsing of shell items
            const auto* si = (ShellItem*) &linkTargetIDListBuffer.GetData()[offset + sizeof(ItemID::ItemIDSize)];
            offset += itemID->ItemIDSize;
        }
    }

    return true;
}
