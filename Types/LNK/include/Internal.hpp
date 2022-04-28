#pragma once

#include <GView.hpp>

namespace GView::Type::LNK
{
constexpr uint32 SIGNATURE           = 0x0000004C;
constexpr uint8 CLASS_IDENTIFIER[16] = { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };

#pragma pack(push, 4)
struct Header
{
    uint32 headerSize;
    uint8 classIdentifier[16];
    uint32 dataFlags;
    uint32 fileAttributeFlags;
    uint64 creationDate;
    uint64 lastAccessDate;
    uint64 lastModificationDate;
    uint32 filesize;
    int32 iconIndex;
    uint32 showWindow;
    uint16 hotKey;
    uint16 unknown0;
    uint32 unknown1;
    uint32 unknown2;
};
#pragma pack(pop)

static_assert(sizeof(Header) == 76);

} // namespace GView::Type::LNK
