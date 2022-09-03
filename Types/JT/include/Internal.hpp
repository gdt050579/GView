#pragma once

#include <GView.hpp>

// https://www.plm.automation.siemens.com/media/global/en/Siemens%20JT%20V10.5%20Format%20Description%20and%20annexs%2010292019_tcm27-58011.pdf

namespace GView::Type::JT
{
#define GET_PAIR_FROM_ENUM(x)                                                                                                              \
    {                                                                                                                                      \
        x, (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))                                                       \
    }

#pragma pack(push, 1)
struct MyGUID
{
    uint32 a;
    uint16 b;
    uint16 c;
    uint8 d[8];

    bool operator==(const MyGUID& other) const
    {
        return memcmp(this, &other, sizeof(MyGUID)) == 0;
    }
};
#pragma pack(pop)

static_assert(sizeof(MyGUID) == 16);

#pragma pack(push, 1)
struct FileHeader
{
    uint8 version[80];
    uint8 byteOrder;
    uint32 emptyField;
    uint32 tocOffset;
    MyGUID lsgSegmentId;
};
#pragma pack(pop)

static_assert(sizeof(FileHeader) == 105);

static std::string_view GetByteOrder(uint8 byteOrder)
{
    switch (byteOrder)
    {
    case 0:
        return "LSB";
    case 1:
        return "MSB";
    default:
        return "INVALID";
    }
}

#pragma pack(push, 1)
struct TOCEntry
{
    MyGUID segmentID;
    uint32 segmentOffset;
    uint32 segmentLength;
    uint32 segmentAttributes;
};

static bool operator==(const TOCEntry& e1, const TOCEntry& e2)
{
    return memcmp(&e1, &e2, sizeof(TOCEntry)) == 0;
}
#pragma pack(pop)

static_assert(sizeof(TOCEntry) == 28);

struct SegmentAttributesAndTypes
{
    uint32 _1 : 1;
    uint32 _2 : 1;
    uint32 _3 : 1;
    uint32 _4 : 1;
    uint32 _5 : 1;
    uint32 _6 : 1;
    uint32 _7 : 1;
    uint32 _8 : 1;
    uint32 _9 : 1;
    uint32 _10 : 1;
    uint32 _11 : 1;
    uint32 _12 : 1;
    uint32 _13 : 1;
    uint32 _14 : 1;
    uint32 _15 : 1;
    uint32 _16 : 1;
    uint32 _17 : 1;
    uint32 _18 : 1;
    uint32 _19 : 1;
    uint32 _20 : 1;
    uint32 _21 : 1;
    uint32 _22 : 1;
    uint32 _23 : 1;
    uint32 _24 : 1;
    uint32 _25 : 1;
    uint32 _26 : 1;
    uint32 _27 : 1;
    uint32 _28 : 1;
    uint32 _29 : 1;
    uint32 _30 : 1;
    uint32 _31 : 1;
    uint32 _32 : 1;
};

static_assert(sizeof(SegmentAttributesAndTypes) == sizeof(uint32));

static std::string GetSegmentAttributes(uint32 segmentAttributes)
{
    SegmentAttributesAndTypes sat{};
    memcpy(&sat, &segmentAttributes, sizeof(uint32));

    std::vector<std::string> flags;
    flags.reserve(32);

    if (sat._1)
        flags.emplace_back("Logical Scene Graph");
    if (sat._2)
        flags.emplace_back("JT B-Rep");
    if (sat._3)
        flags.emplace_back("PMI Data");
    if (sat._4)
        flags.emplace_back("Meta Data");
    if (sat._5)
        flags.emplace_back("Unknown (5)");
    if (sat._6)
        flags.emplace_back("Shape");
    if (sat._7)
        flags.emplace_back("Shape LOD0");
    if (sat._8)
        flags.emplace_back("Shape LOD1");
    if (sat._9)
        flags.emplace_back("Shape LOD2");
    if (sat._10)
        flags.emplace_back("Shape LOD3");
    if (sat._11)
        flags.emplace_back("Shape LOD4");
    if (sat._12)
        flags.emplace_back("Shape LOD5");
    if (sat._13)
        flags.emplace_back("Shape LOD6");
    if (sat._14)
        flags.emplace_back("Shape LOD7");
    if (sat._15)
        flags.emplace_back("Shape LOD8");
    if (sat._16)
        flags.emplace_back("Shape LOD9");
    if (sat._17)
        flags.emplace_back("XT B-Rep");
    if (sat._18)
        flags.emplace_back("Wireframe Representation");
    if (sat._19)
        flags.emplace_back("Unknown (19)");
    if (sat._20)
        flags.emplace_back("ULP");
    if (sat._21)
        flags.emplace_back("Unknown (21)");
    if (sat._22)
        flags.emplace_back("Unknown (22)");
    if (sat._23)
        flags.emplace_back("STT");
    if (sat._24)
        flags.emplace_back("LWPA");
    if (sat._25)
        flags.emplace_back("Unknown (25)");
    if (sat._26)
        flags.emplace_back("Unknown (26)");
    if (sat._27)
        flags.emplace_back("Unknown (27)");
    if (sat._28)
        flags.emplace_back("Unknown (28)");
    if (sat._29)
        flags.emplace_back("Unknown (29)");
    if (sat._30)
        flags.emplace_back("(Multi)XT B-Rep");
    if (sat._31)
        flags.emplace_back("InfoSegment");
    if (sat._32)
        flags.emplace_back("AEC Shape"); // 33?? STEP B-rep

    std::string output = "[";
    for (const auto& s : flags)
    {
        output.append(s + " | ");
    }

    if (flags.empty() == false)
    {
        output.resize(output.size() - 3);
    }
    output.append("]");

    return output;
}

#pragma pack(push, 1)
struct TOCSegment
{
    uint32 entryCount;
    std::vector<TOCEntry> entries;
};
#pragma pack(pop)

static_assert(sizeof(TOCSegment::entryCount) == sizeof(uint32));

} // namespace GView::Type::JT
