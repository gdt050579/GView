#include "Internal.hpp"

using namespace GView::Utils;
using namespace AppCUI::Graphics;

constexpr uint32 MAX_ZONES = 0x100000U;

ZonesList::ZonesList()
{
    list       = nullptr;
    count      = 0;
    allocated  = 0;
    lastZone   = nullptr;
    cacheEnd   = INVALID_OFFSET;
    cacheStart = INVALID_OFFSET;
}
ZonesList::~ZonesList()
{
    if (list)
        delete[] list;
    list       = nullptr;
    lastZone   = nullptr;
    cacheEnd   = INVALID_OFFSET;
    cacheStart = INVALID_OFFSET;
    count      = 0;
    allocated  = 0;
}
bool ZonesList::Reserve(uint32 newAllocatedSize)
{
    if (newAllocatedSize <= allocated)
        return true;

    uint32 newSize = allocated << 1;
    if (newSize == 0)
        newSize = 8;

    while ((newSize < newAllocatedSize) && (newSize < MAX_ZONES))
        newSize = newSize << 1;
    CHECK(newSize < MAX_ZONES, false, "A maximum of %u zones can be create !", MAX_ZONES);
    Zone* tmp = new Zone[newSize];
    if (count > 0)
    {
        memcpy(tmp, list, ((size_t) count) * sizeof(Zone));
    }
    if (list)
        delete[] list;
    list      = tmp;
    allocated = newSize;
    return true;
}

bool ZonesList::Add(uint64 s, uint64 e, ColorPair c, std::string_view txt)
{
    if (count >= allocated)
    {
        CHECK(Reserve(count + 1), false, "");
    }
    list[count].Set(s, e, c, txt);
    count++;
    return true;
}
const Zone* ZonesList::OffsetToZone(uint64 position)
{
    if ((position >= cacheStart) && (position <= cacheEnd) && (position != INVALID_OFFSET))
        return lastZone;

    if ((lastZone) && (position >= lastZone->start) && (position < lastZone->end))
        return lastZone;

    auto z     = list;
    auto e     = z + count;
    Zone* last = nullptr;
    uint64 closestEnd, closestStart;
    closestStart = 0;
    closestEnd   = INVALID_OFFSET;
    if (z)
    {
        for (; z != e; z++)
        {
            if ((position >= z->start) && (position <= z->end))
            {
                last = z;
                continue;
            }
            if ((z->end < position) && (z->end > closestStart))
                closestStart = z->end;
            if ((z->start > position) && (z->start < closestEnd))
                closestEnd = z->start;
        }
    }
    if (last != nullptr)
    {
        if (closestStart > last->start)
            cacheStart = closestStart;
        else
            cacheStart = last->start;
        if (closestEnd < last->end)
            cacheEnd = closestEnd;
        else
            cacheEnd = last->end;
    }
    else
    {
        if ((closestEnd > 0) && (closestEnd != INVALID_OFFSET))
        {
            cacheStart = closestStart;
            cacheEnd   = closestEnd - 1;
        }
        else
        {
            cacheStart = cacheEnd = INVALID_OFFSET;
        }
    }
    lastZone = last;
    return last;
}