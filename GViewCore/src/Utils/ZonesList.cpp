#include "Internal.hpp"

using namespace GView::Utils;
using namespace AppCUI::Graphics;

void ZonesList::Add(uint64 s, uint64 e, ColorPair c, std::string_view txt)
{
    zones.emplace_back(s, e, c, txt);
}

const std::optional<Zone> ZonesList::OffsetToZone(uint64 position) const
{
    for (const auto& zone : cache)
    {
        if (zone.interval.low <= position && position <= zone.interval.high)
        {
            return zone;
        }
    }

    return std::nullopt;
}

void ZonesList::SetCache(const Zone::Interval& interval)
{
    cache.clear();

    for (const auto& zone : zones)
    {
        if ((zone.interval.low >= interval.low && zone.interval.low <= interval.high) ||
            interval.low >= zone.interval.low && interval.low <= zone.interval.high)
        {
            cache.push_back(zone);
        }
    }

    std::sort(
          cache.begin(),
          cache.end(),
          [](const Zone& a, const Zone& b)
          {
              if (a.interval.low == b.interval.low)
              {
                  return a.interval.high < b.interval.high;
              }
              return a.interval.low > b.interval.low;
          });
}
