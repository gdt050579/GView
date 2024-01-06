#include "AdvancedSelection.hpp"

GView::View::DissasmViewer::AdvancedSelection::AdvancedSelection()
{
    Clear();
}

void GView::View::DissasmViewer::AdvancedSelection::Clear()
{
    for (uint32 i = 0; i < MAX_SELECTION_ZONES; i++)
    {
        Clear(i);
    }
}

bool GView::View::DissasmViewer::AdvancedSelection::Clear(uint32 index)
{
    CHECK((index < MAX_SELECTION_ZONES) && (index >= 0),
          false,
          "Invalid selection index (%d) - should be between 0 and %d",
          index,
          AdvancedSelection::MAX_SELECTION_ZONES - 1);
    zones[index].start         = INVALID_LINE_POSITION;
    zones[index].end           = INVALID_LINE_POSITION;
    zones[index].originalPoint = INVALID_LINE_POSITION;
    zones[index].is_alt_selected = false;
    return true;
}

bool GView::View::DissasmViewer::AdvancedSelection::UpdateSelection(uint32 index, LinePosition position, bool ctrl_down, bool alt_down)
{
    CHECK((index < MAX_SELECTION_ZONES) && (index >= 0), false, "Invalid selection index (%d) - should be between 0 and %d", index, MAX_SELECTION_ZONES - 1);
    auto sel = &zones[index];
    if (position < sel->originalPoint)
    {
        sel->start = position;
        sel->end   = sel->originalPoint;
    }
    else
    {
        sel->start = sel->originalPoint;
        sel->end   = position;
    }
    return true;
}

int GView::View::DissasmViewer::AdvancedSelection::BeginSelection(LinePosition position, bool ctrl_down, bool alt_down)
{
    if (!ctrl_down)
    {
        const uint32 last_pos = 0;
        auto& last_zone       = zones[last_pos];
        if ((position >= last_zone.start) && (position <= last_zone.end) && (last_zone.start != INVALID_LINE_POSITION))
        {
            last_zone.end = position;
            return last_pos;
        }
        // a totaly new selection
        last_zone.start = last_zone.originalPoint = last_zone.end = position;
        last_zone.is_alt_selected                                 = alt_down;
        return 0;
    }

    decltype(zones.data()) zone_ptr = nullptr;
    int free                        = -1;
    for (uint32 i = 0; i < MAX_SELECTION_ZONES; i++)
    {
        if (zones[i].start == INVALID_LINE_POSITION)
        {
            if (!zone_ptr)
            {
                zone_ptr = &zones[i];
                free     = i;
            }
            continue;
        }
        if ((position >= zones[i].start) && (position <= zones[i].end))
        {
            zones[i].end = position;
            return i;
        }
    }
    if (zone_ptr)
    {
        // am o sectiune noua
        zone_ptr->start = zone_ptr->originalPoint = zone_ptr->end = position;
        return free;
    }
    return -1;
}

void GView::View::DissasmViewer::AdvancedSelection::ClearStorages()
{
    for (uint32 i = 0; i < MAX_SELECTION_ZONES; i++)
    {
        if (zones[i].start != INVALID_LINE_POSITION)
        {
            zones[i].content.clear();   
        }
    }
}
