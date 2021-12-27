#include "Internal.hpp"

using namespace GView::Utils;


Selection::Selection()
{
	for (uint32 tr = 0; tr < Selection::MAX_SELECTION_ZONES; tr++) 
	{
		zones[tr].start = INVALID_OFFSET;
		zones[tr].end = INVALID_OFFSET;
		zones[tr].originalPoint = INVALID_OFFSET;
	}	
	singleSelectionZone = true;
}
void Selection::Clear()
{
	for (uint32 tr = 0; tr < Selection::MAX_SELECTION_ZONES; tr++)
		zones[tr].start = INVALID_OFFSET;
}
bool Selection::Clear(int index)
{
	CHECK((index < Selection::MAX_SELECTION_ZONES) && (index>=0), false, "Invalid selection index (%d) - should be between 0 and %d", index, Selection::MAX_SELECTION_ZONES - 1);
	zones[index].start = INVALID_OFFSET;
	return true;
}

bool Selection::GetSelection(int index, uint64 &Start, uint64 &End)
{
	CHECK((index < Selection::MAX_SELECTION_ZONES) && (index >= 0), false, "Invalid selection index (%d) - should be between 0 and %d", index, Selection::MAX_SELECTION_ZONES - 1);
	auto sel = zones + index;
	if ((singleSelectionZone) && (index > 0))
		return false;
	if (sel->start == INVALID_OFFSET)
		return false;
	Start = sel->start;
	End = sel->end;
	return true;
}
void Selection::EnableMultiSelection(bool enable)
{
	if ((singleSelectionZone) && (enable))
	{
		// clean up zones 1 to ne		
		for (uint32 tr = 1; tr < Selection::MAX_SELECTION_ZONES; tr++) {
			zones[tr].start = INVALID_OFFSET;
			zones[tr].end = INVALID_OFFSET;
			zones[tr].originalPoint = INVALID_OFFSET;
		}
		singleSelectionZone = false;
		return;
	}
	if ((!enable) && (!singleSelectionZone))
	{
		// curat toate selectiile
		for (uint32 tr = 0; tr < Selection::MAX_SELECTION_ZONES; tr++) {
			zones[tr].start = INVALID_OFFSET;
			zones[tr].end = INVALID_OFFSET;
			zones[tr].originalPoint = INVALID_OFFSET;
		}
		singleSelectionZone = true;
		return;
	}

}

int  Selection::OffsetToSelection(uint64 position, uint64 &Start, uint64 &End)
{
	// for single selection
	if (singleSelectionZone)
	{
		if ((position >= zones->start) && (position <= zones->end))
		{
			Start = zones->start;
			End = zones->end;
			return 0;
		}
		return -1;
	}
	// multiple selections
	for (uint32 tr = 0; tr < Selection::MAX_SELECTION_ZONES; tr++)
	{
		if ((position >= zones[tr].start) && (position <= zones[tr].end))
		{
			Start = zones[tr].start;
			End = zones[tr].end;
			return tr;
		}
	}
	// nu am gasit
	return -1;
}
bool Selection::Contains(uint64 position) const
{
    // for single selection
    if (singleSelectionZone)
        return (position >= zones->start) && (position <= zones->end);
    
    // multiple selections
    for (uint32 tr = 0; tr < Selection::MAX_SELECTION_ZONES; tr++)
    {
        if ((position >= zones[tr].start) && (position <= zones[tr].end))
            return true;
    }
    // nu am gasit
    return false;
}
bool Selection::UpdateSelection(int index, uint64 position)
{
	CHECK((index < Selection::MAX_SELECTION_ZONES) && (index >= 0), false, "Invalid selection index (%d) - should be between 0 and %d", index, Selection::MAX_SELECTION_ZONES - 1);
	auto sel = zones + index;
	if ((singleSelectionZone) && (index>0))
		return false;
	if (position < sel->originalPoint)
	{
		sel->start = position;
		sel->end = sel->originalPoint;
	}
	else {
		sel->start = sel->originalPoint;
		sel->end = position;
	}
	return true;
}
int	 Selection::BeginSelection(uint64 position)
{
	// for single selection
	if (singleSelectionZone)
	{
		if ((position >= zones->start) && (position <= zones->end) && (zones->start!=INVALID_OFFSET))
		{
			zones->end = position;
			return 0;
		}
		// a totaly new selection
		zones->start = zones->originalPoint = zones->end = position;
		return 0;
	}
	// for multiple selections
	decltype(&zones[0]) s = nullptr;
	int free = -1;
	for (int tr = 0; tr < Selection::MAX_SELECTION_ZONES; tr++)
	{		
		if (zones[tr].start == INVALID_OFFSET)
		{
			if (!s) {
				s = &zones[tr];
				free = tr;
			}
			continue;
		}
		if ((position >= zones[tr].start) && (position <= zones[tr].end))
		{
			zones[tr].end = position;
			return tr;
		}
	}
	if (s)
	{
		// am o sectiune noua
		s->start = s->originalPoint = s->end = position;
		return free;
	}
	return -1;
}
bool Selection::SetSelection(int index, uint64 start, uint64 end)
{
	CHECK((index >= 0) && (index < Selection::MAX_SELECTION_ZONES), false, "");
	if ((singleSelectionZone) && (index > 0))
		return false;
	CHECK(start != INVALID_OFFSET, false, "");
	CHECK(end != INVALID_OFFSET, false, "");
	zones[index].originalPoint = start;
	if (start <= end)
	{
		zones[index].start = start;
		zones[index].end = end;
	}
	else {
		zones[index].start = end;
		zones[index].end = start;
	}
	return true;
}