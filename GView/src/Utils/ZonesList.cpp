#include <GViewApp.hpp>

using namespace GView::Utils;

int FileZoneCompareFunction(const void *e1, const void *e2, void* Context)
{
	const Zone *f1 = (const Zone*)e1;
	const Zone *f2 = (const Zone*)e2;
	if (f1->Start < f2->Start)
		return -1;
	if (f1->Start > f2->Start)
		return 1;
	if (f1->End < f2->End)
		return -1;
	if (f1->End > f2->End)
		return 1;
	return 0;
}

ZonesList::ZonesList()
{
	lastZone = nullptr;
	cacheEnd = INVALID_OFFSET;
	cacheStart = INVALID_OFFSET;
}
void ZonesList::Reserve(unsigned int count)
{
	list.reserve(count);
}

bool ZonesList::Add(unsigned long long s, unsigned long long e, ColorPair c, std::u16string_view txt)
{
	list.emplace_back(s, e, c, txt);
	return true;
}
bool ZonesList::Add(unsigned long long s, unsigned long long e, ColorPair c, std::string_view txt)
{
	list.emplace_back(s, e, c, txt);
	return true;
}
const Zone* ZonesList::OffsetToZone(unsigned long long position)
{
	
	if ((position >= cacheStart) && (position <= cacheEnd) && (position != INVALID_OFFSET))
		return lastZone;

	if ((lastZone) && (position >= lastZone->start) && (position < lastZone->end))
		return lastZone;

	auto z = list.data();
	auto e = z + list.size();
	Zone *last = nullptr;
	unsigned long long closestEnd, closestStart;
	closestStart = 0;
	closestEnd = INVALID_OFFSET;
	for (; z != e; z++)
	{
		if ((position >= z->start) && (position <= z->end))
		{
			last = z;
			continue;
		}
		if ((z->end<position) && (z->end>closestStart))
			closestStart = z->end;
		if ((z->start>position) && (z->start<closestEnd))
			closestEnd = z->start;
		// nu are sens sa mai continuu pentru ca toate de acum incolo sunt mai mari
		if (z->start>position)
			break;
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
	else {
		if ((closestEnd>0) && (closestEnd != INVALID_OFFSET))
		{
			cacheStart = closestStart;
			cacheEnd = closestEnd - 1;
		}
		else {
			cacheStart = cacheEnd = INVALID_OFFSET;
		}
	}
	lastZone = last;
	return last;
}