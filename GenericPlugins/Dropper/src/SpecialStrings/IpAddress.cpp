#include "SpecialStrings.hpp"

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
const char* IpAddress::GetName()
{
    return "IP Address";
}

ObjectCategory IpAddress::GetGroup()
{
    return ObjectCategory::SpecialStrings;
}

const char* IpAddress::GetOutputExtension()
{
    return "ip";
}

Priority IpAddress::GetPriority()
{
    return Priority::Text;
}

bool IpAddress::ShouldGroupInOneFile()
{
    return true;
}

Result IpAddress::Check(uint64 offset, DataCache& file, unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint64& start, uint64& end)
{
    return Result::NotFound;
}

} // namespace GView::GenericPlugins::Droppper::SpecialStrings
