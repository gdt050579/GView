#include "Multimedia.hpp"

namespace GView::GenericPlugins::Droppper::Multimedia
{
constexpr uint32 IMAGE_PNG_MAGIC = 0x474E5089;

const char* PNG::GetName()
{
    return "PNG";
}

ObjectCategory PNG::GetGroup()
{
    return ObjectCategory::Multimedia;
}

const char* PNG::GetOutputExtension()
{
    return "png";
}

Priority PNG::GetPriority()
{
    return Priority::Binary;
}

bool PNG::ShouldGroupInOneFile()
{
    return false;
}

Result PNG::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    return Result::NotFound;
}

} // namespace GView::GenericPlugins::Droppper::Multimedia
