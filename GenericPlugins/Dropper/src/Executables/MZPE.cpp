#include "Executables.hpp"

namespace GView::GenericPlugins::Droppper::Executables
{
constexpr uint16 IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr uint32 IMAGE_NT_SIGNATURE  = 0x00004550;

const char* MZPE::GetName()
{
    return "MZPE";
}

ObjectCategory MZPE::GetGroup()
{
    return ObjectCategory::Executables;
}

const char* MZPE::GetOutputExtension()
{
    return "mzpe";
}

Priority MZPE::GetPriority()
{
    return Priority::Binary;
}

bool MZPE::ShouldGroupInOneFile()
{
    return false;
}

Result MZPE::Check(uint64 offset, DataCache& file, unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint64& start, uint64& end)
{
    CHECK(IsMagicU16(prechachedBuffer, prechachedBufferSize, IMAGE_DOS_SIGNATURE), Result::NotFound, "");

    return Result::NotFound;
}

} // namespace GView::GenericPlugins::Droppper::Executables
