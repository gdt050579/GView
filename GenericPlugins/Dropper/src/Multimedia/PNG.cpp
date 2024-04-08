#include "Multimedia.hpp"

namespace GView::GenericPlugins::Droppper::Multimedia
{
// https://en.wikipedia.org/wiki/PNG#File_format
constexpr uint64 IMAGE_PNG_MAGIC = 0x0A1A0A0D474E5089;

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
    CHECK(IsMagicU64(precachedBuffer, IMAGE_PNG_MAGIC), Result::NotFound, "");

    start      = offset;
    end        = offset + sizeof(IMAGE_PNG_MAGIC);
    auto found = false;
    auto pos   = end;

    do {
        auto buffer = file.CopyToBuffer(end, sizeof(uint32), true);
        CHECKBK(buffer.IsValid(), "");

        auto chunk_length = Endian::BigToNative(*reinterpret_cast<uint32*>(buffer.GetData()));
        end += chunk_length;
        end += sizeof(uint32) * 3; // length + type + CRC32
        found = chunk_length != 0;
    } while (found);

    return Result::Buffer;
}

} // namespace GView::GenericPlugins::Droppper::Multimedia
