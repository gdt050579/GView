#include "Images.hpp"

namespace GView::GenericPlugins::Droppper::Images
{
// https://en.wikipedia.org/wiki/PNG#File_format
constexpr uint64 IMAGE_PNG_MAGIC = 0x0A1A0A0D474E5089;

const std::string_view PNG::GetName() const
{
    return "PNG";
}

ObjectCategory PNG::GetGroup() const
{
    return ObjectCategory::Multimedia;
}

uint32 PNG::GetSubGroup() const
{
    return static_cast<uint32>(Types::PNG);
}

const std::string_view PNG::GetOutputExtension() const
{
    return "png";
}

Priority PNG::GetPriority() const
{
    return Priority::Binary;
}

bool PNG::ShouldGroupInOneFile() const
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

    CHECK(end - start >= 67,
          Result::NotFound,
          ""); // https://belkadan.com/blog/2024/01/The-Biggest-Smallest-PNG/#:~:text=The%20smallest%20PNG%20file%20is,or%20a%201x1%20gray%20image.

    return Result::Buffer;
}

} // namespace GView::GenericPlugins::Droppper::Images
