#include "Images.hpp"

namespace GView::GenericPlugins::Droppper::Images
{
// https://en.wikipedia.org/wiki/PNG#File_format
constexpr uint64 IMAGE_PNG_MAGIC = 0x0A1A0A0D474E5089;

const std::string_view PNG::GetName() const
{
    return "PNG";
}

Category PNG::GetCategory() const
{
    return Category::Image;
}

Subcategory PNG::GetSubcategory() const
{
    return Subcategory::PNG;
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

bool PNG::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(IsMagicU64(precachedBuffer, IMAGE_PNG_MAGIC), false, "");

    finding.start = offset;
    finding.end   = offset + sizeof(IMAGE_PNG_MAGIC);
    auto found    = false;
    auto pos      = finding.end;

    do {
        auto buffer = file.CopyToBuffer(finding.end, sizeof(uint32), true);
        CHECKBK(buffer.IsValid(), "");

        auto chunk_length = Endian::BigToNative(*reinterpret_cast<uint32*>(buffer.GetData()));
        finding.end += chunk_length;
        finding.end += sizeof(uint32) * 3; // length + type + CRC32
        found = chunk_length != 0;
    } while (found);

    // https://belkadan.com/blog/2024/01/The-Biggest-Smallest-PNG/#:~:text=The%20smallest%20PNG%20file%20is,or%20a%201x1%20gray%20image.
    CHECK(finding.end - finding.start >= 67, false, "");

    finding.result = Result::Buffer;

    return true;
}

} // namespace GView::GenericPlugins::Droppper::Images
