#include "Images.hpp"
#include <iostream>

namespace GView::GenericPlugins::Droppper::Images
{

constexpr uint16 IMAGE_BMP_MAGIC = 0x4D42;
constexpr uint32 BMP_MIN_FILE_SIZE = 54;
constexpr uint32 BMP_HEADER_SIZE= 14;

const std::string_view BMP::GetName() const
{
    return "BMP";
}
Category BMP::GetCategory() const
{
    return Category::Image;
}

Subcategory BMP::GetSubcategory() const
{
    return Subcategory::BMP;
}

const std::string_view BMP::GetOutputExtension() const
{
    return "bmp";
}

Priority BMP::GetPriority() const
{
    return Priority::Binary;
}

bool BMP::ShouldGroupInOneFile() const
{
    return false;
}

bool BMP::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    // Ensure offset starts at 0, we need the B in BM
    // TODO: Question -> why does the offset starts at 1?
    offset--;

    // Validate BMP magic number
    auto magicBuffer = file.CopyToBuffer(offset, sizeof(IMAGE_BMP_MAGIC), true);
    CHECK(magicBuffer.IsValid(), false, "Failed to read BMP magic number.");
    const uint16 magic = *reinterpret_cast<const uint16*>(magicBuffer.GetData());
    CHECK(magic == IMAGE_BMP_MAGIC, false, "Invalid BMP magic number. Expected: 0x4D42 ('BM').");

    // Read the BMP header
    auto headerBuffer = file.CopyToBuffer(offset, BMP_HEADER_SIZE, true);
    CHECK(headerBuffer.IsValid(), false, "Failed to read BMP header.");

    // Extract the fields from the BMP header
    const uint32 fileSize         = Endian::LittleToNative(*reinterpret_cast<const uint32*>(headerBuffer.GetData() + 2));
    const uint32 pixelArrayOffset = Endian::LittleToNative(*reinterpret_cast<const uint32*>(headerBuffer.GetData() + 10));

    // Ensure the BMP meets the minimum file size
    CHECK(fileSize >= BMP_MIN_FILE_SIZE, false, "BMP file size is smaller than the minimum expected size.");

    // Set finding details
    finding.start  = offset;
    finding.end    = offset + fileSize;
    finding.result = Result::Buffer;

    return true;
}
} // namespace GView::GenericPlugins::Droppper::Images
