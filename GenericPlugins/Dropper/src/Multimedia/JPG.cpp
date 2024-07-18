#include "Images.hpp"

namespace GView::GenericPlugins::Droppper::Images
{
constexpr uint16 IMAGE_JPG_MAGIC_SOI  = 0xFFD8; // Start of Image marker
constexpr uint16 IMAGE_JPG_MAGIC_EOI  = 0xFFD9; // End of Image marker

const std::string_view JPG::GetName() const
{
    return "JPG";
}
Category JPG::GetCategory() const
{
    return Category::Multimedia;
}

Subcategory JPG::GetSubcategory() const
{
    return Subcategory::JPG;
}

const std::string_view JPG::GetOutputExtension() const
{
    return "jpg";
}

Priority JPG::GetPriority() const
{
    return Priority::Binary;
}

bool JPG::ShouldGroupInOneFile() const
{
    return false;
}

bool JPG::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(IsMagicU16(precachedBuffer, IMAGE_JPG_MAGIC_SOI), false, "");

    finding.start = offset;
    finding.end   = offset + sizeof(IMAGE_JPG_MAGIC_SOI);
    auto pos      = finding.end;
    auto found    = false;

    while (true) {
        auto buffer = file.CopyToBuffer(pos, sizeof(uint32), true);
        CHECKBK(buffer.IsValid(), "");

        auto marker = *reinterpret_cast<const uint16*>(buffer.GetData());
        pos += sizeof(uint16);

        if (marker == IMAGE_JPG_MAGIC_EOI) {
            finding.end = pos;
            found       = true;
            break;
        } 
        else if ((marker & 0xFF00) == 0xFF00) {
            auto segment_length = Endian::BigToNative(*reinterpret_cast<const uint16*>(buffer.GetData() + sizeof(uint16)));
            pos += segment_length;
        } else {
            break;
        }
    }
    // https://stackoverflow.com/questions/2253404/what-is-the-smallest-valid-jpeg-file-size-in-bytes
    CHECK(finding.end - finding.start >= 125, false, ""); // Minimum size for JPG?

    finding.result = Result::Buffer;

    return true;
}

}