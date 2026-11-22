#include "Multimedia.hpp"

namespace GView::GenericPlugins::Droppper::Multimedia
{
// https://samples.mplayerhq.hu/SWF/
// https://web.archive.org/web/20130202203813/http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/swf/pdf/swf-file-format-spec.pdf
// https://www.slideshare.net/slideshow/how-to-read-swf/14449245

// 3 byte magics dont fit neatly into uint32, the 00 byte is were the version byte would be
constexpr uint32 SWF_SIGNATURE_BASE            = 0x00535746; // "FWS"
constexpr uint32 SWF_SIGNATURE_COMPRESSED_ZLIB = 0x00535743; // "CWS" for version SWF 6+
constexpr uint32 SWF_SIGNATURE_COMPRESSED_LZMA = 0x0053575A; // "ZWS" for version SWF 13+

constexpr uint8 SWF_RECT_MAXIMAL_SIZE          = 17; // max is 129 bits -> 17 bytes (padding included) (5 + 31 * 4)
constexpr uint8 SWF_RECT_MINIMAL_SIZE          = 2;  // min is 13 bits -> 2 bytes (padding included) (5 + 2 * 4)

const std::string_view SWF::GetName() const
{
    return "SWF";
}

Category SWF::GetCategory() const
{
    return Category::Multimedia;
}

Subcategory SWF::GetSubcategory() const
{
    return Subcategory::SWF;
}

const std::string_view SWF::GetOutputExtension() const
{
    return "SWF";
}

Priority SWF::GetPriority() const
{
    return Priority::Binary;
}

bool SWF::ShouldGroupInOneFile() const
{
    return false;
}

bool SWF::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    // for now test works only for uncompressed
    uint32 signature = GetSwfSignature(precachedBuffer);
    CHECK((signature == SWF_SIGNATURE_BASE), false, "");
    finding.start = offset;
    finding.end   = offset + sizeof(uint8) + sizeof(uint16);

    uint8 version = GetSwfVersion(precachedBuffer);
    CHECK((version > 0), false, "");
    finding.end += sizeof(uint8);

    // for now it's not useful, just checking if it's not 0
    uint32 file_length = GetSwfFileLength(precachedBuffer);
    CHECK(file_length > 0, false, "");
    finding.end += sizeof(uint32);

    // need to find out how many bytes the 'rect' + padding occupy
    uint8 nbytes_rect = GetSwfNumberBytesRect(finding.end, file);
    CHECK((nbytes_rect <= SWF_RECT_MAXIMAL_SIZE), false, "");
    CHECK((nbytes_rect >= SWF_RECT_MINIMAL_SIZE), false, "");
    finding.end += nbytes_rect;

    // frame_rate (uint16) and frame_count (uint16)
    finding.end += (sizeof(uint16) * 2);

    uint32 tag_length = 0;
    do {
        // getting the size of the tag body
        tag_length = GetSwfTagLength(finding.end, file);
        finding.end += tag_length;

        // adding 2 bytes for the size of the record header
        finding.end += sizeof(uint16);

    } while (tag_length);

    // checking if file length from swf is accurate
    CHECK(finding.end - finding.start != file_length, false, "");

    finding.result = Result::Buffer;

    return true;
}
uint32 SWF::GetSwfSignature(BufferView precachedBuffer)
{
    if (precachedBuffer.GetLength() < 4) {
        return 0;
    }
    // get magic (3 bytes) + version (1 byte)
    uint32 found_magic = *reinterpret_cast<const uint32*>(precachedBuffer.GetData());

    // remove version byte
    found_magic <<= 8;
    found_magic >>= 8;

    if (found_magic != SWF_SIGNATURE_BASE && found_magic != SWF_SIGNATURE_COMPRESSED_LZMA && found_magic != SWF_SIGNATURE_COMPRESSED_ZLIB)
        return 0;

    return found_magic;
}
uint8 SWF::GetSwfVersion(BufferView precachedBuffer)
{
    if (precachedBuffer.GetLength() < 4) {
        return 0;
    }
    uint32 version = *reinterpret_cast<const uint32*>(precachedBuffer.GetData());

    // remove 3 bytes of signature
    version >>= (8 * 3);

    return uint8(version);
}
uint32 SWF::GetSwfFileLength(BufferView precachedBuffer)
{
    if (precachedBuffer.GetLength() < 8) {
        return 0;
    }
    uint64 file_length = *reinterpret_cast<const uint64*>(precachedBuffer.GetData());

    // remove 3 bytes of signature + 1 byte of version
    file_length >>= (8 * 4);

    return uint32(file_length);
}
uint8 SWF::GetSwfNumberBytesRect(uint64 offset, DataCache& file)
{
    // first 5 bits (like an "uint5") represent the number of bits used for the next 4 coordinates
    auto buffer = file.CopyToBuffer(offset, sizeof(uint8), true);
    CHECK(buffer.IsValid(), false, "");
    uint8 nbits = *reinterpret_cast<uint8*>(buffer.GetData());
    nbits >>= 3;

    // the next nbits * 4 bits represent 4 signed integers of size nbits
    uint16 nbits_rect = 5 + nbits * 4;
    uint8 nbytes_rect = nbits_rect / 8;

    // take into account padding if necessary
    if (nbits_rect % 8 != 0)
        nbytes_rect ++;
    
    return nbytes_rect;
}

uint32 SWF::GetSwfTagLength(uint64 offset, DataCache& file)
{
    // tags begin with record header of size uint16
    auto buffer = file.CopyToBuffer(offset, sizeof(uint16), true);
    CHECK(buffer.IsValid(), false, "");
    uint16 record_header = *reinterpret_cast<uint16*>(buffer.GetData());

    // only the lower 6 bits are relevant, they contain the length of the tag
    record_header <<= 10;
    uint32 length = (uint32)record_header;

    // if length is not 0x3f, it means it's a short record header
    if (length < 0x3f)
        return (uint32) length;

    // if length is 0x3f, it means it's a long record header -> real length is stored in next 4 bytes as uint32
    // the "length" property also takes into account it's own 4 byte size
    buffer = file.CopyToBuffer(offset + sizeof(uint16), sizeof(uint32), true);
    CHECK(buffer.IsValid(), false, "");
    length = *reinterpret_cast<uint32*>(buffer.GetData());

    return length;
}
} // namespace GView::GenericPlugins::Droppper::Multimedia
