#include "pdf.hpp"
#include <deque>
#include <codecvt>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <podofo/podofo.h>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;
using namespace PoDoFo;

constexpr string_view PDF_ICON = "................"  // 1
                                 "................"  // 2
                                 "rrrrrrrrrrrrr..."  // 3
                                 "rWWWWWWWWWWWWr.."  // 4
                                 "rWWWWWWWWWWWWWr."  // 5
                                 "rWWWWWWWWWWWWWWr"  // 6
                                 "rW....W..WW...Wr"  // 7
                                 "rW.WW.W.W.W.WWWr"  // 8
                                 "rW....W.W.W..WWr"  // 9
                                 "rW.WWWW.W.W.WWWr"  // 10
                                 "rW.WWWW..WW.WWWr"  // 11
                                 "rWWWWWWWWWWWWWWr"  // 12
                                 "rWWWWWWWWWWWWWWr"  // 13
                                 "rrrrrrrrrrrrrrrr"  // 14
                                 "................"  // 15
                                 "................"; // 16

extern "C" {
PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    CHECK(buf.GetLength() >= sizeof(PDF::Header), false, "");

    auto header = buf.GetObject<PDF::Header>();
    CHECK(memcmp(header->identifier, PDF::KEY::PDF_MAGIC, 5) == 0, false, "");
    if (header->version == '1') {
        CHECK(header->point == '.' && header->subVersion >= '0' && header->subVersion <= '7', false, "");
    }
    if (header->version == '2') {
        CHECK(header->point == '.' && header->subVersion == '0', false, "");
    }
    return true;
}

PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new PDF::PDFFile;
}

bool CheckType(GView::Utils::DataCache& data, uint64& offset, const uint64& size_type, const uint8_t PDF_ARRAY[])
{
    uint8_t buffer;
    bool match = true;
    for (uint64 i = 0; i < size_type; ++i) {
        if (!data.Copy(offset + i, buffer) || buffer != PDF_ARRAY[i]) {
            match = false;
            break;
        }
    }
    return match;
}

bool IsEqualType(const std::string& s, const uint64_t& size_type, const uint8_t PDF_ARRAY[])
{
    if (s.size() != size_type) {
        return false;
    }

    for (uint64_t i = 0; i < size_type; i++) {
        if (static_cast<uint8_t>(s[i]) != PDF_ARRAY[i]) {
            return false;
        }
    }
    return true;
}

static bool TerminateProcessing(const int8 buffer)
{
    switch (buffer) {
    case PDF::WSC::SPACE:
    case PDF::WSC::LINE_FEED:
    case PDF::WSC::FORM_FEED:
    case PDF::WSC::CARRIAGE_RETURN:
    case PDF::DC::SOLIDUS:
    case PDF::DC::RIGHT_SQUARE_BRACKET:
    case PDF::DC::LEFT_SQUARE_BRACKET:
    case PDF::DC::LESS_THAN:
    case PDF::DC::GREATER_THAN:
    case PDF::DC::LEFT_PARETHESIS:
    case PDF::DC::RIGHT_PARETHESIS:
    case PDF::DC::LEFT_CURLY_BRACKET:
    case PDF::DC::RIGHT_CURLY_BRACKET:
        return true;
        break;
    default:
        return false;
    }
}

static int HexVal(uint8_t c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static bool HasHashEscaping(GView::Utils::DataCache& data, uint64_t offset, const uint64_t endBuffer)
{
    offset++;
    while (offset < endBuffer) {
        uint8 c;
        if (!data.Copy(offset, c)) {
            break;
        }
        if (TerminateProcessing(c)) {
            break;
        }
        if (c == '#') {
            if (offset + 2 < endBuffer) {
                uint8 c1, c2;
                if (!data.Copy(offset + 1, c1) || !data.Copy(offset + 2, c2)) {
                    break;
                }

                int v1 = HexVal(c1);
                int v2 = HexVal(c2);
                if (v1 >= 0 && v2 >= 0) {
                    return true;
                }
            }
        }
        offset++;
    }
    return false;
}

static std::string DecodeName(GView::Utils::DataCache& data, uint64_t& offset, const uint64_t endBuffer)
{
    std::string result;
    result += "/";
    offset++;
    while (offset < endBuffer) {
        uint8 c;
        if (!data.Copy(offset, c)) {
            break;
        }

        if (TerminateProcessing(c)) {
            break;
        }

        if (c == '#') {
            if (offset + 2 < endBuffer) {
                uint8 c1, c2;
                if (!data.Copy(offset + 1, c1) || !data.Copy(offset + 2, c2)) {
                    break;
                }

                int v1 = HexVal(c1);
                int v2 = HexVal(c2);
                if (v1 >= 0 && v2 >= 0) {
                    uint8_t decoded = static_cast<uint8_t>(v1 * 16 + v2);
                    result.push_back((char) decoded);
                    // Skip the '#' + two hex digits
                    offset += 3;
                    continue;
                }
            }
        }
        result.push_back((char) c);
        offset++;
    }
    // offset--;
    return result;
}

uint64 GetTypeValue(GView::Utils::DataCache& data, uint64& offset, const uint64& dataSize)
{
    std::string lengthValStr;
    uint8_t buffer;
    uint64 value = 0;
    bool error   = false;
    while (offset < dataSize && data.Copy(offset, buffer) && buffer >= '0' && buffer <= '9') {
        lengthValStr.push_back(buffer);
        offset++;
        if (lengthValStr.size() > 20) {
            Dialogs::MessageBox::ShowError("Error!", "Unusual big size for length");
            error = true;
            break;
        }
    }

    if (!lengthValStr.empty() && !error) {
        value = std::stoull(lengthValStr);
    }
    return value;
}

uint8 GetWValue(GView::Utils::DataCache& data, uint64& offset)
{
    std::string lengthValStr;
    uint8_t buffer;
    uint8 value = 0;
    if (data.Copy(offset, buffer)) {
        lengthValStr.push_back(buffer);
        offset++;
    }

    if (!lengthValStr.empty()) {
        value = std::stoull(lengthValStr);
    }
    return value;
}

void GetFilters(GView::Utils::DataCache& data, uint64& offset, const uint64& dataSize, std::vector<std::string>& filters, GView::Utils::ErrorList &errList)
{
    const std::unordered_set<std::string> STANDARD_FILTERS = { "/ASCIIHexDecode", "/ASCII85Decode", "/LZWDecode", "/FlateDecode", "/RunLengthDecode",
                                                                      "/CCITTFaxDecode", "/JBIG2Decode",   "/DCTDecode", "/JPXDecode",   "/Crypt" };
    uint8_t buffer;
    while (data.Copy(offset, buffer) && buffer == PDF::WSC::SPACE && offset < dataSize) {
        offset++;
    }
    bool multipleFilters = false;
    if (data.Copy(offset, buffer) && buffer == PDF::DC::LEFT_SQUARE_BRACKET) // '['
    {
        multipleFilters = true;
        offset++; // skip '['
    }
    while (offset < dataSize) {
        while (data.Copy(offset, buffer) && buffer == PDF::WSC::SPACE && offset < dataSize) {
            offset++;
        }

        if (multipleFilters) {
            if (!data.Copy(offset, buffer)) {
                break;
            }
            if (buffer == PDF::DC::RIGHT_SQUARE_BRACKET) // ']'
            {
                break;
            }
        }

        if (!data.Copy(offset, buffer)) {
            break;
        }

        if (buffer == PDF::DC::SOLIDUS) // '/'
        {
            const uint64 copyOffset = offset;
            std::string filterValue = DecodeName(data, offset, dataSize);
            if (filterValue.length() > 1) {
                filters.push_back(filterValue);
                if (STANDARD_FILTERS.find(filterValue) == STANDARD_FILTERS.end()) {
                    errList.AddWarning("Detected non-standard filter '%s' (0x%llX)", filterValue.c_str(), copyOffset);
                }
            }
        } else {
            offset++;
        }
        if (!multipleFilters) {
            offset--;
            break;
        }
    }
}


void GetDecompressDataValue(Buffer& decompressedData, uint64& offset, const uint8& value, uint64& obj)
{
    for (uint8_t i = 0; i < value; ++i) {
        obj = (obj << 8) | decompressedData[offset + i];
    }
    offset += value;
}

void GetObjectsOffsets(
      const uint64& numEntries, uint64& offset, GView::Utils::DataCache& data, std::vector<uint64_t>& objectOffsets, GView::Utils::ErrorList &errList)
{
    std::unordered_set<uint64_t> seenOffsets; // Store seen offsets

    auto isValidEOFSequence = [](uint8_t eofSequence[2]) -> bool {
        return (eofSequence[0] == PDF::WSC::SPACE && eofSequence[1] == PDF::WSC::CARRIAGE_RETURN) ||
               (eofSequence[0] == PDF::WSC::SPACE && eofSequence[1] == PDF::WSC::LINE_FEED) ||
               (eofSequence[0] == PDF::WSC::CARRIAGE_RETURN && eofSequence[1] == PDF::WSC::LINE_FEED);
    };

    // Read each 20-byte entry
    for (uint64 i = 0; i < numEntries; ++i) {
        PDF::TableEntry entry;
        if (!data.Copy<PDF::TableEntry>(offset, entry)) {
            break;
        }
        if (isValidEOFSequence(entry.eofSequence)) {
            if (entry.flag != PDF::KEY::PDF_FREE_ENTRY) { // Skip the free entries
                uint64_t result  = 0;
                bool leadingZero = true;

                for (size_t j = 0; j < 10; ++j) {
                    uint8_t asciiValue = entry.objectOffset[j];

                    uint8_t digit = asciiValue - '0';

                    if (leadingZero && digit == 0) {
                        continue;
                    } else {
                        leadingZero = false;
                        result      = 10 * result + digit;
                    }
                }

                if (seenOffsets.find(result) == seenOffsets.end()) {
                    objectOffsets.push_back(result);
                    seenOffsets.insert(result);
                }
            }
        } else {
            Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Invalid Cross-Reference Table sequence. It has to be 20 bytes!");
            errList.AddError("Invalid Cross-Reference Table sequence. It has to be 20 bytes (0x%llX)", (uint64_t) offset);
            break;
        }
        offset += PDF::KEY::PDF_XREF_ENTRY;
    }
}

uint64 GetNumberOfEntries(const uint64& crossRefOffset, uint64& offset, const uint64& dataSize, GView::Utils::DataCache& data)
{
    uint8_t buffer;
    uint16_t numEntries = 0;
    if (crossRefOffset > 0) {
        offset = crossRefOffset + 4; // Skip "xref" keyword

        while (offset < dataSize) {
            if (!data.Copy(offset, buffer)) {
                break;
            }
            if (buffer != PDF::WSC::LINE_FEED && buffer != PDF::WSC::CARRIAGE_RETURN && buffer != PDF::WSC::SPACE) {
                break;
            }
            offset++;
        }

        while (offset < dataSize) {
            if (!data.Copy(offset, buffer)) {
                break;
            }
            if (buffer == PDF::WSC::SPACE) {
                offset++;
                break;
            }
            offset++;
        }

        std::string numEntriesStr;
        while (offset < dataSize) {
            if (!data.Copy(offset, buffer)) {
                break;
            }
            if (buffer >= '0' && buffer <= '9') {
                numEntriesStr.push_back(buffer);
            } else {
                break;
            }
            offset++;
        }

        if (!numEntriesStr.empty()) {
            numEntries = static_cast<uint16_t>(std::stoi(numEntriesStr));
        }
    }
    return numEntries;
}

bool GetTrailerOffset(uint64& offset, const uint64& dataSize, GView::Utils::DataCache& data, uint64& trailerOffset)
{
    // trailer segment
    bool foundTrailer = false;
    for (; offset < dataSize - PDF::KEY::PDF_TRAILER_SIZE; ++offset) {
        const bool match = CheckType(data, offset, PDF::KEY::PDF_TRAILER_SIZE, PDF::KEY::PDF_TRAILER_KEY);
        if (match) {
            trailerOffset = offset;
            foundTrailer  = true;
            break;
        }
    }
    return foundTrailer;
}

void HighlightObjectTypes(
      GView::Utils::DataCache& data, Reference<PDF::PDFFile> pdf, BufferViewer::Settings& settings, const uint64_t& dataSize, PDF::PDFObject& pdfObject)
{
    uint8_t buffer;
    uint64_t lengthVal    = 0;
    bool foundLength      = false;
    uint64_t objectOffset = pdfObject.startBuffer;

    // skip nr 0 obj
    while (!CheckType(data, objectOffset, PDF::KEY::PDF_OBJ_SIZE, PDF::KEY::PDF_OBJ) && objectOffset < dataSize) {
        objectOffset++;
    }
    objectOffset += PDF::KEY::PDF_OBJ_SIZE;

    while (objectOffset < pdfObject.endBuffer) {
        if (!data.Copy(objectOffset, buffer)) {
            break;
        } else if (
              CheckType(data, objectOffset, PDF::KEY::PDF_DIC_SIZE, PDF::KEY::PDF_DIC_START) ||
              CheckType(data, objectOffset, PDF::KEY::PDF_DIC_SIZE, PDF::KEY::PDF_DIC_END)) {
            settings.AddZone(objectOffset, PDF::KEY::PDF_DIC_SIZE, ColorPair{ Color::Yellow, Color::DarkBlue }, "Dictionary");
            objectOffset += PDF::KEY::PDF_DIC_SIZE;
        } else if (buffer == PDF::DC::SOLIDUS) {
            uint64_t copyObjectOffset    = objectOffset;
            if (!pdf->hashEscaping) {
                pdf->hashEscaping = HasHashEscaping(data, copyObjectOffset, pdfObject.endBuffer);
            }
            std::string decodedName      = DecodeName(data, copyObjectOffset, pdfObject.endBuffer);
            // get the length for the stream so that we don't have to go through all the bytes
            if (!foundLength && IsEqualType(decodedName, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH)) { // /Length for the stream
                settings.AddZone(objectOffset, copyObjectOffset - objectOffset, ColorPair{ Color::Red, Color::DarkBlue }, "Name");
                objectOffset = copyObjectOffset + 1;
                const uint64_t start_segment = objectOffset;
                lengthVal                    = GetTypeValue(data, objectOffset, dataSize);
                settings.AddZone(start_segment, objectOffset - start_segment, ColorPair{ Color::Green, Color::DarkBlue }, "Numeric");
                foundLength = true;
            } else {
                const uint64_t start_segment = objectOffset;
                objectOffset++;
                bool end_name = false;
                while (objectOffset < dataSize && !end_name) {
                    if (!data.Copy(objectOffset, buffer)) {
                        break;
                    }
                    switch (buffer) {
                    case PDF::WSC::SPACE:
                    case PDF::WSC::LINE_FEED:
                    case PDF::WSC::FORM_FEED:
                    case PDF::WSC::CARRIAGE_RETURN:
                    case PDF::DC::SOLIDUS:
                    case PDF::DC::RIGHT_SQUARE_BRACKET:
                    case PDF::DC::LEFT_SQUARE_BRACKET:
                    case PDF::DC::LESS_THAN:
                    case PDF::DC::GREATER_THAN:
                    case PDF::DC::LEFT_PARETHESIS:
                    case PDF::DC::RIGHT_PARETHESIS:
                        end_name = true;
                        break;
                    default:
                        objectOffset++;
                    }
                }
                settings.AddZone(start_segment, objectOffset - start_segment, ColorPair{ Color::Red, Color::DarkBlue }, "Name");
            }
        } else if (buffer == PDF::KEY::PDF_INDIRECTOBJ) {
            settings.AddZone(objectOffset, 1, ColorPair{ Color::Yellow, Color::Blue }, "Indirect Obj");
            objectOffset++;
        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_STREAM_SIZE, PDF::KEY::PDF_STREAM)) {
            if (foundLength) {
                const uint64_t start_segment = objectOffset;
                objectOffset += PDF::KEY::PDF_STREAM_SIZE + lengthVal;
                while (objectOffset < dataSize && !CheckType(data, objectOffset, PDF::KEY::PDF_ENDSTREAM_SIZE, PDF::KEY::PDF_ENDSTREAM)) {
                    objectOffset++;
                }
                objectOffset += PDF::KEY::PDF_ENDSTREAM_SIZE;
                settings.AddZone(start_segment, objectOffset - start_segment, ColorPair{ Color::Aqua, Color::DarkBlue }, "Stream");
                pdf->pdfStats.streamsCount++;
            } else {
                break;
            }
        } else if (buffer == PDF::DC::LEFT_SQUARE_BRACKET || buffer == PDF::DC::RIGHT_SQUARE_BRACKET) {
            settings.AddZone(objectOffset, 1, ColorPair{ Color::Olive, Color::DarkBlue }, "Array");
            objectOffset++;
        } else if (buffer == '-' || buffer == '+' || (buffer >= '0' && buffer <= '9')) {
            const uint64_t start_segment = objectOffset;
            objectOffset++;
            while (objectOffset < dataSize && data.Copy(objectOffset, buffer) && ((buffer >= '0' && buffer <= '9') || buffer == '.')) {
                objectOffset++;
            }
            settings.AddZone(start_segment, objectOffset - start_segment, ColorPair{ Color::Green, Color::DarkBlue }, "Numeric");
        } else if (buffer == PDF::DC::LEFT_PARETHESIS) {
            const uint64_t start_segment = objectOffset;
            objectOffset++;
            while (objectOffset < dataSize && data.Copy(objectOffset, buffer) && buffer != PDF::DC::RIGHT_PARETHESIS) {
                if (buffer == PDF::DC::REVERSE_SOLIDUS) {
                    objectOffset++;
                }
                objectOffset++;
            }
            settings.AddZone(start_segment, objectOffset - start_segment + 1, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Literal String");
        } else if (buffer == PDF::DC::LESS_THAN) {
            const uint64_t start_segment = objectOffset;
            objectOffset++;
            while (objectOffset < dataSize && data.Copy(objectOffset, buffer) && buffer != PDF::DC::GREATER_THAN) {
                objectOffset++;
            }
            settings.AddZone(start_segment, objectOffset - start_segment + 1, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Hex String");
        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
            settings.AddZone(objectOffset, PDF::KEY::PDF_TRUE_SIZE, ColorPair{ Color::DarkRed, Color::DarkBlue }, "Boolean");
            objectOffset += PDF::KEY::PDF_TRUE_SIZE;
        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_FALSE_SIZE, PDF::KEY::PDF_FALSE)) {
            settings.AddZone(objectOffset, PDF::KEY::PDF_FALSE_SIZE, ColorPair{ Color::DarkRed, Color::DarkBlue }, "Boolean");
            objectOffset += PDF::KEY::PDF_FALSE_SIZE;
        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_NULL_SIZE, PDF::KEY::PDF_NULL)) {
            settings.AddZone(objectOffset, PDF::KEY::PDF_NULL_SIZE, ColorPair{ Color::White, Color::Blue }, "Null");
            objectOffset += PDF::KEY::PDF_NULL_SIZE;
        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_ENDOBJ_SIZE, PDF::KEY::PDF_ENDOBJ)) {
            break;
        } else {
            objectOffset++;
        }
    }
}

bool IsCrossRefStream(uint64 offset, GView::Utils::DataCache& data, const uint64& dataSize)
{
    // number 0 obj
    GetTypeValue(data, offset, dataSize);
    uint8_t buffer;
    if (!data.Copy(offset, buffer)) {
        Dialogs::MessageBox::ShowError("Error!", "IsCrossRefStream - Copy buffer error");
        return false;
    }
    if (buffer != PDF::WSC::SPACE) {
        return false;
    }
    offset++;
    if (!data.Copy(offset, buffer)) {
        Dialogs::MessageBox::ShowError("Error!", "IsCrossRefStream - Copy buffer error");
    }
    if (buffer != '0') {
        return false;
    }
    offset++;
    if (!data.Copy(offset, buffer)) {
        Dialogs::MessageBox::ShowError("Error!", "IsCrossRefStream - Copy buffer error");
    }
    if (buffer != PDF::WSC::SPACE) {
        return false;
    }
    offset++;
    if (!CheckType(data, offset, PDF::KEY::PDF_OBJ_SIZE, PDF::KEY::PDF_OBJ)) {
        return false;
    }
    return true;
}

void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<PDF::PDFFile> pdf)
{
    BufferViewer::Settings settings;

    auto& data            = pdf->obj->GetData();
    const uint64 dataSize = data.GetSize();
    uint64 offset         = dataSize;
    uint64 crossRefOffset = 0;
    uint64 eofOffset      = 0;
    uint64 prevOffset     = 0;
    uint8_t buffer;
    bool foundEOF = false;
    std::vector<uint64_t> objectOffsets;
    std::vector<uint64_t> streamOffsets;

    // HEADER
    settings.AddZone(0, sizeof(PDF::Header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");

    // EOF segment
    while (offset >= (PDF::KEY::PDF_EOF_SIZE + sizeof(PDF::Header)) && !foundEOF) {
        offset--;

        if (!data.Copy(offset, buffer)) {
            continue;
        }

        if (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN) {
            continue;
        }

        // check for %%EOF
        if (buffer == PDF::KEY::PDF_EOF[PDF::KEY::PDF_EOF_SIZE - 1]) {
            bool match = true;
            for (size_t i = 0; i < PDF::KEY::PDF_EOF_SIZE; ++i) {
                if (!data.Copy(offset - PDF::KEY::PDF_EOF_SIZE + 1 + i, buffer) || buffer != PDF::KEY::PDF_EOF[i]) {
                    match = false;
                }
            }

            if (match) {
                foundEOF = true;
                offset -= PDF::KEY::PDF_EOF_SIZE - 1;
                eofOffset = offset;
                settings.AddZone(eofOffset, PDF::KEY::PDF_EOF_SIZE, ColorPair{ Color::Magenta, Color::DarkBlue }, "EOF");
            }
        }
    }

    if (!foundEOF) {
        Dialogs::MessageBox::ShowError("Error!", "Anomaly found: End of file segment (%%EOF) is missing!");
        pdf->errList.AddError("End of file segment (%%EOF) is missing (0x%llX)", (uint64_t) offset);
        return;
    }
    
    // data after the %%EOF segment -> IOC
    if (dataSize - offset >= 10) {
        pdf->errList.AddWarning(
              "Suspicious data found after %%EOF (0x%llX): potential hidden payload or obfuscation", (uint64_t) (offset + PDF::KEY::PDF_EOF_SIZE));
    }

    // offset of the cross-reference
    if (foundEOF) {
        std::string xrefOffsetStr;
        while (offset > 0) {
            offset--;

            if (!data.Copy(offset, buffer)) {
                break;
            }

            if (buffer != PDF::WSC::LINE_FEED && buffer != PDF::WSC::CARRIAGE_RETURN) {
                while (offset > 0) {
                    if (!data.Copy(offset, buffer)) {
                        break;
                    }

                    if (buffer >= '0' && buffer <= '9') {
                        xrefOffsetStr.insert(xrefOffsetStr.begin(), buffer);
                    } else {
                        break;
                    }
                    offset--;
                }
                if (!xrefOffsetStr.empty()) {
                    crossRefOffset = std::stoull(xrefOffsetStr);
                } else {
                    Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Couldn't find the xref offset!");
                    pdf->errList.AddError("Couldn't find the xref offset (0x%llX)", (uint64_t) offset);
                    return;
                }
                break;
            }
        }
    }

    // cross-reference table or cross-reference stream
    pdf->hasXrefTable = CheckType(data, crossRefOffset, PDF::KEY::PDF_XREF_SIZE, PDF::KEY::PDF_XREF);

    // cross-reference table
    if (pdf->hasXrefTable) {
        bool next_table = true;
        while (next_table) {
            PDF::PDFObject pdfObject;
            pdfObject.startBuffer = crossRefOffset;
            pdfObject.type        = PDF::SectionPDFObjectType::CrossRefTable;
            pdfObject.number      = 0;
            // get the offsets from the Cross-Reference Table
            const uint64 numEntries = GetNumberOfEntries(crossRefOffset, offset, dataSize, data);
            if (numEntries == 0) {
                Dialogs::MessageBox::ShowError("Error!", "Anomaly found: 0 entries in the Cross-Reference Table!");
                pdf->errList.AddError("There are 0 entries in the Cross-Reference Table (0x%llX)", (uint64_t) offset);
            }
            while (offset < dataSize) {
                if (!data.Copy(offset, buffer)) {
                    break;
                }
                if (buffer != PDF::WSC::LINE_FEED && buffer != PDF::WSC::CARRIAGE_RETURN && buffer != PDF::WSC::SPACE) {
                    break;
                }
                offset++;
            }

            GetObjectsOffsets(numEntries, offset, data, objectOffsets, pdf->errList);

            pdfObject.endBuffer = offset;
            pdf->AddPDFObject(pdf, pdfObject);

            uint64 trailerOffset    = 0;
            const bool foundTrailer = GetTrailerOffset(offset, dataSize, data, trailerOffset);

            pdfObject.startBuffer = trailerOffset;
            pdfObject.type        = PDF::SectionPDFObjectType::Trailer;
            pdfObject.number      = 0;
            // Find /Prev in the trailer segment
            bool found_prev = false;
            if (foundTrailer) {
                offset = trailerOffset;
                while (offset < dataSize) {
                    if (!data.Copy(offset, buffer)) {
                        break;
                    }
                    if (buffer == PDF::DC::SOLIDUS) {
                        std::string decodedName = DecodeName(data, offset, dataSize);
                        if (IsEqualType(decodedName, PDF::KEY::PDF_PREV_SIZE, PDF::KEY::PDF_PREV)) {

                            while (offset < dataSize && (data.Copy(offset, buffer) &&
                                                         (buffer == PDF::WSC::SPACE || buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN))) {
                                offset++;
                            }

                            prevOffset = GetTypeValue(data, offset, dataSize);
                            if (prevOffset != 0) {
                                found_prev = true;
                            } else {
                                Dialogs::MessageBox::ShowError("Error!", "Anomaly found: /Prev in the trailer has the value equal to zero!");
                                pdf->errList.AddError("/Prev in the trailer has the value equal to zero (0x%llX)", (uint64_t) offset);
                            }
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_ENCRYPT_SIZE, PDF::KEY::PDF_ENCRYPT)) {
                            pdf->pdfStats.isEncrypted = true;
                        }
                    }
                    if (CheckType(data, offset, PDF::KEY::PDF_EOF_SIZE, PDF::KEY::PDF_EOF)) {
                        settings.AddZone(offset, PDF::KEY::PDF_EOF_SIZE, ColorPair{ Color::Magenta, Color::DarkBlue }, "EOF");
                        offset += PDF::KEY::PDF_EOF_SIZE;
                        break;
                    } else {
                        offset++;
                    }
                }
                if (!found_prev) {
                    next_table = false;
                }
            } else {
                Dialogs::MessageBox::ShowError("Error!", "Anomaly found: The trailer is missing!");
                pdf->errList.AddError("The trailer is missing (0x%llX)", (uint64_t) offset);
            }

            pdfObject.endBuffer = offset;
            pdf->AddPDFObject(pdf, pdfObject);

            if (foundTrailer) {
                settings.AddZone(crossRefOffset, trailerOffset - crossRefOffset, ColorPair{ Color::Green, Color::DarkBlue }, "Cross-Reference Table");
                settings.AddZone(trailerOffset, offset - trailerOffset, ColorPair{ Color::Red, Color::DarkBlue }, "Trailer");
            }
            crossRefOffset = prevOffset;
        }
    } else if (IsCrossRefStream(crossRefOffset, data, dataSize)) { // cross-reference stream
        bool next_CR_stream = true;
        std::unordered_set<uint64_t> seenOffsets;
        while (next_CR_stream) {
            offset = crossRefOffset;
            uint8_t tag;
            bool end_tag     = false;
            uint64 lengthVal = 0;
            Buffer streamData;
            std::vector<std::string> filters;

            PDF::TypeFlags typeFlags;
            PDF::WValues wValues         = { 0, 0, 0 };
            PDF::DecodeParms decodeParms = { 1, 1, 8, 1 };

            PDF::PDFObject pdfObject;
            pdfObject.startBuffer = crossRefOffset;
            pdfObject.type        = PDF::SectionPDFObjectType::CrossRefStream;
            pdfObject.number      = GetTypeValue(data, offset, dataSize);

            while (!end_tag && offset < dataSize) {
                if (CheckType(data, offset, PDF::KEY::PDF_STREAM_SIZE, PDF::KEY::PDF_STREAM)) {
                    end_tag = true;
                    offset += PDF::KEY::PDF_STREAM_SIZE;
                    break;
                }

                if (data.Copy(offset, tag) && tag == PDF::DC::SOLIDUS) { // the first byte of tag is "/"
                    std::string decodedName = DecodeName(data, offset, dataSize);
                    if (!typeFlags.hasLength && IsEqualType(decodedName, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH)) { // /Length
                        offset += 1;
                        lengthVal           = GetTypeValue(data, offset, dataSize);
                        typeFlags.hasLength = true;
                    } else if (!typeFlags.hasFilter && IsEqualType(decodedName, PDF::KEY::PDF_FILTER_SIZE, PDF::KEY::PDF_FILTER)) { // /Filter
                        GetFilters(data, offset, dataSize, filters, pdf->errList);
                        typeFlags.hasFilter = true;
                    } else if (!typeFlags.hasPrev && IsEqualType(decodedName, PDF::KEY::PDF_PREV_SIZE, PDF::KEY::PDF_PREV)) { // /Prev
                        offset += 1;
                        prevOffset        = GetTypeValue(data, offset, dataSize);
                        typeFlags.hasPrev = true;
                    } else if (IsEqualType(decodedName, PDF::KEY::PDF_ENCRYPT_SIZE, PDF::KEY::PDF_ENCRYPT)) {
                        pdf->pdfStats.isEncrypted = true;
                    } else if (
                          !typeFlags.hasDecodeParms && IsEqualType(decodedName, PDF::KEY::PDF_DECODEPARMS_SIZE, PDF::KEY::PDF_DECODEPARMS)) { // /DecodeParms
                        offset += 2;
                        uint16_t tag;
                        uint8 buffer;
                        while (offset < dataSize) {
                            if (!data.Copy(offset, tag)) {
                                continue;
                            }
                            if (!data.Copy(offset, buffer)) {
                                continue;
                            }
                            if (tag == PDF::DC::END_TAG) {
                                offset += 2;
                                break;
                            }
                            if (buffer == PDF::DC::SOLIDUS) {
                                std::string decodedName2 = DecodeName(data, offset, dataSize);
                                if (IsEqualType(decodedName2, PDF::KEY::PDF_COLUMNS_SIZE, PDF::KEY::PDF_COLUMNS)) {
                                    offset += 1;
                                    decodeParms.column = GetTypeValue(data, offset, dataSize);
                                } else if (IsEqualType(decodedName2, PDF::KEY::PDF_PREDICTOR_SIZE, PDF::KEY::PDF_PREDICTOR)) {
                                    offset += 1;
                                    decodeParms.predictor = GetTypeValue(data, offset, dataSize);
                                } else if (IsEqualType(decodedName2, PDF::KEY::PDF_BPC_SIZE, PDF::KEY::PDF_BPC)) {
                                    offset += 1;
                                    decodeParms.bitsPerComponent = GetTypeValue(data, offset, dataSize);
                                } else if (IsEqualType(decodedName2, PDF::KEY::PDF_EARLYCG_SIZE, PDF::KEY::PDF_EARLYCG)) {
                                    offset += 1;
                                    decodeParms.earlyChange = GetTypeValue(data, offset, dataSize);
                                }
                            }
                            else {
                                offset++;
                            }
                        }
                        typeFlags.hasDecodeParms = true;
                    } else if (!typeFlags.hasW && IsEqualType(decodedName, PDF::KEY::PDF_W_SIZE, PDF::KEY::PDF_W)) { // /W
                        if (data.Copy(offset, buffer) && buffer != PDF::DC::LEFT_SQUARE_BRACKET) {
                            offset++;
                        }
                        offset++; // skip "["
                        wValues.x = GetWValue(data, offset);
                        offset++;
                        wValues.y = GetWValue(data, offset);
                        offset++;
                        wValues.z = GetWValue(data, offset);
                        offset++;
                        typeFlags.hasW = true;
                    } else {
                        offset++;
                    }
                } else {
                    offset++;
                }
            }
            if (end_tag) {
                if (typeFlags.hasLength) { // copy the stream data
                    while (offset < dataSize && (data.Copy(offset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN))) {
                        offset++;
                    }
                    streamData.Resize(lengthVal);
                    for (uint64 i = 0; i < lengthVal; ++i) {
                        uint8_t byte;
                        if (!data.Copy(offset + i, byte)) {
                            break;
                        }
                        streamData[i] = byte;
                    }
                    offset += lengthVal + PDF::KEY::PDF_ENDSTREAM_SIZE + PDF::KEY::PDF_ENDOBJ_SIZE + PDF::KEY::PDF_STARTXREF_SIZE;
                    bool found_eof = false;
                    while (!found_eof && offset < dataSize) {
                        found_eof = CheckType(data, offset, PDF::KEY::PDF_EOF_SIZE, PDF::KEY::PDF_EOF);
                        if (found_eof) {
                            settings.AddZone(offset, PDF::KEY::PDF_EOF_SIZE, ColorPair{ Color::Magenta, Color::DarkBlue }, "EOF");
                            offset += PDF::KEY::PDF_EOF_SIZE;
                            pdfObject.endBuffer = offset;
                            pdf->AddPDFObject(pdf, pdfObject);
                            settings.AddZone(
                                  crossRefOffset,
                                  offset - crossRefOffset - PDF::KEY::PDF_EOF_SIZE,
                                  ColorPair{ Color::Green, Color::DarkBlue },
                                  "Cross-Reference Stream");
                            break;
                        } else {
                            offset++;
                        }
                    }
                    if (!found_eof) {
                        Dialogs::MessageBox::ShowError("Error!", "Anomaly found: End of file segment (%%EOF) is missing for Cross-Reference Stream!");
                        pdf->errList.AddError("End of file segment (%%EOF) is missing for Cross-Reference Stream (0x%llX)", (uint64_t) offset);
                    }
                }

                if (typeFlags.hasFilter) { // decode data
                    if (filters[0] == PDF::FILTER::FLATE) {
                        Buffer decompressedData;
                        uint64 decompressDataSize = lengthVal;
                        AppCUI::Utils::String message;
                        if (GView::Decoding::ZLIB::DecompressStream(streamData, decompressedData, message, decompressDataSize)) {
                            if (typeFlags.hasDecodeParms) {
                                PDF::PDFFile::ApplyPNGFilter(decompressedData, decodeParms.column, decodeParms.predictor, decodeParms.bitsPerComponent);
                                decompressDataSize = decompressedData.GetLength();
                            }
                            offset = 0;
                            if (!typeFlags.hasW) {
                                Dialogs::MessageBox::ShowError(
                                      "Error!", "Anomaly found: W values missing for objects offset references from the Cross-Reference Stream!");
                                pdf->errList.AddError("W values missing for objects offset references from the Cross-Reference Stream (0x%llX)", (uint64_t) offset);
                                break;
                            }
                            while (offset < decompressDataSize) {
                                uint64_t obj1 = 0, obj2 = 0, obj3 = 0;

                                GetDecompressDataValue(decompressedData, offset, wValues.x, obj1);
                                GetDecompressDataValue(decompressedData, offset, wValues.y, obj2);
                                GetDecompressDataValue(decompressedData, offset, wValues.z, obj3);

                                if (obj1 == 1) { // don't include CR stream as an object
                                    if (seenOffsets.find(obj2) == seenOffsets.end()) {
                                        objectOffsets.push_back(obj2);
                                        seenOffsets.insert(obj2);
                                    }

                                    if (obj2 == crossRefOffset) {
                                        streamOffsets.push_back(obj2);
                                    }
                                }

                                if (offset > decompressDataSize) {
                                    break;
                                }
                            }
                        } else {
                            Dialogs::MessageBox::ShowError("Error!", message);
                            pdf->errList.AddError(message);
                        }
                    } else {
                        Dialogs::MessageBox::ShowError(
                              "Error!", "Unknown Filter for the Cross-Reference Stream!");
                        pdf->errList.AddError("Unknown Filter for the Cross-Reference Stream (0x%llX)", (uint64_t) offset);
                    }
                }

                if (typeFlags.hasPrev) { // offset of the previous cross reference stream
                    crossRefOffset = prevOffset;
                } else {
                    next_CR_stream = false;
                }
            } else {
                Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Cross-Reference Stream is missing!");
                pdf->errList.AddError("Cross-Reference Stream is missing (0x%llX)", (uint64_t) offset);
            }
        }
    } else {
        Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Couldn't find a Cross-Reference Table or Cross-Reference Stream!");
        pdf->errList.AddError("Couldn't find a Cross-Reference Table or Cross-Reference Stream (0x%llX)", (uint64_t) offset);
    }

    std::sort(objectOffsets.begin(), objectOffsets.end());

    for (size_t i = 0; i < objectOffsets.size(); ++i) {
        if (std::find(streamOffsets.begin(), streamOffsets.end(), objectOffsets[i]) != streamOffsets.end()) {
            if (i + 1 < objectOffsets.size()) {
                ++i;
            } else if (i + 1 == objectOffsets.size()) {
                continue;
            }
        }
        uint64_t objOffset = objectOffsets[i];

        PDF::PDFObject pdfObject;
        pdfObject.startBuffer = objOffset;
        pdfObject.type        = PDF::SectionPDFObjectType::Object;
        pdfObject.number      = GetTypeValue(data, objOffset, dataSize);

        uint64_t endobjOffset = (i + 1 < objectOffsets.size()) ? objectOffsets[i + 1] : eofOffset;

        while (!CheckType(data, endobjOffset, PDF::KEY::PDF_ENDOBJ_SIZE, PDF::KEY::PDF_ENDOBJ) && endobjOffset > 0) {
            endobjOffset--;
        }
        endobjOffset += PDF::KEY::PDF_ENDOBJ_SIZE;
        pdfObject.endBuffer   = endobjOffset;
        const uint64_t length = pdfObject.endBuffer - pdfObject.startBuffer;

        settings.AddZone(pdfObject.startBuffer, length, { Color::Teal, Color::DarkBlue }, "Obj " + std::to_string(pdfObject.number));
        pdf->AddPDFObject(pdf, pdfObject);
        HighlightObjectTypes(data, pdf, settings, dataSize, pdfObject);
    }

    pdf->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    if (pdf->hashEscaping) {
        pdf->errList.AddWarning("Hex-escaped name objects detected (#xx)");
    }
}

uint64 GetObjectReference(const uint64& dataSize, GView::Utils::DataCache& data, uint64& objectOffset, uint8& buffer, std::vector<uint64> &objectsNumber)
{
    bool foundObjRef    = false;
    const uint64 number = GetTypeValue(data, objectOffset, dataSize);
    uint64 copyobjectOffset = objectOffset;
    if (!data.Copy(objectOffset, buffer)) {
        Dialogs::MessageBox::ShowError("Error!", "GetObjectReference - Copy buffer error");
    }
    copyobjectOffset++;
    if (!data.Copy(copyobjectOffset, buffer)) {
        Dialogs::MessageBox::ShowError("Error!", "GetObjectReference - Copy buffer error");
    }
    if (buffer == '0') {
        copyobjectOffset += 2;
        if (!data.Copy(copyobjectOffset, buffer)) {
            Dialogs::MessageBox::ShowError("Error!", "GetObjectReference - Copy buffer error");
        }
        if (buffer == PDF::KEY::PDF_INDIRECTOBJ) {
            foundObjRef = true;
        }
    }
    if (foundObjRef) {
        // check if the number already exists in the vector
        if (std::find(objectsNumber.begin(), objectsNumber.end(), number) == objectsNumber.end()) {
            objectsNumber.push_back(number);
        }
        objectOffset = copyobjectOffset;
    }
    return number;
}

std::string GetDictionaryType(GView::Utils::DataCache& data, uint64& objectOffset, const uint64& dataSize, std::vector<std::string>& entries)
{
    uint8 buffer;
    std::string entry;
    while (data.Copy(objectOffset, buffer) && buffer == PDF::WSC::SPACE && objectOffset < dataSize) {
        objectOffset++;
    }
    if (buffer == PDF::DC::SOLIDUS) {
        entry = DecodeName(data, objectOffset, dataSize);
        if (!entry.empty() && std::find(entries.begin(), entries.end(), entry) == entries.end()) {
            entries.push_back(entry);
        }
    }
    return entry;
}

uint64 GetLengthNumber(GView::Utils::DataCache& data, uint64& objectOffset, const uint64& dataSize, vector<PDF::PDFObject>& pdfObjects)
{
    uint64 numberLength = 0;
    uint8 buffer;
    bool foundRef = false;
    objectOffset += 1;
    numberLength = GetTypeValue(data, objectOffset, dataSize);
    uint64 copyOffset = objectOffset;


    if (!data.Copy(copyOffset, buffer)) {
        Dialogs::MessageBox::ShowError("Error!", "Buffer copy failed!");
    }
    copyOffset++;
    if (!data.Copy(copyOffset, buffer)) {
        Dialogs::MessageBox::ShowError("Error!", "Buffer copy failed!");
    }
    if (buffer == '0') {
        copyOffset += 2;
        if (!data.Copy(copyOffset, buffer)) {
            Dialogs::MessageBox::ShowError("Error!", "Buffer copy failed!");
        }
        if (buffer == PDF::KEY::PDF_INDIRECTOBJ) {
            foundRef = true;
        }
    }
    if (foundRef) {
        for (auto& object : pdfObjects) {
            if (object.number == numberLength) {
                uint64 refObjectOffset = object.startBuffer;
                while (refObjectOffset <= object.endBuffer) {
                    if (CheckType(data, refObjectOffset, PDF::KEY::PDF_OBJ_SIZE, PDF::KEY::PDF_OBJ)) {
                        refObjectOffset += PDF::KEY::PDF_OBJ_SIZE;
                        while (data.Copy(refObjectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                            refObjectOffset++;
                        }
                        numberLength = GetTypeValue(data, refObjectOffset, dataSize);
                        break;
                    } else {
                        refObjectOffset++;
                    }
                }
                break;
            }
        }
        objectOffset = copyOffset;
    }
    return numberLength;
}

void InsertValuesIntoStats(std::vector<std::string> &stats, std::vector<std::string> values)
{
    std::set<std::string> uniqueFilters(stats.begin(), stats.end());
    for (const auto& value : values) {
        uniqueFilters.insert(value);
    }
    stats.assign(uniqueFilters.begin(), uniqueFilters.end());
}

static PDF::PDFObject* FindObjectByNumber(std::vector<PDF::PDFObject>& pdfObjects, uint64 number, uint64 start)
{
    for (auto& obj : pdfObjects) {
        if (obj.number == number && obj.startBuffer == start) {
            return &obj;
        }
    }
    return nullptr;
}

static std::string MakeXMPDateReadable(const std::string& xmpDate)
{

    if (xmpDate.size() < 19) {
        return xmpDate;
    }

    if (xmpDate[4] != '-' || xmpDate[7] != '-' || xmpDate[10] != 'T' || xmpDate[13] != ':' || xmpDate[16] != ':') {
        return xmpDate;
    }

    auto isAllDigits = [&](int from, int to) {
        for (int i = from; i <= to; i++) {
            if (i < 0 || static_cast<size_t>(i) >= xmpDate.size() || !std::isdigit((unsigned char) xmpDate[i]))
                return false;
        }
        return true;
    };

    if (!isAllDigits(0, 3) || !isAllDigits(5, 6) || !isAllDigits(8, 9) || !isAllDigits(11, 12) || !isAllDigits(14, 15) || !isAllDigits(17, 18)) {
        return xmpDate;
    }

    std::string year   = xmpDate.substr(0, 4);
    std::string month  = xmpDate.substr(5, 2);
    std::string day    = xmpDate.substr(8, 2);
    std::string hour   = xmpDate.substr(11, 2);
    std::string minute = xmpDate.substr(14, 2);
    std::string second = xmpDate.substr(17, 2);

    std::string offsetStr;
    if (xmpDate.size() > 19) {
        char c = xmpDate[19];
        if (c == 'Z') {
            offsetStr = "Z";
        } else if (c == '+' || c == '-') {
            if (xmpDate.size() >= 25 && xmpDate[22] == ':') {
                offsetStr = xmpDate.substr(19, 6);
            } else {
                offsetStr = xmpDate.substr(19);
            }
        } else {
            // could be a fraction of second or something else; ignore
        }
    }

    std::ostringstream out;
    out << year << "-" << month << "-" << day << " " << hour << ":" << minute << ":" << second;

    if (!offsetStr.empty()) {
        out << " " << offsetStr;
    }
    return out.str();
}

static std::string ExtractBetweenTags(const std::string& src, std::string_view openTag, std::string_view closeTag)
{
    size_t start = src.find(openTag);
    if (start == std::string::npos) {
        return {};
    }
    start += openTag.size();
    if (start >= src.size()) {
        return {};
    }
    size_t end = src.find(closeTag, start);
    if (end == std::string::npos) {
        return {};
    }
    return src.substr(start, end - start);
}


static std::string ExtractXMPValue(const std::string& content, std::string_view mainStartTag, std::string_view mainEndTag)
{
    std::string block = ExtractBetweenTags(content, mainStartTag, mainEndTag);
    if (block.empty()) {
        return {};
    }

    std::string result;
    bool foundLiTag = false;
    size_t pos      = 0;

    const std::string_view liStartTag = "<rdf:li";
    const std::string_view liEndTag   = "</rdf:li>";

    while (true) {
        size_t liOpenPos = block.find(liStartTag, pos);
        if (liOpenPos == std::string::npos) {
            break;
        }

        size_t tagClosePos = block.find(PDF::DC::GREATER_THAN, liOpenPos);
        if (tagClosePos == std::string::npos) {
            break;
        }

        bool isSelfClosing = false;
        {
            std::string_view maybeSelfClosingBlock(block.c_str() + liOpenPos, (tagClosePos + 1) - liOpenPos);
            if (maybeSelfClosingBlock.find("/>") != std::string::npos) {
                isSelfClosing = true;
            }
        }

        foundLiTag = true;
        if (isSelfClosing) {
            pos = tagClosePos + 1;
        } else {
            size_t liContentStart = tagClosePos + 1;
            size_t liClosePos     = block.find(liEndTag, liContentStart);
            if (liClosePos == std::string::npos) {
                break;
            }
            std::string liContent = block.substr(liContentStart, liClosePos - liContentStart);
            if (!liContent.empty()) {
                if (!result.empty()) {
                    result += "; ";
                }
                result += liContent;
            }
            pos = liClosePos + liEndTag.size();
        }
    }
    if (!foundLiTag) {
        return block;
    }
    return result;
}

void ExtractXMPMetadata(const Buffer& buffer, PDF::Metadata& pdfMetadata)
{
    const char* dataPtr  = reinterpret_cast<const char*>(buffer.GetData());
    const size_t dataLen = buffer.GetLength();
    std::string xmlContent(dataPtr, dataLen);

    std::string title = ExtractXMPValue(xmlContent, PDF::KEY::PDF_TITLE_XML, PDF::KEY::PDF_TITLE_END_XML);
    if (!title.empty() && pdfMetadata.title.empty()) {
        pdfMetadata.title = title;
    }

    std::string author = ExtractXMPValue(xmlContent, PDF::KEY::PDF_AUTHOR_XML, PDF::KEY::PDF_AUTHOR_END_XML);
    if (!author.empty() && pdfMetadata.author.empty()) {
        pdfMetadata.author = author;
    }

    std::string creatorTool = ExtractXMPValue(xmlContent, PDF::KEY::PDF_CREATOR_XML, PDF::KEY::PDF_CREATOR_END_XML);
    if (!creatorTool.empty() && pdfMetadata.creator.empty()) {
        pdfMetadata.creator = creatorTool;
    }

    std::string producer = ExtractXMPValue(xmlContent, PDF::KEY::PDF_PRODUCER_XML, PDF::KEY::PDF_PRODUCER_END_XML);
    if (!producer.empty() && pdfMetadata.producer.empty()) {
        pdfMetadata.producer = producer;
    }

    std::string createDate = ExtractXMPValue(xmlContent, PDF::KEY::PDF_CREATIONDATE_XML, PDF::KEY::PDF_CREATIONDATE_END_XML);
    if (!createDate.empty() && pdfMetadata.creationDate.empty()) {
        pdfMetadata.creationDate = MakeXMPDateReadable(createDate);
    }

    std::string modifyDate = ExtractXMPValue(xmlContent, PDF::KEY::PDF_MODDATE_XML, PDF::KEY::PDF_MODDATE_END_XML);
    if (!modifyDate.empty() && pdfMetadata.modifyDate.empty()) {
        pdfMetadata.modifyDate = MakeXMPDateReadable(modifyDate);
    }
}

void ProcessMetadataStream(Reference<GView::Type::PDF::PDFFile> pdf, GView::Utils::DataCache& data, PDF::ObjectNode* objectNode, PDF::Metadata& pdfMetadata)
{
    if (objectNode->pdfObject.hasStream) {
        const uint64 offset = objectNode->decodeObj.streamOffsetStart;
        const uint64 end    = objectNode->decodeObj.streamOffsetEnd;

        if (end <= offset || end > data.GetEntireFile().GetLength()) {
            return;
        }
        const size_t size = static_cast<size_t>(end - offset);

        Buffer buffer;
        buffer.Resize(size);
        memcpy(buffer.GetData(), data.GetEntireFile().GetData() + offset, size);

        // encrypted -> can't open the stream, for now
        if (pdf->pdfStats.isEncrypted) {
            Dialogs::MessageBox::ShowWarning("Warning!", "Unable to decompress the stream because the PDF is encrypted! Raw data will be displayed instead.");
            pdf->errList.AddError("Unable to decompress the stream because the PDF is encrypted (0x%llX)", (uint64_t) offset);
            return;
        }
        // Decode the content of the stream based on the filters
        pdf->DecodeStream(objectNode, buffer, size);
        ExtractXMPMetadata(buffer, pdfMetadata);
    }
}

static int SafeParseInt(const std::string& s, size_t pos, size_t length)
{
    if (pos + length > s.size()) {
        return -1;
    }
    int val = 0;
    for (size_t i = 0; i < length; i++) {
        if (!std::isdigit(static_cast<unsigned char>(s[pos + i]))) {
            return -1;
        }
        val = val * 10 + (s[pos + i] - '0');
    }
    return val;
}

static std::string MakeDateReadable(const std::string& pdfDate)
{
    // Typical PDF date format: D:YYYYMMDDHHmmSSOHH'mm (with some fields optional).
    std::string date = pdfDate;
    if (date.size() >= 2 && date[0] == 'D' && date[1] == ':') {
        date.erase(0, 2);
    }

    // Extract YYYY, MM, DD, HH, mm, SS in sequence (some may be missing)
    size_t idx = 0;
    int year   = SafeParseInt(date, idx, 4);
    if (year < 0) {
        return pdfDate;
    }
    idx += 4;
    int month = -1, day = -1, hour = -1, min_ = -1, sec_ = -1;

    if (idx + 2 <= date.size()) {
        month = SafeParseInt(date, idx, 2);
        if (month >= 1) {
            idx += 2;
        } else {
            month = -1;
        }
    }
    if (month != -1 && idx + 2 <= date.size()) {
        day = SafeParseInt(date, idx, 2);
        if (day >= 1) {
            idx += 2;
        } else {
            day = -1;
        }
    }
    if (day != -1 && idx + 2 <= date.size()) {
        hour = SafeParseInt(date, idx, 2);
        if (hour >= 0) {
            idx += 2;
        } else {
            hour = -1;
        }
    }
    if (hour != -1 && idx + 2 <= date.size()) {
        min_ = SafeParseInt(date, idx, 2);
        if (min_ >= 0) {
            idx += 2;
        } else {
            min_ = -1;
        }
    }
    if (min_ != -1 && idx + 2 <= date.size()) {
        sec_ = SafeParseInt(date, idx, 2);
        if (sec_ >= 0) {
            idx += 2;
        } else {
            sec_ = -1;
        }
    }

    // Check for offset (e.g. +01'00, -08'30, Z)
    std::string offsetStr;
    if (idx < date.size()) {
        char c = date[idx];
        if (c == '+' || c == '-') {
            idx++;
            int offsetH = SafeParseInt(date, idx, 2);
            if (offsetH < 0) {
                offsetH = 0;
            }
            idx += 2;

            // skip apostrophe if present
            if (idx < date.size() && date[idx] == '\'') {
                idx++;
            }

            int offsetM = SafeParseInt(date, idx, 2);
            if (offsetM < 0) {
                offsetM = 0;
            }
            idx += 2;

            std::ostringstream off;
            off << c << std::setw(2) << std::setfill('0') << offsetH << ":" << std::setw(2) << std::setfill('0') << offsetM;
            offsetStr = off.str();
        } else if (c == 'Z') {
            // local time = UTC
            offsetStr = "Z";
        }
    }

    // Build final string
    if (month < 1) {
        month = 1;
    }
    if (day < 1) {
        day = 1;
    }
    if (hour < 0) {
        hour = 0;
    }
    if (min_ < 0) {
        min_ = 0;
    }
    if (sec_ < 0) {
        sec_ = 0;
    }

    // Format: YYYY-MM-DD HH:MM:SS ±HH:MM
    std::ostringstream out;
    out << std::setw(4) << std::setfill('0') << year << "-" << std::setw(2) << std::setfill('0') << month << "-" << std::setw(2) << std::setfill('0') << day
        << " " << std::setw(2) << std::setfill('0') << hour << ":" << std::setw(2) << std::setfill('0') << min_ << ":" << std::setw(2) << std::setfill('0')
        << sec_;

    if (!offsetStr.empty()) {
        out << " " << offsetStr;
    }
    return out.str();
}

static std::string ParseLiteralString(GView::Utils::DataCache& data, uint64& offset, uint64 endOffset)
{
    offset++; // Skip '('
    std::string result;
    int parenLevel = 1;
    while (offset < endOffset && parenLevel > 0) {
        uint8 c;
        if (!data.Copy(offset, c)) {
            break; 
        }
        offset++;

        if (c == '\\') {
            // Next char might be an escaped parenthesis,
            // a special escape (\n, \r, etc.), or octal digits.
            char esc;
            if (!data.Copy(offset, esc)) {
                break;
            }
            offset++;

            switch (esc) {
            case 'n':
                result.push_back('\n');
                break;
            case 'r':
                result.push_back('\r');
                break;
            case 't':
                result.push_back('\t');
                break;
            case 'b':
                result.push_back('\b');
                break;
            case 'f':
                result.push_back('\f');
                break;

            // \( -> '(' , \) -> ')' , \\ -> '\'
            //   Note: These do NOT change parenLevel, because
            //   they’re considered "escaped" parentheses.
            case PDF::DC::LEFT_PARETHESIS:
            case PDF::DC::RIGHT_PARETHESIS:
            case '\\':
                result.push_back(esc);
                break;

            default: {
                if (esc >= '0' && esc <= '7') {
                    unsigned octVal = (esc - '0');
                    for (int i = 0; i < 2; i++) {
                        if (offset < endOffset) {
                            char possibleDigit;
                            if (data.Copy(offset, possibleDigit) && (possibleDigit >= '0' && possibleDigit <= '7')) {
                                offset++;
                                octVal = (octVal << 3) + (possibleDigit - '0');
                            } else {
                                break;
                            }
                        }
                    }
                    result.push_back(static_cast<char>(octVal & 0xFF));
                } else {
                    result.push_back(esc);
                }
                break;
            }
            }
        } else if (c == PDF::DC::LEFT_PARETHESIS) {
            parenLevel++;
            result.push_back(PDF::DC::LEFT_PARETHESIS);
        } else if (c == PDF::DC::RIGHT_PARETHESIS) {
            parenLevel--;
            if (parenLevel > 0) {
                result.push_back(PDF::DC::RIGHT_PARETHESIS);
            }
        } else {
            result.push_back(static_cast<char>(c));
        }
    }
    return result;
}

static void ProcessMetadataObject(GView::Utils::DataCache& data, const PDF::ObjectNode& objectNode, PDF::Metadata& pdfMetadata)
{
    uint64 offset          = objectNode.pdfObject.startBuffer;
    const uint64 endOffset = objectNode.pdfObject.endBuffer;
    uint8 buffer;
    while (offset < endOffset) {
        if (!data.Copy(offset, buffer)) {
            break;
        }
        if (buffer == PDF::DC::SOLIDUS) {
            std::string decodedName = DecodeName(data, offset, objectNode.pdfObject.endBuffer);

            if (offset < endOffset) {
                if (!data.Copy(offset, buffer)) {
                    break;
                }
                while (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN || buffer == PDF::WSC::SPACE) {
                    offset++;
                    if (data.Copy(offset, buffer)) {
                        break;
                    }
                }
                if (buffer == PDF::DC::LEFT_PARETHESIS) {
                    std::string value = ParseLiteralString(data, offset, endOffset);
                    if (IsEqualType(decodedName, PDF::KEY::PDF_TITLE_SIZE, PDF::KEY::PDF_TITLE) && pdfMetadata.title.empty()) {
                        pdfMetadata.title = value;
                    } else if (IsEqualType(decodedName, PDF::KEY::PDF_AUTHOR_SIZE, PDF::KEY::PDF_AUTHOR) && pdfMetadata.author.empty()) {
                        pdfMetadata.author = value;
                    } else if (IsEqualType(decodedName, PDF::KEY::PDF_CREATOR_SIZE, PDF::KEY::PDF_CREATOR) && pdfMetadata.creator.empty()) {
                        pdfMetadata.creator = value;
                    } else if (IsEqualType(decodedName, PDF::KEY::PDF_PRODUCER_SIZE, PDF::KEY::PDF_PRODUCER) && pdfMetadata.producer.empty()) {
                        pdfMetadata.producer = value;
                    } else if (IsEqualType(decodedName, PDF::KEY::PDF_CREATIONDATE_SIZE, PDF::KEY::PDF_CREATIONDATE) && pdfMetadata.creationDate.empty()) {
                        pdfMetadata.creationDate = MakeDateReadable(value);
                    } else if (IsEqualType(decodedName, PDF::KEY::PDF_MODDATE_SIZE, PDF::KEY::PDF_MODDATE) && pdfMetadata.modifyDate.empty()) {
                        pdfMetadata.modifyDate = MakeDateReadable(value);
                    }
                }
            }
        } else {
            offset++;
        }
    }
}

static void FindAndProcessMetadataObjects(
      Reference<GView::Type::PDF::PDFFile> pdf)
{
    auto& data = pdf->obj->GetData();
    std::unordered_set<uint64> toFind(pdf->metadataObjectNumbers.begin(), pdf->metadataObjectNumbers.end());
    std::function<void(PDF::ObjectNode&)> searchTree = [&](PDF::ObjectNode& node) {
        if (toFind.empty()) {
            return;
        }
        auto it = toFind.find(node.pdfObject.number);
        if (it != toFind.end()) {
            bool isXML = false;
            for (const auto type : node.pdfObject.dictionaryTypes) {
                if (type == "/Metadata") {
                    isXML = true;
                }
            }
            if (!isXML) {
                // from "Name" objects like /Producer /Title
                ProcessMetadataObject(data, node, pdf->pdfMetadata);
            } else {
                // stream <XML data> endstream
                ProcessMetadataStream(pdf, data, &node, pdf->pdfMetadata);
            }
            toFind.erase(it);
            if (toFind.empty()) {
                return;
            };
        }

        for (auto& child : node.children) {
            searchTree(child);
            if (toFind.empty()) {
                return;
            }
        }
    };
    searchTree(pdf->objectNodeRoot);
}

void ProcessPDFTree(
      const uint64& dataSize,
      GView::Utils::DataCache& data,
      PDF::ObjectNode& objectNode,
      vector<PDF::PDFObject>& pdfObjects,
      vector<uint64>& processedObjects,
      PDF::PDFStats& pdfStats,
      vector<uint64>& metadataObjectNumbers,
      GView::Utils::ErrorList &errList)
{
    // TODO: treat the other particular cases for getting the references of the objects
    uint64 objectOffset = objectNode.pdfObject.startBuffer;
    uint8 buffer;
    uint64 streamLength = 0;
    bool foundLength    = false;
    bool issueFound = false;
    std::vector<uint64> objectsNumber;     
    processedObjects.push_back(objectNode.pdfObject.number);
    objectNode.pdfObject.hasStream = false;

    while (objectOffset < objectNode.pdfObject.endBuffer) {
        if (!data.Copy(objectOffset, buffer)) {
            break;
        }
        // skip the < alnum > objects
        if (buffer == PDF::DC::LESS_THAN) {
            objectOffset++;
            if (!data.Copy(objectOffset, buffer)) {
                break;
            }
            if (isalnum(buffer)) {
                while (objectOffset < objectNode.pdfObject.endBuffer && buffer != PDF::DC::GREATER_THAN) {
                    if (!data.Copy(objectOffset, buffer)) {
                        break;
                    }
                    objectOffset++;
                }
            }
        }
        if (buffer == PDF::DC::LEFT_PARETHESIS) {
            while (objectOffset < objectNode.pdfObject.endBuffer && buffer != PDF::DC::RIGHT_PARETHESIS) {
                if (!data.Copy(objectOffset, buffer)) {
                    break;
                }
                objectOffset++;
            }
        }
        if (data.Copy(objectOffset, buffer) && buffer == PDF::DC::SOLIDUS) {
            // this is for name what use #xx in their component
            const uint64 copyOffset = objectOffset;
            std::string decodedName = DecodeName(data, objectOffset, objectNode.pdfObject.endBuffer);
            // /Length
            if (IsEqualType(decodedName, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH) && !foundLength) {
                uint64 copyObjectOffset = objectOffset;
                if (!data.Copy(copyObjectOffset, buffer)) {
                    break;
                }
                if (buffer == PDF::WSC::SPACE) {
                    streamLength = GetLengthNumber(data, objectOffset, dataSize, pdfObjects);
                    foundLength  = true;
                } else {
                    objectOffset = copyObjectOffset;
                }
                objectOffset--;
                // skip the /Parent
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_PARENT_SIZE, PDF::KEY::PDF_PARENT)) {
                if (!data.Copy(objectOffset, buffer)) {
                    break;
                }
                while (buffer != PDF::KEY::PDF_INDIRECTOBJ && objectOffset < objectNode.pdfObject.endBuffer) {
                    if (!data.Copy(objectOffset, buffer)) {
                        break;
                    }
                    objectOffset++;
                }
            }
            // /Filter
            else if (IsEqualType(decodedName, PDF::KEY::PDF_FILTER_SIZE, PDF::KEY::PDF_FILTER)) {
                GetFilters(data, objectOffset, dataSize, objectNode.decodeObj.filters, errList);
                InsertValuesIntoStats(pdfStats.filtersTypes, objectNode.decodeObj.filters);
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_DECODEPARMS_SIZE, PDF::KEY::PDF_DECODEPARMS)) {
                objectNode.decodeObj.decodeParams.hasDecodeParms = true;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_COLUMNS_SIZE, PDF::KEY::PDF_COLUMNS) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                objectNode.decodeObj.decodeParams.column = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_PREDICTOR_SIZE, PDF::KEY::PDF_PREDICTOR) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                objectNode.decodeObj.decodeParams.predictor = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_BPC_SIZE, PDF::KEY::PDF_BPC) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                objectNode.decodeObj.decodeParams.bitsPerComponent = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_EARLYCG_SIZE, PDF::KEY::PDF_EARLYCG) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                objectNode.decodeObj.decodeParams.earlyChange = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_K_SIZE, PDF::KEY::PDF_K) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                if (!data.Copy(objectOffset, buffer)) {
                    break;
                }
                bool isNegative = false;
                if (buffer == '-') {
                    isNegative = true;
                }
                objectOffset++;
                objectNode.decodeObj.decodeParams.K = GetTypeValue(data, objectOffset, dataSize);
                if (isNegative) {
                    objectNode.decodeObj.decodeParams.K *= -1;
                }
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_ROWS_SIZE, PDF::KEY::PDF_ROWS) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                objectNode.decodeObj.decodeParams.rows = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_ENDOFLINE_SIZE, PDF::KEY::PDF_ENDOFLINE) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
                    objectNode.decodeObj.decodeParams.endOfLine = true;
                    objectOffset += PDF::KEY::PDF_TRUE_SIZE;
                } else {
                    objectNode.decodeObj.decodeParams.endOfLine = false;
                    objectOffset += PDF::KEY::PDF_FALSE_SIZE;
                }
            } else if (
                  IsEqualType(decodedName, PDF::KEY::PDF_ENCODEDBYTEALIGN_SIZE, PDF::KEY::PDF_ENCODEDBYTEALIGN) &&
                  objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
                    objectNode.decodeObj.decodeParams.encodedByteAlign = true;
                    objectOffset += PDF::KEY::PDF_TRUE_SIZE;
                } else {
                    objectNode.decodeObj.decodeParams.encodedByteAlign = false;
                    objectOffset += PDF::KEY::PDF_FALSE_SIZE;
                }
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_ENDOFBLOCK_SIZE, PDF::KEY::PDF_ENDOFBLOCK) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
                    objectNode.decodeObj.decodeParams.endOfBlock = true;
                    objectOffset += PDF::KEY::PDF_TRUE_SIZE;
                } else {
                    objectNode.decodeObj.decodeParams.endOfBlock = false;
                    objectOffset += PDF::KEY::PDF_FALSE_SIZE;
                }
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_BLACKIS1_SIZE, PDF::KEY::PDF_BLACKIS1) && objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
                    objectNode.decodeObj.decodeParams.blackIs1 = true;
                    objectOffset += PDF::KEY::PDF_TRUE_SIZE;
                } else {
                    objectNode.decodeObj.decodeParams.blackIs1 = false;
                    objectOffset += PDF::KEY::PDF_FALSE_SIZE;
                }
            } else if (
                  IsEqualType(decodedName, PDF::KEY::PDF_DMGROWSBEFERROR_SIZE, PDF::KEY::PDF_DMGROWSBEFERROR) &&
                  objectNode.decodeObj.decodeParams.hasDecodeParms) {
                objectOffset += 1;
                objectNode.decodeObj.decodeParams.dmgRowsBefError = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_TYPE_SIZE, PDF::KEY::PDF_TYPE)) {
                const uint64 copyTypeOffset      = objectOffset;
                std::string typeNameObject = GetDictionaryType(data, objectOffset, dataSize, objectNode.pdfObject.dictionaryTypes);
                if (IsEqualType(typeNameObject, PDF::KEY::PDF_EMBEDDEDFILE_SIZE, PDF::KEY::PDF_EMBEDDEDFILE)) {
                    errList.AddWarning(
                          "Contains an embedded file payload (/EmbeddedFile) in the Object %llX (0x%llX)",
                          (uint64_t) objectNode.pdfObject.number,
                          (uint64_t) (copyTypeOffset));
                }
                InsertValuesIntoStats(pdfStats.dictionaryTypes, objectNode.pdfObject.dictionaryTypes);
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_SUBTYPE_SIZE, PDF::KEY::PDF_SUBTYPE)) {
                GetDictionaryType(data, objectOffset, dataSize, objectNode.pdfObject.dictionarySubtypes);
                InsertValuesIntoStats(pdfStats.dictionarySubtypes, objectNode.pdfObject.dictionarySubtypes);
                objectOffset--;
            } else if (
                  IsEqualType(decodedName, PDF::KEY::PDF_JS_SIZE, PDF::KEY::PDF_JS)) {
                objectOffset++;
                if (!data.Copy(objectOffset, buffer)) {
                    break;
                }
                if (buffer >= '0' && buffer <= '9')
                {
                    const uint64 number = GetObjectReference(dataSize, data, objectOffset, buffer, objectsNumber);
                    errList.AddWarning("Contains a JavaScript block (/JS) in the Object %llX", (uint64_t) number);
                } else {
                    errList.AddWarning("Contains a JavaScript block (/JS) (0x%llX)", (uint64_t) objectOffset);
                }
                objectNode.pdfObject.hasJS = true;
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_JAVASCRIPT_SIZE, PDF::KEY::PDF_JAVASCRIPT)) {
                errList.AddWarning("Contains a JavaScript action (/JavaScript) (0x%llX)", (uint64_t) (copyOffset));
                objectNode.pdfObject.hasJS = true;
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_EMBEDDEDFILES_SIZE, PDF::KEY::PDF_EMBEDDEDFILES)) {
                errList.AddWarning("Contains an embedded file index (/EmbeddedFiles) (0x%llX)", (uint64_t) (copyOffset));
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_OPENACTION_SIZE, PDF::KEY::PDF_OPENACTION)) {
                errList.AddWarning("Contains an open action (/OpenAction) (0x%llX)", (uint64_t) (copyOffset));
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_LAUNCH_SIZE, PDF::KEY::PDF_LAUNCH)) {
                errList.AddWarning("Contains a launch action (/Launch) (0x%llX)", (uint64_t) (copyOffset));
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_ADDITIONALACTIONS_SIZE, PDF::KEY::PDF_ADDITIONALACTIONS)) {
                errList.AddWarning("Contains additional actions (/AA) (0x%llX)", (uint64_t) (copyOffset));
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_URI_SIZE, PDF::KEY::PDF_URI)) {
                bool correctURI = false;
                uint64 copyobjectOffset = objectOffset;
                if (!data.Copy(copyobjectOffset, buffer)) {
                    break;
                }
                if (buffer == PDF::DC::LEFT_PARETHESIS) {
                    correctURI = true;
                }
                if (!correctURI) {
                    copyobjectOffset++;
                    if (!data.Copy(copyobjectOffset, buffer)) {
                        break;
                    }
                    if (buffer == PDF::DC::LEFT_PARETHESIS) {
                        correctURI = true;
                    }
                }
                if (correctURI) {
                    errList.AddWarning("Contains an external link (/URI) (0x%llX)", (uint64_t) (copyOffset));
                }
                objectOffset--;
            } else if (IsEqualType(decodedName, PDF::KEY::PDF_METADATA_OBJ_SIZE, PDF::KEY::PDF_METADATA_OBJ)) {
                objectOffset++;
                const uint64 number = GetObjectReference(dataSize, data, objectOffset, buffer, objectsNumber);
                if (std::find(metadataObjectNumbers.begin(), metadataObjectNumbers.end(), number) == metadataObjectNumbers.end()) {
                    metadataObjectNumbers.push_back(number);
                }
                if (std::count(processedObjects.begin(), processedObjects.end(), number) == 0) {
                    if (std::find(objectsNumber.begin(), objectsNumber.end(), number) == objectsNumber.end()) {
                        objectsNumber.push_back(number);
                    }
                }
            } else {
                objectOffset--;
            }
        }
        // object has a stream
        if (CheckType(data, objectOffset, PDF::KEY::PDF_STREAM_SIZE, PDF::KEY::PDF_STREAM) && foundLength) {
            objectNode.pdfObject.hasStream = true;
            objectOffset += PDF::KEY::PDF_STREAM_SIZE;
            // skip some bytes
            while (data.Copy(objectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                objectOffset++;
            }
            objectNode.decodeObj.streamOffsetStart = objectOffset;
            objectOffset += streamLength;
            objectNode.decodeObj.streamOffsetEnd = objectOffset;
            // additional checking
            while (data.Copy(objectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                objectOffset++;
            }
            if (!CheckType(data, objectOffset, PDF::KEY::PDF_ENDSTREAM_SIZE, PDF::KEY::PDF_ENDSTREAM) && !issueFound) {
                Dialogs::MessageBox::ShowError("Error!", "Wrong end stream token! Object number: " + std::to_string(objectNode.pdfObject.number));
                errList.AddError("Wrong end stream token! Object %llX (0x%llX)", (uint64_t) objectNode.pdfObject.number, (uint64_t) objectOffset);
                issueFound = true;
            } else {
                PDF::ObjectNode streamChild;
                streamChild.pdfObject.type   = PDF::SectionPDFObjectType::Stream;
                streamChild.pdfObject.number = objectNode.pdfObject.number;
                streamChild.pdfObject.hasStream    = false;
                streamChild.pdfObject.startBuffer = objectNode.decodeObj.streamOffsetStart;
                streamChild.pdfObject.endBuffer    = objectNode.decodeObj.streamOffsetEnd;
                objectNode.children.push_back(streamChild);
                break;
            }
        }
        // get the next object (nr 0 R)
        if (buffer >= '0' && buffer <= '9') {
            bool foundObjRef    = false;
            const uint64 number = GetTypeValue(data, objectOffset, dataSize);
            uint64 copyOffset   = objectOffset;
            if (!data.Copy(copyOffset, buffer)) {
                break;
            }
            copyOffset++;
            if (!data.Copy(copyOffset, buffer)) {
                break;
            }
            if (buffer == '0') {
                copyOffset += 2;
                if (!data.Copy(copyOffset, buffer)) {
                    break;
                }
                if (buffer == PDF::KEY::PDF_INDIRECTOBJ) {
                    foundObjRef = true;
                }
            }
            if (foundObjRef) {
                if (std::count(processedObjects.begin(), processedObjects.end(), number) == 0)
                {
                    if (std::find(objectsNumber.begin(), objectsNumber.end(), number) == objectsNumber.end()) {
                        objectsNumber.push_back(number);
                    }
                }
                objectOffset = copyOffset;
            }
        } else {
            objectOffset++;
        }
    }

    if (!foundLength && objectNode.pdfObject.hasStream && !issueFound) {
        Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Missing /Length for an object which has a stream!");
        errList.AddError("Missing /Length for an object which has a stream (0x%llX)", (uint64_t) objectOffset);
        issueFound = true;
    }

    if (auto* found = FindObjectByNumber(pdfObjects, objectNode.pdfObject.number, objectNode.pdfObject.startBuffer)) {
        found->hasStream          = objectNode.pdfObject.hasStream;
        found->filters            = objectNode.decodeObj.filters;
        found->dictionaryTypes    = objectNode.pdfObject.dictionaryTypes;
        found->dictionarySubtypes = objectNode.pdfObject.dictionarySubtypes;
        found->hasJS              = objectNode.pdfObject.hasJS;
    }

    for (auto& objectNumber : objectsNumber) {
        for (auto& object : pdfObjects) {
            if (objectNumber == object.number) {
                PDF::ObjectNode newObject;
                newObject.pdfObject = object;
                objectNode.children.push_back(newObject);
            }
        }
    }
    for (uint64 i = 0; i < objectNode.children.size(); i++) {
        if (std::count(processedObjects.begin(), processedObjects.end(), objectNode.children[i].pdfObject.number) == 0) {
            ProcessPDFTree(dataSize, data, objectNode.children[i], pdfObjects, processedObjects, pdfStats, metadataObjectNumbers, errList);
        }
    }
}

static void ProcessPDF(Reference<PDF::PDFFile> pdf)
{
    auto& data            = pdf->obj->GetData();
    const uint64 dataSize = data.GetSize();
    std::vector<uint64> objectsNumber;

    if (pdf->hasXrefTable) {
        bool firstTrailer = false;
        for (auto& object : pdf->pdfObjects) {
            if (object.type == PDF::SectionPDFObjectType::Trailer && !firstTrailer) {
                uint64 objectOffset           = object.startBuffer;
                pdf->objectNodeRoot.pdfObject = object;
                pdf->objectNodeRoot.pdfObject.hasStream = false;
                uint8 buffer;

                while (objectOffset < object.endBuffer - PDF::KEY::PDF_STARTXREF_SIZE) {
                    if (!data.Copy(objectOffset, buffer)) {
                        break;
                    }
                    if (CheckType(data, objectOffset, PDF::KEY::PDF_STARTXREF_SIZE, PDF::KEY::PDF_STARTXREF)) {
                        break;
                    } else if (
                          CheckType(data, objectOffset, PDF::KEY::PDF_DIC_SIZE, PDF::KEY::PDF_DIC_START) ||
                          CheckType(data, objectOffset, PDF::KEY::PDF_DIC_SIZE, PDF::KEY::PDF_DIC_END)) {
                        objectOffset += PDF::KEY::PDF_DIC_SIZE;
                    } else if (buffer >= '0' && buffer <= '9') { // get the next object (nr 0 R)
                        GetObjectReference(dataSize, data, objectOffset, buffer, objectsNumber);
                    } else if (buffer == PDF::DC::SOLIDUS) {
                        // js case here?
                        uint64_t copyObjectOffset = objectOffset;
                        std::string decodedName         = DecodeName(data, copyObjectOffset, object.endBuffer);
                        if (IsEqualType(decodedName, PDF::KEY::PDF_INFO_SIZE, PDF::KEY::PDF_INFO)) {
                            copyObjectOffset++;
                            const uint64 number = GetObjectReference(dataSize, data, copyObjectOffset, buffer, objectsNumber);
                            // only unique entries 
                            if (std::find(pdf->metadataObjectNumbers.begin(), pdf->metadataObjectNumbers.end(), number) == pdf->metadataObjectNumbers.end()) {
                                pdf->metadataObjectNumbers.push_back(number);
                            }
                            objectOffset = copyObjectOffset;
                        }
                        objectOffset++;
                        bool end_name = false;
                        while (objectOffset < object.endBuffer && !end_name) {
                            if (!data.Copy(objectOffset, buffer)) {
                                break;
                            }
                            switch (buffer) {
                            case PDF::WSC::SPACE:
                            case PDF::WSC::LINE_FEED:
                            case PDF::WSC::FORM_FEED:
                            case PDF::WSC::CARRIAGE_RETURN:
                            case PDF::DC::SOLIDUS:
                            case PDF::DC::RIGHT_SQUARE_BRACKET:
                            case PDF::DC::LEFT_SQUARE_BRACKET:
                            case PDF::DC::LESS_THAN:
                            case PDF::DC::GREATER_THAN:
                            case PDF::DC::LEFT_PARETHESIS:
                            case PDF::DC::RIGHT_PARETHESIS:
                                end_name = true;
                                break;
                            default:
                                objectOffset++;
                            }
                        }
                    } else {
                        objectOffset++;
                    }
                }
                firstTrailer = true;
            }
        }
    } else {
        bool crossStreamCnt = false;
        bool foundLength    = false;
        uint64 streamLength = 0;
        for (auto& object : pdf->pdfObjects) {
            if (object.type == PDF::SectionPDFObjectType::CrossRefStream && !crossStreamCnt) {
                uint64 objectOffset           = object.startBuffer;
                pdf->objectNodeRoot.pdfObject = object;
                uint8 buffer;

                while (objectOffset < object.endBuffer - PDF::KEY::PDF_STARTXREF_SIZE) {
                    if (!data.Copy(objectOffset, buffer)) {
                        break;
                    } else if (buffer >= '0' && buffer <= '9') { // get the next object (nr 0 R)
                        GetObjectReference(dataSize, data, objectOffset, buffer, objectsNumber);
                    } else if (data.Copy(objectOffset, buffer) && buffer == PDF::DC::SOLIDUS) {
                        const uint64 copyOffset       = objectOffset;
                        std::string decodedName = DecodeName(data, objectOffset, object.endBuffer);
                        if (IsEqualType(decodedName, PDF::KEY::PDF_FILTER_SIZE, PDF::KEY::PDF_FILTER)) {
                            GetFilters(data, objectOffset, dataSize, pdf->objectNodeRoot.decodeObj.filters, pdf->errList);
                            InsertValuesIntoStats(pdf->pdfStats.filtersTypes, pdf->objectNodeRoot.decodeObj.filters);
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH) && !foundLength) {
                            streamLength = GetLengthNumber(data, objectOffset, dataSize, pdf->pdfObjects);
                            foundLength  = true;
                        }
                        else if (IsEqualType(decodedName, PDF::KEY::PDF_COLUMNS_SIZE, PDF::KEY::PDF_COLUMNS)) {
                            objectOffset += 1;
                            pdf->objectNodeRoot.decodeObj.decodeParams.column = GetTypeValue(data, objectOffset, dataSize);
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_PREDICTOR_SIZE, PDF::KEY::PDF_PREDICTOR)) {
                            objectOffset += 1;
                            pdf->objectNodeRoot.decodeObj.decodeParams.predictor = GetTypeValue(data, objectOffset, dataSize);
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_BPC_SIZE, PDF::KEY::PDF_BPC)) {
                            objectOffset += 1;
                            pdf->objectNodeRoot.decodeObj.decodeParams.bitsPerComponent = GetTypeValue(data, objectOffset, dataSize);
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_EARLYCG_SIZE, PDF::KEY::PDF_EARLYCG)) {
                            objectOffset += 1;
                            pdf->objectNodeRoot.decodeObj.decodeParams.earlyChange = GetTypeValue(data, objectOffset, dataSize);
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_TYPE_SIZE, PDF::KEY::PDF_TYPE)) {
                            const uint64 copyObjectOffset = objectOffset;
                            std::string typeNameObject = GetDictionaryType(data, objectOffset, dataSize, pdf->objectNodeRoot.pdfObject.dictionaryTypes);
                            if (IsEqualType(typeNameObject, PDF::KEY::PDF_EMBEDDEDFILE_SIZE, PDF::KEY::PDF_EMBEDDEDFILE)) {
                                pdf->errList.AddWarning(
                                      "Contains an embedded file payload (/EmbeddedFile) in the Object %llX (0x%llX)",
                                      (uint64_t) pdf->objectNodeRoot.pdfObject.number,
                                      copyObjectOffset);
                            }
                            InsertValuesIntoStats(pdf->pdfStats.dictionaryTypes, pdf->objectNodeRoot.pdfObject.dictionaryTypes);
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_SUBTYPE_SIZE, PDF::KEY::PDF_SUBTYPE)) {
                            GetDictionaryType(data, objectOffset, dataSize, pdf->objectNodeRoot.pdfObject.dictionarySubtypes);
                            InsertValuesIntoStats(pdf->pdfStats.dictionarySubtypes, pdf->objectNodeRoot.pdfObject.dictionarySubtypes);
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_JS_SIZE, PDF::KEY::PDF_JS)) {
                            objectOffset++;
                            if (!data.Copy(objectOffset, buffer)) {
                                break;
                            }
                            if (buffer >= '0' && buffer <= '9') {
                                const uint64 number = GetObjectReference(dataSize, data, objectOffset, buffer, objectsNumber);
                                pdf->errList.AddWarning("Contains a JavaScript block (/JS) in the Object %llX", (uint64_t) number);
                            } else {
                                pdf->errList.AddWarning("Contains a JavaScript block (/JS) (0x%llX)", (uint64_t) objectOffset);
                            }
                            pdf->objectNodeRoot.pdfObject.hasJS = true;
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_JAVASCRIPT_SIZE, PDF::KEY::PDF_JAVASCRIPT)) {
                            pdf->errList.AddWarning("Contains a JavaScript action (/JavaScript) (0x%llX)", (uint64_t) (copyOffset));
                            pdf->objectNodeRoot.pdfObject.hasJS = true;
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_EMBEDDEDFILES_SIZE, PDF::KEY::PDF_EMBEDDEDFILES)) {
                            pdf->errList.AddWarning("Contains an embedded file index (/EmbeddedFiles) (0x%llX)", (uint64_t) (copyOffset));
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_OPENACTION_SIZE, PDF::KEY::PDF_OPENACTION)) {
                            pdf->errList.AddWarning("Contains an open action (/OpenAction) (0x%llX)", (uint64_t) (copyOffset));
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_LAUNCH_SIZE, PDF::KEY::PDF_LAUNCH)) {
                            pdf->errList.AddWarning("Contains a launch action (/Launch) (0x%llX)", (uint64_t) (copyOffset));
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_ADDITIONALACTIONS_SIZE, PDF::KEY::PDF_ADDITIONALACTIONS)) {
                            pdf->errList.AddWarning("Contains additional actions (/AA) (0x%llX)", (uint64_t) (copyOffset));
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_URI_SIZE, PDF::KEY::PDF_URI)) {
                            bool correctURI = false;
                            uint64 copyObjectOffset = objectOffset;
                            if (!data.Copy(copyObjectOffset, buffer)) {
                                break;
                            }
                            if (buffer == PDF::DC::LEFT_PARETHESIS) {
                                correctURI = true;
                            }
                            if (!correctURI) {
                                copyObjectOffset++;
                                if (!data.Copy(copyObjectOffset, buffer)) {
                                    break;
                                }
                                if (buffer == PDF::DC::LEFT_PARETHESIS) {
                                    correctURI = true;
                                }
                            }
                            if (correctURI) {
                                pdf->errList.AddWarning("Contains an external link (/URI) (0x%llX)", (uint64_t) (copyOffset));
                            }
                        } else if (IsEqualType(decodedName, PDF::KEY::PDF_INFO_SIZE, PDF::KEY::PDF_INFO)) {
                            objectOffset++;
                            const uint64 number = GetObjectReference(dataSize, data, objectOffset, buffer, objectsNumber);
                            // only unique entries
                            if (std::find(pdf->metadataObjectNumbers.begin(), pdf->metadataObjectNumbers.end(), number) == pdf->metadataObjectNumbers.end()) {
                                pdf->metadataObjectNumbers.push_back(number);
                            }
                        } else {
                            objectOffset++;
                        }
                    } else if (CheckType(data, objectOffset, PDF::KEY::PDF_STREAM_SIZE, PDF::KEY::PDF_STREAM) && foundLength) {
                        pdf->objectNodeRoot.pdfObject.hasStream = true;
                        objectOffset += PDF::KEY::PDF_STREAM_SIZE;
                        // skip some bytes
                        while (data.Copy(objectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                            objectOffset++;
                        }
                        pdf->objectNodeRoot.decodeObj.streamOffsetStart = objectOffset;
                        objectOffset += streamLength;
                        pdf->objectNodeRoot.decodeObj.streamOffsetEnd = objectOffset;
                        // additional checking
                        while (data.Copy(objectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                            objectOffset++;
                        }
                        if (!CheckType(data, objectOffset, PDF::KEY::PDF_ENDSTREAM_SIZE, PDF::KEY::PDF_ENDSTREAM)) {
                            Dialogs::MessageBox::ShowError("Error!", "Wrong end stream token!");
                            pdf->errList.AddError("Wrong end stream token (0x%llX)", (uint64_t) objectOffset);
                        } else {
                            PDF::ObjectNode streamChild;
                            streamChild.pdfObject.type = PDF::SectionPDFObjectType::Stream;
                            streamChild.pdfObject.number = pdf->objectNodeRoot.pdfObject.number;
                            streamChild.pdfObject.hasStream    = false;
                            streamChild.pdfObject.startBuffer = pdf->objectNodeRoot.decodeObj.streamOffsetStart;
                            streamChild.pdfObject.endBuffer    = pdf->objectNodeRoot.decodeObj.streamOffsetEnd;
                            pdf->objectNodeRoot.children.push_back(streamChild);
                            break;
                        }
                    } else {
                        objectOffset++;
                    }
                }
                crossStreamCnt = true;
            } else if (object.type == PDF::SectionPDFObjectType::CrossRefStream) {
                objectsNumber.push_back(object.number);
            }
        }
    }

    if (auto* found = FindObjectByNumber(pdf->pdfObjects, pdf->objectNodeRoot.pdfObject.number, pdf->objectNodeRoot.pdfObject.startBuffer)) {
        found->filters            = pdf->objectNodeRoot.decodeObj.filters;
        found->dictionaryTypes    = pdf->objectNodeRoot.pdfObject.dictionaryTypes;
        found->dictionarySubtypes = pdf->objectNodeRoot.pdfObject.dictionarySubtypes;
        found->hasStream          = pdf->objectNodeRoot.pdfObject.hasStream;
        found->hasJS              = pdf->objectNodeRoot.pdfObject.hasJS;
    }

    for (auto& objectNumber : objectsNumber) {
        for (auto& object : pdf->pdfObjects) {
            if (objectNumber == object.number) {
                PDF::ObjectNode newObject;
                newObject.pdfObject = object;
                pdf->objectNodeRoot.children.push_back(newObject);
            }
        }
    }

    for (uint64 i = 0; i < pdf->objectNodeRoot.children.size(); i++) {
        ProcessPDFTree(dataSize, data, pdf->objectNodeRoot.children[i], pdf->pdfObjects, pdf->processedObjects, pdf->pdfStats, pdf->metadataObjectNumbers, pdf->errList);
    }

    // process the rest of the objects that don't have references

    for (auto& object : pdf->pdfObjects) {
        if ((std::count(pdf->processedObjects.begin(), pdf->processedObjects.end(), object.number) == 0) && (object.number != 0) &&
            (object.type != PDF::SectionPDFObjectType::CrossRefStream)) {
            pdf->objectNodeRoot.children.emplace_back();
            auto& childNode = pdf->objectNodeRoot.children.back();

            childNode.pdfObject = object;
            ProcessPDFTree(dataSize, data, childNode, pdf->pdfObjects, pdf->processedObjects, pdf->pdfStats, pdf->metadataObjectNumbers, pdf->errList);
        }
    }
    pdf->pdfStats.objectCount = pdf->pdfObjects.size();
    FindAndProcessMetadataObjects(pdf);

}

std::u16string PDF::PDFFile::to_u16string(uint32_t value)
{
    std::wstring wstr = std::to_wstring(value);
    return std::u16string(wstr.begin(), wstr.end());
}

PDF::ObjectNode* PDF::PDFFile::FindNodeByPath(Reference<GView::Type::PDF::PDFFile> pdf, std::u16string_view path)
{
    if (!pdf.IsValid()) {
        return nullptr;
    }

    if (path.empty()) {
        return &pdf->objectNodeRoot;
    }

    // split path by '/'
    std::vector<std::u16string> tokens;
    size_t start = 0;
    while (start < path.size()) {
        auto end = path.find(u'/', start);
        if (end == std::u16string_view::npos) {
            end = path.size();
        }

        tokens.emplace_back(path.substr(start, end - start));
        start = (end < path.size()) ? (end + 1) : end;
    }

    PDF::ObjectNode* currentNode = &pdf->objectNodeRoot;
    std::u16string rootName;
    switch (currentNode->pdfObject.type) {
    case PDF::SectionPDFObjectType::Trailer:
        rootName = u"Trailer";
        break;
    case PDF::SectionPDFObjectType::CrossRefStream:
        rootName = u"CrossRefStream ";
        rootName += to_u16string(static_cast<uint32_t>(currentNode->pdfObject.number));
        break;
    case PDF::SectionPDFObjectType::Stream:
        rootName = u"Stream ";
        rootName += to_u16string(static_cast<uint32_t>(currentNode->pdfObject.number));
        break;
    default:
        rootName = u"Object ";
        rootName += to_u16string(static_cast<uint32_t>(currentNode->pdfObject.number));
        break;
    }

    if (!tokens.empty() && tokens[0] == rootName) {
        // we are already sitting on that node
        // so skip this token:
        tokens.erase(tokens.begin());
    }

    for (auto &tk : tokens) {
        PDF::ObjectNode* found = nullptr;
        for (auto &child : currentNode->children) {
            std::u16string childName;
            switch (child.pdfObject.type) {
            case PDF::SectionPDFObjectType::Trailer:
                childName = u"Trailer";
                break;
            case PDF::SectionPDFObjectType::CrossRefStream:
                childName = u"CrossRefStream ";
                childName += to_u16string(static_cast<uint32_t>(child.pdfObject.number));
                break;
            case PDF::SectionPDFObjectType::Stream:
                childName = u"Stream ";
                childName += to_u16string(static_cast<uint32_t>(child.pdfObject.number));
                break;
            default:
                childName = u"Object ";
                childName += to_u16string(static_cast<uint32_t>(child.pdfObject.number));
                break;
            }

            // if match -> descend
            if (childName == tk) {
                found = &child;
                break;
            }
        }
        if (!found) {
            return nullptr;
        }

        currentNode = found;
    }

    return currentNode;
}

PDF::ObjectNode* PDF::PDFFile::FindNodeByObjectNumber(uint32_t number)
{
    std::deque<PDF::ObjectNode*> queue;
    queue.push_back(&this->objectNodeRoot);

    while (!queue.empty()) {
        auto* front = queue.front();
        queue.pop_front();

        if (front->pdfObject.number == number) {
            return front;
        }

        for (auto& ch : front->children) {
            queue.push_back(&ch);
        }
    }
    return nullptr;
}

void PDF::PDFFile::PopulateHeader(View::ContainerViewer::Settings &settings, const PDFStats pdfStats)
{
    settings.AddProperty("Objects count", std::to_string(pdfStats.objectCount));
    settings.AddProperty("Streams count", std::to_string(pdfStats.streamsCount));

    bool first = true;
    LocalUnicodeStringBuilder<512> ub;
    for (auto& filter : pdfStats.filtersTypes) {
        if (!first) {
            ub.Add(u", ");
        }
        ub.Add(filter);
        first = false;
    }
    settings.AddProperty("Filters", ub);

    first = true;
    ub.Clear();
    for (auto& type : pdfStats.dictionaryTypes) {
        if (!first) {
            ub.Add(u", ");
        }
        ub.Add(type);
        first = false;
    }
    settings.AddProperty("Dictionary Types", ub);

    first = true;
    ub.Clear();
    for (auto& subtype : pdfStats.dictionarySubtypes) {
        if (!first) {
            ub.Add(u", ");
        }
        ub.Add(subtype);
        first = false;
    }
    settings.AddProperty("Dictionary Subtypes", ub);
    settings.AddProperty("File encrypted", pdfStats.isEncrypted ? "Yes" : "No");
}

void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<GView::Type::PDF::PDFFile> pdf)
{
    ContainerViewer::Settings settings;
    pdf->PopulateHeader(settings, pdf->pdfStats);

    settings.SetPathSeparator((char16) '/');
    settings.SetIcon(PDF_ICON);
    settings.SetColumns({
          "n:&Object,a:l,w:60",
          "n:&Type,a:r,w:20",
          "n:&Offset start,a:r,w:20",
          "n:&Size,a:r,w:20",
          "n:&Filters,a:r,w:30",
          "n:&Dictionary Types,a:r,w:20",
          "n:&Dictionary Subtypes,a:r,w:22",
          "n:&Has JS?,a:r,w:10",
    });

    settings.SetEnumerateCallback(win->GetObject()->GetContentType<GView::Type::PDF::PDFFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(win->GetObject()->GetContentType<GView::Type::PDF::PDFFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

    win->CreateViewer(settings);
}

std::u16string GetTxtFileName(const std::u16string_view pdfPath)
{
    std::u16string result{ pdfPath };

    auto lastDot = result.rfind(u'.');
    if (lastDot != std::u16string::npos) {
        result.erase(lastDot);
    }

    result += u".txt";
    return result;
}

std::string ExtractTextFromPDF(Reference<GView::Type::PDF::PDFFile> pdf)
{
    PoDoFo::PdfMemDocument doc;

    auto& dataCache = pdf->obj->GetData();
    const auto fileBuffer = dataCache.GetEntireFile();

    // construct a PoDoFo::bufferview from the underlying data.
    // cast the pointer to const char* since bufferview is defined as cspan<char>.
    PoDoFo::bufferview buffer(reinterpret_cast<const char*>(fileBuffer.GetData()), fileBuffer.GetLength());

    doc.LoadFromBuffer(buffer);

    std::string extractedText;
    const auto& pages = doc.GetPages();
    const uint64 totalPages = static_cast<uint64>(pages.GetCount());

    ProgressStatus::Init("Extracting text", totalPages);

    LocalString<128> ls;
    for (unsigned i = 0; i < pages.GetCount(); i++) {
        const auto& page = pages.GetPageAt(i);
        std::vector<PoDoFo::PdfTextEntry> entries;
        page.ExtractTextTo(entries);

        for (auto& entry : entries) {
            extractedText.append(entry.Text.data());
            extractedText.append("\n");
        }

        ls.Format("Page %u/%u", i + 1, pages.GetCount());
        ProgressStatus::Update(i + 1, ls.GetText());
    }
    return extractedText;
}

void CreateTextView(const std::string& textToShow, const std::u16string_view& pdfName)
{
    Buffer textBuffer;
    textBuffer.Resize(textToShow.size());
    memcpy(textBuffer.GetData(), textToShow.data(), textToShow.size());

    BufferView bv = textBuffer;
    GView::App::OpenBuffer(bv, pdfName, pdfName, GView::App::OpenMethod::BestMatch);
}

bool SaveExtractedTextToFile(const std::string& text, const std::u16string_view& filePath)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    std::string utf8FilePath = convert.to_bytes(filePath.data(), filePath.data() + filePath.size());

    std::ofstream ofs(utf8FilePath, std::ios::out | std::ios::binary);
    if (!ofs) {
        return false;
    }

    ofs.write(text.data(), text.size());
    ofs.close();

    return true;
}

bool PDF::PDFFile::ExtractAndSaveTextWithDialog(Reference<GView::Type::PDF::PDFFile> pdf)
{
    auto extractedText = ExtractTextFromPDF(pdf);
    if (extractedText.empty()) {
        Dialogs::MessageBox::ShowNotification("Notification", "Couldn't find text to extract from this PDF!");
        return false;
    }

    // build default ".txt" name based on the PDF filename
    std::u16string_view pdfU16Path = pdf->obj->GetPath();
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    std::string pdfUTF8Path = convert.to_bytes(pdfU16Path.data(), pdfU16Path.data() + pdfU16Path.size());

    std::filesystem::path pdfFsPath(pdfUTF8Path);
    std::string defaultTxtName       = pdfFsPath.stem().string() + ".txt";
    std::filesystem::path defaultDir = pdfFsPath.parent_path();

    // show "Save As" dialog
    auto chosenPathOpt = AppCUI::Dialogs::FileDialog::ShowSaveFileWindow(defaultTxtName, "Text Files:txt|All files:*", defaultDir);

    // if canceled
    if (!chosenPathOpt.has_value()) {
        return false;
    }
    auto chosenFsPath = chosenPathOpt.value();

    // force the extension to be ".txt" if not present
    if (chosenFsPath.extension() != ".txt") {
        chosenFsPath.replace_extension(".txt");
    }

    // convert to std::u16string
    std::wstring wide = chosenFsPath.wstring();
    std::u16string savePath = std::u16string(wide.begin(), wide.end());

    // save extracted text
    if (!SaveExtractedTextToFile(extractedText, savePath)) {
        Dialogs::MessageBox::ShowError("Error!", "Failed to save text to the chosen file path!");
        return false;
    }

    std::u16string msg = u"The text from the PDF has been saved! File name: ";
    msg += savePath;
    Dialogs::MessageBox::ShowNotification(u"Success!", msg);

    return true;
}

bool PDF::PDFFile::ExtractAndOpenText(Reference<GView::Type::PDF::PDFFile> pdf)
{
    auto extractedText = ExtractTextFromPDF(pdf);
    if (!extractedText.empty()) {
        CreateTextView(extractedText, pdf->obj->GetName());
    } else {
        Dialogs::MessageBox::ShowNotification("Notification", "Couldn't find text to extract from this PDF!");
    }
    return true;
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto pdf = win->GetObject()->GetContentType<PDF::PDFFile>();
    pdf->Update();

    // viewers
    CreateBufferView(win, pdf);
    ProcessPDF(pdf);
    CreateContainerView(win, pdf);

    win->AddPanel(Pointer<TabPage>(new PDF::Panels::Sections(pdf, win)), false);
    win->AddPanel(Pointer<TabPage>(new PDF::Panels::Information(pdf)), true);
    win->AddPanel(Pointer<TabPage>(new PDF::Panels::Warnings(pdf)), true);

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Extension"]   = { "pdf" };
    sect["Priority"]    = 1;
    sect["Pattern"]     = "magic:25 50 44 46 2D";
    sect["Description"] = "Portable Document Format (*.pdf)";
}
}