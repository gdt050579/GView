#include "pdf.hpp"
#include <deque>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

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

uint64 GetTypeValue(GView::Utils::DataCache& data, uint64& offset, const uint64& dataSize)
{
    std::string lengthValStr;
    uint8_t buffer;
    uint64 value = 0;
    while (offset < dataSize && data.Copy(offset, buffer) && buffer >= '0' && buffer <= '9') {
        lengthValStr.push_back(buffer);
        offset++;
    }

    if (!lengthValStr.empty()) {
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

void GetFilters(GView::Utils::DataCache& data, uint64& offset, const uint64& dataSize, std::vector<std::string>& filters)
{
    uint8_t buffer;
    std::string filterValue;
    while (data.Copy(offset, buffer) && buffer == PDF::WSC::SPACE && offset < dataSize) {
        offset++;
    }
    // [ -> we have a list of filters
    if (data.Copy(offset, buffer) && buffer == PDF::DC::LEFT_SQUARE_BRACKET)
    {
        offset++;
        while (data.Copy(offset, buffer) && buffer != PDF::DC::RIGHT_SQUARE_BRACKET && offset < dataSize) {
            if (!data.Copy(offset, buffer)) {
                break;
            }
            if (buffer == PDF::DC::RIGHT_SQUARE_BRACKET) {
                break;
            }
            if (buffer == PDF::DC::SOLIUDS) {
                filterValue.clear();
                filterValue += "/";
                offset++;
                while (data.Copy(offset, buffer) && buffer != PDF::DC::SOLIUDS && buffer != PDF::DC::GREATER_THAN && buffer != PDF::WSC::LINE_FEED &&
                       buffer != PDF::WSC::SPACE && buffer != PDF::DC::RIGHT_SQUARE_BRACKET) {
                    filterValue += static_cast<char>(buffer);
                    offset++;
                }
                if (filterValue.length() > 1) {
                    filters.push_back(filterValue);
                }
            } else {
                offset++;
            }
        }
    } else {
        // a single filter
        offset++; // skip "/"
        filterValue.clear();
        filterValue += "/";
        while (offset < dataSize) {
            if (!data.Copy(offset, buffer)) {
                break;
            }
            if (buffer == PDF::DC::SOLIUDS || buffer == PDF::DC::GREATER_THAN || buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::SPACE) {
                break;
            } else {
                filterValue += static_cast<char>(buffer);
                offset++;
            }
        }
        if (filterValue.length() > 1) {
            filters.push_back(filterValue);
        }
    }
    offset--;
}

void GetDecompressDataValue(Buffer& decompressedData, uint64& offset, const uint8& value, uint64& obj)
{
    for (uint8_t i = 0; i < value; ++i) {
        obj = (obj << 8) | decompressedData[offset + i];
    }
    offset += value;
}

void GetObjectsOffsets(const uint64& numEntries, uint64& offset, GView::Utils::DataCache& data, std::vector<uint64_t>& objectOffsets)
{
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
                objectOffsets.push_back(result);
            }
        } else {
            Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Invalid Cross-Reference Table sequence. It has to be 20 bytes!");
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
        const bool match = CheckType(data, offset, PDF::KEY::PDF_TRAILER_SIZE, PDF::KEY::PDF_TRAILER);
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
        } else if (buffer == PDF::DC::SOLIUDS) {
            // get the length for the stream so that we don't have to go through all the bytes
            if (!foundLength && CheckType(data, objectOffset, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH)) { // /Length for the stream
                settings.AddZone(objectOffset, PDF::KEY::PDF_STREAM_LENGTH_SIZE, ColorPair{ Color::Red, Color::DarkBlue }, "Name");
                objectOffset += PDF::KEY::PDF_STREAM_LENGTH_SIZE + 1;
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
                    case PDF::DC::SOLIUDS:
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
        return;
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

            GetObjectsOffsets(numEntries, offset, data, objectOffsets);

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
                    if (CheckType(data, offset, PDF::KEY::PDF_PREV_SIZE, PDF::KEY::PDF_PREV)) {
                        offset += PDF::KEY::PDF_PREV_SIZE;

                        while (offset < dataSize && (data.Copy(offset, buffer) &&
                                                     (buffer == PDF::WSC::SPACE || buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN))) {
                            offset++;
                        }

                        prevOffset = GetTypeValue(data, offset, dataSize);
                        if (prevOffset != 0) {
                            found_prev = true;
                        } else {
                            Dialogs::MessageBox::ShowError("Error!", "Anomaly found: /Prev in the trailer has the value equal to zero!");
                        }
                    } else if (CheckType(data, offset, PDF::KEY::PDF_EOF_SIZE, PDF::KEY::PDF_EOF)) {
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

                if (data.Copy(offset, tag) && tag == PDF::DC::SOLIUDS) { // the first byte of tag is "/"
                    if (!typeFlags.hasLength && CheckType(data, offset, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH)) { // /Length
                        offset += PDF::KEY::PDF_STREAM_LENGTH_SIZE + 1;
                        lengthVal           = GetTypeValue(data, offset, dataSize);
                        typeFlags.hasLength = true;
                    } else if (!typeFlags.hasFilter && CheckType(data, offset, PDF::KEY::PDF_FILTER_SIZE, PDF::KEY::PDF_FILTER)) { // /Filter
                        offset += PDF::KEY::PDF_FILTER_SIZE;
                        GetFilters(data, offset, dataSize, filters);
                        typeFlags.hasFilter = true;
                    } else if (!typeFlags.hasPrev && CheckType(data, offset, PDF::KEY::PDF_PREV_SIZE, PDF::KEY::PDF_PREV)) { // /Prev
                        offset += PDF::KEY::PDF_PREV_SIZE + 1;
                        prevOffset        = GetTypeValue(data, offset, dataSize);
                        typeFlags.hasPrev = true;
                    } else if (
                          !typeFlags.hasDecodeParms && CheckType(data, offset, PDF::KEY::PDF_DECODEPARMS_SIZE, PDF::KEY::PDF_DECODEPARMS)) { // /DecodeParms
                        offset += PDF::KEY::PDF_DECODEPARMS_SIZE + 2;
                        uint16_t tag;
                        while (offset < dataSize) {
                            if (!data.Copy(offset, tag)) {
                                continue;
                            }
                            if (tag == PDF::DC::END_TAG) {
                                offset += 2;
                                break;
                            }
                            if (CheckType(data, offset, PDF::KEY::PDF_COLUMNS_SIZE, PDF::KEY::PDF_COLUMNS)) {
                                offset += PDF::KEY::PDF_COLUMNS_SIZE + 1;
                                decodeParms.column = GetTypeValue(data, offset, dataSize);
                            } else if (CheckType(data, offset, PDF::KEY::PDF_PREDICTOR_SIZE, PDF::KEY::PDF_PREDICTOR)) {
                                offset += PDF::KEY::PDF_PREDICTOR_SIZE + 1;
                                decodeParms.predictor = GetTypeValue(data, offset, dataSize);
                            } else if (CheckType(data, offset, PDF::KEY::PDF_BPC_SIZE, PDF::KEY::PDF_BPC)) {
                                offset += PDF::KEY::PDF_BPC_SIZE + 1;
                                decodeParms.bitsPerComponent = GetTypeValue(data, offset, dataSize);
                            } else if (CheckType(data, offset, PDF::KEY::PDF_EARLYCG_SIZE, PDF::KEY::PDF_EARLYCG)) {
                                offset += PDF::KEY::PDF_EARLYCG_SIZE + 1;
                                decodeParms.earlyChange = GetTypeValue(data, offset, dataSize);
                            } else {
                                offset++;
                            }
                        }
                        typeFlags.hasDecodeParms = true;
                    } else if (!typeFlags.hasW && CheckType(data, offset, PDF::KEY::PDF_W_SIZE, PDF::KEY::PDF_W)) { // /W
                        offset += PDF::KEY::PDF_W_SIZE;
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
                                break;
                            }
                            while (offset < decompressDataSize) {
                                uint64_t obj1 = 0, obj2 = 0, obj3 = 0;

                                GetDecompressDataValue(decompressedData, offset, wValues.x, obj1);
                                GetDecompressDataValue(decompressedData, offset, wValues.y, obj2);
                                GetDecompressDataValue(decompressedData, offset, wValues.z, obj3);

                                if (obj1 == 1) { // don't include CR stream as an object
                                    objectOffsets.push_back(obj2);
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
                        }
                    } else {
                        Dialogs::MessageBox::ShowError(
                              "Error!", "Unknown Filter for the Cross-Reference Stream!");
                    }
                }

                if (typeFlags.hasPrev) { // offset of the previous cross reference stream
                    crossRefOffset = prevOffset;
                } else {
                    next_CR_stream = false;
                }
            } else {
                Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Cross-Reference Stream is missing!");
            }
        }
    } else {
        Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Couldn't find a Cross-Reference Table or Cross-Reference Stream!");
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
}

void GetObjectReference(const uint64& dataSize, GView::Utils::DataCache& data, uint64& objectOffset, uint8& buffer, std::vector<uint64> &objectsNumber)
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
}

uint64 GetLengthNumber(GView::Utils::DataCache& data, uint64& objectOffset, const uint64& dataSize, vector<PDF::PDFObject>& pdfObjects)
{
    uint64 numberLength = 0;
    uint8 buffer;
    bool foundRef = false;
    objectOffset += PDF::KEY::PDF_STREAM_LENGTH_SIZE + 1;
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

void ProcessPDFTree(
      const uint64& dataSize, GView::Utils::DataCache& data, PDF::ObjectNode& objectNode, vector<PDF::PDFObject>& pdfObjects, vector<uint64> &processedObjects)
{
    // TODO: treat the other particular cases for getting the references of the objects
    uint64 objectOffset = objectNode.pdfObject.startBuffer;
    uint8 buffer;
    uint64 streamLength = 0;
    bool foundLength    = false;
    bool issueFound = false;
    std::vector<uint64> objectsNumber;     
    processedObjects.push_back(objectNode.pdfObject.number);
    objectNode.hasStream = false;

    while (objectOffset < objectNode.pdfObject.endBuffer) {
        if (!data.Copy(objectOffset, buffer)) {
            break;
        }
        // skip the /Parent
        if (CheckType(data, objectOffset, PDF::KEY::PDF_PARENT_SIZE, PDF::KEY::PDF_PARENT)) { 
            objectOffset += PDF::KEY::PDF_PARENT_SIZE;
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
        if (data.Copy(objectOffset, buffer) && buffer == PDF::DC::SOLIUDS) {
            // /Length
            if (CheckType(data, objectOffset, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH) && !foundLength) {
                uint64 copyObjectOffset = objectOffset;
                copyObjectOffset += PDF::KEY::PDF_STREAM_LENGTH_SIZE;
                if (!data.Copy(copyObjectOffset, buffer)) {
                    break;
                }
                if (buffer == PDF::WSC::SPACE) {
                    streamLength = GetLengthNumber(data, objectOffset, dataSize, pdfObjects);
                    foundLength  = true;
                } else {
                    objectOffset = copyObjectOffset;
                }
            }
            // /Filter
            else if (CheckType(data, objectOffset, PDF::KEY::PDF_FILTER_SIZE, PDF::KEY::PDF_FILTER)) {
                objectOffset += PDF::KEY::PDF_FILTER_SIZE;
                GetFilters(data, objectOffset, dataSize, objectNode.metadata.filters);
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_COLUMNS_SIZE, PDF::KEY::PDF_COLUMNS)) {
                objectOffset += PDF::KEY::PDF_COLUMNS_SIZE + 1;
                objectNode.metadata.decodeParams.column = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_PREDICTOR_SIZE, PDF::KEY::PDF_PREDICTOR)) {
                objectOffset += PDF::KEY::PDF_PREDICTOR_SIZE + 1;
                objectNode.metadata.decodeParams.predictor = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_BPC_SIZE, PDF::KEY::PDF_BPC)) {
                objectOffset += PDF::KEY::PDF_BPC_SIZE + 1;
                objectNode.metadata.decodeParams.bitsPerComponent = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_EARLYCG_SIZE, PDF::KEY::PDF_EARLYCG)) {
                objectOffset += PDF::KEY::PDF_EARLYCG_SIZE + 1;
                objectNode.metadata.decodeParams.earlyChange = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_K_SIZE, PDF::KEY::PDF_K)) {
                objectOffset += PDF::KEY::PDF_K_SIZE + 1;
                if (!data.Copy(objectOffset, buffer)) {
                    break;
                }
                bool isNegative = false;
                if (buffer == '-') {
                    isNegative = true;
                }
                objectOffset++;
                objectNode.metadata.decodeParams.K = GetTypeValue(data, objectOffset, dataSize);
                if (isNegative) {
                    objectNode.metadata.decodeParams.K *= -1;
                }
                objectOffset--;
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_ROWS_SIZE, PDF::KEY::PDF_ROWS)) {
                objectOffset += PDF::KEY::PDF_ROWS_SIZE + 1;
                objectNode.metadata.decodeParams.rows = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_ENDOFLINE_SIZE, PDF::KEY::PDF_ENDOFLINE)) {
                objectOffset += PDF::KEY::PDF_ENDOFLINE_SIZE + 1;
                if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
                    objectNode.metadata.decodeParams.endOfLine = true;
                    objectOffset += PDF::KEY::PDF_TRUE_SIZE;
                } else {
                    objectNode.metadata.decodeParams.endOfLine = false;
                    objectOffset += PDF::KEY::PDF_FALSE_SIZE;
                }
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_ENCODEDBYTEALIGN_SIZE, PDF::KEY::PDF_ENCODEDBYTEALIGN)) {
                objectOffset += PDF::KEY::PDF_ENCODEDBYTEALIGN_SIZE + 1;
                if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
                    objectNode.metadata.decodeParams.encodedByteAlign = true;
                    objectOffset += PDF::KEY::PDF_TRUE_SIZE;
                } else {
                    objectNode.metadata.decodeParams.encodedByteAlign = false;
                    objectOffset += PDF::KEY::PDF_FALSE_SIZE;
                }
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_ENDOFBLOCK_SIZE, PDF::KEY::PDF_ENDOFBLOCK)) {
                objectOffset += PDF::KEY::PDF_ENDOFBLOCK_SIZE + 1;
                if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
                    objectNode.metadata.decodeParams.endOfBlock = true;
                    objectOffset += PDF::KEY::PDF_TRUE_SIZE;
                } else {
                    objectNode.metadata.decodeParams.endOfBlock = false;
                    objectOffset += PDF::KEY::PDF_FALSE_SIZE;
                }
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_BLACKIS1_SIZE, PDF::KEY::PDF_BLACKIS1)) {
                objectOffset += PDF::KEY::PDF_BLACKIS1_SIZE + 1;
                if (CheckType(data, objectOffset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
                    objectNode.metadata.decodeParams.blackIs1 = true;
                    objectOffset += PDF::KEY::PDF_TRUE_SIZE;
                } else {
                    objectNode.metadata.decodeParams.blackIs1 = false;
                    objectOffset += PDF::KEY::PDF_FALSE_SIZE;
                }
            } else if (CheckType(data, objectOffset, PDF::KEY::PDF_DMGROWSBEFERROR_SIZE, PDF::KEY::PDF_DMGROWSBEFERROR)) {
                objectOffset += PDF::KEY::PDF_DMGROWSBEFERROR_SIZE + 1;
                objectNode.metadata.decodeParams.dmgRowsBefError = GetTypeValue(data, objectOffset, dataSize);
                objectOffset--;
            } 
        }
        // object has a stream
        if (CheckType(data, objectOffset, PDF::KEY::PDF_STREAM_SIZE, PDF::KEY::PDF_STREAM) && foundLength) {
            objectNode.hasStream = true;
            objectOffset += PDF::KEY::PDF_STREAM_SIZE;
            // skip some bytes
            while (data.Copy(objectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                objectOffset++;
            }
            objectNode.metadata.streamOffsetStart = objectOffset;
            objectOffset += streamLength;
            objectNode.metadata.streamOffsetEnd = objectOffset;
            // additional checking
            while (data.Copy(objectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                objectOffset++;
            }
            if (!CheckType(data, objectOffset, PDF::KEY::PDF_ENDSTREAM_SIZE, PDF::KEY::PDF_ENDSTREAM) && !issueFound) {
                Dialogs::MessageBox::ShowError("Error!", "Wrong end stream token! Object number: " + std::to_string(objectNode.pdfObject.number));
                issueFound = true;
            } else {
                PDF::ObjectNode streamChild;
                streamChild.pdfObject.type   = PDF::SectionPDFObjectType::Stream;
                streamChild.pdfObject.number = objectNode.pdfObject.number;
                streamChild.hasStream        = false;
                streamChild.pdfObject.startBuffer = objectNode.metadata.streamOffsetStart;
                streamChild.pdfObject.endBuffer   = objectNode.metadata.streamOffsetEnd;
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

    if (!foundLength && objectNode.hasStream && !issueFound) {
        Dialogs::MessageBox::ShowError("Error!", "Anomaly found: Missing /Length for an object which has a stream!");
        issueFound = true;
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
            ProcessPDFTree(dataSize, data, objectNode.children[i], pdfObjects, processedObjects);
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
                pdf->objectNodeRoot.hasStream = false;
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
                    } else if (buffer == PDF::DC::SOLIUDS) {
                        const uint64_t start_segment = objectOffset;
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
                            case PDF::DC::SOLIUDS:
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
                    } else if (data.Copy(objectOffset, buffer) && buffer == PDF::DC::SOLIUDS) {
                        if (CheckType(data, objectOffset, PDF::KEY::PDF_FILTER_SIZE, PDF::KEY::PDF_FILTER)) {
                            objectOffset += PDF::KEY::PDF_FILTER_SIZE;
                            GetFilters(data, objectOffset, dataSize, pdf->objectNodeRoot.metadata.filters);
                        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH) && !foundLength) {
                            streamLength = GetLengthNumber(data, objectOffset, dataSize, pdf->pdfObjects);
                            foundLength  = true;
                        }
                        else if (CheckType(data, objectOffset, PDF::KEY::PDF_COLUMNS_SIZE, PDF::KEY::PDF_COLUMNS)) {
                            objectOffset += PDF::KEY::PDF_COLUMNS_SIZE + 1;
                            pdf->objectNodeRoot.metadata.decodeParams.column = GetTypeValue(data, objectOffset, dataSize);
                        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_PREDICTOR_SIZE, PDF::KEY::PDF_PREDICTOR)) {
                            objectOffset += PDF::KEY::PDF_PREDICTOR_SIZE + 1;
                            pdf->objectNodeRoot.metadata.decodeParams.predictor = GetTypeValue(data, objectOffset, dataSize);
                        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_BPC_SIZE, PDF::KEY::PDF_BPC)) {
                            objectOffset += PDF::KEY::PDF_BPC_SIZE + 1;
                            pdf->objectNodeRoot.metadata.decodeParams.bitsPerComponent = GetTypeValue(data, objectOffset, dataSize);
                        } else if (CheckType(data, objectOffset, PDF::KEY::PDF_EARLYCG_SIZE, PDF::KEY::PDF_EARLYCG)) {
                            objectOffset += PDF::KEY::PDF_EARLYCG_SIZE + 1;
                            pdf->objectNodeRoot.metadata.decodeParams.earlyChange = GetTypeValue(data, objectOffset, dataSize);
                        } else {
                            objectOffset++;
                        }
                    } else if (CheckType(data, objectOffset, PDF::KEY::PDF_STREAM_SIZE, PDF::KEY::PDF_STREAM) && foundLength) {
                        pdf->objectNodeRoot.hasStream = true;
                        objectOffset += PDF::KEY::PDF_STREAM_SIZE;
                        // skip some bytes
                        while (data.Copy(objectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                            objectOffset++;
                        }
                        pdf->objectNodeRoot.metadata.streamOffsetStart = objectOffset;
                        objectOffset += streamLength;
                        pdf->objectNodeRoot.metadata.streamOffsetEnd = objectOffset;
                        // additional checking
                        while (data.Copy(objectOffset, buffer) && (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN)) {
                            objectOffset++;
                        }
                        if (!CheckType(data, objectOffset, PDF::KEY::PDF_ENDSTREAM_SIZE, PDF::KEY::PDF_ENDSTREAM)) {
                            Dialogs::MessageBox::ShowError("Error!", "Wrong end stream token!");
                        } else {
                            PDF::ObjectNode streamChild;
                            streamChild.pdfObject.type = PDF::SectionPDFObjectType::Stream;
                            streamChild.pdfObject.number = pdf->objectNodeRoot.pdfObject.number;
                            streamChild.hasStream        = false;
                            streamChild.pdfObject.startBuffer = pdf->objectNodeRoot.metadata.streamOffsetStart;
                            streamChild.pdfObject.endBuffer   = pdf->objectNodeRoot.metadata.streamOffsetEnd;
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
        ProcessPDFTree(dataSize, data, pdf->objectNodeRoot.children[i], pdf->pdfObjects, pdf->processedObjects);
    }

    // process the rest of the objects that don't have references

    for (auto& object : pdf->pdfObjects) {
        if ((std::count(pdf->processedObjects.begin(), pdf->processedObjects.end(), object.number) == 0) && (object.number != 0) &&
            (object.type != PDF::SectionPDFObjectType::CrossRefStream)) {
            pdf->objectNodeRoot.children.emplace_back();
            auto& childNode = pdf->objectNodeRoot.children.back();

            childNode.pdfObject = object;
            ProcessPDFTree(dataSize, data, childNode, pdf->pdfObjects, pdf->processedObjects);
        }
    }
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

        if (front->pdfObject.number == number)
            return front;

        for (auto& ch : front->children)
            queue.push_back(&ch);
    }
    return nullptr;
}

void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<GView::Type::PDF::PDFFile> pdf)
{
    ContainerViewer::Settings settings;

    settings.SetPathSeparator((char16) '/');
    settings.SetIcon(PDF_ICON);
    settings.SetColumns({
          "n:&Object,a:l,w:60",
          "n:&Type,a:r,w:20",
          "n:&Offset start,a:r,w:20",
          "n:&Size,a:r,w:20",
          "n:&Filters,a:r,w:30",
    });

    settings.SetEnumerateCallback(win->GetObject()->GetContentType<GView::Type::PDF::PDFFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(win->GetObject()->GetContentType<GView::Type::PDF::PDFFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

    win->CreateViewer(settings);
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto pdf = win->GetObject()->GetContentType<PDF::PDFFile>();
    pdf->Update();

    // viewers
    CreateBufferView(win, pdf);
    ProcessPDF(pdf);
    CreateContainerView(win, pdf);
    // win->CreateViewer<TextViewer::Settings>();

    win->AddPanel(Pointer<TabPage>(new PDF::Panels::Sections(pdf, win)), false);
    win->AddPanel(Pointer<TabPage>(new PDF::Panels::Information(pdf)), true);

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