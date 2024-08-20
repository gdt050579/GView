#include "pdf.hpp"

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
    CHECK(header->version1 == '1' && header->point == '.' && header->versionN >= '0' && header->versionN <= '7', false, "");
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
    filterValue += "/";
    if (data.Copy(offset, buffer) && buffer == PDF::WSC::SPACE) { // /Filter /
        offset++;
    }
    offset++; // skip "/"
    while (offset < dataSize) {
        if (!data.Copy(offset, buffer)) {
            break;
        }
        if (buffer == PDF::DC::SOLIUDS || buffer == PDF::DC::GREATER_THAN || buffer == PDF::WSC::LINE_FEED) {
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

static void GetPreviousRow(const Buffer& data, uint64_t offset, uint8_t* buffer, const uint64_t rowLength)
{
    if (offset >= rowLength) {
        memcpy(buffer, data.GetData() + offset - rowLength, rowLength);
    } else {
        memset(buffer, 0, rowLength);
    }
}

static void ApplyFilter(Buffer& data, uint64_t offset, uint8_t* rowBuffer, const uint64_t rowLength, const uint8_t bytesPerComponent, const uint8_t predictor)
{
    GetPreviousRow(data, offset, rowBuffer, rowLength);

    for (uint64_t i = 0; i < rowLength; ++i) {
        uint8_t newValue       = data.GetData()[offset];
        uint8_t left           = (offset % bytesPerComponent == 0) ? 0 : data.GetData()[offset - bytesPerComponent];
        uint8_t above          = rowBuffer[i];
        uint8_t aboveLeft      = (offset >= rowLength && (offset - bytesPerComponent) >= rowLength) ? rowBuffer[i - bytesPerComponent] : 0;
        uint8_t paethPredictor = 0, p = 0, pLeft = 0, pAbove = 0, pAboveLeft = 0;

        switch (predictor) {
        case PDF::PREDICTOR::SUB:
            newValue = data.GetData()[offset] + left;
            break;
        case PDF::PREDICTOR::UP:
            newValue = data.GetData()[offset] + above;
            break;
        case PDF::PREDICTOR::AVERAGE:
            newValue = data.GetData()[offset] + ((left + above) / 2);
            break;
        case PDF::PREDICTOR::PAETH:
            paethPredictor = left + above - aboveLeft;
            p              = data.GetData()[offset] - paethPredictor;
            pLeft          = std::abs(p - left);
            pAbove         = std::abs(p - above);
            pAboveLeft     = std::abs(p - aboveLeft);
            newValue       = data.GetData()[offset] + (pLeft <= pAbove && pLeft <= pAboveLeft ? left : pAbove <= pAboveLeft ? above : aboveLeft);
            break;
        case PDF::PREDICTOR::NONE:
        case PDF::PREDICTOR::OPTIMUM:
            return; // No filtering needed for None or Optimum
        default:
            // unknown predictor
            return;
        }

        data.GetData()[offset] = newValue;
        ++offset;
    }
}

void ApplyPNGFilter(Buffer& data, const uint16_t& column, const uint8_t& predictor, const uint8_t& bitsPerComponent)
{
    if (!data.IsValid()) {
        return;
    }

    const uint8_t bytesPerComponent = (bitsPerComponent + 7) / 8; // ceil(bitsPerComponent / 8)
    const uint64_t rowLength        = column * bytesPerComponent + 1;
    const uint64_t dataLength       = data.GetLength();

    Buffer rowBuffer;
    rowBuffer.Resize(rowLength);

    for (uint64_t offset = 0; offset < dataLength;) {
        ApplyFilter(data, offset, rowBuffer.GetData(), rowLength, bytesPerComponent, predictor);
        offset += rowLength;
    }

    const uint64_t newSize = dataLength - (dataLength / (rowLength + 1));
    Buffer filteredData;
    filteredData.Resize(newSize);

    uint64_t srcOffset = 0;
    uint64_t dstOffset = 0;
    while (srcOffset < dataLength) {
        if (srcOffset % rowLength != 0) { // Skip filter type byte
            filteredData.GetData()[dstOffset++] = data.GetData()[srcOffset];
        }
        ++srcOffset;
    }

    data = std::move(filteredData);
}

void HighlightObjectTypes(
      GView::Utils::DataCache& data,
      Reference<PDF::PDFFile> pdf,
      BufferViewer::Settings& settings,
      const uint64_t& offset,
      const uint64_t& dataSize,
      const uint64 objNum)
{
    uint8_t buffer;
    uint64_t lengthVal     = 0;
    bool found_length      = false;
    uint64_t object_offset = offset;

    PDF::PDFObject pdfObject;
    pdfObject.startBuffer = offset;
    pdfObject.type        = 1;
    pdfObject.number      = objNum;

    while (object_offset < dataSize && (data.Copy(object_offset, buffer) && (buffer != PDF::WSC::LINE_FEED && buffer != PDF::WSC::CARRIAGE_RETURN))) {
        object_offset++;
    }
    while (object_offset < dataSize) {
        if (!data.Copy(object_offset, buffer)) {
            break;
        }
        if (CheckType(data, object_offset, PDF::KEY::PDF_ENDOBJ_SIZE, PDF::KEY::PDF_ENDOBJ)) {
            pdfObject.endBuffer = object_offset + PDF::KEY::PDF_ENDOBJ_SIZE;
            pdf->AddPDFObject(pdf, pdfObject);
            break;
        } else if (
              CheckType(data, object_offset, PDF::KEY::PDF_DIC_SIZE, PDF::KEY::PDF_DIC_START) ||
              CheckType(data, object_offset, PDF::KEY::PDF_DIC_SIZE, PDF::KEY::PDF_DIC_END)) {
            settings.AddZone(object_offset, PDF::KEY::PDF_DIC_SIZE, ColorPair{ Color::Yellow, Color::DarkBlue }, "Dictionary");
            object_offset += PDF::KEY::PDF_DIC_SIZE;
        } else if (buffer == PDF::DC::SOLIUDS) {
            // get the length for the stream so that we don't have to go through all the bytes
            if (!found_length && CheckType(data, object_offset, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH)) { // /Length for the stream
                settings.AddZone(object_offset, PDF::KEY::PDF_STREAM_LENGTH_SIZE, ColorPair{ Color::Red, Color::DarkBlue }, "Name");
                object_offset += PDF::KEY::PDF_STREAM_LENGTH_SIZE + 1;
                const uint64_t start_segment = object_offset;
                lengthVal                    = GetTypeValue(data, object_offset, dataSize);
                settings.AddZone(start_segment, object_offset - start_segment, ColorPair{ Color::Green, Color::DarkBlue }, "Numeric");
                found_length = true;
            } else {
                const uint64_t start_segment = object_offset;
                object_offset++;
                bool end_name = false;
                while (object_offset < dataSize && !end_name) {
                    if (!data.Copy(object_offset, buffer)) {
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
                        object_offset++;
                    }
                }
                settings.AddZone(start_segment, object_offset - start_segment, ColorPair{ Color::Red, Color::DarkBlue }, "Name");
            }
        } else if (buffer == PDF::KEY::PDF_INDIRECTOBJ) {
            settings.AddZone(object_offset, 1, ColorPair{ Color::Yellow, Color::Blue }, "Indirect Obj");
            object_offset++;
        } else if (CheckType(data, object_offset, PDF::KEY::PDF_STREAM_SIZE, PDF::KEY::PDF_STREAM)) {
            if (found_length) {
                const uint64_t start_segment = object_offset;
                object_offset += PDF::KEY::PDF_STREAM_SIZE + lengthVal;
                while (object_offset < dataSize && !CheckType(data, object_offset, PDF::KEY::PDF_ENDSTREAM_SIZE, PDF::KEY::PDF_ENDSTREAM)) {
                    object_offset++;
                }
                object_offset += PDF::KEY::PDF_ENDSTREAM_SIZE;
                settings.AddZone(start_segment, object_offset - start_segment, ColorPair{ Color::Aqua, Color::DarkBlue }, "Stream");
            } else {
                break;
            }
        } else if (buffer == PDF::DC::LEFT_SQUARE_BRACKET || buffer == PDF::DC::RIGHT_SQUARE_BRACKET) {
            settings.AddZone(object_offset, 1, ColorPair{ Color::Olive, Color::DarkBlue }, "Array");
            object_offset++;
        } else if (buffer == '-' || buffer == '+' || (buffer >= '0' && buffer <= '9')) {
            const uint64_t start_segment = object_offset;
            object_offset++;
            while (object_offset < dataSize && data.Copy(object_offset, buffer) && ((buffer >= '0' && buffer <= '9') || buffer == '.')) {
                object_offset++;
            }
            settings.AddZone(start_segment, object_offset - start_segment, ColorPair{ Color::Green, Color::DarkBlue }, "Numeric");
        } else if (buffer == PDF::DC::LEFT_PARETHESIS) {
            const uint64_t start_segment = object_offset;
            object_offset++;
            while (object_offset < dataSize && data.Copy(object_offset, buffer) && buffer != PDF::DC::RIGHT_PARETHESIS) {
                if (buffer == PDF::DC::REVERSE_SOLIDUS) {
                    object_offset++;
                }
                object_offset++;
            }
            settings.AddZone(start_segment, object_offset - start_segment + 1, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Literal String");
        } else if (buffer == PDF::DC::LESS_THAN) {
            const uint64_t start_segment = object_offset;
            object_offset++;
            while (object_offset < dataSize && data.Copy(object_offset, buffer) && buffer != PDF::DC::GREATER_THAN) {
                object_offset++;
            }
            settings.AddZone(start_segment, object_offset - start_segment + 1, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Hex String");
        } else if (CheckType(data, object_offset, PDF::KEY::PDF_TRUE_SIZE, PDF::KEY::PDF_TRUE)) {
            settings.AddZone(object_offset, PDF::KEY::PDF_TRUE_SIZE, ColorPair{ Color::DarkRed, Color::DarkBlue }, "Boolean");
            object_offset += PDF::KEY::PDF_TRUE_SIZE;
        } else if (CheckType(data, object_offset, PDF::KEY::PDF_FALSE_SIZE, PDF::KEY::PDF_FALSE)) {
            settings.AddZone(object_offset, PDF::KEY::PDF_FALSE_SIZE, ColorPair{ Color::DarkRed, Color::DarkBlue }, "Boolean");
            object_offset += PDF::KEY::PDF_FALSE_SIZE;
        } else if (CheckType(data, object_offset, PDF::KEY::PDF_NULL_SIZE, PDF::KEY::PDF_NULL)) {
            settings.AddZone(object_offset, PDF::KEY::PDF_NULL_SIZE, ColorPair{ Color::White, Color::Blue }, "Null");
            object_offset += PDF::KEY::PDF_NULL_SIZE;
        } else if (CheckType(data, object_offset, PDF::KEY::PDF_ENDOBJ_SIZE, PDF::KEY::PDF_ENDOBJ)) {
            break;
        } else {
            object_offset++;
        }
    }
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
                }
                break;
            }
        }
    }

    // PDF 1.0-1.4
    if (pdf->versionUnder5) {
        bool next_table = true;
        while (next_table) {
            PDF::PDFObject pdfObject;
            pdfObject.startBuffer = crossRefOffset;
            pdfObject.type        = 2;
            pdfObject.number      = 0;
            // get the offsets from the Cross-Reference Table
            const uint64 numEntries = GetNumberOfEntries(crossRefOffset, offset, dataSize, data);
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
            pdfObject.type        = 4;
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
                        found_prev = true;
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
            }

            pdfObject.endBuffer = offset;
            pdf->AddPDFObject(pdf, pdfObject);

            if (foundTrailer) {
                settings.AddZone(crossRefOffset, trailerOffset - crossRefOffset, ColorPair{ Color::Green, Color::DarkBlue }, "Cross-Reference Table");
                settings.AddZone(trailerOffset, offset - trailerOffset, ColorPair{ Color::Red, Color::DarkBlue }, "Trailer");
            }
            crossRefOffset = prevOffset;
        }
    } else { // PDF 1.5-1.7

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
            PDF::DecodeParms decodeParms = { 1, 1, 8 };

            PDF::PDFObject pdfObject;
            pdfObject.startBuffer = crossRefOffset;
            pdfObject.type        = 3;
            pdfObject.number      = 0;

            while (!end_tag) {
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
                }

                if (typeFlags.hasFilter) { // decode data
                    if (filters[0] == PDF::FILTER::FLATE) {
                        Buffer decompressedData;
                        uint64 decompressDataSize = lengthVal;
                        if (GView::ZLIB::DecompressStream(streamData, lengthVal, decompressedData, decompressDataSize)) {
                            if (typeFlags.hasDecodeParms) {
                                ApplyPNGFilter(decompressedData, decodeParms.column, decodeParms.predictor, decodeParms.bitsPerComponent);
                                decompressDataSize = decompressedData.GetLength();
                            }
                            offset = 0;
                            while (offset < decompressDataSize) {
                                uint64_t obj1 = 0, obj2 = 0, obj3 = 0;

                                GetDecompressDataValue(decompressedData, offset, wValues.x, obj1);
                                GetDecompressDataValue(decompressedData, offset, wValues.y, obj2);
                                GetDecompressDataValue(decompressedData, offset, wValues.z, obj3);

                                if (obj1 == 1 && obj2 != crossRefOffset) { // don't include CR stream as an object
                                    objectOffsets.push_back(obj2);
                                }

                                if (offset > decompressDataSize) {
                                    break;
                                }
                            }
                        }
                    }
                }

                if (typeFlags.hasPrev) { // offset of the previous cross reference stream
                    crossRefOffset = prevOffset;
                } else {
                    next_CR_stream = false;
                }
            }
        }
    }

    std::sort(objectOffsets.begin(), objectOffsets.end());

    for (size_t i = 0; i < objectOffsets.size(); ++i) {
        uint64_t objOffset = objectOffsets[i];
        uint64_t length    = (i + 1 < objectOffsets.size()) ? objectOffsets[i + 1] - objOffset : eofOffset - objOffset;
        settings.AddZone(objOffset, length, { Color::Teal, Color::DarkBlue }, "Obj " + std::to_string(i + 1));
        HighlightObjectTypes(data, pdf, settings, objOffset, dataSize, i + 1);
    }

    pdf->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
}

void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<GView::Type::PDF::PDFFile> pdf)
{
    ContainerViewer::Settings settings;

    settings.SetPathSeparator((char16) '/');
    settings.SetIcon(PDF_ICON);
    settings.SetColumns({
          "n:&Object,a:l,w:20",
          "n:&Type,a:r,w:40",
          "n:&Position,a:r,w:40",
          "n:&Compressed Size,a:r,w:20",
          "n:&Uncompressed Size,a:r,w:20",
          "n:&Filter,a:r,w:40",
    });

    settings.SetEnumerateCallback(win->GetObject()->GetContentType<GView::Type::PDF::PDFFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(win->GetObject()->GetContentType<GView::Type::PDF ::PDFFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

    win->CreateViewer(settings);
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto pdf = win->GetObject()->GetContentType<PDF::PDFFile>();
    pdf->Update();

    // viewers
    CreateBufferView(win, pdf);
    // CreateContainerView(win, pdf);
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