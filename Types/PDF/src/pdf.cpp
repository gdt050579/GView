#include "pdf.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        if (buf.GetLength() < sizeof(PDF::Header)) {
            return false;
        }
        auto header = buf.GetObject<PDF::Header>();
        if (std::memcmp(header->identifier, PDF::KEY::PDF_MAGIC, 5) != 0) {
            return false;
        }
        if (header->version_1 != '1' || header->point != '.' || (header->version_N < '0' || header->version_N > '7'))
        {
            return false;
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

    void GetFilters(GView::Utils::DataCache& data, uint64& offset, const uint64& dataSize, std::vector<std::string> &filters)
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

    void GetObjectsOffsets(const uint64& numEntries, uint64& offset, GView::Utils::DataCache& data, std::vector<uint64_t> &objectOffsets)
    {
        // Read each 20-byte entry
        for (uint16_t i = 0; i < numEntries; ++i) {
            char entry[21];
            memset(entry, 0, sizeof(entry));

            for (size_t j = 0; j < 20; ++j) {
                if (!data.Copy(offset + j, entry[j])) {
                    break;
                }
            }

            if (entry[17] != 'f') { // skip the free entries
                std::string entryStr(entry);
                std::string byteOffsetStr = entryStr.substr(0, 10);

                uint64_t byteOffset = std::stoull(byteOffsetStr);
                objectOffsets.push_back(byteOffset);
            }
            offset += 20;
        }
    }

    uint64 GetNumberOfEntries(const uint64& crossRefOffset, uint64& offset, const uint64& dataSize, GView::Utils::DataCache &data)
    {
        uint8_t buffer;
        uint16_t numEntries = 0;
        if (crossRefOffset > 0) {
            offset              = crossRefOffset + 4; // Skip "xref" keyword

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

    void ApplyPNGFilter(Buffer& data, const uint16_t &column, const uint8_t &predictor, const uint8_t &bitsPerComponent)
    {
        if (!data.IsValid()) {
            return;
        }

        const uint8_t bytesPerComponent = (bitsPerComponent + 7) / 8; // ceil(bitsPerComponent / 8)
        const uint64_t rowLength        = column * bytesPerComponent + 1;
        const uint64_t dataLength   = data.GetLength();

        Buffer rowBuffer;
        rowBuffer.Resize(rowLength);

        auto getPrevRow = [&](uint64_t offset, uint8_t* buffer) {
            if (offset >= rowLength) {
                std::memcpy(buffer, data.GetData() + offset - rowLength, rowLength);
            } else {
                std::memset(buffer, 0, rowLength);
            }
        };

        auto applyFilter = [&](uint64_t offset) {
            getPrevRow(offset, rowBuffer.GetData());
            for (uint64_t i = 0; i < rowLength; ++i) {
                uint8_t newValue  = data.GetData()[offset];
                uint8_t left           = (offset % bytesPerComponent == 0) ? 0 : data.GetData()[offset - bytesPerComponent];
                uint8_t above          = rowBuffer[i];
                uint8_t aboveLeft      = (offset >= rowLength && (offset - bytesPerComponent) >= rowLength) ? rowBuffer[i - bytesPerComponent] : 0;
                uint8_t paethPredictor = 0, p = 0, pLeft = 0, pAbove = 0, pAboveLeft = 0;

                switch (predictor) {
                case 11: // PNG Sub Filter
                    newValue = data.GetData()[offset] + left;
                    break;
                case 12: // PNG Up Filter
                    newValue = data.GetData()[offset] + above;
                    break;
                case 13: // PNG Average Filter
                    newValue = data.GetData()[offset] + ((left + above) / 2);
                    break;
                case 14: // PNG Paeth Filter
                    paethPredictor = left + above - aboveLeft;
                    p              = data.GetData()[offset] - paethPredictor;
                    pLeft          = std::abs(p - left);
                    pAbove         = std::abs(p - above);
                    pAboveLeft     = std::abs(p - aboveLeft);
                    newValue = data.GetData()[offset] + (pLeft <= pAbove && pLeft <= pAboveLeft ? left : pAbove <= pAboveLeft ? above : aboveLeft);
                    break;
                case 10:    // PNG None Filter
                case 15:    // PNG Optimum Filter
                    return; // No filtering needed for None or Optimum
                default:
                    // unknown predictor
                    return;
                }

                data.GetData()[offset] = newValue;
                ++offset;
            }
        };

        for (uint64_t offset = 0; offset < dataLength;) {
            applyFilter(offset);
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

        const std::vector<ColorPair> colors = { ColorPair{ Color::Teal, Color::DarkBlue }, ColorPair{ Color::Yellow, Color::DarkBlue } };

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
                    settings.AddZone(eofOffset, dataSize - eofOffset, ColorPair{ Color::Magenta, Color::DarkBlue }, "EOF");
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
        if (pdf->version_under_5) {

            bool next_table = true;
            while (next_table) {

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

                uint64 trailerOffset = 0;
                const bool foundTrailer = GetTrailerOffset(offset, dataSize, data, trailerOffset);

                // Find /Prev in the trailer segment
                bool found_prev = false;
                if (foundTrailer) {
                    for (offset = trailerOffset; offset < eofOffset - PDF::KEY::PDF_PREV_SIZE; ++offset) {
                        const bool match = CheckType(data, offset, PDF::KEY::PDF_PREV_SIZE, PDF::KEY::PDF_PREV);
                        if (match) {
                            offset += PDF::KEY::PDF_PREV_SIZE;

                            while (offset < dataSize && (data.Copy(offset, buffer) && (buffer == PDF::WSC::SPACE || buffer == PDF::WSC::LINE_FEED ||
                                                                                        buffer == PDF::WSC::CARRIAGE_RETURN))) {
                                offset++;
                            }

                            prevOffset = GetTypeValue(data, offset, dataSize);
                            found_prev = true;
                            break;
                        }
                    }
                    if (!found_prev) {
                        next_table = false;
                    }
                }

                if (foundTrailer) {
                    settings.AddZone(crossRefOffset, trailerOffset - crossRefOffset, ColorPair{ Color::Green, Color::DarkBlue }, "Cross-Reference Table");
                    settings.AddZone(trailerOffset, eofOffset - trailerOffset + PDF::KEY::PDF_EOF_SIZE, ColorPair{ Color::Red, Color::DarkBlue }, "Trailer");
                }
                crossRefOffset = prevOffset;
            }
        } else {    // PDF 1.5-1.7

            bool next_CR_stream = true;
            while (next_CR_stream) {

                offset = crossRefOffset;
                uint8_t tag;
                bool end_tag = false;
                // 0 = /Length, 1 = /Filter, 2 = /Prev, 3 = /DecodeParms, 4 = /W
                bool typeFound[] = { false, false, false, false, false }; 
                uint64 lengthVal = 0;
                Buffer streamData;
                std::vector<std::string> filters;
                bool filterType = 0; // FLATE ONLY

                struct WValues{ // W[x y z]
                    uint8 x;
                    uint8 y;
                    uint8 z;
                };

                struct DecodeParms {
                    uint8 predictor;
                    uint16 column;
                    uint8 bitsPerComponent;
                };

                WValues wValues = { 0, 0, 0 };
                DecodeParms decodeParms = { 1, 1, 8};

                while (!end_tag) {
                    if (CheckType(data, offset, PDF::KEY::PDF_STREAM_SIZE, PDF::KEY::PDF_STREAM)) {
                        end_tag = true;
                        offset += PDF::KEY::PDF_STREAM_SIZE;
                        break;
                    }

                    if (data.Copy(offset, tag) && tag == PDF::DC::SOLIUDS) {                                                 // the first byte of tag is "/"
                        if (!typeFound[0] && CheckType(data, offset, PDF::KEY::PDF_STREAM_LENGTH_SIZE, PDF::KEY::PDF_STREAM_LENGTH)) { // /Length
                            offset += PDF::KEY::PDF_STREAM_LENGTH_SIZE + 1;
                            lengthVal    = GetTypeValue(data, offset, dataSize);
                            typeFound[0] = true;
                        } 
                        else if (!typeFound[1] && CheckType(data, offset, PDF::KEY::PDF_FILTER_SIZE, PDF::KEY::PDF_FILTER)) { // /Filter
                            offset += PDF::KEY::PDF_FILTER_SIZE;
                            GetFilters(data, offset, dataSize, filters);
                            typeFound[1] = true;
                        } 
                        else if (!typeFound[2] && CheckType(data, offset, PDF::KEY::PDF_PREV_SIZE, PDF::KEY::PDF_PREV)) { // /Prev
                            offset += PDF::KEY::PDF_PREV_SIZE + 1;
                            prevOffset   = GetTypeValue(data, offset, dataSize);
                            typeFound[2] = true;
                        }
                        else if (!typeFound[3] && CheckType(data, offset, PDF::KEY::PDF_DECODEPARMS_SIZE, PDF::KEY::PDF_DECODEPARMS)) { // /DecodeParms
                            offset += PDF::KEY::PDF_DECODEPARMS_SIZE + 2;
                            uint16_t tag;
                            while (offset < dataSize) {
                                if (!data.Copy(offset, tag)) {
                                    continue;
                                }
                                if (tag == PDF::DC::END_TAG)
                                {
                                    offset += 2;
                                    break;
                                }
                                if (CheckType(data, offset, PDF::KEY::PDF_COLUMNS_SIZE, PDF::KEY::PDF_COLUMNS)) {
                                    offset += PDF::KEY::PDF_COLUMNS_SIZE + 1;
                                    decodeParms.column = GetTypeValue(data, offset, dataSize);
                                }
                                else if (CheckType(data, offset, PDF::KEY::PDF_PREDICTOR_SIZE, PDF::KEY::PDF_PREDICTOR)) {
                                    offset += PDF::KEY::PDF_PREDICTOR_SIZE + 1;
                                    decodeParms.predictor = GetTypeValue(data, offset, dataSize);
                                }
                                else if (CheckType(data, offset, PDF::KEY::PDF_BPC_SIZE, PDF::KEY::PDF_BPC)) {
                                    offset += PDF::KEY::PDF_BPC_SIZE + 1;
                                    decodeParms.bitsPerComponent = GetTypeValue(data, offset, dataSize);
                                } else {
                                    offset++;
                                }
                            }
                            typeFound[3] = true;
                        }
                        else if (!typeFound[4] && CheckType(data, offset, PDF::KEY::PDF_W_SIZE, PDF::KEY::PDF_W)) { // /W
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
                            typeFound[4] = true;
                        } 
                        else {
                            offset++;
                        }
                    } else {
                        offset++;
                    }
                }
                if (end_tag) {
                    if (typeFound[0]) { // copy the stream data
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
                                offset += PDF::KEY::PDF_EOF_SIZE;
                                settings.AddZone(crossRefOffset, offset - crossRefOffset, ColorPair{ Color::Green, Color::DarkBlue }, "Cross-Reference Stream");
                                break;
                            } else {
                                offset++;
                            }
                        }
                    }

                    if (typeFound[1]) { // decode data
                        if (filters[0] == PDF::FILTER::FLATE) {
                            Buffer decompressedData;
                            uint64 decompressDataSize = lengthVal;
                            if (GView::ZLIB::DecompressStream(streamData, lengthVal, decompressedData, decompressDataSize))
                            {
                                if (typeFound[3]) {
                                    ApplyPNGFilter(
                                          decompressedData, decodeParms.column, decodeParms.predictor, decodeParms.bitsPerComponent);
                                    decompressDataSize = decompressedData.GetLength();
                                }
                                offset                            = 0;
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

                    if (typeFound[2]) { // offset of the previous cross reference stream
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
            settings.AddZone(objOffset, length, colors[i % colors.size()], "Obj " + std::to_string(i + 1));
        }

        pdf->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        auto pdf = win->GetObject()->GetContentType<PDF::PDFFile>();
        pdf->Update();

        // viewers
        CreateBufferView(win, pdf);
        //win->CreateViewer<TextViewer::Settings>();

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

int main()
{
    return 0;
}
