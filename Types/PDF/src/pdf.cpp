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
        if (std::memcmp(header->identifier, PDF::PDF_MAGIC, 5) != 0) {
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
        uint8_t buffer;
        bool foundTrailer = false;
        for (; offset < dataSize - PDF::PDF_TRAILER_SIZE; ++offset) {
            bool match = true;
            for (size_t i = 0; i < PDF::PDF_TRAILER_SIZE; ++i) {
                if (!data.Copy(offset + i, buffer) || buffer != PDF::PDF_TRAILER[i]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                trailerOffset = offset;
                foundTrailer  = true;
                break;
            }
        }
        return foundTrailer;
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
        while (offset >= (PDF::PDF_EOF_SIZE + sizeof(PDF::Header)) && !foundEOF) {
            offset--;

            if (!data.Copy(offset, buffer)) {
                continue;
            }

            if (buffer == PDF::WSC::LINE_FEED || buffer == PDF::WSC::CARRIAGE_RETURN) {
                continue;
            }

            // check for %%EOF
            if (buffer == PDF::PDF_EOF[PDF::PDF_EOF_SIZE - 1]) {
                bool match = true;
                for (size_t i = 0; i < PDF::PDF_EOF_SIZE; ++i) {
                    if (!data.Copy(offset - PDF::PDF_EOF_SIZE + 1 + i, buffer) || buffer != PDF::PDF_EOF[i]) {
                        match = false;
                    }
                }

                if (match) {
                    foundEOF = true;
                    offset -= PDF::PDF_EOF_SIZE - 1;
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
                    for (offset = trailerOffset; offset < eofOffset - PDF::PDF_PREV_SIZE; ++offset) {
                        bool match = true;
                        for (size_t i = 0; i < PDF::PDF_PREV_SIZE; ++i) {
                            if (!data.Copy(offset + i, buffer) || buffer != PDF::PDF_PREV[i]) {
                                match = false;
                                break;
                            }
                        }

                        if (match) {
                            offset += PDF::PDF_PREV_SIZE;

                            while (offset < eofOffset && (data.Copy(offset, buffer) && (buffer == PDF::WSC::SPACE || buffer == PDF::WSC::LINE_FEED ||
                                                                                        buffer == PDF::WSC::CARRIAGE_RETURN))) {
                                offset++;
                            }

                            // Read the /Prev offset number
                            std::string prevOffsetStr;
                            while (offset < eofOffset && data.Copy(offset, buffer) && buffer >= '0' && buffer <= '9') {
                                prevOffsetStr.push_back(buffer);
                                offset++;
                            }

                            if (!prevOffsetStr.empty()) {
                                prevOffset = std::stoull(prevOffsetStr);
                            }
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
                    settings.AddZone(trailerOffset, eofOffset - trailerOffset + PDF::PDF_EOF_SIZE, ColorPair{ Color::Red, Color::DarkBlue }, "Trailer");
                }
                crossRefOffset = prevOffset;
            }

            std::sort(objectOffsets.begin(), objectOffsets.end());

            for (size_t i = 0; i < objectOffsets.size(); ++i) {
                uint64_t objOffset = objectOffsets[i];
                uint64_t length    = (i + 1 < objectOffsets.size()) ? objectOffsets[i + 1] - objOffset : eofOffset - objOffset;
                settings.AddZone(objOffset, length, colors[i % colors.size()], "Obj " + std::to_string(i + 1));
            }
        } else {    // PDF 1.5-1.7
            
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
