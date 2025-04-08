#include "pdf.hpp"
#include <nlohmann/json.hpp>
#include <regex>
using nlohmann::json;

using namespace GView::Type::PDF;

PDFFile::PDFFile()
{
}

bool PDFFile::Update()
{
    memset(&header, 0, sizeof(Header));

    auto& data = this->obj->GetData();
    CHECK(data.Copy<Header>(0, header), false, "");

    return true;
}

void PDFFile::AddPDFObject(Reference<GView::Type::PDF::PDFFile> pdf, const PDFObject& obj)
{
    auto it = std::lower_bound(
          pdf->pdfObjects.begin(), pdf->pdfObjects.end(), obj, [](const PDFObject& a, const PDFObject& b) { return a.startBuffer < b.startBuffer; });

    pdf->pdfObjects.insert(it, obj);
}

bool PDFFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    this->currentPath = path;
    this->currentChildNodes.clear();
    this->currentItemIndex = 0;

    if (path.empty()) {
        this->currentChildNodes.push_back(&this->objectNodeRoot);
        return true;
    }

    Reference<GView::Type::PDF::PDFFile> pdfRef = this;
    const auto node                             = FindNodeByPath(pdfRef, path);
    if (!node) {
        return false;
    }
    for (auto& child : node->children) {
        this->currentChildNodes.push_back(&child);
    }
    return !this->currentChildNodes.empty();
}

bool PDFFile::PopulateItem(TreeViewItem item)
{
    if (currentItemIndex >= currentChildNodes.size()) {
        return false;
    }

    auto* childNode = currentChildNodes[currentItemIndex++];
    LocalString<128> tmp;
    NumericFormatter n;
    const static NumericFormat NUMERIC_FORMAT{ NumericFormatFlags::HexPrefix, 16 };

    if (childNode->pdfObject.type == PDF::SectionPDFObjectType::Trailer) {
        item.SetText(u"Trailer");
    } else if (childNode->pdfObject.type == PDF::SectionPDFObjectType::CrossRefStream) {
        std::u16string tmpName = u"CrossRefStream ";
        tmpName += to_u16string((uint32_t) childNode->pdfObject.number);
        item.SetText(tmpName);
    } else if (childNode->pdfObject.type == PDF::SectionPDFObjectType::Stream) {
        std::u16string tmpName = u"Stream ";
        tmpName += to_u16string((uint32_t) childNode->pdfObject.number);
        item.SetText(tmpName);
    } else {
        std::u16string tmpName = u"Object ";
        tmpName += PDF::PDFFile::to_u16string((uint32_t) childNode->pdfObject.number);
        item.SetText(tmpName);
    }

    const char16_t* typeName = u"Unknown";
    switch (childNode->pdfObject.type) {
    case PDF::SectionPDFObjectType::Trailer:
        typeName = u"Trailer";
        break;
    case PDF::SectionPDFObjectType::CrossRefStream:
        typeName = u"CrossRefStream";
        break;
    case PDF::SectionPDFObjectType::Stream:
        typeName = u"Stream";
        break;
    case PDF::SectionPDFObjectType::Object:
        typeName = u"Object";
        break;
    }

    item.SetText(1, typeName);
    item.SetText(2, tmp.Format("%s", n.ToString(childNode->pdfObject.startBuffer, NUMERIC_FORMAT).data()));
    const auto size = childNode->pdfObject.endBuffer - childNode->pdfObject.startBuffer;
    item.SetText(3, tmp.Format("%s", n.ToString(size, NUMERIC_FORMAT).data()));

    LocalUnicodeStringBuilder<512> ub;
    bool first = true;
    for (const auto& filter : childNode->decodeObj.filters) {
        if (!first) {
            ub.Add(u", ");
        }
        ub.Add(filter);
        first = false;
    }
    item.SetText(4, ub);

    ub.Clear();
    first = true;
    for (const auto& type : childNode->pdfObject.dictionaryTypes) {
        if (!first) {
            ub.Add(u", ");
        }
        ub.Add(type);
        first = false;
    }
    item.SetText(5, ub);

    ub.Clear();
    first = true;
    for (const auto& subtype : childNode->pdfObject.dictionarySubtypes) {
        if (!first) {
            ub.Add(u", ");
        }
        ub.Add(subtype);
        first = false;
    }
    item.SetText(6, ub);
    if (childNode->pdfObject.hasJS == false) {
        item.SetText(7, "No");
    } else {
        item.SetText(7, "Yes");
    }

    item.SetExpandable(!childNode->children.empty());

    item.SetData(static_cast<uint64_t>(childNode->pdfObject.number));

    return (currentItemIndex < currentChildNodes.size());
}

static bool IsValidJSON(const std::string& data)
{
    try {
        const auto json = nlohmann::json::parse(data);
        return true;
    } catch (...) {
        return false;
    }
}

static bool IsValidJavaScript(const std::string& data)
{
    const std::regex jsPattern(R"(\b(function|var|let|const|=>|console\.log|document\.)\b)");
    return std::regex_search(data, jsPattern);
}

void PDFFile::DecodeStream(ObjectNode* node, Buffer& buffer, const size_t size)
{
    // decompress the stream
    // /DCTDecode -> LoadJPGToImage from JPG
    if (!node->decodeObj.filters.empty()) {
        for (const auto& filter : node->decodeObj.filters) {
            if (filter == PDF::FILTER::FLATE) {
                Buffer decompressedData;
                uint64 decompressDataSize = size;
                String message;
                if (GView::Decoding::ZLIB::DecompressStream(buffer, decompressedData, message, decompressDataSize)) {
                    if (node->decodeObj.decodeParams.predictor != 1) {
                        ApplyPNGFilter(
                              decompressedData,
                              node->decodeObj.decodeParams.column,
                              node->decodeObj.decodeParams.predictor,
                              node->decodeObj.decodeParams.bitsPerComponent);
                        decompressDataSize = decompressedData.GetLength();
                    }
                    buffer = decompressedData;
                } else {
                    Dialogs::MessageBox::ShowError("Error!", message);
                }
            } else if (filter == PDF::FILTER::RUNLENGTH) {
                Buffer runLengthDecompressed;
                String message;
                if (RunLengthDecode(buffer, runLengthDecompressed, message)) {
                    buffer = runLengthDecompressed;
                } else {
                    Dialogs::MessageBox::ShowError("Error!", message);
                }
            } else if (filter == PDF::FILTER::ASCIIHEX) {
                String message;
                Buffer asciiHexDecompressed;
                if (ASCIIHexDecode(buffer, asciiHexDecompressed, message)) {
                    buffer = asciiHexDecompressed;
                } else {
                    Dialogs::MessageBox::ShowError("Error!", message);
                }
            } else if (filter == PDF::FILTER::ASCII85) {
                String message;
                Buffer ascii85Decompressed;
                if (ASCII85Decode(buffer, ascii85Decompressed, message)) {
                    buffer = ascii85Decompressed;
                } else {
                    Dialogs::MessageBox::ShowError("Error!", message);
                }
            } else if (filter == PDF::FILTER::JPX) {
                // this one has to be a separate plugin for JPEG2000
                // for the moment being you can only see the decompressed data
                Buffer jpxDecompressed;
                uint32_t width = 0, height = 0;
                uint8_t components = 0;
                String message;
                if (JPXDecode(buffer, jpxDecompressed, width, height, components, message)) {
                    buffer = jpxDecompressed;
                } else {
                    Dialogs::MessageBox::ShowError("Error!", message);
                }
            } else if (filter == PDF::FILTER::LZW) {
                Buffer lzwDecompressed;
                String message;
                if (LZWDecodeStream(buffer, lzwDecompressed, node->decodeObj.decodeParams.earlyChange, message)) {
                    if (node->decodeObj.decodeParams.predictor != 1) {
                        ApplyPNGFilter(
                              lzwDecompressed,
                              node->decodeObj.decodeParams.column,
                              node->decodeObj.decodeParams.predictor,
                              node->decodeObj.decodeParams.bitsPerComponent);
                    }
                    buffer = std::move(lzwDecompressed);
                } else {
                    Dialogs::MessageBox::ShowError("Error!", message);
                }
            } else if (filter == PDF::FILTER::JBIG2) {
                Buffer jbig2Decompressed;
                String message;
                if (JBIG2Decode(buffer, jbig2Decompressed, message)) {
                    buffer = std::move(jbig2Decompressed);
                } else {
                    Dialogs::MessageBox::ShowError("Error!", message);
                }
            }
        }
    }
}

void PDFFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    const auto objectNumber = static_cast<uint32_t>(item.GetData(-1));
    if (objectNumber == static_cast<uint32_t>(-1)) {
        return;
    }

    const auto node = FindNodeByObjectNumber(objectNumber);
    if (!node) {
        return;
    }

    const auto entireFile = this->obj->GetData().GetEntireFile();
    if (!entireFile.IsValid()) {
        return;
    }

    if (node->pdfObject.hasStream) {
        const uint64 offset = node->decodeObj.streamOffsetStart;
        const uint64 end    = node->decodeObj.streamOffsetEnd;
        if (end <= offset || end > entireFile.GetLength()) {
            return;
        }

        const size_t size = static_cast<size_t>(end - offset);

        Buffer buffer;
        buffer.Resize(size);
        memcpy(buffer.GetData(), entireFile.GetData() + offset, size);

        std::u16string tmpName = u"Stream ";
        tmpName += to_u16string((uint32_t) node->pdfObject.number);
        LocalUnicodeStringBuilder<64> streamName;
        CHECKRET(streamName.Set(tmpName), "")

        // encrypted -> can't open the stream, for now
        if (pdfStats.isEncrypted) {
            Dialogs::MessageBox::ShowWarning("Warning!", "Unable to decompress the stream because the PDF is encrypted! Raw data will be displayed instead.");
            GView::App::OpenBuffer(buffer, streamName.ToStringView(), streamName.ToStringView(), GView::App::OpenMethod::BestMatch);
            return;
        }
        // Decode the content of the stream based on the filters
        DecodeStream(node, buffer, size);

        // json
        std::string newData(buffer.GetData(), buffer.GetData() + buffer.GetLength());
        if (IsValidJSON(newData)) {
            GView::App::OpenBuffer(buffer, streamName.ToStringView(), streamName.ToStringView(), GView::App::OpenMethod::ForceType, "json");
            return;
        }
        // js
        if (IsValidJavaScript(newData)) {
            GView::App::OpenBuffer(buffer, streamName.ToStringView(), streamName.ToStringView(), GView::App::OpenMethod::ForceType, "js");
            return;
        }

        GView::App::OpenBuffer(buffer, streamName.ToStringView(), streamName.ToStringView(), GView::App::OpenMethod::BestMatch);
    }
}

std::string PDFFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    json context;
    context["Name"]        = obj->GetName();
    context["ContentSize"] = obj->GetData().GetSize();
    return context.dump();
}
