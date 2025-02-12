#include "pdf.hpp"
#include <nlohmann/json.hpp>
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
    auto node                                   = FindNodeByPath(pdfRef, path);
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
    for (auto& filter : childNode->metadata.filters) {
        if (!first) {
            ub.Add(u", ");
        }
        ub.Add(filter);
        first = false;
    }
    item.SetText(4, ub);

    item.SetExpandable(!childNode->children.empty());

    item.SetData(static_cast<uint64_t>(childNode->pdfObject.number));

    return (currentItemIndex < currentChildNodes.size());
}


void PDFFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    const auto objectNumber = static_cast<uint32_t>(item.GetData(-1));
    if (objectNumber == static_cast<uint32_t>(-1)) {
        return;
    }

    auto node = FindNodeByObjectNumber(objectNumber);
    if (!node) {
        return;
    }

    auto entireFile = this->obj->GetData().GetEntireFile();
    if (!entireFile.IsValid()) {
        return;
    }

    if (node->hasStream) {
        const uint64 offset = node->metadata.streamOffsetStart;
        const uint64 end    = node->metadata.streamOffsetEnd;
        if (end <= offset || end > entireFile.GetLength()) {
            return;
        }

        const size_t size = static_cast<size_t>(end - offset);

        Buffer buffer;
        buffer.Resize(size);
        memcpy(buffer.GetData(), entireFile.GetData() + offset, size);

        // decompress the stream
        if (!node->metadata.filters.empty()) {
            for (auto& filter : node->metadata.filters) {
                if (filter == PDF::FILTER::FLATE) {
                    Buffer decompressedData;
                    uint64 decompressDataSize = size;
                    AppCUI::Utils::String message;
                    if (GView::Decoding::ZLIB::DecompressStream(buffer, decompressedData, message, decompressDataSize)) {
                        buffer = decompressedData;
                    } else {
                        Dialogs::MessageBox::ShowError("Error!", message);
                    }
                }
            }
        }
        std::u16string tmpName = u"Stream ";
        tmpName += to_u16string((uint32_t) node->pdfObject.number);
        LocalUnicodeStringBuilder<64> streamName;
        CHECKRET(streamName.Set(tmpName), "")

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
