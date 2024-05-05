#include "eml.hpp"

namespace GView::Type::EML
{
using namespace GView::View::LexicalViewer;

EMLFile::EMLFile()
{
}

void EMLFile::ExtractFieldNameAndBody(TextParser text, uint32& start, uint32& end, std::u16string& fieldName, std::u16string& fieldBody)
{
    // header-field name
    end = text.ParseUntilText(start, ":", false);

    fieldName = text.GetSubString(start, end);

    // ltrim
    start = end = text.ParseSpace(end + 1, SpaceType::SpaceAndTabs);

    // header-field body
    end = ParseHeaderFieldBody(text, start);

    fieldBody = text.GetSubString(start, end);

    // remove CRLF
    size_t pos = 0;
    while ((pos = fieldBody.find(u"\r\n", pos)) != std::u16string::npos)
        fieldBody.replace(pos, 2, u"");
}

std::u16string EMLFile::ExtractContentType(TextParser text, uint32 start, uint32 end)
{
    start = text.ParseUntilText(start, "content-type", true);

    if (start >= text.Len()) {
        return u"";
    }

    std::u16string fieldName, fieldBody;
    ExtractFieldNameAndBody(text, start, end, fieldName, fieldBody);

    return fieldBody.substr(0, fieldBody.find(u';'));
}

bool EMLFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    auto temp = parent.GetData<EML_Item_Record>();

    unicodeString.Add(obj->GetData().GetEntireFile());
    TextParser text(unicodeString.ToStringView());

    itemsIndex = 0;
    items.clear();

    ParsePart(text, 0, text.Len());

    return items.size() > 0;
}

bool EMLFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    EML_Item_Record& itemData = items[itemsIndex];
    TextParser text(unicodeString.ToStringView());

    if (itemData.leafNode) {
        item.SetText(0, contentType);
    } else {
        item.SetText(0, ExtractContentType(text, itemData.startIndex, itemData.startIndex + itemData.dataLength));
    }

    item.SetText(1, String().Format("%u", itemData.dataLength));
    item.SetText(2, String().Format("%u", itemData.startIndex + itemData.parentStartIndex));

    item.SetData<EML_Item_Record>(&itemData);

    itemsIndex++;
    return itemsIndex < items.size();
}

void EMLFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    auto itemData = item.GetData<EML_Item_Record>();

    auto bufferView = obj->GetData().GetEntireFile();
    BufferView itemBufferView(bufferView.GetData() + itemData->startIndex, itemData->dataLength);

    if (!itemData->leafNode) {
        GView::App::OpenBuffer(itemBufferView, obj->GetName(), path, GView::App::OpenMethod::ForceType, "eml");
    } else {
        const auto& encodingHeader =
              std::find_if(headerFields.begin(), headerFields.end(), [](const auto& item) { return item.first == u"Content-Transfer-Encoding"; });

        if (encodingHeader != headerFields.end() && encodingHeader->second == u"base64") {
            Buffer output;

            bool hasWarning;
            String warningMessage;
            if (GView::Unpack::Base64::Decode(itemBufferView, output, hasWarning, warningMessage)) {
                if (hasWarning) {
                    AppCUI::Dialogs::MessageBox::ShowError("Warning!", warningMessage);
                }
                GView::App::OpenBuffer(output, obj->GetName(), path, GView::App::OpenMethod::BestMatch);
            } else {
                AppCUI::Dialogs::MessageBox::ShowError("Error!", "Malformed base64 buffer!");
            }

        } else {
            GView::App::OpenBuffer(itemBufferView, obj->GetName(), path, GView::App::OpenMethod::BestMatch);
        }
    }
}

uint32 EMLFile::ParseHeaderFieldBody(TextParser text, uint32 start)
{
    uint32 end = text.ParseUntilText(start, "\r\n", false);

    while (end + 2 < text.Len()) {
        auto ch = text[end + 2];
        if (ch != ' ' && ch != '\t')
            break;

        end = text.ParseUntilText(end + 2, "\r\n", false);
    }

    return end;
}

void EMLFile::ParseHeaders(GView::View::LexicalViewer::TextParser text, uint32& index)
{
    uint32 start = index, end = index;

    while (start < text.Len()) {
        if (text.GetSubString(start, start + 2) == u"\r\n") // end of headers
        {
            start += 2; // skip CRLF
            break;
        }

        std::u16string fieldName, fieldBody;
        ExtractFieldNameAndBody(text, start, end, fieldName, fieldBody);
        
        if (fieldName == u"Content-Type") {
            contentType = fieldBody;
        }

        // the field index is there to preserve the order of insertion
        headerFields.push_back({ fieldName, fieldBody });

        start = end + 2;
    }

    index = start;
}

void EMLFile::ParsePart(GView::View::LexicalViewer::TextParser text, uint32 start, uint32 end)
{
    ParseHeaders(text, start);

    TextParser contentTypeParser(contentType);

    uint32 typeEnd = contentTypeParser.ParseUntilText(0, "/", false);
    CHECKRET(typeEnd != contentTypeParser.Len(), "");

    u16string_view type = contentTypeParser.GetSubString(0, typeEnd);

    if (type == u"multipart") {
        // get the boundary for the parts
        std::string boundary;

        uint32 boundaryStart = contentTypeParser.ParseUntilNextCharacterAfterText(typeEnd, "boundary=", true);
        CHECKRET(boundaryStart != contentTypeParser.Len(), "");

        uint32 boundaryEnd;

        if (contentTypeParser[boundaryStart] == '"') {
            // the boundary is enclosed in quotes
            boundaryStart++;
            boundaryEnd = contentTypeParser.ParseUntilText(boundaryStart, "\"", false);
        } else {
            boundaryEnd = contentTypeParser.ParseUntilText(boundaryStart, ";", false);
        }

        boundary = "--";
        for (char16 ch : contentTypeParser.GetSubString(boundaryStart, boundaryEnd))
            boundary.push_back((char) ch);

        // get the start and end for each subpart
        uint32 partStart = start;
        uint32 partEnd;

        do {
            partStart = text.ParseUntilNextCharacterAfterText(partStart, boundary, false);
            partStart = text.ParseSpace(partStart, SpaceType::All);

            if (text.ParseUntilText(partStart, "--", false) == partStart) {
                // end of part
                break;
            }

            partEnd = text.ParseUntilText(partStart, boundary, false);

            // TODO: get the parent's index
            items.emplace_back(EML_Item_Record{ .parentStartIndex = 0, .startIndex = partStart, .dataLength = partEnd - partStart, .leafNode = false });

            partStart = partEnd;
        } while (partEnd < end);

        return;
    }

    if (type == u"message") {
        items.emplace_back(EML_Item_Record{ .parentStartIndex = 0, .startIndex = start, .dataLength = end - start, .leafNode = false });
        return;
    }

    // base case
    // simple type (text|application|...)
    items.emplace_back(EML_Item_Record{ .parentStartIndex = 0, .startIndex = start, .dataLength = end - start, .leafNode = true });

    return;
}
} // namespace GView::Type::EML
