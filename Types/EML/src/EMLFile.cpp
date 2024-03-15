#include "eml.hpp"

namespace GView::Type::EML
{
using namespace GView::View::LexicalViewer;

EMLFile::EMLFile()
{
}

bool EMLFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    auto bufferView = obj->GetData().GetEntireFile();

    // TODO: maybe modify the TextParser to accept uint8 chars instead of converting
    Buffer buffer; buffer.Resize(bufferView.GetLength() * 2);
    for (uint32 index = 0; index < bufferView.GetLength(); ++index)
    {
        buffer[index * 2] = bufferView[index];
        buffer[index * 2 + 1] = 0;
    }

    TextParser text(u16string_view((char16_t*) buffer.GetData(), bufferView.GetLength()));

    itemsIndex = 0;
    items.clear();

    ParsePart(text, 0, text.Len());

    return items.size() > 0;
}

bool EMLFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    EML_Item_Record& itemData = items[itemsIndex];

    auto bufferView = obj->GetData().GetEntireFile();

    string_view itemName((char*) bufferView.GetData() + itemData.startIndex, 32);

    item.SetText(itemName);
    item.SetData<EML_Item_Record>(&itemData);

    itemsIndex++;
    return itemsIndex < items.size();
}

void EMLFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    auto data = item.GetData<EML_Item_Record>();

    auto bufferView = obj->GetData().GetEntireFile();

    BufferView itemBufferView(bufferView.GetData() + data->startIndex, data->dataLength);

    if (!data->leafNode)
    {
        GView::App::OpenBuffer(itemBufferView, obj->GetName(), "child", GView::App::OpenMethod::ForceType, "eml");
    }
    else
    {
        GView::App::OpenBuffer(itemBufferView, obj->GetName(), "child", GView::App::OpenMethod::BestMatch);
    }
}

uint32 EMLFile::ParseHeaderFieldBody(TextParser text, uint32 start)
{
    uint32 end = text.ParseUntillText(start, "\r\n", false);
    
    while (end + 2 < text.Len())
    {
        auto ch = text[end + 2];
        if (ch != ' ' && ch != '\t')
            break;

        end = text.ParseUntillText(end + 2, "\r\n", false);
    }

    return end;
}

void EMLFile::ParseHeaders(GView::View::LexicalViewer::TextParser text, uint32& index)
{
    uint32 start = index, end = index;

    while (start < text.Len())
    {
        if (text.GetSubString(start, start + 2) == u"\r\n") // end of headers
        {
            start += 2; // skip CRLF
            break;
        }

        // header-field name
        end = text.ParseUntillText(start, ":", false);

        std::u16string fieldName(text.GetSubString(start, end));

        // ltrim
        start = end = text.ParseSpace(end + 1, SpaceType::All);

        // header-field body
        end = ParseHeaderFieldBody(text, start);

        std::u16string fieldBody(text.GetSubString(start, end));

        // remove CRLF
        size_t pos = 0;
        while ((pos = fieldBody.find(u"\r\n", pos)) != std::u16string::npos)
            fieldBody.replace(pos, 2, u"");

        // the field index is there to preserve the order of insertion
        headerFields.push_back({ fieldName, fieldBody });

        start = end + 2;
    }

    index = start;
}

void EMLFile::ParsePart(GView::View::LexicalViewer::TextParser text, uint32 start, uint32 end)
{
    ParseHeaders(text, start);

    const auto& contentTypeHeader = std::find_if(headerFields.begin(), headerFields.end(), [](const auto& item) { return item.first == u"Content-Type"; });
    CHECKRET(contentTypeHeader != headerFields.end(), "");

    TextParser contentTypeParser(contentTypeHeader->second);

    uint32 typeEnd = contentTypeParser.ParseUntillText(0, "/", false);
    CHECKRET(typeEnd != contentTypeParser.Len(), "");

    u16string_view type = contentTypeParser.GetSubString(0, typeEnd);

    // TODO: handle message/rfc822

    if (type == u"multipart")
    {
        // get the boundary for the parts
        std::string boundary;

        uint32 boundaryStart = contentTypeParser.ParseUntilNextCharacterAfterText(typeEnd, "boundary=", true);
        CHECKRET(boundaryStart != contentTypeParser.Len(), "");

        uint32 boundaryEnd;

        if (contentTypeParser[boundaryStart] == '"')
        {
            // the boundary is enclosed in quotes
            boundaryStart++;
            boundaryEnd = contentTypeParser.ParseUntillText(boundaryStart, "\"", false);
        }
        else
        {
            boundaryEnd = contentTypeParser.ParseUntillText(boundaryStart, ";", false);
        }

        boundary = "--";
        for (char16 ch : contentTypeParser.GetSubString(boundaryStart, boundaryEnd))
            boundary.push_back((char) ch);

        // get the start and end for each subpart
        uint32 partStart = start;
        uint32 partEnd;

        do
        {
            partStart = text.ParseUntilNextCharacterAfterText(partStart, boundary, false);
            partStart = text.ParseSpace(partStart, SpaceType::All);

            if (text.ParseUntillText(partStart, "--", false) == partStart)
            {
                // end of part
                break;
            }

            partEnd = text.ParseUntillText(partStart, boundary, false);
            // ParsePart(syntax, partStart, partEnd);

            items.emplace_back(EML_Item_Record{ .startIndex = partStart, .dataLength = partEnd - partStart, .leafNode = false });

            partStart = partEnd;
        } while (partEnd < end);

        return;
    }

    if (type == u"message")
    {
        items.emplace_back(EML_Item_Record{ .startIndex = start, .dataLength = end - start, .leafNode = false });
        return;
    }


    // base case
    // simple type (text|application|...)

    // TODO: remove later
    {
        // const auto& encodingHeader =
        //       std::find_if(headerFields.begin(), headerFields.end(), [](const auto& item) { return item.first == u"Content-Transfer-Encoding"; });
        //
        // if (encodingHeader != headerFields.end() && encodingHeader->second == u"base64")
        //{
        //    const auto& view = text.GetSubString(start, end);
        //    BufferView bufferView(view.data(), view.size() * 2);
        //    Buffer output;

        //    if (Base64Decode(bufferView, output))
        //    {
        //        // TODO: change child to something else
        //        GView::App::OpenBuffer(output, obj->GetName(), "child", GView::App::OpenMethod::BestMatch);
        //    }
        //    else
        //    {
        //        AppCUI::Dialogs::MessageBox::ShowError("Error!", "Malformed base64 buffer!");
        //    }
        //}
        //else
        //{
        //    HandlePart(syntax, start, end);
        //}

        //HandlePart(syntax, start, end);
    }

    items.emplace_back(EML_Item_Record { .startIndex = start, .dataLength = end - start, .leafNode = true });

    return;
}
} // namespace GView::Type::EML
