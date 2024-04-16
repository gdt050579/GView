#include "eml.hpp"

namespace GView::Type::EML
{
using namespace GView::View::LexicalViewer;

EMLFile::EMLFile()
{
}

bool EMLFile::ProcessData()
{
    unicodeString.Set(obj->GetData().GetEntireFile());
    TextParser text(unicodeString.ToStringView());

    itemsIndex = 0;
    items.clear();

    ParsePart(text, 0, text.Len());
    if (items.empty())
        return false;

    uint32 modeNr = 1, attachmentsNr = 1;
    for (auto& itemData : items) {
        itemData.contentType = itemData.leafNode ? contentType : ExtractContentType(text, itemData.startIndex, itemData.startIndex + itemData.dataLength);
        itemData.identifier  = GetIdentifierFromContentType(itemData.contentType);
        if (!itemData.identifier.empty())
            continue;
        if (itemData.contentType.starts_with(u"multipart")) {
            itemData.identifier = u"body message";
        } else if (itemData.contentType.starts_with(u"application")) {
            LocalString<32> attachment = {};
            attachment.SetFormat("attachment %u", attachmentsNr);
            LocalUnicodeStringBuilder<32> sb = {};
            sb.Set(attachment.GetText());
            itemData.identifier = sb.ToStringView();
            attachmentsNr++;
        } else {
            LocalString<32> mode = {};
            mode.SetFormat("mode %u", modeNr);
            LocalUnicodeStringBuilder<32> sb = {};
            sb.Set(mode.GetText());
            itemData.identifier = sb.ToStringView();
            modeNr++;
        }
    }

    return true;
}

std::u16string EMLFile::ExtractContentType(TextParser text, uint32 start, uint32 end)
{
    start = text.ParseUntillText(start, "content-type", true);

    if (start >= text.Len()) {
        return u"";
    }

    // TODO: make a function that extracts both the header and the field body
    start = text.ParseUntillText(start, ":", false);
    start = text.ParseSpace(start + 1, SpaceType::All);
    end   = ParseHeaderFieldBody(text, start);

    std::u16string fieldBody(text.GetSubString(start, end));

    size_t pos = 0;
    while ((pos = fieldBody.find(u"\r\n", pos)) != std::u16string::npos)
        fieldBody.replace(pos, 2, u"");

    return fieldBody.substr(0, fieldBody.find(u';'));
}

bool EMLFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    itemsIndex = 0;
    return true;
}

bool EMLFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    EML_Item_Record& itemData = items[itemsIndex];
    TextParser text(unicodeString.ToStringView());

    std::u16string contentTypeNode = itemData.leafNode ? contentType : ExtractContentType(text, itemData.startIndex, itemData.startIndex + itemData.dataLength);

    item.SetText(0, itemData.identifier);
    item.SetText(1, itemData.contentType);
    item.SetText(2, String().Format("%u", itemData.dataLength));
    item.SetText(3, String().Format("%u", itemData.startIndex + itemData.parentStartIndex));

    item.SetData<EML_Item_Record>(&itemData);

    itemsIndex++;
    return itemsIndex < items.size();
}

void EMLFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    auto itemData = item.GetData<EML_Item_Record>();

    TextParser text(unicodeString.ToStringView());
    auto currentContentType = ExtractContentType(text, itemData->startIndex, itemData->startIndex + itemData->dataLength);

    auto bufferView = obj->GetData().GetEntireFile();
    BufferView itemBufferView(bufferView.GetData() + itemData->startIndex, itemData->dataLength);

    if (!itemData->leafNode) {
        auto bufferName = GetGViewFileName(currentContentType, itemData->identifier);
        GView::App::OpenBuffer(itemBufferView, bufferName, path, GView::App::OpenMethod::ForceType, "eml");
    } else {
        const auto& encodingHeader =
              std::find_if(headerFields.begin(), headerFields.end(), [](const auto& item) { return item.first == u"Content-Transfer-Encoding"; });

        if (encodingHeader != headerFields.end() && encodingHeader->second == u"base64") {
            Buffer output;
            if (GView::Unpack::Base64::Decode(itemBufferView, output)) {
                const auto headerValueName = GetBufferNameFromHeaderFields();
                const auto bufferName      = GetGViewFileName(headerValueName, itemData->identifier);
                GView::App::OpenBuffer(output, bufferName, path, GView::App::OpenMethod::BestMatch);
            } else {
                AppCUI::Dialogs::MessageBox::ShowError("Error!", "Malformed base64 buffer!");
            }

        } else {
            const auto headerValueName = GetBufferNameFromHeaderFields();
            const auto bufferName      = GetGViewFileName(headerValueName, itemData->identifier);
            GView::App::OpenBuffer(itemBufferView, bufferName, path, GView::App::OpenMethod::BestMatch);
        }
    }
}

uint32 EMLFile::ParseHeaderFieldBody(TextParser text, uint32 start)
{
    uint32 end = text.ParseUntillText(start, "\r\n", false);

    while (end + 2 < text.Len()) {
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

    while (start < text.Len()) {
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

        if (fieldName == u"Content-Type") {
            contentType = fieldBody;
        }

        // the field index is there to preserve the order of insertion
        headerFields.push_back({ fieldName, fieldBody });

        start = end + 2;
    }

    index = start;
}

std::optional<std::u16string> EMLFile::TryGetNameQuotes(std::u16string& contentTypeToSearch, bool removeIfFound)
{
    auto name_it = contentTypeToSearch.find(u"name=");
    if (name_it == std::u16string::npos)
        return { std::nullopt };
    if (name_it + 5 /*strlen("name=")*/ + 2 /* 2* '"' */ >= contentTypeToSearch.size())
        return {};
    name_it += 5; // strlen("name=")
    const auto actual_name = contentTypeToSearch.substr(name_it + 1, contentTypeToSearch.size() - name_it - 2);
    auto name_string       = std::u16string(actual_name);
    if (removeIfFound) {
        contentTypeToSearch.erase(name_it - 5, 5 + 2 + actual_name.size()); // strlen("name="
        if (contentTypeToSearch[contentTypeToSearch.size() - 1] == u' ')
            contentTypeToSearch.erase(contentTypeToSearch.size() - 1, 1);
        if (contentTypeToSearch[contentTypeToSearch.size() - 1] == u';')
            contentTypeToSearch.erase(contentTypeToSearch.size() - 1, 1);
    }
    return name_string;
}

std::u16string EMLFile::GetIdentifierFromContentType(std::u16string& contentTypeToChange)
{
    auto name_value = TryGetNameQuotes(contentTypeToChange, true);
    if (name_value.has_value())
        return name_value.value();

    return u"";
}

std::u16string EMLFile::GetBufferNameFromHeaderFields()
{
    for (auto& header : headerFields) {
        auto name_value = TryGetNameQuotes(header.second);
        if (name_value.has_value())
            return name_value.value();
    }

    return std::u16string(obj->GetName());
}

std::u16string EMLFile::GetGViewFileName(const std::u16string& value, const std::u16string& prefix)
{
    LocalUnicodeStringBuilder<64> sb = {};
    if (!prefix.empty()) {
        sb.Add(prefix);
        sb.AddChar(':');
        sb.AddChar(' ');
    }
    sb.Add(value);
    std::u16string output;
    sb.ToString(output);
    return output;
}

void EMLFile::ParsePart(GView::View::LexicalViewer::TextParser text, uint32 start, uint32 end)
{
    ParseHeaders(text, start);

    TextParser contentTypeParser(contentType);

    uint32 typeEnd = contentTypeParser.ParseUntillText(0, "/", false);
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
            boundaryEnd = contentTypeParser.ParseUntillText(boundaryStart, "\"", false);
        } else {
            boundaryEnd = contentTypeParser.ParseUntillText(boundaryStart, ";", false);
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

            if (text.ParseUntillText(partStart, "--", false) == partStart) {
                // end of part
                break;
            }

            partEnd = text.ParseUntillText(partStart, boundary, false);

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
