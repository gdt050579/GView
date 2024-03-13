#include "eml.hpp"

namespace GView::Type::EML
{
using namespace GView::View::LexicalViewer;

EMLFile::EMLFile()
{
}

void EMLFile::PreprocessText(GView::View::LexicalViewer::TextEditor&)
{
    // no preprocessing
}

void EMLFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
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

void EMLFile::HandlePart(GView::View::LexicalViewer::SyntaxManager& syntax, uint32 start, uint32 end)
{
    Buffer buffer;
    buffer.Add(syntax.text.GetSubString(start, end));
    // TODO: change child to something else
    GView::App::OpenBuffer(buffer, obj->GetName(), "child", GView::App::OpenMethod::BestMatch);

    //syntax.tokens.Add(1, start, end, TokenColor::String, TokenAlignament::StartsOnNewLine);
}


void EMLFile::ParseHeaders(GView::View::LexicalViewer::TextParser text, uint32& index, std::vector<std::pair<std::u16string, std::u16string>>& headersContainer)
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
        headersContainer.push_back({ fieldName, fieldBody });

        start = end + 2;
    }

    index = start;
}


void EMLFile::ParsePart(GView::View::LexicalViewer::SyntaxManager& syntax, uint32 start, uint32 end)
{
    std::vector<std::pair<std::u16string, std::u16string>> headers;

    ParseHeaders(syntax.text, start, headers);

    const auto& contentTypeHeader = std::find_if(headers.begin(), headers.end(), [](const auto& item) { return item.first == u"Content-Type"; });
    CHECKRET(contentTypeHeader != headers.end(), "");

    TextParser contentTypeParser(contentTypeHeader->second);

    uint32 typeEnd = contentTypeParser.ParseUntillText(0, "/", false);
    CHECKRET(typeEnd != contentTypeParser.Len(), "");

    u16string_view type = contentTypeParser.GetSubString(0, typeEnd);

    // TODO: handle message/rfc822

    if (type != u"multipart") {
        // base case
        // simple type (text|application|...)

        // TODO: remove later
        {
            const auto& encodingHeader =
                  std::find_if(headers.begin(), headers.end(), [](const auto& item) { return item.first == u"Content-Transfer-Encoding"; });
            
            if (encodingHeader != headers.end() && encodingHeader->second == u"base64")
            {
                const auto& view = syntax.text.GetSubString(start, end);
                BufferView bufferView(view.data(), view.size() * 2);
                Buffer output;

                //if (Base64Decode(bufferView, output))
                //{
                //    // TODO: change child to something else
                //    GView::App::OpenBuffer(output, obj->GetName(), "child", GView::App::OpenMethod::BestMatch);
                //}
                //else
                //{
                //    AppCUI::Dialogs::MessageBox::ShowError("Error!", "Malformed base64 buffer!");
                //}
            }
            else
            {
                HandlePart(syntax, start, end);
            }
        }

        return;
    }

    // TODO: ar merge un tree view pentru eml-urile care au mai multe multiparts
    // imbricate (fiecare element din treeview sa fie deschis de un alt plugin)

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
        partStart = syntax.text.ParseUntilNextCharacterAfterText(partStart, boundary, false);
        partStart = syntax.text.ParseSpace(partStart, SpaceType::All);

        if (syntax.text.ParseUntillText(partStart, "--", false) == partStart)
        {
            // end of part
            break;
        }
        
        partEnd   = syntax.text.ParseUntillText(partStart, boundary, false);
        ParsePart(syntax, partStart, partEnd);

        partStart = partEnd;
    } while (partEnd < end);
}

void EMLFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    ParsePart(syntax, 0, syntax.text.Len());
}

bool EMLFile::StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result)
{
    return TextParser::ExtractContentFromString(string, result, StringFormat::All);
}

bool EMLFile::ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result)
{
    NOT_IMPLEMENTED(false);
}
} // namespace GView::Type::EML
