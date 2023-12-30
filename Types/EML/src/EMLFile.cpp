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
    syntax.tokens.Add(1, start, end, TokenColor::String, TokenAlignament::StartsOnNewLine);
}


void EMLFile::ParseHeaders(GView::View::LexicalViewer::TextParser text, uint32& index)
{
    uint32 start = index, end = index;

    while (start < text.Len())
    {
        if (text.GetSubString(start, start + 2) == u"\r\n") // end of headers
        {
            start += 2; // skip the bytes
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

        // remove \r\n
        size_t pos = 0;
        while ((pos = fieldBody.find(u"\r\n", pos)) != std::string::npos)
            fieldBody.replace(pos, 2, u"");

        // the field index is there to preserve the order of insertion
        headerFields.push_back({ fieldName, fieldBody });

        start = end + 2;
    }

    index = start;
}

void EMLFile::ParseParts(GView::View::LexicalViewer::SyntaxManager& syntax, uint32& index, string_view boundary)
{
    uint32 start = index, end;

    start = syntax.text.ParseUntillText(start, boundary, false);
    end   = start + boundary.size();

    // boundary
    syntax.tokens.Add(1, start, end, TokenColor::Comment, TokenAlignament::StartsOnNewLine);
    start = end;

    while (start < syntax.text.Len())
    {
        end = syntax.text.ParseUntillText(start, boundary, false);

        if (end == syntax.text.Len())
            break;

        // content
        HandlePart(syntax, start, end);

        start = syntax.text.ParseUntillText(start, boundary, false);
        end   = start + boundary.size();

        // boundary
        syntax.tokens.Add(1, start, end, TokenColor::Comment, TokenAlignament::StartsOnNewLine);

        start = end;
    }

    index = start;
}

void EMLFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    uint32 index = 0;
    
    ParseHeaders(syntax.text, index);

    const auto& it = std::find_if(headerFields.begin(), headerFields.end(), 
        [](const auto& item) { return item.first == u"Content-Type"; });
    CHECKRET(it != headerFields.end(), "");

    TextParser contentTypeParser(it->second);

    uint32 typeEnd = contentTypeParser.ParseUntillText(0, "/", false);
    CHECKRET(typeEnd != contentTypeParser.Len(), "");

    u16string_view type = contentTypeParser.GetSubString(0, typeEnd);
    
    if (type == u"multipart")
    {
        // get the boundary for the parts
        std::string boundary;
    
        // TODO: ar merge un tree view pentru eml-urile care au mai multe multiparts 
        // imbricate (fiecare element din treeview sa fie deschis de un alt plugin)
        
        uint32 boundaryStart = contentTypeParser.ParseUntilNextCharacterAfterText(typeEnd, "boundary=", true);
        CHECKRET(boundaryStart != contentTypeParser.Len(), "");

        uint32 boundaryEnd;

        if (contentTypeParser[boundaryStart] == '"')
        {
            // the boundary is enclosed in quotes
            boundaryStart++;
            // TODO: remove workaround after I get a solution for the ParseUntillText bug
            boundaryEnd = contentTypeParser.Parse(boundaryStart, [](char16 ch) { return ch != '"'; });
            // boundaryEnd = contentTypeParser.ParseUntillText(boundaryStart, "\"", false);
        }
        else
        {
            boundaryEnd = contentTypeParser.Parse(boundaryStart, [](char16 ch) { return ch != ';'; });
            // boundaryEnd = contentTypeParser.ParseUntillText(boundaryStart, ";", false);
        }

        boundary = "--";
        for (char16_t ch : contentTypeParser.GetSubString(boundaryStart, boundaryEnd))
            boundary.push_back(ch);

        ParseParts(syntax, index, boundary);
    }
    else
    {
        // simple type (text|application|...)
        HandlePart(syntax, index, syntax.text.Len());
    }
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
