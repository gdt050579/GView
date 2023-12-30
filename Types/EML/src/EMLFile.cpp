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

void EMLFile::ParseHeaders(GView::View::LexicalViewer::TextParser text, uint32& index)
{
    uint32 start = index, end = index;

    while (start < text.Len())
    {
        if (text.GetSubString(start, start + 2) == u"\r\n") // end of headers
            break;
        
        // key
        end = text.ParseUntillText(start, ":", false);

        std::u16string key(text.GetSubString(start, end));

        // ltrim
        start = end = text.ParseSpace(end + 1, SpaceType::All);

        // value
        end = ParseHeaderFieldBody(text, start);

        std::u16string value(text.GetSubString(start, end));

        size_t pos = 0;
        while ((pos = value.find(u"\r\n", pos)) != std::string::npos)
            value.replace(pos, 2, u"");

        headerFields.insert({ key, value });

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
        syntax.tokens.Add(1, start, end, TokenColor::String, TokenAlignament::StartsOnNewLine);

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

    auto it = headerFields.find(u"Content-Type");
    if (it == headerFields.end())
        return;

    TextParser boundaryParser(it->second);

    std::string boundary;
    // get the boundary for the parts
    {
        // TODO: check if not multipart (could only be text/plain)
        
        uint32 boundaryStart = boundaryParser.ParseUntilNextCharacterAfterText(0, "boundary=", true);
        CHECKRET(boundaryStart < boundaryParser.Len(), "");

        uint32 boundaryEnd;

        if (boundaryParser[boundaryStart] == '"')
        {
            // the boundary is enclosed in quotes
            boundaryStart++;
            // TODO: remove workaround after I get a solution for the ParseUntillText bug
            boundaryEnd = boundaryParser.Parse(boundaryStart, [](char16 ch) { return ch != '"'; });
            //boundaryEnd = boundaryParser.ParseUntillText(boundaryStart, "\"", false);
        }
        else
        {
            boundaryEnd = boundaryParser.Parse(boundaryStart, [](char16 ch) { return ch != ';'; });
            //boundaryEnd = boundaryParser.ParseUntillText(boundaryStart, ";", false);
        }

        boundary = "--";
        for (char16_t ch : boundaryParser.GetSubString(boundaryStart, boundaryEnd))
            boundary.push_back(ch);
    }

    ParseParts(syntax, index, boundary);
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
