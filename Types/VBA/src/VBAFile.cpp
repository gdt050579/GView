#include "vba.hpp"

namespace GView::Type::VBA
{
using namespace GView::View::LexicalViewer;

VBAFile::VBAFile()
{
}

void VBAFile::PreprocessText(GView::View::LexicalViewer::TextEditor&)
{
    // nothing to do --> there is no pre-processing needed for a VBA format
}

void VBAFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
    CHECKRET(str.SetFormat("Unknown: 0x%08X", id), "");
}


uint32 ParseUntilSpace(GView::View::LexicalViewer::TextParser text, uint32 index)
{
    return text.Parse(index, [](char16 c) { return !isspace(c); });
}

void VBAFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    uint32 start = 0;
    uint32 end   = 0;

    TokenAlignament presetAlignament = TokenAlignament::None;


    while (start < syntax.text.Len()) {

        auto c = syntax.text[start];

        if (c == ' ') {
            end = syntax.text.ParseSpace(end, SpaceType::Space);
            if ((uint32) presetAlignament & (uint32) TokenAlignament::StartsOnNewLine) {
                syntax.tokens.Add(1, start, end, TokenColor::Word, presetAlignament);
                presetAlignament = TokenAlignament::None;
            }
            start = end;
            continue;
        }

        if (isalpha(c)) {
            end = syntax.text.Parse(start, [](char16 c) { return (bool) isalnum(c) || c == '_'; });
            syntax.tokens.Add(1, start, end, TokenColor::Word, presetAlignament | TokenAlignament::AddSpaceAfter);
            start = syntax.text.ParseSpace(end, SpaceType::Space);
            presetAlignament = TokenAlignament::None;  // TODO: i hate this
            continue;
        }

        if (isdigit(c)) {
            end = syntax.text.Parse(start, [](char16 c) { return (bool) isdigit(c); });
            syntax.tokens.Add(1, start, end, TokenColor::Number, presetAlignament | TokenAlignament::AddSpaceAfter);
            start = end;
            continue;
        }

        // TODO: check for a range of operators
        // TODO: fix spacing for certain operators
        if (c == '=' || c == '(' || c == ')' || c == ',' || c == '.' || c == '_' || c == '&') {
            end = start + 1;
            syntax.tokens.Add(1, start, end, TokenColor::Operator, presetAlignament | TokenAlignament::AddSpaceAfter);
            start = syntax.text.ParseSpace(end, SpaceType::Space);
            presetAlignament = TokenAlignament::None; // TODO: i hate this
            continue;
        }

        // TODO: account for all types of strings if they are permitted in the language
        if (c == '"') {
            end = syntax.text.ParseString(start);
            syntax.tokens.Add(1, start, end, TokenColor::String, presetAlignament | TokenAlignament::AddSpaceAfter);
            start = syntax.text.ParseSpace(end, SpaceType::Space);
            continue;
        }

        if (c == '\r' || c == '\n') {
            end = syntax.text.ParseUntillStartOfNextLine(start);
            presetAlignament = TokenAlignament::StartsOnNewLine;
            start = end;
            continue;
        }

        if (c == '\'') {
            end = syntax.text.ParseUntillEndOfLine(start);
            syntax.tokens.Add(1, start, end, TokenColor::Comment, presetAlignament | TokenAlignament::NewLineAfter);
            start = syntax.text.ParseUntillStartOfNextLine(end);
            continue;
        }

        break;
    }

    //syntax.tokens.Add(1, 0, 5, TokenColor::Keyword);
    //syntax.tokens.Add(1, 5, 10, TokenColor::String, TokenAlignament::StartsOnNewLine);
}

bool VBAFile::StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result)
{
    return TextParser::ExtractContentFromString(string, result, StringFormat::All);
}

bool VBAFile::ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result)
{
    NOT_IMPLEMENTED(false);
}
} // namespace GView::Type::VBA
