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


uint32 ParseString(GView::View::LexicalViewer::TextParser text, uint32 index)
{
    uint32 end = text.Parse(index + 1, [](char16 c) { return c != '"'; });
    return end + 1;
}

UnicodeStringBuilder KEYWORDS[] = { UnicodeStringBuilder("Attribute"), UnicodeStringBuilder("Sub"), UnicodeStringBuilder("Private"), UnicodeStringBuilder("As"),        UnicodeStringBuilder("Dim"),  UnicodeStringBuilder("End"),
                                    UnicodeStringBuilder("ByVal"),     UnicodeStringBuilder("Set"), UnicodeStringBuilder("While"),
                                    UnicodeStringBuilder("Wend"),      UnicodeStringBuilder("If"),  UnicodeStringBuilder("Then") };

UnicodeStringBuilder KEYWORDS2[] = { UnicodeStringBuilder("True"), UnicodeStringBuilder("False") };

const char operators[] = "=(),._&$+-*/<>#";

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

        bool parseSpace = false;
        if (isalpha(c)) {
            end = syntax.text.Parse(start, [](char16 c) { return (bool) isalnum(c) || c == '_'; });

            TokenColor color = TokenColor::Word;
            for (auto keyword : KEYWORDS) {
                if (syntax.text.GetSubString(start, end) == keyword) {
                    color = TokenColor::Keyword;
                    break;
                }
            }

            for (auto keyword : KEYWORDS2) {
                if (syntax.text.GetSubString(start, end) == keyword) {
                    color = TokenColor::Keyword2;
                    break;
                }
            }

            syntax.tokens.Add(1, start, end, color, presetAlignament);
            parseSpace = true;
        }

        if (isdigit(c)) {
            end = syntax.text.Parse(start, [](char16 c) { return (bool) isdigit(c); });
            syntax.tokens.Add(1, start, end, TokenColor::Number, presetAlignament);
            parseSpace = true;
        }

        for (char op : operators) {
            if (c == op) {
                end = start + 1;
                syntax.tokens.Add(1, start, end, TokenColor::Operator, presetAlignament);
                parseSpace = true;
                break;
            }
        }

        if (c == '"') {
            end = ParseString(syntax.text, start);
            syntax.tokens.Add(1, start, end, TokenColor::String, presetAlignament);
            parseSpace = true;
        }

        if (parseSpace) {
            start = syntax.text.ParseSpace(end, SpaceType::Space);

            if (start > end) {
                presetAlignament = TokenAlignament::AddSpaceBefore;
            } else {
                presetAlignament = TokenAlignament::None;
            }
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
