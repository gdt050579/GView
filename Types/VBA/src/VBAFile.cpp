#include "vba.hpp"

namespace GView::Type::VBA
{
using namespace GView::View::LexicalViewer;

namespace CharacterType
{
    constexpr uint32 PossibleWordStart   = 0;
    constexpr uint32 PossibleNumberStart = 1;
    constexpr uint32 PossibleStringStart = 2;
    constexpr uint32 Space               = 3;
    constexpr uint32 NewLine             = 4;
    constexpr uint32 Other               = 1000;

    inline uint32 GetCharacterType(char16 ch)
    {
        if (ch >= 'a' && ch <= 'z')
            return PossibleWordStart;
        if (ch >= 'A' && ch <= 'Z')
            return PossibleWordStart;
        if (ch >= '0' && ch <= '9')
            return PossibleNumberStart;
        if (ch == ' ' || ch == '\t')
            return Space;
        if (ch == '\r' || ch == '\n')
            return NewLine;
        if (ch == '"')
            return PossibleStringStart;
        return Other;
    }

    inline bool IsAWordCharacter(char16 ch)
    {
        if (ch >= 'a' && ch <= 'z')
            return true;
        if (ch >= 'A' && ch <= 'Z')
            return true;
        if (ch >= '0' && ch <= '9')
            return true;
        if (ch == '_')
            return true;
        return false;
    }

} // namespace CharacterType

namespace TokenType
{
    constexpr uint32 Word     = 0;
    constexpr uint32 Number   = 1;
    constexpr uint32 Keyword  = 2;
    constexpr uint32 Operator = 3;
    constexpr uint32 String   = 4;
    constexpr uint32 Invalid  = 0xffffffff;

} // namespace TokenType

VBAFile::VBAFile()
{
}

void VBAFile::PreprocessText(GView::View::LexicalViewer::TextEditor&)
{
    // nothing to do --> there is no pre-processing needed for a VBA format
}
void VBAFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
    switch (id)
    {
    default:
        str.SetFormat("Unknown: 0x%08X", id);
        break;
    }
}

uint32 VBAFile::ParseWord(GView::View::LexicalViewer::SyntaxManager& syntax, uint32 pos)
{
    auto next = syntax.text.Parse(pos, CharacterType::IsAWordCharacter);
    auto text = syntax.text.GetSubString(pos, next);
    std::string_view alias;

    if (text == u"End" && CharacterType::GetCharacterType(syntax.text[next]) == CharacterType::Space)
    {
        auto pos2 = syntax.text.ParseSpace(next, SpaceType::SpaceAndTabs);
        if (CharacterType::GetCharacterType(syntax.text[pos2]) == CharacterType::PossibleWordStart)
        {
            auto next2 = syntax.text.Parse(pos2, CharacterType::IsAWordCharacter);
            auto text2 = syntax.text.GetSubString(pos2, next2);

            if (text2 == u"Sub")
            {
                next  = next2;
                alias = "End Sub";
            }
        }
    }

    if (text == u"Range")
    {
        syntax.tokens.Add(
              TokenType::Keyword,
              pos,
              next,
              TokenColor::Keyword,
              TokenDataType::None,
              TokenAlignament::AddSpaceAfter | this->NewLineRequired,
              true);
    }
    else
    {
        auto t = syntax.tokens.Add(
              TokenType::Word,
              pos,
              next,
              TokenColor::Word,
              TokenDataType::None,
              TokenAlignament::AddSpaceAfter | this->NewLineRequired,
              false);

        if (alias.empty() == false)
            t.SetText(alias);
    }
    return next;
}

void VBAFile::Tokenize(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    auto len  = syntax.text.Len();
    auto pos  = 0U;
    auto next = 0U;
    Token t;
    this->NewLineRequired = TokenAlignament::None;

    while (pos < len)
    {
        auto chType = CharacterType::GetCharacterType(syntax.text[pos]);
        switch (chType)
        {
        case CharacterType::PossibleWordStart:
            pos = ParseWord(syntax, pos);
            break;
        case CharacterType::PossibleNumberStart:
            next = syntax.text.ParseNumber(pos, NumberFormat::DecimalOnly | NumberFormat::FloatingPoint);
            syntax.tokens.Add(
                  TokenType::Number,
                  pos,
                  next,
                  TokenColor::Number,
                  TokenDataType::Number,
                  TokenAlignament::AddSpaceAfter | this->NewLineRequired,
                  false);
            pos = next;
            break;
        case CharacterType::PossibleStringStart:
            next = syntax.text.ParseString(pos, StringFormat::DoubleQuotes | StringFormat::TripleQuotes);
            syntax.tokens.Add(
                  TokenType::String,
                  pos,
                  next,
                  TokenColor::String,
                  TokenDataType::String,
                  TokenAlignament::AddSpaceAfter | this->NewLineRequired,
                  false);
            pos = next;
            break;
        case CharacterType::Space:
            pos = syntax.text.ParseSpace(pos, SpaceType::SpaceAndTabs);
            break;
        case CharacterType::NewLine:
            pos = syntax.text.ParseSpace(pos, SpaceType::NewLine);
            break;
        default:
            next = syntax.text.ParseSameGroupID(pos, CharacterType::GetCharacterType);
            t    = syntax.tokens.Add(
                  TokenType::Invalid,
                  pos,
                  next,
                  TokenColor::Error,
                  TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore | this->NewLineRequired);
            t.SetError("Invalid character for VBA");
            pos = next;
            break;
        }
        this->NewLineRequired = chType == CharacterType::NewLine ? TokenAlignament::StartsOnNewLine : TokenAlignament::None;
    }
}

void VBAFile::CreateBlocks(GView::View::LexicalViewer::SyntaxManager& syntax)
{
}

void VBAFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    Tokenize(syntax);
    CreateBlocks(syntax);
}
} // namespace GView::Type::VBA