#include "json.hpp"

namespace GView::Type::JSON
{
using namespace GView::View::LexicalViewer;

namespace CharacterType
{
    constexpr uint32 open_brace          = 0;
    constexpr uint32 closed_brace        = 1;
    constexpr uint32 double_quotes       = 2;
    constexpr uint32 colon               = 3;
    constexpr uint32 alphanum_characters = 4;
    constexpr uint32 comma               = 5;
    constexpr uint32 spaces              = 6;
    constexpr uint32 open_bracket        = 7;
    constexpr uint32 closed_bracket      = 8;
    constexpr uint32 invalid             = 9;

    uint32 GetCharacterType(char16 ch)
    {
        if (ch == '{')
            return open_brace;
        if (ch == '}')
            return closed_brace;
        if (ch == '"')
            return double_quotes;
        if (ch == ':')
            return colon;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-')
            return alphanum_characters;
        if (ch == ',')
            return comma;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')
            return spaces;
        if (ch == '[')
            return open_bracket;
        if (ch == ']')
            return closed_bracket;
        return invalid;
    }
} // namespace CharacterType

#define CHAR_CASE(char_type, align)                                                                                                        \
    case CharacterType::char_type:                                                                                                         \
        syntax.tokens.Add(TokenType::char_type, pos, pos + 1, TokenColor::Operator, TokenDataType::None, (align), true);                   \
        pos++;                                                                                                                             \
        break;

JSONFile::JSONFile()
{
}

void JSONFile::ParseFile(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    auto len  = syntax.text.Len();
    auto pos  = 0u;
    auto next = 0u;
    while (pos < len)
    {
        auto char_type = CharacterType::GetCharacterType(syntax.text[pos]);
        switch (char_type)
        {
            CHAR_CASE(open_brace, TokenAlignament::StartsOnNewLine | TokenAlignament::NewLineAfter);
            CHAR_CASE(closed_brace, TokenAlignament::StartsOnNewLine | TokenAlignament::NewLineAfter);
            CHAR_CASE(open_bracket, TokenAlignament::None);
            CHAR_CASE(closed_bracket, TokenAlignament::NewLineAfter);
            CHAR_CASE(colon, TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter | TokenAlignament::SameColumn);
            CHAR_CASE(comma, TokenAlignament::NewLineAfter | TokenAlignament::AfterPreviousToken);
        case CharacterType::spaces:
            pos = syntax.text.ParseSpace(pos, SpaceType::All);
            break;
        case CharacterType::double_quotes:
            next = syntax.text.ParseString(pos, StringFormat::DoubleQuotes);
            if (syntax.tokens.GetLastTokenID() == TokenType::colon)
            {
                syntax.tokens.Add(TokenType::value, pos, next, TokenColor::Word, TokenAlignament::AddSpaceBefore);
            }
            else
            {
                syntax.tokens.Add(
                      TokenType::key, pos, next, TokenColor::Keyword, TokenAlignament::StartsOnNewLine | TokenAlignament::AddSpaceAfter);
            }
            pos = next;
            break;
        case CharacterType::alphanum_characters:
            next = syntax.text.ParseSameGroupID(pos, CharacterType::GetCharacterType);
            syntax.tokens.Add(TokenType::value, pos, next, TokenColor::Word, TokenAlignament::AddSpaceBefore);
            pos = next;
            break;
        default:
            next = syntax.text.ParseSameGroupID(pos, CharacterType::GetCharacterType);
            syntax.tokens.Add(TokenType::invalid, pos, next, TokenColor::Error, TokenAlignament::AddSpaceBefore)
                  .SetError("Invalid character for json file");
            pos = next;
            break;
        }
    }
}
void JSONFile::BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    TokenIndexStack braces, brackets;
    auto len      = syntax.tokens.Len();
    auto pos      = 0u;
    auto last_val = 0u;
    for (; pos < len; pos++)
    {
        auto token_type = syntax.tokens[pos].GetTypeID(TokenType::invalid);
        switch (token_type)
        {
        case TokenType::open_bracket:
            brackets.Push(pos);
            break;
        case TokenType::open_brace:
            braces.Push(pos);
            break;
        case TokenType::closed_brace:
            if (!braces.Empty())
            {
                last_val = braces.Pop();
                syntax.blocks.Add(last_val, pos, BlockAlignament::ToRightOfCurrentBlock, BlockFlags::EndMarker);
            }
            else
            {
                syntax.tokens[pos].SetError("Expected open brace");
            }
            break;
        case TokenType::closed_bracket:
            if (!brackets.Empty())
            {
                last_val = brackets.Pop();
                syntax.blocks.Add(last_val, pos, BlockAlignament::AsBlockStartToken, BlockFlags::EndMarker);
                for (auto index = last_val + 1; index < pos; index++)
                {
                    auto block = syntax.tokens[index].GetBlock();
                    if (block.IsValid())
                    {
                        index = block.GetEndToken().GetIndex();
                    }
                    else
                    {
                        syntax.tokens[index].SetAlignament(TokenAlignament::None);
                    }
                }
            }
            else
            {
                syntax.tokens[pos].SetError("Expected open bracket");
            }
            break;
        }
    }

    len = syntax.blocks.Len();
    LocalString<128> tmp;

    for (auto index = 0u;index<len;index++)
    {
        auto block = syntax.blocks[index];
        block.SetFoldMessage(tmp.Format("Tokens: %d", block.GetEndToken().GetIndex() - block.GetStartToken().GetIndex()));
    }
}

void JSONFile::PreprocessText(GView::View::LexicalViewer::TextEditor&)
{
    // nothing to do --> there is no pre-processing needed for a JSON format
}
void JSONFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
    switch (id)
    {
    default:
        str.SetFormat("Unknown: 0x%08X", id);
        break;
    }
}
void JSONFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    ParseFile(syntax);
    BuildBlocks(syntax);
}
} // namespace GView::Type::JSON