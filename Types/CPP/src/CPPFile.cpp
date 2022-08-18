#include "cpp.hpp"

namespace GView::Type::CPP
{
using namespace GView::View::LexicalViewer;
namespace TokenType
{
    constexpr uint32 Comment         = 0;
    constexpr uint32 ArrayOpen       = 1;
    constexpr uint32 ArrayClose      = 2;
    constexpr uint32 BlockOpen       = 3;
    constexpr uint32 BlockClose      = 4;
    constexpr uint32 ExpressionOpen  = 5;
    constexpr uint32 ExpressionClose = 6;
    constexpr uint32 Number          = 7;
    constexpr uint32 String          = 8;
    constexpr uint32 Comma           = 9;
    constexpr uint32 Semicolumn      = 10;
    constexpr uint32 Preprocess      = 11;
    constexpr uint32 Word            = 12;
    constexpr uint32 Operator        = 13;
    constexpr uint32 None            = 0xFFFFFFFF;

} // namespace TokenType

namespace CharType
{
    constexpr uint8 Word              = 0;
    constexpr uint8 Number            = 1;
    constexpr uint8 Operator          = 2;
    constexpr uint8 Comma             = 3;
    constexpr uint8 Semicolumn        = 4;
    constexpr uint8 Preprocess        = 5;
    constexpr uint8 String            = 6;
    constexpr uint8 BlockOpen         = 7;
    constexpr uint8 BlockClose        = 8;
    constexpr uint8 ArrayOpen         = 9;
    constexpr uint8 ArrayClose        = 10;
    constexpr uint8 ExpressionOpen    = 11;
    constexpr uint8 ExpressionClose   = 12;
    constexpr uint8 Space             = 13;
    constexpr uint8 Invalid           = 14;
    constexpr uint8 SingleLineComment = 15; // virtual (not in Cpp_Groups_IDs)
    constexpr uint8 Comment           = 16; // virtual (not in Cpp_Groups_IDs)

    uint8 Cpp_Groups_IDs[] = { Invalid,    Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                               Invalid,    Invalid,  Space,      Space,      Invalid,   Invalid,        Space,
                               Invalid,    Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                               Invalid,    Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                               Invalid,    Invalid,  Invalid,    Invalid,    Space,     Operator,       String,
                               Preprocess, Invalid,  Operator,   Operator,   String,    ExpressionOpen, ExpressionClose,
                               Operator,   Operator, Comma,      Operator,   Invalid,   Operator,       Number,
                               Number,     Number,   Number,     Number,     Number,    Number,         Number,
                               Number,     Number,   Operator,   Semicolumn, Invalid,   Operator,       Invalid,
                               Operator,   Invalid,  Word,       Word,       Word,      Word,           Word,
                               Word,       Word,     Word,       Word,       Word,      Word,           Word,
                               Word,       Word,     Word,       Word,       Word,      Word,           Word,
                               Word,       Word,     Word,       Word,       Word,      Word,           Word,
                               ArrayOpen,  Operator, ArrayClose, Operator,   Word,      Invalid,        Word,
                               Word,       Word,     Word,       Word,       Word,      Word,           Word,
                               Word,       Word,     Word,       Word,       Word,      Word,           Word,
                               Word,       Word,     Word,       Word,       Word,      Word,           Word,
                               Word,       Word,     Word,       Word,       BlockOpen, Operator,       BlockClose,
                               Operator,   Invalid };

    inline uint32 GetCharType(char16 c)
    {
        if (c < ARRAY_LEN(Cpp_Groups_IDs))
            return Cpp_Groups_IDs[c];
        return Invalid;
    }
} // namespace CharType

CPPFile::CPPFile()
{
}

bool CPPFile::Update()
{
    return true;
}
uint32 CPPFile::TokenizeWord(const GView::View::LexicalViewer::TextParser& text, TokensList& tokenList, uint32 pos)
{
    auto next = text.Parse(
          pos,
          [](char16 ch)
          {
              auto type = CharType::GetCharType(ch);
              return (type == CharType::Word) || (type == CharType::Number);
          });
    auto align = TokenAlignament::None;
    if (tokenList.GetLastTokenID() == TokenType::Word)
        align = TokenAlignament::SpaceOnLeft;
    tokenList.Add(TokenType::Word, pos, next, TokenColor::Word, align);
    return next;
}
uint32 CPPFile::TokenizeOperator(const GView::View::LexicalViewer::TextParser& text, TokensList& tokenList, uint32 pos)
{
    auto next = text.ParseSameGroupID(pos, CharType::GetCharType);
    tokenList.Add(TokenType::Operator, pos, next, TokenColor::Operator);
    return next;
}
uint32 CPPFile::TokenizePreprocessDirective(const GView::View::LexicalViewer::TextParser& text, uint32 pos)
{
    auto next = text.ParseTillEndOfLine(pos);

    // check for multi-line format
    if ((next > 0) && (text[next - 1] == '\\'))
    {
        pos = text.ParseTillStartOfNextLine(next); // skip CR, CRLF, LF or LFCRif any
        // repeat the flow
        while (true)
        {
            next = text.ParseTillEndOfLine(next);
            if ((next > 0) && (text[next - 1] == '\\'))
            {
                next = text.ParseTillStartOfNextLine(next);
                continue;
            }
            break;
        }
        return next;
    }

    // check for #if...#endif (TODO)
    return next;
}

void CPPFile::Tokenize(const TextParser& text, TokensList& tokenList)
{
    auto len  = text.Len();
    auto idx  = 0U;
    auto next = 0U;

    while (idx < len)
    {
        auto ch   = text[idx];
        auto type = CharType::GetCharType(ch);

        // check for comments
        if (ch == '/')
        {
            auto next = text[idx + 1];
            if (next == '/')
                type = CharType::SingleLineComment;
            else if (next == '*')
                type = CharType::Comment;
        }
        switch (type)
        {
        case CharType::Space:
            idx = text.ParseSpace(idx, SpaceType::All);
            break;
        case CharType::SingleLineComment:
            next = text.ParseTillEndOfLine(idx);
            tokenList.Add(
                  TokenType::Comment,
                  idx,
                  next,
                  TokenColor::Comment,
                  TokenDataType::MetaInformation,
                  TokenAlignament::NewLineAfter | TokenAlignament::SpaceOnLeft);
            idx = next;
            break;
        case CharType::Comment:
            next = std::min<>(text.ParseTillText(idx, "*/", false) + 2U /*size of "\*\/" */, len);
            tokenList.Add(
                  TokenType::Comment,
                  idx,
                  next,
                  TokenColor::Comment,
                  TokenDataType::MetaInformation,
                  TokenAlignament::SpaceOnLeft | TokenAlignament::SpaceOnRight);
            idx = next;
            break;
        case CharType::ArrayOpen:
            tokenList.Add(TokenType::ArrayOpen, idx, idx + 1, TokenColor::Operator);
            idx++;
            break;
        case CharType::ArrayClose:
            tokenList.Add(TokenType::ArrayClose, idx, idx + 1, TokenColor::Operator);
            idx++;
            break;
        case CharType::ExpressionOpen:
            tokenList.Add(TokenType::ExpressionOpen, idx, idx + 1, TokenColor::Operator);
            idx++;
            break;
        case CharType::ExpressionClose:
            tokenList.Add(TokenType::ExpressionClose, idx, idx + 1, TokenColor::Operator);
            idx++;
            break;
        case CharType::BlockOpen:
            tokenList.Add(TokenType::BlockOpen, idx, idx + 1, TokenColor::Operator, TokenAlignament::NewLineAfter);
            idx++;
            break;
        case CharType::BlockClose:
            tokenList.Add(TokenType::BlockClose, idx, idx + 1, TokenColor::Operator, TokenAlignament::NewLineAfter);
            idx++;
            break;
        case CharType::Number:
            next = text.ParseNumber(idx);
            tokenList.Add(TokenType::Number, idx, next, TokenColor::Number);
            idx = next;
            break;
        case CharType::String:
            next = text.ParseString(idx, StringFormat::DoubleQuotes | StringFormat::SingleQuotes | StringFormat::AllowEscapeSequences);
            tokenList.Add(TokenType::String, idx, next, TokenColor::String);
            idx = next;
            break;
        case CharType::Comma:
            tokenList.Add(
                  TokenType::Comma, idx, idx + 1, TokenColor::Operator, TokenAlignament::SpaceOnLeft | TokenAlignament::SpaceOnRight);
            idx++;
            break;
        case CharType::Semicolumn:
            tokenList.Add(TokenType::Comma, idx, idx + 1, TokenColor::Operator, TokenAlignament::NewLineAfter);
            idx++;
            break;
        case CharType::Preprocess:
            next = TokenizePreprocessDirective(text, idx);
            tokenList.Add(
                  TokenType::Preprocess,
                  idx,
                  next,
                  TokenColor::Preprocesor,
                  TokenDataType::MetaInformation,
                  TokenAlignament::NewLineAfter | TokenAlignament::NewLineBefore);
            idx = next;
            break;
        case CharType::Word:
            idx = TokenizeWord(text, tokenList, idx);
            break;
        case CharType::Operator:
            idx = TokenizeOperator(text, tokenList, idx);
            break;
        default:
            next = text.ParseSameGroupID(idx, CharType::GetCharType);
            tokenList.AddErrorToken(idx, next, "Invalid character sequance");
            idx = next;
            break;
        }
    }
}
void CPPFile::AnalyzeText(const TextParser& text, TokensList& tokenList)
{
    tokenList.ResetLastTokenID(TokenType::None);
    Tokenize(text, tokenList);
}
} // namespace GView::Type::CPP