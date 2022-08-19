#include "cpp.hpp"

namespace GView::Type::CPP
{
using namespace GView::View::LexicalViewer;
namespace TokenType
{
    constexpr uint32 None            = 0xFFFFFFFF;
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
} // namespace TokenType
namespace OperatorType
{
    constexpr uint32 Bigger       = 0;
    constexpr uint32 Smaller      = 1;
    constexpr uint32 Assign       = 2;
    constexpr uint32 BiggerOrEq   = 3;
    constexpr uint32 SmallerOrEQ  = 4;
    constexpr uint32 Equal        = 5;
    constexpr uint32 Different    = 6;
    constexpr uint32 Plus         = 7;
    constexpr uint32 Minus        = 8;
    constexpr uint32 Multiply     = 9;
    constexpr uint32 Division     = 10;
    constexpr uint32 Modulo       = 11;
    constexpr uint32 MemberAccess = 12;
    constexpr uint32 Pointer      = 13;
    constexpr uint32 Increment    = 14;
    constexpr uint32 Decrement    = 15;
    constexpr uint32 LogicAND     = 16;
    constexpr uint32 LogicOR      = 17;
    constexpr uint32 AND          = 18;
    constexpr uint32 OR           = 19;
    constexpr uint32 XOR          = 20;
    constexpr uint32 LogicNOT     = 21;
    constexpr uint32 NOT          = 22;
    constexpr uint32 Condition    = 23;
    constexpr uint32 TWO_POINTS   = 24;
    constexpr uint32 Namespace    = 25;
    constexpr uint32 PlusEQ       = 26;
    constexpr uint32 MinusEQ      = 27;
    constexpr uint32 MupliplyEQ   = 28;
    constexpr uint32 DivisionEQ   = 29;
    constexpr uint32 ModuloEQ     = 30;
    constexpr uint32 AndEQ        = 31;
    constexpr uint32 OrEQ         = 32;
    constexpr uint32 XorEQ        = 33;
    constexpr uint32 LeftShift    = 34;
    constexpr uint32 RightShift   = 35;
    constexpr uint32 RightShiftEQ = 36;
    constexpr uint32 LeftShiftEQ  = 37;
    constexpr uint32 Spaceship    = 38;
}
namespace Operators
{
    constexpr uint32 HASH_DEVIDER            = 134;
    uint32 operator_hash_table[HASH_DEVIDER] = { TokenType::None,
                                                 TokenType::Operator | (OperatorType::LogicNOT << 16),
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::XorEQ << 16),
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::Modulo << 16),
                                                 TokenType::Operator | (OperatorType::AND << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::Multiply << 16),
                                                 TokenType::Operator | (OperatorType::Plus << 16),
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::Minus << 16),
                                                 TokenType::Operator | (OperatorType::MemberAccess << 16),
                                                 TokenType::Operator | (OperatorType::Division << 16),
                                                 TokenType::Operator | (OperatorType::Spaceship << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::Equal << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::OrEQ << 16),
                                                 TokenType::Operator | (OperatorType::TWO_POINTS << 16),
                                                 TokenType::Operator | (OperatorType::Decrement << 16),
                                                 TokenType::Operator | (OperatorType::Smaller << 16),
                                                 TokenType::Operator | (OperatorType::Assign << 16),
                                                 TokenType::Operator | (OperatorType::Bigger << 16),
                                                 TokenType::Operator | (OperatorType::Condition << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::MinusEQ << 16),
                                                 TokenType::Operator | (OperatorType::Pointer << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::BiggerOrEq << 16),
                                                 TokenType::Operator | (OperatorType::RightShift << 16),
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::Namespace << 16),
                                                 TokenType::Operator | (OperatorType::ModuloEQ << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::Different << 16),
                                                 TokenType::Operator | (OperatorType::XOR << 16),
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::LogicAND << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::MupliplyEQ << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::RightShiftEQ << 16),
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::AndEQ << 16),
                                                 TokenType::Operator | (OperatorType::LogicOR << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::OR << 16),
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::NOT << 16),
                                                 TokenType::Operator | (OperatorType::Increment << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::DivisionEQ << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::PlusEQ << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::LeftShiftEQ << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::Operator | (OperatorType::LeftShift << 16),
                                                 TokenType::Operator | (OperatorType::SmallerOrEQ << 16),
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None };

    bool TextToOperatorID(const char16* txt, uint32 size, uint32& opID, uint32& opSize)
    {
        // compute the hashes over the entire 3 cases
        uint32 hash1 = 0, hash2 = 0, hash3 = 0;
        if (((*txt) > 32) && ((*txt) < 128))
        {
            hash1 = (*txt) - 32;
            txt++;
            if ((size > 1) && (((*txt) > 32) && ((*txt) < 128)))
            {
                hash2 = (hash1 << 5) + (*txt) - 32;
                txt++;
                if ((size > 2) && (((*txt) > 32) && ((*txt) < 128)))
                    hash3 = (hash2 << 5) + (*txt) - 32;
            }
        }
        hash1 %= HASH_DEVIDER;
        hash2 %= HASH_DEVIDER;
        hash3 %= HASH_DEVIDER;
        auto op = operator_hash_table[hash3];
        if (op != TokenType::None)
        {
            opID   = op;
            opSize = 3;
            return true;
        }
        op = operator_hash_table[hash2];
        if (op != TokenType::None)
        {
            opID   = op;
            opSize = 2;
            return true;
        }
        op = operator_hash_table[hash1];
        if (op != TokenType::None)
        {
            opID   = op;
            opSize = 1;
            return true;
        }
        return false; // invalid operator
    }
}; // namespace Operators

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
                               Number,     Number,   Operator,   Semicolumn, Operator,  Operator,       Operator,
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
    auto txt  = text.GetSubString(pos, next);
    uint32 tokenType, sz;
    if (Operators::TextToOperatorID(txt.data(), (uint32) txt.size(), tokenType, sz))
    {
        TokenAlignament align = TokenAlignament::SpaceOnLeft | TokenAlignament::SpaceOnRight;        
        auto opType           = tokenType >> 16;
        if ((opType == OperatorType::Namespace) || (opType == OperatorType::Pointer) ||
            (opType == OperatorType::MemberAccess) || (opType == OperatorType::TWO_POINTS))
            align = TokenAlignament::None;
        tokenList.Add(tokenType, pos, pos + sz, TokenColor::Operator, align);
        return pos + sz;
    }
    else
    {
        // unknown operator
        tokenList.AddErrorToken(pos, next, "Invalid C++ operator");
        return next;
    }
}
uint32 CPPFile::TokenizePreprocessDirective(const GView::View::LexicalViewer::TextParser& text, uint32 pos)
{
    auto next = text.ParseUntillEndOfLine(pos);

    // check for multi-line format
    if ((next > 0) && (text[next - 1] == '\\'))
    {
        pos = text.ParseUntillStartOfNextLine(next); // skip CR, CRLF, LF or LFCRif any
        // repeat the flow
        while (true)
        {
            next = text.ParseUntillEndOfLine(next);
            if ((next > 0) && (text[next - 1] == '\\'))
            {
                next = text.ParseUntillStartOfNextLine(next);
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
            next = text.ParseUntillEndOfLine(idx);
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
            next = text.ParseUntilNextCharacterAfterText(idx, "*/", false);
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
            tokenList.Add(
                  TokenType::BlockClose, idx, idx + 1, TokenColor::Operator, TokenAlignament::StartsOnNewLine|TokenAlignament::NewLineAfter);
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