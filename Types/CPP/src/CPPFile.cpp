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
    // Operators
    constexpr uint32 OperatorBIGGER         = 100;
    constexpr uint32 OperatorSMALLER        = 101;
    constexpr uint32 OperatorASSIGN         = 102;
    constexpr uint32 OperatorBIGGER_EQ      = 103;
    constexpr uint32 OperatorSMALLER_EQ     = 104;
    constexpr uint32 OperatorEQUAL          = 105;
    constexpr uint32 OperatorDIFFERENT      = 106;
    constexpr uint32 OperatorPLUS           = 107;
    constexpr uint32 OperatorMINUS          = 108;
    constexpr uint32 OperatorMULTIPLY       = 109;
    constexpr uint32 OperatorDIVISION       = 110;
    constexpr uint32 OperatorMODULO         = 111;
    constexpr uint32 OperatorMEMBER         = 112;
    constexpr uint32 OperatorPOINTER        = 113;
    constexpr uint32 OperatorINCREMENT      = 114;
    constexpr uint32 OperatorDECREMENT      = 115;
    constexpr uint32 OperatorLOGIC_AND      = 116;
    constexpr uint32 OperatorLOGIC_OR       = 117;
    constexpr uint32 OperatorAND            = 118;
    constexpr uint32 OperatorOR             = 119;
    constexpr uint32 OperatorXOR            = 120;
    constexpr uint32 OperatorLOGIC_NOT      = 121;
    constexpr uint32 OperatorNOT            = 122;
    constexpr uint32 OperatorCONDITION      = 123;
    constexpr uint32 OperatorTWO_POINTS     = 124;
    constexpr uint32 OperatorNAMESPACE      = 125;
    constexpr uint32 OperatorPLUS_EQ        = 126;
    constexpr uint32 OperatorMINUS_EQ       = 127;
    constexpr uint32 OperatorMUL_EQ         = 128;
    constexpr uint32 OperatorDIV_EQ         = 129;
    constexpr uint32 OperatorMODULO_EQ      = 130;
    constexpr uint32 OperatorAND_EQ         = 131;
    constexpr uint32 OperatorOR_EQ          = 132;
    constexpr uint32 OperatorXOR_EQ         = 133;
    constexpr uint32 OperatorLEFT_SHIFT     = 134;
    constexpr uint32 OperatorRIGHT_SHIFT    = 135;
    constexpr uint32 OperatorRIGHT_SHIFT_EQ = 136;
    constexpr uint32 OperatorLEFT_SHIFT_EQ  = 137;
    constexpr uint32 OperatorSPACESHIP      = 138;
} // namespace TokenType
namespace Operators
{
    constexpr uint32 HASH_DEVIDER            = 134;
    uint32 operator_hash_table[HASH_DEVIDER] = { TokenType::None,
                                                 TokenType::OperatorLOGIC_NOT,
                                                 TokenType::None,
                                                 TokenType::OperatorXOR_EQ,
                                                 TokenType::None,
                                                 TokenType::OperatorMODULO,
                                                 TokenType::OperatorAND,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorMULTIPLY,
                                                 TokenType::OperatorPLUS,
                                                 TokenType::None,
                                                 TokenType::OperatorMINUS,
                                                 TokenType::OperatorMEMBER,
                                                 TokenType::OperatorDIVISION,
                                                 TokenType::OperatorSPACESHIP,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorEQUAL,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorOR_EQ,
                                                 TokenType::OperatorTWO_POINTS,
                                                 TokenType::OperatorDECREMENT,
                                                 TokenType::OperatorSMALLER,
                                                 TokenType::OperatorASSIGN,
                                                 TokenType::OperatorBIGGER,
                                                 TokenType::OperatorCONDITION,
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
                                                 TokenType::OperatorMINUS_EQ,
                                                 TokenType::OperatorPOINTER,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorBIGGER_EQ,
                                                 TokenType::OperatorRIGHT_SHIFT,
                                                 TokenType::None,
                                                 TokenType::OperatorNAMESPACE,
                                                 TokenType::OperatorMODULO_EQ,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorDIFFERENT,
                                                 TokenType::OperatorXOR,
                                                 TokenType::None,
                                                 TokenType::OperatorLOGIC_AND,
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
                                                 TokenType::OperatorMUL_EQ,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorRIGHT_SHIFT_EQ,
                                                 TokenType::None,
                                                 TokenType::OperatorAND_EQ,
                                                 TokenType::OperatorLOGIC_OR,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorOR,
                                                 TokenType::None,
                                                 TokenType::OperatorNOT,
                                                 TokenType::OperatorINCREMENT,
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
                                                 TokenType::OperatorDIV_EQ,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorPLUS_EQ,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorLEFT_SHIFT_EQ,
                                                 TokenType::None,
                                                 TokenType::None,
                                                 TokenType::OperatorLEFT_SHIFT,
                                                 TokenType::OperatorSMALLER_EQ,
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
    if (Operators::TextToOperatorID(txt.data(),(uint32)txt.size(),tokenType,sz))
    {
        TokenAlignament align = TokenAlignament::SpaceOnLeft | TokenAlignament::SpaceOnRight;
        if ((tokenType == TokenType::OperatorNAMESPACE) || (tokenType == TokenType::OperatorPOINTER) ||
            (tokenType == TokenType::OperatorMEMBER) || (tokenType == TokenType::OperatorTWO_POINTS))
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