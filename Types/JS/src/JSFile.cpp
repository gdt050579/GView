#include "js.hpp"

namespace GView::Type::JS
{
    using namespace GView::View::LexicalViewer;

    namespace OperatorType
    {
        constexpr uint32 Bigger = 0;
        constexpr uint32 Smaller = 1;
        constexpr uint32 Assign = 2;
        constexpr uint32 BiggerOrEq = 3;
        constexpr uint32 SmallerOrEQ = 4;
        constexpr uint32 Equal = 5;
        constexpr uint32 Different = 6;
        constexpr uint32 Plus = 7;
        constexpr uint32 Minus = 8;
        constexpr uint32 Multiply = 9;
        constexpr uint32 Division = 10;
        constexpr uint32 Modulo = 11;
        constexpr uint32 MemberAccess = 12;
        constexpr uint32 Pointer = 13;
        constexpr uint32 Increment = 14;
        constexpr uint32 Decrement = 15;
        constexpr uint32 LogicAND = 16;
        constexpr uint32 LogicOR = 17;
        constexpr uint32 AND = 18;
        constexpr uint32 OR = 19;
        constexpr uint32 XOR = 20;
        constexpr uint32 LogicNOT = 21;
        constexpr uint32 NOT = 22;
        constexpr uint32 Condition = 23;
        constexpr uint32 TWO_POINTS = 24;
        constexpr uint32 Namespace = 25;
        constexpr uint32 PlusEQ = 26;
        constexpr uint32 MinusEQ = 27;
        constexpr uint32 MupliplyEQ = 28;
        constexpr uint32 DivisionEQ = 29;
        constexpr uint32 ModuloEQ = 30;
        constexpr uint32 AndEQ = 31;
        constexpr uint32 OrEQ = 32;
        constexpr uint32 XorEQ = 33;
        constexpr uint32 LeftShift = 34;
        constexpr uint32 RightShift = 35;
        constexpr uint32 RightShiftEQ = 36;
        constexpr uint32 LeftShiftEQ = 37;
        constexpr uint32 Spaceship = 38;
    } // namespace OperatorType
    namespace Operators
    {
        uint8 chars_ids[128] = { 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0,  0, 0,  0,
                                 0, 4, 0, 0, 0, 9, 11, 0, 0, 0, 7, 5, 0, 6, 10, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 2,  3, 1,  15,
                                 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0,  0, 13, 0,
                                 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 12, 0, 14, 0 };

        constexpr uint32 HASH_DEVIDER = 133;
        uint32 operator_hash_table[HASH_DEVIDER] = {
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::Bigger << 8) | (uint32)(1 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Smaller << 8) | (uint32)(2 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Assign << 8) | (uint32)(3 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::LogicNOT << 8) | (uint32)(4 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Plus << 8) | (uint32)(5 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Minus << 8) | (uint32)(6 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Multiply << 8) | (uint32)(7 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Division << 8) | (uint32)(8 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Modulo << 8) | (uint32)(9 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::MemberAccess << 8) | (uint32)(10 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::AND << 8) | (uint32)(11 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::OR << 8) | (uint32)(12 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::XOR << 8) | (uint32)(13 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::NOT << 8) | (uint32)(14 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Condition << 8) | (uint32)(15 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::TWO_POINTS << 8) | (uint32)(16 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Spaceship << 8) | (uint32)(2145 << 16),
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::XorEQ << 8) | (uint32)(419 << 16),
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::ModuloEQ << 8) | (uint32)(291 << 16),
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::PlusEQ << 8) | (uint32)(163 << 16),
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::Increment << 8) | (uint32)(165 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::RightShift << 8) | (uint32)(33 << 16),
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::BiggerOrEq << 8) | (uint32)(35 << 16),
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
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::Pointer << 8) | (uint32)(193 << 16),
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::MinusEQ << 8) | (uint32)(195 << 16),
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::Decrement << 8) | (uint32)(198 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::LeftShift << 8) | (uint32)(66 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::SmallerOrEQ << 8) | (uint32)(67 << 16),
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
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::AndEQ << 8) | (uint32)(355 << 16),
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::MupliplyEQ << 8) | (uint32)(227 << 16),
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::LogicAND << 8) | (uint32)(363 << 16),
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::Equal << 8) | (uint32)(99 << 16),
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
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::LeftShiftEQ << 8) | (uint32)(2115 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::OrEQ << 8) | (uint32)(387 << 16),
            TokenType::None,
            TokenType::None,
            TokenType::None,
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::DivisionEQ << 8) | (uint32)(259 << 16),
            TokenType::None,
            (uint32)TokenType::Operator | (uint32)(OperatorType::RightShiftEQ << 8) | (uint32)(1059 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Namespace << 8) | (uint32)(528 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::LogicOR << 8) | (uint32)(396 << 16),
            (uint32)TokenType::Operator | (uint32)(OperatorType::Different << 8) | (uint32)(131 << 16),
            TokenType::None
        };

        bool TextToOperatorID(const char16* txt, uint32 size, uint32& opID, uint32& opSize)
        {
            // compute the hashes over the entire 3 cases
            uint32 hash1 = 0, hash2 = 0, hash3 = 0;
            if (((*txt) < 128) && (chars_ids[*txt] != 0))
            {
                hash1 = chars_ids[*txt];
                txt++;
                if ((size > 1) && ((*txt) < 128) && (chars_ids[*txt] != 0))
                {
                    hash2 = (hash1 << 5) + chars_ids[*txt];
                    txt++;
                    if ((size > 2) && ((*txt) < 128) && (chars_ids[*txt] != 0))
                        hash3 = (hash2 << 5) + chars_ids[*txt];
                }
            }
            auto op = operator_hash_table[hash3 % HASH_DEVIDER];
            if ((op != TokenType::None) && ((op >> 16) == hash3))
            {
                opID = (op & 0xFF) | ((op & 0xFF00) << 8);
                opSize = 3;
                return true;
            }
            op = operator_hash_table[hash2 % HASH_DEVIDER];
            if ((op != TokenType::None) && ((op >> 16) == hash2))
            {
                opID = (op & 0xFF) | ((op & 0xFF00) << 8);
                opSize = 2;
                return true;
            }
            op = operator_hash_table[hash1 % HASH_DEVIDER];
            if ((op != TokenType::None) && ((op >> 16) == hash1))
            {
                opID = (op & 0xFF) | ((op & 0xFF00) << 8);
                opSize = 1;
                return true;
            }
            return false; // invalid operator
        }
    }; // namespace Operators

    int32 BinarySearch(uint32 hash, uint32* list, int32 elementsCount)
    {
        if (elementsCount <= 0)
            return -1;
        auto start = 0;
        auto end = elementsCount - 1;
        while (start <= end)
        {
            auto mij = (start + end) >> 1;
            auto h_mij = list[mij];
            if (hash < h_mij)
            {
                end = mij - 1;
                continue;
            }
            if (hash > h_mij)
            {
                start = mij + 1;
                continue;
            }
            return mij;
        }
        return -1;
    }

    namespace Keyword {
        uint32 list[] = { 0x06ECB7E7,0x081FB565,0x08D22E0F,0x0903C7AE,0x0BF5A9A6,0x0BF7CB59,0x0C4AFE69,0x0DC628CE,0x112A90D4,0x128BDC5B,0x14204413,0x159AC2B7,0x16378A88,0x1A2BBEF3,0x1E54727D,0x2446530A,0x26129D76,0x27A252D4,0x27CB3B23,0x28258718,0x28999611,0x2951C89F,0x2E329B2A,0x2FEBCEF5,0x32E76161,0x39386E06,0x3F617060,0x41387A9E,0x419C3BA5,0x4288E94C,0x43AD5579,0x49346080,0x4A7181DF,0x4F82B9C9,0x55F0DD53,0x5E70F23D,0x601B3C5E,0x621CD814,0x62CB0D0C,0x645BA277,0x664FD1D4,0x67C2444A,0x6AF0FE62,0x6BFBD198,0x6C5395C0,0x70DAEE4F,0x74F440F8,0x78B04FBE,0x7A78762F,0x7B71324F,0x816CB000,0x83D03615,0x84EA5130,0x85EE37BF,0x8684C5F8,0x8912C4E5,0x8A58AD26,0x8A9E6B73,0x8D39BDE6,0x913B2BFB,0x933B5BDE,0x93E05F71,0x96234BD4,0x97EB7E50,0x9A90A8A0,0x9B2538B1,0x9C0C3BA8,0x9D0F221F,0x9D85D64E,0x9E212406,0x9ED1A63B,0x9ED64249,0xA0EB0F08,0xA179DD8A,0xA710DC3C,0xA90B999B,0xAB3E0BFF,0xAC1DB00E,0xACF38390,0xAE7183F0,0xB1727E44,0xB1B3C06A,0xB7C358F9,0xB8440699,0xBA4B77EF,0xBDBF5BF0,0xBDF0855A,0xBE28AC52,0xC18234D0,0xC9648178,0xCB532AE5,0xCC909380,0xCD80829D,0xD290C23B,0xD2C8C28E,0xD35EC4C9,0xD472DC59,0xD5F0C82E,0xD72BCD52,0xDA2BD281,0xDB3FB489,0xDD4EC22C,0xDEF08C82,0xDFE6493B,0xE0DE22ED,0xE259526E,0xE9359601,0xEA1B7675,0xEACDFCFD,0xEBEE50C5,0xED7F94C7,0xEE88998F,0xF112B61B,0xF25D9F4F,0xF5A30FE6,0xF77E01D4,0xF7863C98,0xF9B5A4FF,0xFB080CB3,0xFD12C898,0xFEE4436A };
        uint32 TextToKeywordID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end) {
            auto res = BinarySearch(text.ComputeHash32(start, end, false), list, 121);
            if (res == -1) return TokenType::None;
            return 1000 + res;
        };
    }

    namespace Constant {
        uint32 list[] = { 0x0B069958,0x2F8F13BA,0x4DB211E5,0x77074BA4 };
        uint32 TextToConstantID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end) {
            auto res = BinarySearch(text.ComputeHash32(start, end, false), list, 4);
            if (res == -1) return TokenType::None;
            return 8000 + res;
        };
    }

    namespace Datatype {
        uint32 list[] = { 0x17C16538,0x1BD670A0,0x48B5725F,0x506B03FA,0x645A021F,0x65F46EBF,0x8A25E7BE,0x95E97E5E,0xA6C45D85,0xA84C031D,0xB8C60CBA,0xBA226BD5,0xC2ECDF53, };
        uint32 TextToDatatypeID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end) {
            auto res = BinarySearch(text.ComputeHash32(start, end, false), list, 13);
            if (res == -1) return TokenType::None;
            return 6000 + res;
        };
    }

    namespace CharType
    {
        constexpr uint8 Word = 0;
        constexpr uint8 Number = 1;
        constexpr uint8 Operator = 2;
        constexpr uint8 Comma = 3;
        constexpr uint8 Semicolumn = 4;
        constexpr uint8 Preprocess = 5;
        constexpr uint8 String = 6;
        constexpr uint8 BlockOpen = 7;
        constexpr uint8 BlockClose = 8;
        constexpr uint8 ArrayOpen = 9;
        constexpr uint8 ArrayClose = 10;
        constexpr uint8 ExpressionOpen = 11;
        constexpr uint8 ExpressionClose = 12;
        constexpr uint8 Space = 13;
        constexpr uint8 Invalid = 14;
        constexpr uint8 SingleLineComment = 15; // virtual (not in Cpp_Groups_IDs)
        constexpr uint8 Comment = 16; // virtual (not in Cpp_Groups_IDs)
        constexpr uint8 Backquote = 17;

        uint8 Cpp_Groups_IDs[] = { Invalid,    Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                                   Invalid,    Invalid,  Space,      Space,      Invalid,   Invalid,        Space,
                                   Invalid,    Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                                   Invalid,    Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                                   Invalid,    Invalid,  Invalid,    Invalid,    Space,     Operator,       String,
                                   Preprocess, Invalid,  Operator,   Operator,   String,    ExpressionOpen, ExpressionClose,
                                   Operator,   Operator, Comma,      Operator,   Operator,  Operator,       Number,
                                   Number,     Number,   Number,     Number,     Number,    Number,         Number,
                                   Number,     Number,   Operator,   Semicolumn, Operator,  Operator,       Operator,
                                   Operator,   Invalid,  Word,       Word,       Word,      Word,           Word,
                                   Word,       Word,     Word,       Word,       Word,      Word,           Word,
                                   Word,       Word,     Word,       Word,       Word,      Word,           Word,
                                   Word,       Word,     Word,       Word,       Word,      Word,           Word,
                                   ArrayOpen,  Operator, ArrayClose, Operator,   Word,      Backquote,      Word,
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

    JSFile::JSFile()
    {
    }

    bool JSFile::Update()
    {
        return true;
    }
    uint32 JSFile::TokenizeWord(const GView::View::LexicalViewer::TextParser& text, TokensList& tokenList, uint32 pos)
    {
        auto next = text.Parse(
            pos,
            [](char16 ch)
            {
                auto type = CharType::GetCharType(ch);
                return (type == CharType::Word) || (type == CharType::Number);
            });
        auto tokColor = TokenColor::Word;
        auto tokType = Keyword::TextToKeywordID(text, pos, next);
        auto align = TokenAlignament::None;
        auto opID = 0U;
        bool disableSimilarSearch = false;
        if (tokType == TokenType::None)
        {
            tokType = Constant::TextToConstantID(text, pos, next);
            if (tokType == TokenType::None)
            {
                tokType = Datatype::TextToDatatypeID(text, pos, next);
                if (tokType == TokenType::None)
                {
                    tokType = TokenType::Word;
                    align = TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore;
                }
                else
                {
                    tokColor = TokenColor::Datatype;
                }
            }
            else
            {
                tokColor = TokenColor::Constant;
                disableSimilarSearch = true;
            }
        }
        else
        {
            tokColor = TokenColor::Keyword;
            align = TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore;
            disableSimilarSearch = true;
            switch (tokType)
            {
            case TokenType::Keyword_Else:
                if (tokenList.GetLastTokenID() == TokenType::BlockClose)
                {
                    align = align | TokenAlignament::AfterPreviousToken;
                }
                break;
            case TokenType::Keyword_If:
            case TokenType::Keyword_While:
            case TokenType::Keyword_For:
                align = align | TokenAlignament::StartsOnNewLine;
                break;
            default:
                break;
            }

        }

        tokenList.Add(tokType, pos, next, tokColor, TokenDataType::None, align, disableSimilarSearch);
        return next;
    }
    uint32 JSFile::TokenizeOperator(const GView::View::LexicalViewer::TextParser& text, TokensList& tokenList, uint32 pos)
    {
        auto next = text.ParseSameGroupID(pos, CharType::GetCharType);
        auto txt = text.GetSubString(pos, next);
        uint32 tokenType, sz;
        if (Operators::TextToOperatorID(txt.data(), (uint32)txt.size(), tokenType, sz))
        {
            TokenAlignament align = TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter;
            auto opType = tokenType >> 16;
            switch (opType)
            {
            case OperatorType::Namespace:
                align = TokenAlignament::AfterPreviousToken;
                if (tokenList.GetLastTokenID() == TokenType::Word)
                    tokenList.GetLastToken().SetTokenColor(TokenColor::Keyword2);
                break;
            case OperatorType::Pointer:
            case OperatorType::MemberAccess:
            case OperatorType::TWO_POINTS:
                align = TokenAlignament::AfterPreviousToken;
                break;
            case OperatorType::Assign:
            case OperatorType::PlusEQ:
            case OperatorType::MinusEQ:
            case OperatorType::MupliplyEQ:
            case OperatorType::DivisionEQ:
            case OperatorType::ModuloEQ:
            case OperatorType::AndEQ:
            case OperatorType::OrEQ:
            case OperatorType::XorEQ:
            case OperatorType::RightShiftEQ:
            case OperatorType::LeftShiftEQ:
                align |= TokenAlignament::SameColumn;
                break;
            }

            tokenList.Add(tokenType, pos, pos + sz, TokenColor::Operator, TokenDataType::None, align, true);
            return pos + sz;
        }
        else
        {
            // unknown operator
            tokenList.Add(TokenType::Operator, pos, next, TokenColor::Word).SetError("Invalid C++ operator");
            return next;
        }
    }
    uint32 JSFile::TokenizePreprocessDirective(const TextParser& text, TokensList& list, BlocksList& blocks, uint32 pos)
    {
        auto eol = text.ParseUntillEndOfLine(pos);
        auto start = pos;
        pos = text.ParseSpace(pos + 1, SpaceType::SpaceAndTabs);
        if ((CharType::GetCharType(text[pos])) != CharType::Word)
        {
            // we have an error
            list.Add(TokenType::Preprocess,
                start,
                eol,
                TokenColor::Preprocesor,
                TokenAlignament::StartsOnNewLine | TokenAlignament::NewLineAfter)
                .SetError("Invalid preprocess directive");
            return eol;
        }
        // we have a good preprocess directive ==> lets formalize it
        auto next = text.ParseSameGroupID(pos, CharType::GetCharType);
        list.Add(
            TokenType::Preprocess,
            start,
            eol /*next*/,
            TokenColor::Preprocesor,
            TokenAlignament::StartsOnNewLine | TokenAlignament::AddSpaceAfter | TokenAlignament::NewLineAfter);

        //auto tknIndex = list.Len();
        //Tokenize(next, eol, text, list, blocks);
        //auto tknCount = list.Len();
        //// change the color of every added token
        //for (auto index = tknIndex; index < tknCount; index++)
        //    list[index].SetTokenColor(TokenColor::Preprocesor);
        //// make sure that last token has a new line after it
        //list.GetLastToken().UpdateAlignament(TokenAlignament::NewLineAfter);
        //// crete a block
        //blocks.Add(tknIndex - 1, tknCount-1, BlockAlignament::AsBlockStartToken);

        return eol;
    }
    void JSFile::BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax)
    {
        TokenIndexStack stBlocks;
        TokenIndexStack exprBlocks;
        auto len = syntax.tokens.Len();
        for (auto index = 0U; index < len; index++)
        {
            auto typeID = syntax.tokens[index].GetTypeID(TokenType::None);
            switch (typeID)
            {
            case TokenType::BlockOpen:
                stBlocks.Push(index);
                break;
            case TokenType::BlockClose:
                syntax.blocks.Add(stBlocks.Pop(), index, BlockAlignament::ParentBlockWithIndent, BlockFlags::EndMarker);
                break;
            case TokenType::ExpressionOpen:
                exprBlocks.Push(index);
                break;
            case TokenType::ExpressionClose:
                syntax.blocks.Add(
                    exprBlocks.Pop(), index, BlockAlignament::CurrentToken, BlockFlags::EndMarker | BlockFlags::ManualCollapse);
                break;
            }
        }
    }
    void JSFile::Tokenize(const TextParser& text, TokensList& tokenList, BlocksList& blocks)
    {
        Tokenize(0, text.Len(), text, tokenList, blocks);
    }
    void JSFile::Tokenize(
        uint32 start, uint32 end, const TextParser& text, TokensList& tokenList, BlocksList& blocks)
    {
        auto idx = start;
        auto next = 0U;

        while (idx < end)
        {
            auto ch = text[idx];
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
                    TokenAlignament::NewLineAfter | TokenAlignament::AddSpaceBefore,
                    true);
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
                    TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter,
                    true);
                idx = next;
                break;
            case CharType::ArrayOpen:
                tokenList.Add(TokenType::ArrayOpen, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
                idx++;
                break;
            case CharType::ArrayClose:
                tokenList.Add(TokenType::ArrayClose, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
                idx++;
                break;
            case CharType::ExpressionOpen:
                tokenList.Add(TokenType::ExpressionOpen, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
                idx++;
                break;
            case CharType::ExpressionClose:
                tokenList.Add(TokenType::ExpressionClose, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
                idx++;
                break;
            case CharType::BlockOpen:
                tokenList.Add(
                    TokenType::BlockOpen,
                    idx,
                    idx + 1,
                    TokenColor::Operator,
                    TokenDataType::None,
                    TokenAlignament::NewLineAfter | TokenAlignament::StartsOnNewLine,
                    true);
                idx++;
                break;
            case CharType::BlockClose:
                tokenList.Add(
                    TokenType::BlockClose,
                    idx,
                    idx + 1,
                    TokenColor::Operator,
                    TokenDataType::None,
                    TokenAlignament::StartsOnNewLine | TokenAlignament::NewLineAfter | TokenAlignament::ClearIndentAfterPaint,
                    true);
                idx++;
                break;
            case CharType::Number:
                next = text.ParseNumber(idx);
                tokenList.Add(TokenType::Number, idx, next, TokenColor::Number, TokenDataType::Number);
                idx = next;
                break;
            case CharType::String:
                next = text.ParseString(idx, StringFormat::DoubleQuotes | StringFormat::SingleQuotes | StringFormat::AllowEscapeSequences);
                tokenList.Add(TokenType::String, idx, next, TokenColor::String, TokenDataType::String);
                idx = next;
                break;
            case CharType::Backquote:
                //De adaugat si ${}
                next = text.ParseString(idx, StringFormat::Apostrophe);
                tokenList.Add(TokenType::String, idx, next, TokenColor::String, TokenDataType::String);
                idx = next;
                break;
            case CharType::Comma:
                tokenList.Add(
                    TokenType::Comma,
                    idx,
                    idx + 1,
                    TokenColor::Operator,
                    TokenDataType::None,
                    TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter,
                    true);
                idx++;
                break;
            case CharType::Semicolumn:
                tokenList.Add(
                    TokenType::Semicolumn,
                    idx,
                    idx + 1,
                    TokenColor::Operator,
                    TokenDataType::None,
                    TokenAlignament::NewLineAfter | TokenAlignament::AfterPreviousToken | TokenAlignament::ClearIndentAfterPaint,
                    true);
                idx++;
                break;
            case CharType::Preprocess:
                idx = TokenizePreprocessDirective(text, tokenList, blocks, idx);
                break;
            case CharType::Word:
                idx = TokenizeWord(text, tokenList, idx);
                break;
            case CharType::Operator:
                idx = TokenizeOperator(text, tokenList, idx);
                break;
            default:
                next = text.ParseSameGroupID(idx, CharType::GetCharType);
                tokenList.Add(TokenType::Word, idx, next, TokenColor::Word).SetError("Invalid character sequance");
                idx = next;
                break;
            }
        }
    }
    void JSFile::IndentSimpleInstructions(GView::View::LexicalViewer::TokensList& list)
    {
        /*
        auto len = list.Len();
        auto idx = 0U;
        while (idx < len)
        {
            auto typeID = list[idx].GetTypeID(TokenType::None);
            if ((typeID == (TokenType::Keyword | (KeywordsType::If << 16))) || (typeID == (TokenType::Keyword | (KeywordsType::While << 16))) ||
                (typeID == (TokenType::Keyword | (KeywordsType::For << 16))))
            {
                if (list[idx + 1].GetTypeID(TokenType::None) == TokenType::ExpressionOpen)
                {
                    auto block = list[idx + 1].GetBlock();
                    if (block.IsValid())
                    {
                        auto endToken = block.GetEndToken();
                        if (endToken.IsValid())
                        {
                            // we have the following format if|while|for follower by (...)
                            auto nextTok = list[endToken.GetIndex() + 1];
                            if ((nextTok.IsValid()) && (nextTok.GetTypeID(TokenType::None) != TokenType::BlockOpen))
                            {
                                nextTok.UpdateAlignament(TokenAlignament::IncrementIndentBeforePaint | TokenAlignament::StartsOnNewLine);
                            }
                            // if the case is for
                            if (typeID == (TokenType::Keyword | (KeywordsType::For << 16)))
                            {
                                // search for every ';' between (...) and remove any new line
                                auto endTokID = endToken.GetIndex();
                                for (auto tkIdx = idx + 2; tkIdx < endTokID; tkIdx++)
                                {
                                    auto currentTok = list[tkIdx];
                                    if (currentTok.GetTypeID(TokenType::None) == TokenType::Semicolumn)
                                        currentTok.SetAlignament(TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore);
                                }
                            }
                        }
                    }
                }
            }
            idx++;
        }*/
    }
    void JSFile::CreateFoldUnfoldLinks(GView::View::LexicalViewer::SyntaxManager& syntax)
    {
        /* Search for the following cases
         * for|if|while|switch (...) {...} and add collapse/expand on for|if and while
         * word (...) {...} or word (...) cons {...} and add collapse/expand on word
         * do {...} while (...) -> both do and while should compact the {...}
         */
         /*
         auto len = syntax.blocks.Len();
         for (auto idx = 0U; idx < len; idx++)
         {
             auto block = syntax.blocks[idx];
             // search for {...} blocks
             auto startToken = block.GetStartToken();
             if (startToken.GetTypeID(TokenType::None) != TokenType::BlockOpen)
                 continue;
             auto precToken = startToken.Precedent();
             auto precTokenID = precToken.GetTypeID(TokenType::None);
             if (precTokenID == (TokenType::Keyword | (KeywordsType::Else << 16)))
             {
                 // found else {...} case ==> make sure that else can fold/unfold the next block
                 precToken.SetBlock(block);
                 continue;
             }
             if (precTokenID == (TokenType::Keyword | (KeywordsType::Do << 16)))
             {
                 // found else do {...} case ==> make sure that 'do' token can fold/unfold the next block
                 precToken.SetBlock(block);
                 // check for do {...} while
                 auto endToken = block.GetEndToken();
                 if (endToken.GetTypeID(TokenType::None) == TokenType::BlockClose)
                 {
                     auto nextToken = endToken.Next();
                     if (nextToken.GetTypeID(TokenType::None) == (TokenType::Keyword | (KeywordsType::While << 16)))
                     {
                         nextToken.SetBlock(block);
                         nextToken.SetAlignament(
                             TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter | TokenAlignament::AfterPreviousToken);
                     }
                 }
                 continue;
             }

             if (precTokenID == (TokenType::Keyword | (KeywordsType::Const << 16)))
                 precToken = precToken.Precedent();
             // at this point precToken should be a (...) block
             if (precToken.GetTypeID(TokenType::None) != TokenType::ExpressionClose)
                 continue;
             auto targetToken = precToken.GetBlock().GetStartToken().Precedent();
             auto targetTokenID = targetToken.GetTypeID(TokenType::None);
             if ((targetTokenID == TokenType::Word) || ((targetTokenID & 0xFFFF) == TokenType::Keyword))
             {
                 // all good
                 targetToken.SetBlock(block);
             }
         }*/
    }
    void JSFile::RemoveLineContinuityCharacter(TextEditor& editor)
    {
        auto pos = 0;
        do
        {
            auto res = editor.Find(pos, "\\");
            if (!res.has_value())
                break;
            pos = res.value() + 1;
            auto next = editor[pos];
            if ((next == '\n') || (next == '\r'))
            {
                auto nextAfterNext = editor[pos + 1];
                if (((nextAfterNext == '\n') || (nextAfterNext == '\r')) && (nextAfterNext != next))
                {
                    // case like \CRLF or \LFCR
                    editor.Delete(res.value(), 3);
                }
                else
                {
                    // case line \CR or \LF
                    editor.Delete(res.value(), 2);
                }
            }
        } while (true);
    }
    void JSFile::PreprocessText(GView::View::LexicalViewer::TextEditor& editor)
    {
        // change alternate character set to their original character
        // https://en.cppreference.com/w/cpp/language/operator_alternative
        // very simplistic
        editor.ReplaceAll("<%", "{");
        editor.ReplaceAll("%>", "}");
        editor.ReplaceAll("%:%:", "##");
        editor.ReplaceAll("%:", "#");
        editor.ReplaceAll(":>", "]");
        // check for < : case
        auto pos = 0;
        do
        {
            auto res = editor.Find(pos, "<:");
            if (!res.has_value())
                break;
            pos = res.value() + 2;
            if ((editor[pos] == ':') && ((editor[pos + 1] == '>') || (editor[pos + 1] == ':')))
            {
                // skip it
            }
            else
            {
                editor.Replace(res.value(), 2, "[");
            }
        } while (true);

        // remove line continuity
        RemoveLineContinuityCharacter(editor);
    }
    void JSFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
    {
        switch (id)
        {
        case TokenType::None:
            str.Set("Unknwon/Error");
            break;
        case TokenType::Comment:
            str.Set("Comment");
            break;
        case TokenType::ArrayOpen:
            str.Set("Array (open)");
            break;
        case TokenType::ArrayClose:
            str.Set("Array (close)");
            break;
        case TokenType::BlockOpen:
            str.Set("Block (open)");
            break;
        case TokenType::BlockClose:
            str.Set("Block (close)");
            break;
        case TokenType::ExpressionOpen:
            str.Set("Expression (open)");
            break;
        case TokenType::ExpressionClose:
            str.Set("Expression (close)");
            break;
        case TokenType::Number:
            str.Set("Number constant");
            break;
        case TokenType::String:
            str.Set("String");
            break;
        case TokenType::Comma:
            str.Set("Separator (comma)");
            break;
        case TokenType::Semicolumn:
            str.Set("Separator (semicolumn)");
            break;
        case TokenType::Preprocess:
            str.Set("Preprocess directive");
            break;
        case TokenType::Word:
            str.Set("Word");
            break;
        case TokenType::Operator:
            str.Set("Operator");
            break;
        }
        if (TokenType::IsKeyword(id))
        {
            str.Set("Keyword");
        }
        if (TokenType::IsDatatype(id))
        {
            str.Set("Datatype");
        }
        if (TokenType::IsConstant(id))
        {
            str.Set("Constant");
        }
    }
    void JSFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
    {
        syntax.tokens.ResetLastTokenID(TokenType::None);
        Tokenize(syntax.text, syntax.tokens, syntax.blocks);
        BuildBlocks(syntax);
        IndentSimpleInstructions(syntax.tokens);
        CreateFoldUnfoldLinks(syntax);
    }
} // namespace GView::Type::CPP