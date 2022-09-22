#include "js.hpp"

namespace GView::Type::JS
{
using namespace GView::View::LexicalViewer;

int32 BinarySearch(uint32 hash, uint32* list, int32 elementsCount)
{
    if (elementsCount <= 0)
        return -1;
    auto start = 0;
    auto end   = elementsCount - 1;
    while (start <= end)
    {
        auto mij   = (start + end) >> 1;
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

namespace Keyword
{
    uint32 list[] = {
        0x06ECB7E7, 0x081FB565, 0x08D22E0F, 0x0903C7AE, 0x0BF5A9A6, 0x0BF7CB59, 0x0C4AFE69, 0x0DC628CE, 0x112A90D4, 0x128BDC5B, 0x14204413,
        0x159AC2B7, 0x16378A88, 0x1A2BBEF3, 0x1E54727D, 0x2446530A, 0x26129D76, 0x27A252D4, 0x27CB3B23, 0x28258718, 0x28999611, 0x2951C89F,
        0x2E329B2A, 0x2FEBCEF5, 0x32E76161, 0x39386E06, 0x3F617060, 0x41387A9E, 0x419C3BA5, 0x4288E94C, 0x43AD5579, 0x49346080, 0x4A7181DF,
        0x4F82B9C9, 0x55F0DD53, 0x5E70F23D, 0x601B3C5E, 0x621CD814, 0x62CB0D0C, 0x645BA277, 0x664FD1D4, 0x67C2444A, 0x6AF0FE62, 0x6BFBD198,
        0x6C5395C0, 0x70DAEE4F, 0x74F440F8, 0x78B04FBE, 0x7A78762F, 0x7B71324F, 0x816CB000, 0x83D03615, 0x84EA5130, 0x85EE37BF, 0x8684C5F8,
        0x8912C4E5, 0x8A58AD26, 0x8A9E6B73, 0x8D39BDE6, 0x913B2BFB, 0x933B5BDE, 0x93E05F71, 0x96234BD4, 0x97EB7E50, 0x9A90A8A0, 0x9B2538B1,
        0x9C0C3BA8, 0x9D0F221F, 0x9D85D64E, 0x9E212406, 0x9ED1A63B, 0x9ED64249, 0xA0EB0F08, 0xA179DD8A, 0xA710DC3C, 0xA90B999B, 0xAB3E0BFF,
        0xAC1DB00E, 0xACF38390, 0xAE7183F0, 0xB1727E44, 0xB1B3C06A, 0xB7C358F9, 0xB8440699, 0xBA4B77EF, 0xBDBF5BF0, 0xBDF0855A, 0xBE28AC52,
        0xC18234D0, 0xC9648178, 0xCB532AE5, 0xCC909380, 0xCD80829D, 0xD290C23B, 0xD2C8C28E, 0xD35EC4C9, 0xD472DC59, 0xD5F0C82E, 0xD72BCD52,
        0xDA2BD281, 0xDB3FB489, 0xDD4EC22C, 0xDEF08C82, 0xDFE6493B, 0xE0DE22ED, 0xE259526E, 0xE9359601, 0xEA1B7675, 0xEACDFCFD, 0xEBEE50C5,
        0xED7F94C7, 0xEE88998F, 0xF112B61B, 0xF25D9F4F, 0xF5A30FE6, 0xF77E01D4, 0xF7863C98, 0xF9B5A4FF, 0xFB080CB3, 0xFD12C898, 0xFEE4436A
    };
    uint32 TextToKeywordID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
    {
        auto res = BinarySearch(text.ComputeHash32(start, end, false), list, 121);
        if (res == -1)
            return TokenType::None;
        return 1000 + res;
    };
} // namespace Keyword

namespace Constant
{
    uint32 list[] = { 0x0B069958, 0x2F8F13BA, 0x4DB211E5, 0x77074BA4 };
    uint32 TextToConstantID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
    {
        auto res = BinarySearch(text.ComputeHash32(start, end, false), list, 4);
        if (res == -1)
            return TokenType::None;
        return 8000 + res;
    };
} // namespace Constant

namespace Datatype
{
    uint32 list[] = {
        0x17C16538, 0x1BD670A0, 0x48B5725F, 0x506B03FA, 0x645A021F, 0x65F46EBF, 0x8A25E7BE,
        0x95E97E5E, 0xA6C45D85, 0xA84C031D, 0xB8C60CBA, 0xBA226BD5, 0xC2ECDF53,
    };
    uint32 TextToDatatypeID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
    {
        auto res = BinarySearch(text.ComputeHash32(start, end, false), list, 13);
        if (res == -1)
            return TokenType::None;
        return 6000 + res;
    };
} // namespace Datatype

namespace Operators
{

    struct OperatorPair
    {
        uint32 tokenType;
        uint32 hash;
    };

    uint8 chars_ids[128]          = { 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0,  0, 0,  0,
                                      0, 13, 0, 0, 0, 6, 9, 0, 0, 0, 4, 2, 0, 3, 16, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0, 7,  1, 8,  12,
                                      0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0,  0, 10, 0,
                                      0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 11, 0, 14, 0 };
    constexpr uint32 HASH_DEVIDER = 265;
    OperatorPair operator_hash_table[HASH_DEVIDER] = { { TokenType::None, 0 },
                                                       { TokenType::Operator_Assignment, 0x00000001 },
                                                       { TokenType::Operator_Plus, 0x00000002 },
                                                       { TokenType::Operator_Minus, 0x00000003 },
                                                       { TokenType::Operator_Multiply, 0x00000004 },
                                                       { TokenType::Operator_Division, 0x00000005 },
                                                       { TokenType::Operator_Modulo, 0x00000006 },
                                                       { TokenType::Operator_Smaller, 0x00000007 },
                                                       { TokenType::Operator_Bigger, 0x00000008 },
                                                       { TokenType::Operator_AND, 0x00000009 },
                                                       { TokenType::Operator_XOR, 0x0000000a },
                                                       { TokenType::Operator_OR, 0x0000000b },
                                                       { TokenType::Operator_Condition, 0x0000000c },
                                                       { TokenType::Operator_LogicalNOT, 0x0000000d },
                                                       { TokenType::Operator_NOT, 0x0000000e },
                                                       { TokenType::Operator_TWO_POINTS, 0x0000000f },
                                                       { TokenType::Operator_MemberAccess, 0x00000010 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_AndAssignment, 0x00000121 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_UnsignedRightShiftAssignment, 0x00042101 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_LogicAND, 0x00000129 },
                                                       { TokenType::Operator_Equal, 0x00000021 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_ArrowFunction, 0x00000028 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_XorAssignment, 0x00000141 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_PlusAssignment, 0x00000041 },
                                                       { TokenType::Operator_Increment, 0x00000042 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_OrAssignment, 0x00000161 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_StrictDifferent, 0x00003421 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_MinusAssignment, 0x00000061 },
                                                       { TokenType::Operator_LogicOR, 0x0000016b },
                                                       { TokenType::Operator_Decrement, 0x00000063 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_MupliplyAssignment, 0x00000081 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_Exponential, 0x00000084 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_Different, 0x000001a1 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_DivisionAssignment, 0x000000a1 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_ModuloAssignment, 0x000000c1 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_LogicNullishAssignment, 0x00003181 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_LogicORAssignment, 0x00002d61 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_SmallerOrEQ, 0x000000e1 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_LogicANDAssignment, 0x00002521 },
                                                       { TokenType::Operator_LeftShift, 0x000000e7 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_RightShiftAssignment, 0x00002101 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_LeftShiftAssignment, 0x00001ce1 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_SignRightShift, 0x00002108 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_ExponentiationAssignment, 0x00001081 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_BiggerOrEq, 0x00000101 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_StrictEqual, 0x00000421 },
                                                       { TokenType::None, 0 },
                                                       { TokenType::Operator_RightShift, 0x00000108 } };

    uint32 TextToOperatorID(const char16* txt, uint32 size, uint32& opSize)
    {
        // compute the hashes over the entire 3 cases
        uint32 hash1 = 0, hash2 = 0, hash3 = 0, hash4 = 0;
        if (((*txt) < 128) && (chars_ids[*txt] != 0))
        {
            hash1 = chars_ids[*txt];
            txt++;
            if ((size > 1) && ((*txt) < 128) && (chars_ids[*txt] != 0))
            {
                hash2 = (hash1 << 5) + chars_ids[*txt];
                txt++;
                if ((size > 2) && ((*txt) < 128) && (chars_ids[*txt] != 0))
                {
                    hash3 = (hash2 << 5) + chars_ids[*txt];
                    txt++;
                    if ((size > 3) && ((*txt) < 128) && (chars_ids[*txt] != 0))
                        hash4 = (hash3 << 5) + chars_ids[*txt];
                }
            }
        }
        {
            auto op = operator_hash_table[hash4 % HASH_DEVIDER];
            if ((op.tokenType != TokenType::None) && (op.hash == hash4))
            {
                opSize = 4;
                return op.tokenType;
            }
        }
        {
            auto op = operator_hash_table[hash3 % HASH_DEVIDER];
            if ((op.tokenType != TokenType::None) && (op.hash == hash3))
            {
                opSize = 3;
                return op.tokenType;
            }
        }
        {
            auto op = operator_hash_table[hash2 % HASH_DEVIDER];
            if ((op.tokenType != TokenType::None) && (op.hash == hash2))
            {
                opSize = 2;
                return op.tokenType;
            }
        }
        {
            auto op = operator_hash_table[hash1 % HASH_DEVIDER];
            if ((op.tokenType != TokenType::None) && (op.hash == hash1))
            {
                opSize = 1;
                return op.tokenType;
            }
        }
        return TokenType::None; // invalid operator
    }
} // namespace Operators

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
    constexpr uint8 Backquote         = 17;
    constexpr uint8 NewLine           = 18;

    uint8 Cpp_Groups_IDs[] = { Invalid,    Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                               Invalid,    Invalid,  Space,      NewLine,    Invalid,   Invalid,        NewLine,
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
    auto tokType  = Keyword::TextToKeywordID(text, pos, next);
    auto align    = TokenAlignament::None;
    auto opID     = 0U;
    auto flags    = TokenFlags::None;

    if (tokType == TokenType::None)
    {
        tokType = Constant::TextToConstantID(text, pos, next);
        if (tokType == TokenType::None)
        {
            tokType = Datatype::TextToDatatypeID(text, pos, next);
            if (tokType == TokenType::None)
            {
                tokType              = TokenType::Word;
                const auto lastToken = tokenList.GetLastTokenID();
                if (TokenType::IsClassicKeyword(lastToken))
                {
                    align = TokenAlignament::AddSpaceAfter;
                }
                else
                {
                    align = TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore;
                }
            }
            else
            {
                tokColor = TokenColor::Datatype;
            }
        }
        else
        {
            tokColor = TokenColor::Constant;
            flags    = TokenFlags::DisableSimilaritySearch;
        }
    }
    else
    {
        tokColor = TokenColor::Keyword;
        align    = TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore;
        flags    = TokenFlags::DisableSimilaritySearch;

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
    /*
    if (next - pos > SIZABLE_VALUE)
        flags = flags | TokenFlags::Sizeable;
        */
    tokenList.Add(tokType, pos, next, tokColor, TokenDataType::None, align, flags |TokenFlags::Sizeable);
    return next;
}
uint32 JSFile::TokenizeOperator(const GView::View::LexicalViewer::TextParser& text, TokensList& tokenList, uint32 pos)
{
    auto next = text.ParseSameGroupID(pos, CharType::GetCharType);
    uint32 next2;
    auto txt = text.GetSubString(pos, next);
    uint32 tokenType, sz;
    tokenType = Operators::TextToOperatorID(txt.data(), (uint32) txt.size(), sz);
    if (tokenType != TokenType::None)
    {
        TokenAlignament align = TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter;
        switch (tokenType)
        {
        case TokenType::Operator_MemberAccess:
            align = TokenAlignament::AfterPreviousToken;
            break;
        case TokenType::Operator_Assignment:
        case TokenType::Operator_PlusAssignment:
            align = TokenAlignament::SameColumn | TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore;
            break;
        case TokenType::Operator_Minus:
            next2 = text.ParseSpace(pos + 1);
            if (CharType::GetCharType(text[next2]) == CharType::Number)
            {
                // x = - 5
                if (TokenType::IsOperator(tokenList.GetLastTokenID()))
                {
                    next = text.ParseNumber(next2);
                    LocalUnicodeStringBuilder<128> tmp;
                    tmp.AddChar('-');
                    tmp.Add(text.GetSubString(next2, next));
                    auto t = tokenList.Add(TokenType::Number, pos, next, TokenColor::Number, TokenDataType::Number);
                    t.SetText(tmp);
                    // tokenList.Add(TokenType::Number, pos, next, TokenColor::Number, TokenDataType::Number);
                    return next;
                }
            }
            break;

            /*
            case TokenType::Assign:
            case TokenType::PlusEQ:
            case TokenType::MinusEQ:
            case TokenType::MupliplyEQ:
            case TokenType::DivisionEQ:
            case TokenType::ModuloEQ:
            case TokenType::AndEQ:
            case TokenType::OrEQ:
            case TokenType::XorEQ:
            case TokenType::RightShiftEQ:
            case TokenType::LeftShiftEQ:
                align |= TokenAlignament::SameColumn;
                break;
                */
        }

        align = align | TokenAlignament::WrapToNextLine;
        tokenList.Add(tokenType, pos, pos + sz, TokenColor::Operator, TokenDataType::None, align, TokenFlags::DisableSimilaritySearch);
        return pos + sz;
    }
    else
    {
        // unknown operator
        tokenList.Add(TokenType::Word, pos, next, TokenColor::Word).SetError("Invalid JS operator");
        return next;
    }
}
uint32 JSFile::TokenizePreprocessDirective(const TextParser& text, TokensList& list, BlocksList& blocks, uint32 pos)
{
    auto eol   = text.ParseUntillEndOfLine(pos);
    auto start = pos;
    pos        = text.ParseSpace(pos + 1, SpaceType::SpaceAndTabs);
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

    // auto tknIndex = list.Len();
    // Tokenize(next, eol, text, list, blocks);
    // auto tknCount = list.Len();
    //// change the color of every added token
    // for (auto index = tknIndex; index < tknCount; index++)
    //     list[index].SetTokenColor(TokenColor::Preprocesor);
    //// make sure that last token has a new line after it
    // list.GetLastToken().UpdateAlignament(TokenAlignament::NewLineAfter);
    //// crete a block
    // blocks.Add(tknIndex - 1, tknCount-1, BlockAlignament::AsBlockStartToken);

    return eol;
}
void JSFile::BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    TokenIndexStack stBlocks;
    TokenIndexStack exprBlocks;
    TokenIndexStack arrayBlocks;
    auto indexArrayBlock = 0u;
    auto len             = syntax.tokens.Len();
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
            syntax.blocks.Add(exprBlocks.Pop(), index, BlockAlignament::CurrentToken, BlockFlags::EndMarker | BlockFlags::ManualCollapse);
            break;
        case TokenType::ArrayOpen:
            arrayBlocks.Push(index);
            break;
        case TokenType::ArrayClose:
            indexArrayBlock = arrayBlocks.Pop();
            if (indexArrayBlock < index)
            {
                if (index - indexArrayBlock >= 5)
                    syntax.blocks.Add(indexArrayBlock, index, BlockAlignament::CurrentToken, BlockFlags::EndMarker);
                else
                    syntax.blocks.Add(
                          indexArrayBlock, index, BlockAlignament::CurrentToken, BlockFlags::EndMarker | BlockFlags::ManualCollapse);
            }
            break;
        }
    }
}
void JSFile::Tokenize(const TextParser& text, TokensList& tokenList, BlocksList& blocks)
{
    Tokenize(0, text.Len(), text, tokenList, blocks);
}
void JSFile::Tokenize(uint32 start, uint32 end, const TextParser& text, TokensList& tokenList, BlocksList& blocks)
{
    auto idx     = start;
    auto next    = 0U;
    bool newLine = false;
    while (idx < end)
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
        case CharType::NewLine:
            idx     = text.ParseSpace(idx, SpaceType::NewLine);
            newLine = true;
            break;
        case CharType::Space:
            idx = text.ParseSpace(idx, SpaceType::SpaceAndTabs);
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
                  TokenFlags::DisableSimilaritySearch);
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
                  TokenFlags::DisableSimilaritySearch);
            idx = next;
            break;
        case CharType::ArrayOpen:
            tokenList.Add(
                  TokenType::ArrayOpen,
                  idx,
                  idx + 1,
                  TokenColor::Operator,
                  TokenDataType::None,
                  TokenAlignament::None,
                  TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::ArrayClose:
            tokenList.Add(
                  TokenType::ArrayClose,
                  idx,
                  idx + 1,
                  TokenColor::Operator,
                  TokenDataType::None,
                  TokenAlignament::None,
                  TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::ExpressionOpen:
            tokenList.Add(
                  TokenType::ExpressionOpen,
                  idx,
                  idx + 1,
                  TokenColor::Operator,
                  TokenDataType::None,
                  TokenAlignament::AfterPreviousToken,
                  TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::ExpressionClose:
            tokenList.Add(
                  TokenType::ExpressionClose,
                  idx,
                  idx + 1,
                  TokenColor::Operator,
                  TokenDataType::None,
                  TokenAlignament::AfterPreviousToken,
                  TokenFlags::DisableSimilaritySearch);
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
                  TokenFlags::DisableSimilaritySearch);
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
                  TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::Number:
            next = text.ParseNumber(idx);
            if (next - idx > SIZABLE_VALUE)
                tokenList.Add(
                      TokenType::Number, idx, next, TokenColor::Number, TokenDataType::Number, TokenAlignament::None, TokenFlags::Sizeable);
            else
                tokenList.Add(TokenType::Number, idx, next, TokenColor::Number, TokenDataType::Number);
            idx = next;
            break;
        case CharType::String:
            next = text.ParseString(idx, StringFormat::DoubleQuotes | StringFormat::SingleQuotes | StringFormat::AllowEscapeSequences);
            if (next - idx > SIZABLE_VALUE)
                tokenList.Add(
                      TokenType::Number, idx, next, TokenColor::String, TokenDataType::String, TokenAlignament::None, TokenFlags::Sizeable);
            else
                tokenList.Add(TokenType::Number, idx, next, TokenColor::String, TokenDataType::String);
            idx = next;
            break;
        case CharType::Backquote:
            // De adaugat si ${}
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
                  TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter | TokenAlignament::WrapToNextLine,
                  TokenFlags::DisableSimilaritySearch);
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
                  TokenFlags::DisableSimilaritySearch);
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
            tokenList.Add(TokenType::Word, idx, next, TokenColor::Word, TokenDataType::MetaInformation)
                  .SetError("Invalid character sequance");
            idx = next;
            break;
        }
        if (newLine && type != CharType::NewLine)
        {
            tokenList.GetLastToken().UpdateAlignament(TokenAlignament::StartsOnNewLine);
            newLine = false;
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
        pos       = res.value() + 1;
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
    auto foundIE11Comment = false;
    do
    {
        auto res         = editor.Find(0, "/*@cc_on", true);
        foundIE11Comment = false;
        if (res.has_value())
        {
            auto next = editor.Find(res.value(), "@*/");
            if (next.has_value())
            {
                editor.Delete(next.value(), 3);
                editor.Delete(res.value(), 8);
                foundIE11Comment = true;
            }
        }
    } while (foundIE11Comment);
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
    if (TokenType::IsOperator(id))
    {
        str.Set("Operator");
    }
}
void JSFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    syntax.tokens.ResetLastTokenID(TokenType::None);
    Tokenize(syntax.text, syntax.tokens, syntax.blocks);
    BuildBlocks(syntax);
    OperatorAlignament(syntax.tokens);
    IndentSimpleInstructions(syntax.tokens);
    CreateFoldUnfoldLinks(syntax);
}
void JSFile::OperatorAlignament(GView::View::LexicalViewer::TokensList& tokenList)
{
    auto len = tokenList.Len();
    for (auto index = 0u; index < len; index++)
    {
        Token t = tokenList[index];
        if (t.GetTypeID(TokenType::None) == TokenType::Operator_MemberAccess)
        {
            t.Next().UpdateAlignament(TokenAlignament::AfterPreviousToken, TokenAlignament::AddSpaceBefore);
        }

        if (t.GetTypeID(TokenType::None) == TokenType::Keyword_For && t.Next().GetTypeID(TokenType::None) == TokenType::ExpressionOpen)
        {
            auto idx = index + 1;
            auto end = t.Next().GetBlock().GetEndToken().GetIndex();
            for (; idx < end; idx++)
            {
                Token t2 = tokenList[idx];
                if (t2.GetTypeID(TokenType::None) == TokenType::Semicolumn)
                {
                    t2.Precedent().UpdateAlignament(TokenAlignament::None, TokenAlignament::AddSpaceAfter);
                    t2.SetAlignament(TokenAlignament::AddSpaceAfter);
                }
            }
            Token t3 = tokenList[end + 1];
            if (t3.GetTypeID(TokenType::None) == TokenType::BlockOpen)
            {
                t.SetBlock(t3.GetBlock());
            }
        }
    }
}
} // namespace GView::Type::JS