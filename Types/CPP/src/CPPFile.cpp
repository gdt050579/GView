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
    constexpr uint32 Keyword         = 14;
    constexpr uint32 Constant        = 15;
    constexpr uint32 Datatype        = 16;

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
} // namespace OperatorType
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
struct HashText
{
    uint32 hash;
    uint32 id;
};
HashText* BinarySearch(uint32 hash, HashText* list, int32 elementsCount)
{
    if (elementsCount <= 0)
        return nullptr;
    auto start = 0;
    auto end   = elementsCount - 1;
    while (start <= end)
    {
        auto mij   = (start + end) >> 1;
        auto h_mij = list[mij].hash;
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
        return list + mij;
    }
    return nullptr;
}

namespace KeywordsType
{
    constexpr uint32 Atomic_commit            = 0;
    constexpr uint32 While                    = 1;
    constexpr uint32 Import                   = 2;
    constexpr uint32 Reinterpret_cast         = 3;
    constexpr uint32 Asm                      = 4;
    constexpr uint32 Final                    = 5;
    constexpr uint32 Typename                 = 6;
    constexpr uint32 Protected                = 7;
    constexpr uint32 Typedef                  = 8;
    constexpr uint32 New                      = 9;
    constexpr uint32 Register                 = 10;
    constexpr uint32 If                       = 11;
    constexpr uint32 Mutable                  = 12;
    constexpr uint32 Catch                    = 13;
    constexpr uint32 Const_cast               = 14;
    constexpr uint32 Reflexpr                 = 15;
    constexpr uint32 Constexpr                = 16;
    constexpr uint32 Virtual                  = 17;
    constexpr uint32 Noexcept                 = 18;
    constexpr uint32 Do                       = 19;
    constexpr uint32 Private                  = 20;
    constexpr uint32 Const                    = 21;
    constexpr uint32 Dynamic_cast             = 22;
    constexpr uint32 Delete                   = 23;
    constexpr uint32 Explicit                 = 24;
    constexpr uint32 Template                 = 25;
    constexpr uint32 Using                    = 26;
    constexpr uint32 Sizeof                   = 27;
    constexpr uint32 Throw                    = 28;
    constexpr uint32 Enum                     = 29;
    constexpr uint32 Return                   = 30;
    constexpr uint32 Extern                   = 31;
    constexpr uint32 Auto                     = 32;
    constexpr uint32 Struct                   = 33;
    constexpr uint32 Default                  = 34;
    constexpr uint32 Switch                   = 35;
    constexpr uint32 Volatile                 = 36;
    constexpr uint32 Case                     = 37;
    constexpr uint32 Requires                 = 38;
    constexpr uint32 Transaction_safe         = 39;
    constexpr uint32 Concept                  = 40;
    constexpr uint32 Transaction_safe_dynamic = 41;
    constexpr uint32 Static_cast              = 42;
    constexpr uint32 Typeid                   = 43;
    constexpr uint32 Class                    = 44;
    constexpr uint32 Try                      = 45;
    constexpr uint32 For                      = 46;
    constexpr uint32 Continue                 = 47;
    constexpr uint32 Else                     = 48;
    constexpr uint32 Compl                    = 49;
    constexpr uint32 Decltype                 = 50;
    constexpr uint32 Inline                   = 51;
    constexpr uint32 Override                 = 52;
    constexpr uint32 Consteval                = 53;
    constexpr uint32 Alignof                  = 54;
    constexpr uint32 Break                    = 55;
    constexpr uint32 Namespace                = 56;
    constexpr uint32 Friend                   = 57;
    constexpr uint32 Public                   = 58;
    constexpr uint32 Thread_local             = 59;
    constexpr uint32 Co_return                = 60;
    constexpr uint32 Static                   = 61;
    constexpr uint32 Co_await                 = 62;
    constexpr uint32 Module                   = 63;
    constexpr uint32 Atomic_cancel            = 64;
    constexpr uint32 This                     = 65;
    constexpr uint32 Union                    = 66;
    constexpr uint32 Alignas                  = 67;
    constexpr uint32 Synchronized             = 68;
    constexpr uint32 Goto                     = 69;
    constexpr uint32 Constinit                = 70;
    constexpr uint32 Co_yield                 = 71;
    constexpr uint32 Export                   = 72;
    constexpr uint32 Atomic_noexcept          = 73;
    constexpr uint32 Static_assert            = 74;
    constexpr uint32 Operator                 = 75;
} // namespace KeywordsType
namespace Keyword
{
    HashText list[] = {
        { 0x049E68E4, KeywordsType::Atomic_commit }, { 0x0DC628CE, KeywordsType::While },
        { 0x112A90D4, KeywordsType::Import },        { 0x13251E95, KeywordsType::Reinterpret_cast },
        { 0x1472C0A0, KeywordsType::Asm },           { 0x159AC2B7, KeywordsType::Final },
        { 0x19A9984E, KeywordsType::Typename },      { 0x1E54727D, KeywordsType::Protected },
        { 0x221EDE24, KeywordsType::Typedef },       { 0x28999611, KeywordsType::New },
        { 0x2D6871C0, KeywordsType::Register },      { 0x39386E06, KeywordsType::If },
        { 0x3B0333A9, KeywordsType::Mutable },       { 0x4288E94C, KeywordsType::Catch },
        { 0x44E4E5F2, KeywordsType::Const_cast },    { 0x4ED2A4FD, KeywordsType::Reflexpr },
        { 0x5AA35603, KeywordsType::Constexpr },     { 0x5D967EBC, KeywordsType::Virtual },
        { 0x61338257, KeywordsType::Noexcept },      { 0x621CD814, KeywordsType::Do },
        { 0x62CB0D0C, KeywordsType::Private },       { 0x664FD1D4, KeywordsType::Const },
        { 0x676A80DC, KeywordsType::Dynamic_cast },  { 0x67C2444A, KeywordsType::Delete },
        { 0x68E79149, KeywordsType::Explicit },      { 0x694AAA0B, KeywordsType::Template },
        { 0x69CE1407, KeywordsType::Using },         { 0x6EE13AFD, KeywordsType::Sizeof },
        { 0x7A78762F, KeywordsType::Throw },         { 0x816CB000, KeywordsType::Enum },
        { 0x85EE37BF, KeywordsType::Return },        { 0x9087DDB7, KeywordsType::Extern },
        { 0x923FA396, KeywordsType::Auto },          { 0x92C2BE20, KeywordsType::Struct },
        { 0x933B5BDE, KeywordsType::Default },       { 0x93E05F71, KeywordsType::Switch },
        { 0x94E1036D, KeywordsType::Volatile },      { 0x9B2538B1, KeywordsType::Case },
        { 0x9B8CAA55, KeywordsType::Requires },      { 0xA01A5581, KeywordsType::Transaction_safe },
        { 0xA3383D13, KeywordsType::Concept },       { 0xA4F6AD07, KeywordsType::Transaction_safe_dynamic },
        { 0xA7226423, KeywordsType::Static_cast },   { 0xA8953BD8, KeywordsType::Typeid },
        { 0xAB3E0BFF, KeywordsType::Class },         { 0xAC1DB00E, KeywordsType::Try },
        { 0xACF38390, KeywordsType::For },           { 0xB1727E44, KeywordsType::Continue },
        { 0xBDBF5BF0, KeywordsType::Else },          { 0xBEEDB7F2, KeywordsType::Compl },
        { 0xBEF43EA5, KeywordsType::Decltype },      { 0xC2CB5034, KeywordsType::Inline },
        { 0xC4B95C3D, KeywordsType::Override },      { 0xC9101B72, KeywordsType::Consteval },
        { 0xC919731F, KeywordsType::Alignof },       { 0xC9648178, KeywordsType::Break },
        { 0xCACE7AA0, KeywordsType::Namespace },     { 0xCBA09F8D, KeywordsType::Friend },
        { 0xCC909380, KeywordsType::Public },        { 0xCD3C1AA1, KeywordsType::Thread_local },
        { 0xD27D73DE, KeywordsType::Co_return },     { 0xD290C23B, KeywordsType::Static },
        { 0xD34FD592, KeywordsType::Co_await },      { 0xD79F909D, KeywordsType::Module },
        { 0xD994FC43, KeywordsType::Atomic_cancel }, { 0xDA2BD281, KeywordsType::This },
        { 0xDBDED6F4, KeywordsType::Union },         { 0xEC3C3C7A, KeywordsType::Alignas },
        { 0xF112B61B, KeywordsType::Synchronized },  { 0xF5A30FE6, KeywordsType::Goto },
        { 0xF6522276, KeywordsType::Constinit },     { 0xF874CA49, KeywordsType::Co_yield },
        { 0xFB080CB3, KeywordsType::Export },        { 0xFB60E40F, KeywordsType::Atomic_noexcept },
        { 0xFB9673DE, KeywordsType::Static_assert }, { 0xFBD4EEFD, KeywordsType::Operator },
    };
    uint32 TextToKeywordID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
    {
        auto* res = BinarySearch(text.ComputeHash32(start, end, false), list, 76);
        if (res == nullptr)
            return TokenType::None;
        return TokenType::Keyword | (res->id << 16);
    };
} // namespace Keyword
namespace ConstantsType
{
    constexpr uint32 False   = 0;
    constexpr uint32 Nullptr = 1;
    constexpr uint32 True    = 2;
    constexpr uint32 Null    = 3;
} // namespace ConstantsType
namespace Constant
{
    HashText list[] = {
        { 0x0B069958, ConstantsType::False },
        { 0x0BBDE79E, ConstantsType::Nullptr },
        { 0x4DB211E5, ConstantsType::True },
        { 0x77074BA4, ConstantsType::Null },
    };
    uint32 TextToConstantID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
    {
        auto* res = BinarySearch(text.ComputeHash32(start, end, false), list, 4);
        if (res == nullptr)
            return TokenType::None;
        return TokenType::Constant | (res->id << 16);
    };
} // namespace Constant
namespace DatatypesType
{
    constexpr uint32 Unsigned       = 0;
    constexpr uint32 Int16_t        = 1;
    constexpr uint32 String         = 2;
    constexpr uint32 String_view    = 3;
    constexpr uint32 Uint8_t        = 4;
    constexpr uint32 Int8_t         = 5;
    constexpr uint32 Void           = 6;
    constexpr uint32 Wstring_view   = 7;
    constexpr uint32 Wstring        = 8;
    constexpr uint32 Char8_t        = 9;
    constexpr uint32 U16string      = 10;
    constexpr uint32 Uint64_t       = 11;
    constexpr uint32 U32string_view = 12;
    constexpr uint32 Int64_t        = 13;
    constexpr uint32 Size_t         = 14;
    constexpr uint32 Char16_t       = 15;
    constexpr uint32 U32string      = 16;
    constexpr uint32 Int            = 17;
    constexpr uint32 Uint16_t       = 18;
    constexpr uint32 Double         = 19;
    constexpr uint32 U16string_view = 20;
    constexpr uint32 Float          = 21;
    constexpr uint32 Char32_t       = 22;
    constexpr uint32 Char           = 23;
    constexpr uint32 Signed         = 24;
    constexpr uint32 U8string       = 25;
    constexpr uint32 Short          = 26;
    constexpr uint32 Int32_t        = 27;
    constexpr uint32 Long           = 28;
    constexpr uint32 Wchar_t        = 29;
    constexpr uint32 Bool           = 30;
    constexpr uint32 Uint32_t       = 31;
    constexpr uint32 U8string_view  = 32;
} // namespace DatatypesType
namespace Datatype
{
    HashText list[] = {
        { 0x0C547726, DatatypesType::Unsigned },       { 0x0DFE5EDA, DatatypesType::Int16_t },
        { 0x17C16538, DatatypesType::String },         { 0x210B6458, DatatypesType::String_view },
        { 0x306340A8, DatatypesType::Uint8_t },        { 0x40FFA2F9, DatatypesType::Int8_t },
        { 0x48B5725F, DatatypesType::Void },           { 0x504690E9, DatatypesType::Wstring_view },
        { 0x50736EE7, DatatypesType::Wstring },        { 0x5807E43C, DatatypesType::Char8_t },
        { 0x5C5F1A4A, DatatypesType::U16string },      { 0x682FE470, DatatypesType::Uint64_t },
        { 0x7167ED94, DatatypesType::U32string_view }, { 0x7270198F, DatatypesType::Int64_t },
        { 0x7C6A8FB7, DatatypesType::Size_t },         { 0x801A266D, DatatypesType::Char16_t },
        { 0x86A803CC, DatatypesType::U32string },      { 0x95E97E5E, DatatypesType::Int },
        { 0x96C45519, DatatypesType::Uint16_t },       { 0xA0EB0F08, DatatypesType::Double },
        { 0xA6BB769A, DatatypesType::U16string_view }, { 0xA6C45D85, DatatypesType::Float },
        { 0xA846FC93, DatatypesType::Char32_t },       { 0xA84C031D, DatatypesType::Char },
        { 0xB5712015, DatatypesType::Signed },         { 0xB71DD581, DatatypesType::U8string },
        { 0xBA226BD5, DatatypesType::Short },          { 0xC04A1FBC, DatatypesType::Int32_t },
        { 0xC2ECDF53, DatatypesType::Long },           { 0xC523B9F1, DatatypesType::Wchar_t },
        { 0xC894953D, DatatypesType::Bool },           { 0xE9B20787, DatatypesType::Uint32_t },
        { 0xF277D373, DatatypesType::U8string_view },
    };
    uint32 TextToDatatypeID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
    {
        auto* res = BinarySearch(text.ComputeHash32(start, end, false), list, 33);
        if (res == nullptr)
            return TokenType::None;
        return TokenType::Datatype | (res->id << 16);
    };
} // namespace Datatype

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
                               Operator,   Operator, Comma,      Operator,   Operator,  Operator,       Number,
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
    auto tokColor = TokenColor::Word;
    auto tokType  = Keyword::TextToKeywordID(text, pos, next);
    auto align    = TokenAlignament::None;
    auto opID     = 0U;
    if (tokType == TokenType::None)
    {
        tokType = Constant::TextToConstantID(text, pos, next);
        if (tokType == TokenType::None)
        {
            tokType = Datatype::TextToDatatypeID(text, pos, next);
            if (tokType == TokenType::None)
            {
                tokType = TokenType::Word;
            }
            else
            {
                tokColor = TokenColor::Datatype;
            }
        }
        else
        {
            tokColor = TokenColor::Constant;
        }
        auto lastTokenID = tokenList.GetLastTokenID();
        switch (lastTokenID & 0xFFFF)
        {
        case TokenType::ArrayOpen:
        case TokenType::ExpressionOpen:
            align = TokenAlignament::None;
            break;
        case TokenType::Operator:
            opID  = lastTokenID >> 16;
            align = TokenAlignament::None;
            if ((opID != OperatorType::MemberAccess) && (opID != OperatorType::Namespace) && (opID != OperatorType::Pointer) &&
                (opID != OperatorType::TWO_POINTS))
                align = TokenAlignament::AddSpaceBefore;

            break;
        default:
            align = TokenAlignament::AddSpaceBefore;
            break;
        }
    }
    else
    {
        tokColor = TokenColor::Keyword;
        align    = TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore;
        if (((tokType >> 16) == KeywordsType::Else) && (tokenList.GetLastTokenID() == TokenType::BlockClose))
        {
            // if (...) { ... } else ...
            align = align | TokenAlignament::AfterPreviousToken;
        }
    }

    tokenList.Add(tokType, pos, next, tokColor, align);
    return next;
}
uint32 CPPFile::TokenizeOperator(const GView::View::LexicalViewer::TextParser& text, TokensList& tokenList, uint32 pos)
{
    auto next = text.ParseSameGroupID(pos, CharType::GetCharType);
    auto txt  = text.GetSubString(pos, next);
    uint32 tokenType, sz;
    if (Operators::TextToOperatorID(txt.data(), (uint32) txt.size(), tokenType, sz))
    {
        TokenAlignament align = TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter;
        auto opType           = tokenType >> 16;
        if ((opType == OperatorType::Namespace) || (opType == OperatorType::Pointer) || (opType == OperatorType::MemberAccess) ||
            (opType == OperatorType::TWO_POINTS))
            align = TokenAlignament::AfterPreviousToken;
        if (opType == OperatorType::Namespace)
        {
            if (tokenList.GetLastTokenID() == TokenType::Word)
                tokenList.GetLastToken().SetTokenColor(TokenColor::Keyword2);
        }
        tokenList.Add(tokenType, pos, pos + sz, TokenColor::Operator, TokenDataType::None, align, true);
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
void CPPFile::BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax)
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
            syntax.blocks.Add(stBlocks.Pop(), index, BlockAlignament::ToRightOfCurrentBlock, true);
            break;
        case TokenType::ExpressionOpen:
            exprBlocks.Push(index);
            break;
        case TokenType::ExpressionClose:
            syntax.blocks.Add(exprBlocks.Pop(), index, BlockAlignament::AsBlockStartToken, true);
            break;
        }
    }
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
                  TokenAlignament::NewLineAfter | TokenAlignament::AddSpaceBefore,
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
                  TokenAlignament::StartsOnNewLine | TokenAlignament::NewLineAfter,
                  true);
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
                  TokenAlignament::NewLineAfter | TokenAlignament::AfterPreviousToken,
                  true);
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
                  TokenAlignament::NewLineAfter | TokenAlignament::NewLineBefore,
                  true);
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
void CPPFile::IndentSimpleInstructions(GView::View::LexicalViewer::TokensList& list)
{
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
                            nextTok.UpdateAlignament(TokenAlignament::StartsOnNewLineWithIndent);
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
    }
}
void CPPFile::CreateFoldUnfoldLinks(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    /* Search for the following cases
     * for|if|while|switch (...) {...} and add collapse/expand on for|if and while
     * word (...) {...} or word (...) cons {...} and add collapse/expand on word
     * do {...} while (...) -> both do and while should compact the {...}
     */
    auto len = syntax.blocks.Len();
    for (auto idx = 0U; idx < len; idx++)
    {
        auto block = syntax.blocks[idx];
        // search for {...} blocks
        auto startToken = block.GetStartToken();
        if (startToken.GetTypeID(TokenType::None) != TokenType::BlockOpen)
            continue;
        auto precToken   = startToken.Precedent();
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
        auto targetToken   = precToken.GetBlock().GetStartToken().Precedent();
        auto targetTokenID = targetToken.GetTypeID(TokenType::None);
        if ((targetTokenID == TokenType::Word) || ((targetTokenID & 0xFFFF) == TokenType::Keyword))
        {
            // all good
            targetToken.SetBlock(block);
        }
    }
}
void CPPFile::RemoveLineContinuityCharacter(TextEditor& editor)
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
void CPPFile::PreprocessText(GView::View::LexicalViewer::TextEditor& editor)
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
void CPPFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    syntax.tokens.ResetLastTokenID(TokenType::None);
    Tokenize(syntax.text, syntax.tokens);
    BuildBlocks(syntax);
    IndentSimpleInstructions(syntax.tokens);
    CreateFoldUnfoldLinks(syntax);
}
} // namespace GView::Type::CPP