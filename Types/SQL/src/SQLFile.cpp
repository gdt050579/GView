#include "sql.hpp"

namespace GView::Type::SQL
{
    using namespace GView::View::LexicalViewer;

    struct HashText {
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

    namespace OperatorType
    {
        constexpr uint32 Bigger        = 0;
        constexpr uint32 Smaller       = 1;
        constexpr uint32 Equal         = 2;
        constexpr uint32 BiggerOrEq    = 3;
        constexpr uint32 SmallerOrEq   = 4;
        constexpr uint32 Different     = 5;
        /*constexpr uint32 Different2     = 6;*/
        constexpr uint32 Plus          = 7;
        constexpr uint32 Minus         = 8;
        constexpr uint32 Multiply      = 9;
        constexpr uint32 Division      = 10;
        constexpr uint32 Modulo        = 11;
        constexpr uint32 MemberAccess  = 12;
        constexpr uint32 Comma         = 13;
        constexpr uint32 Semicolumn    = 14;
        constexpr uint32 ParenOpen     = 15;
        constexpr uint32 ParenClose    = 16;
        constexpr uint32 Concat        = 17;
        constexpr uint32 Cast          = 18;
        constexpr uint32 JsonArrow     = 19;
        constexpr uint32 JsonArrowText = 20;
    } // namespace OperatorType

    namespace Operators
    {
        uint8 chars_ids[128]                     = { 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0, 0, 0,  0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0, 0, 0,
                                                     0, 4, 0, 0, 0, 9, 0, 0, 13, 14, 7, 5, 11, 6, 10, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 12, 2,  3, 1, 0,
                                                     0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0, 0, 0,  0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0, 0, 0,
                                                     0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0, 0, 0,  0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  15, 0, 0, 0 };
        constexpr uint32 HASH_DEVIDER            = 50;
        uint32 operator_hash_table[HASH_DEVIDER] = { TokenType::None,
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Bigger << 8) | (uint32) (990687777 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Smaller << 8) | (uint32) (957132539 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Equal << 8) | (uint32) (940354920 << 16),
                                                     TokenType::None,
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Plus << 8) | (uint32) (772578730 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Minus << 8) | (uint32) (671913016 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Multiply << 8) | (uint32) (789356349 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Division << 8) | (uint32) (705468254 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Modulo << 8) | (uint32) (537692064 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::MemberAccess << 8) | (uint32) (722245873 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Comma << 8) | (uint32) (688690635 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Semicolumn << 8) | (uint32) (1041020634 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::ParenOpen << 8) | (uint32) (755801111 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::ParenClose << 8) | (uint32) (739023492 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Different << 8) | (uint32) (2482446367 << 16),
                                                     TokenType::None,
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::SmallerOrEq << 8) | (uint32) (2499223986 << 16),
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::JsonArrowText << 8) | (uint32) (1371494052 << 16),
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Cast << 8) | (uint32) (2550542581 << 16),
                                                     TokenType::None,
                                                     TokenType::None,
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Different << 8) | (uint32) (2428715011 << 16),
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::BiggerOrEq << 8) | (uint32) (284975636 << 16),
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::JsonArrow << 8) | (uint32) (298648946 << 16),
                                                     TokenType::None,
                                                     (uint32) TokenType::Operator | (uint32) (OperatorType::Concat << 8) | (uint32) (1431891397 << 16),
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None,
                                                     TokenType::None };

        bool TextToOperatorID(const char16* txt, uint32 size, uint32& opID, uint32& opSize)
        {
            // compute the hashes over the entire 3 cases
            uint32 hash1 = 0, hash2 = 0, hash3 = 0;
            if (((*txt) < 128) && (chars_ids[*txt] != 0)) {
                hash1 = chars_ids[*txt];
                txt++;
                if ((size > 1) && ((*txt) < 128) && (chars_ids[*txt] != 0)) {
                    hash2 = (hash1 << 5) + chars_ids[*txt];
                    txt++;
                    if ((size > 2) && ((*txt) < 128) && (chars_ids[*txt] != 0))
                        hash3 = (hash2 << 5) + chars_ids[*txt];
                }
            }
            auto op = operator_hash_table[hash3 % HASH_DEVIDER];
            if ((op != TokenType::None) && ((op >> 16) == hash3)) {
                opID   = (op & 0xFF) | ((op & 0xFF00) << 8);
                opSize = 3;
                return true;
            }
            op = operator_hash_table[hash2 % HASH_DEVIDER];
            if ((op != TokenType::None) && ((op >> 16) == hash2)) {
                opID   = (op & 0xFF) | ((op & 0xFF00) << 8);
                opSize = 2;
                return true;
            }
            op = operator_hash_table[hash1 % HASH_DEVIDER];
            if ((op != TokenType::None) && ((op >> 16) == hash1)) {
                opID   = (op & 0xFF) | ((op & 0xFF00) << 8);
                opSize = 1;
                return true;
            }
            return false; // invalid operator
        }
    } // namespace Operators

    namespace KeywordsType
    {
        constexpr uint32 Where       = 0;
        constexpr uint32 Index       = 1;
        constexpr uint32 False       = 2;
        constexpr uint32 Like        = 3;
        constexpr uint32 With        = 4;
        constexpr uint32 And         = 5;
        constexpr uint32 Select      = 6;
        constexpr uint32 Left        = 7;
        constexpr uint32 Explain     = 8;
        constexpr uint32 All         = 9;
        constexpr uint32 Offset      = 10;
        constexpr uint32 Alter       = 11;
        constexpr uint32 Create      = 12;
        constexpr uint32 Update      = 13;
        constexpr uint32 Not         = 14;
        constexpr uint32 Cross       = 15;
        constexpr uint32 Distinct    = 16;
        constexpr uint32 Into        = 17;
        constexpr uint32 Over        = 18;
        constexpr uint32 Limit       = 19;
        constexpr uint32 Commit      = 20;
        constexpr uint32 Values      = 21;
        constexpr uint32 Except      = 22;
        constexpr uint32 Exists      = 23;
        constexpr uint32 Unique      = 24;
        constexpr uint32 In          = 25;
        constexpr uint32 Truncate    = 26;
        constexpr uint32 Table       = 27;
        constexpr uint32 True        = 28;
        constexpr uint32 Is          = 29;
        constexpr uint32 Schema      = 30;
        constexpr uint32 Foreign     = 31;
        constexpr uint32 By          = 32;
        constexpr uint32 Primary     = 33;
        constexpr uint32 Recursive   = 34;
        constexpr uint32 Or          = 35;
        constexpr uint32 As          = 36;
        constexpr uint32 Group       = 37;
        constexpr uint32 On          = 38;
        constexpr uint32 References  = 39;
        constexpr uint32 Delete      = 40;
        constexpr uint32 Key         = 41;
        constexpr uint32 Begin       = 42;
        constexpr uint32 Using       = 43;
        constexpr uint32 End         = 44;
        constexpr uint32 Nullif      = 45;
        constexpr uint32 Order       = 46;
        constexpr uint32 Transaction = 47;
        constexpr uint32 Null        = 48;
        constexpr uint32 Right       = 49;
        constexpr uint32 Rollback    = 50;
        constexpr uint32 Generated   = 51;
        constexpr uint32 When        = 52;
        constexpr uint32 Coalesce    = 53;
        constexpr uint32 Analyze     = 54;
        constexpr uint32 Default     = 55;
        constexpr uint32 From        = 56;
        constexpr uint32 Privileges  = 57;
        constexpr uint32 Case        = 58;
        constexpr uint32 Unknown     = 59;
        constexpr uint32 Database    = 60;
        constexpr uint32 Window      = 61;
        constexpr uint32 Between     = 62;
        constexpr uint32 Identity    = 63;
        constexpr uint32 Drop        = 64;
        constexpr uint32 Savepoint   = 65;
        constexpr uint32 Cast        = 66;
        constexpr uint32 Fetch       = 67;
        constexpr uint32 Grant       = 68;
        constexpr uint32 Check       = 69;
        constexpr uint32 Constraint  = 70;
        constexpr uint32 Merge       = 71;
        constexpr uint32 Else        = 72;
        constexpr uint32 Set         = 73;
        constexpr uint32 Insert      = 74;
        constexpr uint32 Join        = 75;
        constexpr uint32 Public      = 76;
        constexpr uint32 Inner       = 77;
        constexpr uint32 Partition   = 78;
        constexpr uint32 Having      = 79;
        constexpr uint32 View        = 80;
        constexpr uint32 Union       = 81;
        constexpr uint32 Revoke      = 82;
        constexpr uint32 Then        = 83;
        constexpr uint32 Intersect   = 84;
        constexpr uint32 Full        = 85;
    } // namespace KeywordsType
    namespace Keyword
    {
        HashText list[] = {
            { 0x056C1458, KeywordsType::Where },      { 0x090AA9AB, KeywordsType::Index },      { 0x0B069958, KeywordsType::False },
            { 0x0BE7CF36, KeywordsType::Like },       { 0x0C4AFE69, KeywordsType::With },       { 0x0F29C2A6, KeywordsType::And },
            { 0x11C2662D, KeywordsType::Select },     { 0x124AEC70, KeywordsType::Left },       { 0x1271AB5C, KeywordsType::Explain },
            { 0x13254BC4, KeywordsType::All },        { 0x14C8D3CA, KeywordsType::Offset },     { 0x22CE6F6B, KeywordsType::Alter },
            { 0x26BB595D, KeywordsType::Create },     { 0x280F9474, KeywordsType::Update },     { 0x29B19C8A, KeywordsType::Not },
            { 0x29F5189B, KeywordsType::Cross },      { 0x2AE09C8D, KeywordsType::Distinct },   { 0x2F91A723, KeywordsType::Into },
            { 0x31F6520F, KeywordsType::Over },       { 0x32DAD934, KeywordsType::Limit },      { 0x334BD0FC, KeywordsType::Commit },
            { 0x34474C3B, KeywordsType::Values },     { 0x38ADCBF0, KeywordsType::Except },     { 0x3BBE55BD, KeywordsType::Exists },
            { 0x3DBE3B26, KeywordsType::Unique },     { 0x41387A9E, KeywordsType::In },         { 0x423C87B7, KeywordsType::Truncate },
            { 0x4A9C9BDF, KeywordsType::Table },      { 0x4DB211E5, KeywordsType::True },       { 0x4E388F15, KeywordsType::Is },
            { 0x527D0336, KeywordsType::Schema },     { 0x52D19DF3, KeywordsType::Foreign },    { 0x542BCC94, KeywordsType::By },
            { 0x5A2E5FD9, KeywordsType::Primary },    { 0x5BEE3C77, KeywordsType::Recursive },  { 0x5D342984, KeywordsType::Or },
            { 0x5E25208D, KeywordsType::As },         { 0x5FB91E8C, KeywordsType::Group },      { 0x61342FD0, KeywordsType::On },
            { 0x6392F7CB, KeywordsType::References }, { 0x67C2444A, KeywordsType::Delete },     { 0x6815C86C, KeywordsType::Key },
            { 0x68348A7E, KeywordsType::Begin },      { 0x69CE1407, KeywordsType::Using },      { 0x6A8E75AA, KeywordsType::End },
            { 0x6BB7F203, KeywordsType::Nullif },     { 0x732C1097, KeywordsType::Order },      { 0x75095723, KeywordsType::Transaction },
            { 0x77074BA4, KeywordsType::Null },       { 0x78E32DE5, KeywordsType::Right },      { 0x7CCAD87D, KeywordsType::Rollback },
            { 0x7CDD4142, KeywordsType::Generated },  { 0x7F778519, KeywordsType::When },       { 0x861CB29A, KeywordsType::Coalesce },
            { 0x8C7100D3, KeywordsType::Analyze },    { 0x933B5BDE, KeywordsType::Default },    { 0x95CD8075, KeywordsType::From },
            { 0x980B85ED, KeywordsType::Privileges }, { 0x9B2538B1, KeywordsType::Case },       { 0x9B759FB9, KeywordsType::Unknown },
            { 0xA165DDB8, KeywordsType::Database },   { 0xA172B7DD, KeywordsType::Window },     { 0xA4EE076F, KeywordsType::Between },
            { 0xA945349B, KeywordsType::Identity },   { 0xA9A58D8C, KeywordsType::Drop },       { 0xA9BAD65E, KeywordsType::Savepoint },
            { 0xAA25504E, KeywordsType::Cast },       { 0xAD7EBFE3, KeywordsType::Fetch },      { 0xB155676D, KeywordsType::Grant },
            { 0xB3711C47, KeywordsType::Check },      { 0xB822E25A, KeywordsType::Constraint }, { 0xB9764627, KeywordsType::Merge },
            { 0xBDBF5BF0, KeywordsType::Else },       { 0xC6270703, KeywordsType::Set },        { 0xC6A39628, KeywordsType::Insert },
            { 0xC922BC79, KeywordsType::Join },       { 0xCC909380, KeywordsType::Public },     { 0xD8DE6A27, KeywordsType::Inner },
            { 0xD9095409, KeywordsType::Partition },  { 0xDAECDD5C, KeywordsType::Having },     { 0xDBA4F4F8, KeywordsType::View },
            { 0xDBDED6F4, KeywordsType::Union },      { 0xDC064A33, KeywordsType::Revoke },     { 0xE522E976, KeywordsType::Then },
            { 0xF05A4AE6, KeywordsType::Intersect },  { 0xFF79B33C, KeywordsType::Full },
        };
        uint32 TextToKeywordID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
        {
            auto* res = BinarySearch(text.ComputeHash32(start, end, false), list, 86);
            if (res == nullptr)
                return TokenType::None;
            return TokenType::Keyword | (res->id << 16);
        };
    }

    namespace ConstantsType
    {
        constexpr uint32 False = 0;
        constexpr uint32 True  = 1;
        constexpr uint32 Null  = 2;
    } // namespace ConstantsType
    namespace Constant
    {
        HashText list[] = {
            { 0x0B069958, ConstantsType::False },
            { 0x4DB211E5, ConstantsType::True },
            { 0x77074BA4, ConstantsType::Null },
        };
        uint32 TextToConstantID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
        {
            auto* res = BinarySearch(text.ComputeHash32(start, end, false), list, 3);
            if (res == nullptr)
                return TokenType::None;
            return TokenType::Constant | (res->id << 16);
        };
    }

    namespace DatatypesType
    {
        constexpr uint32 Decimal           = 0;
        constexpr uint32 Jsonb             = 1;
        constexpr uint32 Uuid              = 2;
        constexpr uint32 Json              = 3;
        constexpr uint32 Timestamptz       = 4;
        constexpr uint32 Nvarchar          = 5;
        constexpr uint32 Time              = 6;
        constexpr uint32 Character_varying = 7;
        constexpr uint32 Blob              = 8;
        constexpr uint32 Boolean           = 9;
        constexpr uint32 Numeric           = 10;
        constexpr uint32 Doubleprecision   = 11;
        constexpr uint32 Bytea             = 12;
        constexpr uint32 Smallint          = 13;
        constexpr uint32 Bigint            = 14;
        constexpr uint32 Character         = 15;
        constexpr uint32 Int               = 16;
        constexpr uint32 Double            = 17;
        constexpr uint32 Float             = 18;
        constexpr uint32 Char              = 19;
        constexpr uint32 Timestamp         = 20;
        constexpr uint32 Text              = 21;
        constexpr uint32 Integer           = 22;
        constexpr uint32 Varbinary         = 23;
        constexpr uint32 Bool              = 24;
        constexpr uint32 Datetime          = 25;
        constexpr uint32 Interval          = 26;
        constexpr uint32 Timetz            = 27;
        constexpr uint32 Date              = 28;
        constexpr uint32 Real              = 29;
        constexpr uint32 Xml               = 30;
        constexpr uint32 Serial            = 31;
        constexpr uint32 Binary            = 32;
        constexpr uint32 Nchar             = 33;
        constexpr uint32 Bigserial         = 34;
        constexpr uint32 Varchar           = 35;
    } // namespace DatatypesType
    namespace Datatype
    {
        HashText list[] = {
            { 0x1F088D4C, DatatypesType::Decimal },     { 0x217239F3, DatatypesType::Jsonb },
            { 0x278A5432, DatatypesType::Uuid },        { 0x36A1A243, DatatypesType::Json },
            { 0x3A6B561D, DatatypesType::Timestamptz }, { 0x5BC874BE, DatatypesType::Nvarchar },
            { 0x5D3C9BE4, DatatypesType::Time },        { 0x60AB5ED3, DatatypesType::Character_varying },
            { 0x63BCB0AA, DatatypesType::Blob },        { 0x65F46EBF, DatatypesType::Boolean },
            { 0x68F8A468, DatatypesType::Numeric },     { 0x7438DBF4, DatatypesType::Doubleprecision },
            { 0x77B1EC5A, DatatypesType::Bytea },       { 0x819D3215, DatatypesType::Smallint },
            { 0x8A67A5CA, DatatypesType::Bigint },      { 0x8B3AA710, DatatypesType::Character },
            { 0x95E97E5E, DatatypesType::Int },         { 0xA0EB0F08, DatatypesType::Double },
            { 0xA6C45D85, DatatypesType::Float },       { 0xA84C031D, DatatypesType::Char },
            { 0xB283D523, DatatypesType::Timestamp },   { 0xBDE64E3E, DatatypesType::Text },
            { 0xBFD2C445, DatatypesType::Integer },     { 0xC78D68C7, DatatypesType::Varbinary },
            { 0xC894953D, DatatypesType::Bool },        { 0xCCEA6D90, DatatypesType::Datetime },
            { 0xCEDD8578, DatatypesType::Interval },    { 0xD11E96FE, DatatypesType::Timetz },
            { 0xD472DC59, DatatypesType::Date },        { 0xD6DFB05D, DatatypesType::Real },
            { 0xDA706EB6, DatatypesType::Xml },         { 0xDBCDCD79, DatatypesType::Serial },
            { 0xDD856CFC, DatatypesType::Binary },      { 0xE0333069, DatatypesType::Nchar },
            { 0xEC9DFB2D, DatatypesType::Bigserial },   { 0xF82DB032, DatatypesType::Varchar },
        };
        uint32 TextToDatatypeID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end)
        {
            auto* res = BinarySearch(text.ComputeHash32(start, end, false), list, 36);
            if (res == nullptr)
                return TokenType::None;
            return TokenType::Datatype | (res->id << 16);
        };
    }

    namespace CharType
    {
        constexpr uint8 Word              = 0;
        constexpr uint8 Number            = 1;
        constexpr uint8 Operator          = 2;
        constexpr uint8 Comma             = 3;
        constexpr uint8 Semicolumn        = 4;
        constexpr uint8 String            = 6;
        constexpr uint8 BlockOpen         = 7;
        constexpr uint8 BlockClose        = 8;
        constexpr uint8 ArrayOpen         = 9;
        constexpr uint8 ArrayClose        = 10;
        constexpr uint8 ExpressionOpen    = 11;
        constexpr uint8 ExpressionClose   = 12;
        constexpr uint8 Space             = 13;
        constexpr uint8 Invalid           = 14;

        uint8 Sql_Groups_IDs[] = { Invalid,   Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                                   Invalid,   Invalid,  Space,      Space,      Invalid,   Invalid,        Space,
                                   Invalid,   Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                                   Invalid,   Invalid,  Invalid,    Invalid,    Invalid,   Invalid,        Invalid,
                                   Invalid,   Invalid,  Invalid,    Invalid,    Space,     Operator,       String,
                                   Operator,  Operator, Operator,   Operator,   String,    ExpressionOpen, ExpressionClose,
                                   Operator,  Operator, Comma,      Operator,   Operator,  Operator,       Number,
                                   Number,    Number,   Number,     Number,     Number,    Number,         Number,
                                   Number,    Number,   Operator,   Semicolumn, Operator,  Operator,       Operator,
                                   Operator,  Operator, Word,       Word,       Word,      Word,           Word,
                                   Word,      Word,     Word,       Word,       Word,      Word,           Word,
                                   Word,      Word,     Word,       Word,       Word,      Word,           Word,
                                   Word,      Word,     Word,       Word,       Word,      Word,           Word,
                                   ArrayOpen, Operator, ArrayClose, Operator,   Word,      String,         Word,
                                   Word,      Word,     Word,       Word,       Word,      Word,           Word,
                                   Word,      Word,     Word,       Word,       Word,      Word,           Word,
                                   Word,      Word,     Word,       Word,       Word,      Word,           Word,
                                   Word,      Word,     Word,       Word,       BlockOpen, Operator,       BlockClose,
                                   Operator,  Invalid };

            inline uint32 GetCharType(char16 c)
        {
            if (c < ARRAY_LEN(Sql_Groups_IDs))
                return Sql_Groups_IDs[c];
            return Invalid;
        }
    }

	SQLFile::SQLFile()
	{
	}

	bool SQLFile::Update() {
        return true;
	}

    uint32 SQLFile::TokenizeWord(const GView::View::LexicalViewer::TextParser& text, TokensList& tokenList, uint32 pos)
    {
        auto next = text.Parse(pos, [](char16 ch) 
        {
            auto type = CharType::GetCharType(ch);
            return (type == CharType::Word) || (type == CharType::Number);
        });
        auto tokColor   = TokenColor::Word;
        auto tokType    = Keyword::TextToKeywordID(text, pos, next);
        auto align      = TokenAlignament::None;
        auto opID       = 0U;
        auto tokenFlags = TokenFlags::None;

        if (tokType == TokenType::None) {
            tokType = Constant::TextToConstantID(text, pos, next);
            if (tokType == TokenType::None) 
            {
                tokType = Datatype::TextToDatatypeID(text, pos, next);
                if (tokType == TokenType::None) 
                {
                    tokType = TokenType::String;
                } else 
                {
                    tokColor = TokenColor::Datatype;
                }
            } 
            else 
            {
                tokColor   = TokenColor::Constant;
                tokenFlags = TokenFlags::DisableSimilaritySearch;
            }
            auto lastTokenID = tokenList.GetLastTokenID();
            switch (lastTokenID & 0xFFFF) 
            {
            case TokenType::ExpressionOpen:
                align = TokenAlignament::None;
                break;
            case TokenType::Operator:
                opID  = lastTokenID >> 16;
                align = TokenAlignament::None;
                if ((opID != OperatorType::MemberAccess))
                    align = TokenAlignament::AddSpaceBefore;

                break;
            default:
                align = TokenAlignament::AddSpaceBefore;
                break;
            }
        } 
        else 
        {
            tokColor   = TokenColor::Keyword;
            align      = TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore;
            tokenFlags = TokenFlags::DisableSimilaritySearch;
            if (((tokType >> 16) == KeywordsType::Else) && (tokenList.GetLastTokenID() == TokenType::BlockClose))
            {
                // if (...) { ... } else ...
                align = align | TokenAlignament::AfterPreviousToken;
            }
        }

        tokenList.Add(tokType, pos, next, tokColor, TokenDataType::None, align, tokenFlags);
        return next;
    }

    uint32 SQLFile::TokenizeOperator(const GView::View::LexicalViewer::TextParser& text, TokensList& tokenList, uint32 pos)
    {
        auto next = text.ParseSameGroupID(pos, CharType::GetCharType);
        auto txt  = text.GetSubString(pos, next);
        uint32 tokenType, sz;
        if (Operators::TextToOperatorID(txt.data(), (uint32) txt.size(), tokenType, sz)) {
            TokenAlignament align = TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter;
            auto opType           = tokenType >> 16;
            switch (opType) {
            case OperatorType::MemberAccess:
                align = TokenAlignament::AfterPreviousToken;
                break;
            }

            tokenList.Add(tokenType, pos, pos + sz, TokenColor::Operator, TokenDataType::None, align, TokenFlags::DisableSimilaritySearch);
            return pos + sz;
        } else {
            // unknown operator
            tokenList.Add(TokenType::Operator, pos, next, TokenColor::Word).SetError("Invalid C++ operator");
            return next;
        }
    }

    void SQLFile::BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax)
    {
        TokenIndexStack stBlocks;
        TokenIndexStack exprBlocks;
        auto len = syntax.tokens.Len();
        for (auto index = 0U; index < len; index++) {
            auto typeID = syntax.tokens[index].GetTypeID(TokenType::None);
            switch (typeID) {
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
            }
        }
    }

    void SQLFile::Tokenize(const TextParser& text, TokensList& tokenList, BlocksList& blocks)
    {
        Tokenize(0, text.Len(), text, tokenList, blocks);
    }

    void SQLFile::Tokenize(uint32 start, uint32 end, const TextParser& text, TokensList& tokenList, BlocksList& blocks)
    {
        auto idx  = start;
        auto next = 0U;

        while (idx < end) {
            auto ch   = text[idx];
            auto type = CharType::GetCharType(ch);

            switch (type) {
            case CharType::Space:
                idx = text.ParseSpace(idx, SpaceType::All);
                break;
            //case CharType::ArrayOpen:
            //    tokenList.Add(
            //          TokenType::ArrayOpen,
            //          idx,
            //          idx + 1,
            //          TokenColor::Operator,
            //          TokenDataType::None,
            //          TokenAlignament::None,
            //          TokenFlags::DisableSimilaritySearch);
            //    idx++;
            //    break;
            //case CharType::ArrayClose:
            //    tokenList.Add(
            //          TokenType::ArrayClose,
            //          idx,
            //          idx + 1,
            //          TokenColor::Operator,
            //          TokenDataType::None,
            //          TokenAlignament::None,
            //          TokenFlags::DisableSimilaritySearch);
            //    idx++;
            //    break;
            case CharType::ExpressionOpen:
                tokenList.Add(
                      TokenType::ExpressionOpen,
                      idx,
                      idx + 1,
                      TokenColor::Operator,
                      TokenDataType::None,
                      TokenAlignament::None,
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
                      TokenAlignament::None,
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
                      TokenAlignament::NewLineAfter | TokenAlignament::AddSpaceBefore,
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
                tokenList.Add(TokenType::Number, idx, next, TokenColor::Number, TokenDataType::Number);
                idx = next;
                break;
            case CharType::String:
                next = text.ParseString(idx, StringFormat::DoubleQuotes | StringFormat::SingleQuotes | StringFormat::AllowEscapeSequences);
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
            case CharType::Word:
                idx = TokenizeWord(text, tokenList, idx);
                break;
            case CharType::Operator:
                idx = TokenizeOperator(text, tokenList, idx);
                break;
            default:
                next = text.ParseSameGroupID(idx, CharType::GetCharType);
                tokenList.Add(TokenType::String, idx, next, TokenColor::Word).SetError("Invalid character sequance");
                idx = next;
                break;
            }
        }
    }

    void SQLFile::RemoveLineContinuityCharacter(GView::View::LexicalViewer::TextEditor& editor)
    {
        auto pos = 0;
        do {
            auto res = editor.Find(pos, "\\");
            if (!res.has_value())
                break;
            pos       = res.value() + 1;
            auto next = editor[pos];
            if ((next == '\n') || (next == '\r')) {
                auto nextAfterNext = editor[pos + 1];
                if (((nextAfterNext == '\n') || (nextAfterNext == '\r')) && (nextAfterNext != next)) {
                    // case like \CRLF or \LFCR
                    editor.Delete(res.value(), 3);
                } else {
                    // case line \CR or \LF
                    editor.Delete(res.value(), 2);
                }
            }
        } while (true);
    }

    void SQLFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
    {
        switch (id & 0xFFFFFFFF) {
        case TokenType::None:
            str.Set("Unknwon/Error");
            break;
        case TokenType::Comment:
            str.Set("Comment");
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
        case TokenType::Operator:
            str.Set("Operator");
            break;
        case TokenType::Keyword:
            str.Set("Keyword");
            break;
        case TokenType::Constant:
            str.Set("Constant");
            break;
        case TokenType::Datatype:
            str.Set("Data type");
            break;
        }
    }



	void SQLFile::PreprocessText(GView::View::LexicalViewer::TextEditor& editor)
    {
    }

    void SQLFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
    {
        syntax.tokens.ResetLastTokenID(TokenType::None);
        Tokenize(syntax.text, syntax.tokens, syntax.blocks);
        BuildBlocks(syntax);
    }

    bool SQLFile::StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result)
    {
        return TextParser::ExtractContentFromString(string, result, StringFormat::All);
    }

    bool SQLFile::ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result)
    {
        return false;
    }

    GView::Utils::JsonBuilderInterface* SQLFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
    {
        auto builder = GView::Utils::JsonBuilderInterface::Create();
        builder->AddU16String("Name", obj->GetName());
        builder->AddUInt("ContentSize", obj->GetData().GetSize());
        return builder;
    }
}
