#include "cpp.hpp"

namespace GView::Type::CPP
{
using namespace GView::View::LexicalViewer;
namespace TokenType
{
    constexpr uint32 Comment = 0;

} // namespace TokenType

namespace CharType
{
    constexpr uint8 Word            = 0;
    constexpr uint8 Number          = 1;
    constexpr uint8 Operator        = 2;
    constexpr uint8 Comma           = 3;
    constexpr uint8 Semicolumn      = 4;
    constexpr uint8 Preprocess      = 5;
    constexpr uint8 String          = 6;
    constexpr uint8 BlockOpen       = 7;
    constexpr uint8 BlockClose      = 8;
    constexpr uint8 ArrayOpen       = 9;
    constexpr uint8 ArrayClose      = 10;
    constexpr uint8 ExpressionOpen  = 11;
    constexpr uint8 ExpressionClose = 12;
    constexpr uint8 Space           = 13;
    constexpr uint8 Invalid         = 14;

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

void CPPFile::AnalyzeText(const TextParser& text, TokensList& tokenList)
{
}
} // namespace GView::Type::CPP