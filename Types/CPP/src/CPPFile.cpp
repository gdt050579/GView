#include "cpp.hpp"

namespace GView::Type::CPP
{
using namespace GView::View::LexicalViewer;
namespace TokenType
{
    constexpr uint32 Comment    = 0;

} // namespace TokenType

namespace CharType
{
    constexpr uint8 Word                = 0;


    inline uint32 GetCharType(char16 c)
    {
        //if (c < ARRAY_LEN(Ini_Groups_IDs))
        //    return Ini_Groups_IDs[c];
        return Word;
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
} // namespace GView::Type::INI