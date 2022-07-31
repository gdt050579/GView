#include "ini.hpp"

namespace GView::Type::INI
{
using namespace GView::View::LexicalViewer;

enum class ParserState
{
    ExpectKeyValueOrSection,
    ExpectEqual,
    ExpectValueOrArray,
    ExpectArrayValue
};
namespace CharType
{
    constexpr uint32 Word                = 0;
    constexpr uint32 SpaceOrNewLine      = 1;
    constexpr uint32 Comma               = 2;
    constexpr uint32 Equal               = 3;
    constexpr uint32 String              = 4;
    constexpr uint32 Comment             = 5;
    constexpr uint32 SectionOrArrayStart = 6;
    constexpr uint32 SectionOrArrayEnd   = 7;
    constexpr uint32 Other               = 8;

    inline uint32 GetCharType(char16 c)
    {
        return Other;
    }
} // namespace CharType

INIFile::INIFile()
{
}

bool INIFile::Update()
{
    return true;
}

void INIFile::AnalyzeText(const TextParser& text, TokensList& tokenList)
{
    const auto len = text.Len();
    auto state     = ParserState::ExpectKeyValueOrSection;
    uint32 next    = 0;
    uint32 pos     = 0;

    while (pos < len)
    {
        auto chType = CharType::GetCharType(text[pos]);
        switch (chType)
        {
        case CharType::SpaceOrNewLine:
            pos = text.ParseSpace(pos, SpaceType::All);
            break;
        case CharType::Comment:
            next = text.ParseTillNextLine(pos);
            // Add coment
            pos = next;
            break;
        case CharType::SectionOrArrayStart:
            next = text.Parse(pos, [](char16 ch) { return (ch != ']') && (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10); });
            // add section (pos,nex)
            pos = next;
            break;
        case CharType::String:
            next = text.ParseString(pos);
            // add string
            pos = next;
            break;
        case CharType::Word:
            next = text.Parse(
                  pos,
                  [](char16 ch) {
                      return (ch != ']') && (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10) && (ch != ',') && (ch != '=') &&
                             (ch != ':');
                  });
            // add word
            pos = next;
            break;
        case CharType::Comma:
            // add comma
            pos++;
            break;
        case CharType::Other:
            next = text.ParseSameGroupID(pos, CharType::GetCharType);
            // add other --> with error
            pos = next;
            break;
        case CharType::SectionOrArrayEnd:
            pos = next + 1;
            break;
        }
    }
}
} // namespace GView::Type::INI