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
    constexpr uint8 Word                = 0;
    constexpr uint8 SpaceOrNewLine      = 1;
    constexpr uint8 Comma               = 2;
    constexpr uint8 Equal               = 3;
    constexpr uint8 String              = 4;
    constexpr uint8 Comment             = 5;
    constexpr uint8 SectionOrArrayStart = 6;
    constexpr uint8 SectionOrArrayEnd   = 7;
    constexpr uint8 Invalid             = 8;

    uint8 Ini_Groups_IDs[] = { Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        SpaceOrNewLine,
                               SpaceOrNewLine, Invalid,
                               Invalid,        SpaceOrNewLine,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               Invalid,        Invalid,
                               SpaceOrNewLine, Word,
                               String,         Comment,
                               Word,           Word,
                               Word,           String,
                               Word,           Word,
                               Word,           Word,
                               Comma,          Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Equal,          Comment,
                               Word,           Equal,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           SectionOrArrayStart,
                               Word,           SectionOrArrayEnd,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word,
                               Word,           Word };

    inline uint32 GetCharType(char16 c)
    {
        if (c < ARRAY_LEN(Ini_Groups_IDs))
            return Ini_Groups_IDs[c];
        return Word;
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
            tokenList.Add(TokenType::Comment, pos, next);
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
        case CharType::Invalid:
            next = text.ParseSameGroupID(pos, CharType::GetCharType);
            tokenList.Add(TokenType::Unknown, pos, next);
            pos = next;
            break;
        case CharType::SectionOrArrayEnd:
            pos = next + 1;
            break;
        }
    }
}
} // namespace GView::Type::INI