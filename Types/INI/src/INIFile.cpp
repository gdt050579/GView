#include "ini.hpp"

namespace GView::Type::INI
{
using namespace GView::View::LexicalViewer;
namespace TokenType
{
    constexpr uint32 Comment    = 0;
    constexpr uint32 Section    = 1;
    constexpr uint32 Key        = 2;
    constexpr uint32 Equal      = 3;
    constexpr uint32 Value      = 4;
    constexpr uint32 ArrayStart = 5;
    constexpr uint32 Comma      = 6;
    constexpr uint32 ArrayEnd   = 7;

} // namespace TokenType
enum class ParserState
{
    ExpectKeyValueOrSection,
    ExpectEqual,
    ExpectCommaOrEndOfArray,
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
struct ParserData
{
    const TextParser& text;
    TokensList& tokenList;
    ParserState state;
    uint32 len;
    uint32 pos;
    ParserData(const TextParser& _text, TokensList& _tokenList)
        : text(_text), tokenList(_tokenList), pos(0), state(ParserState::ExpectKeyValueOrSection)
    {
        len = text.Len();
    }
    void AddValue(uint32 start, uint32 end)
    {
        if (end <= start)
        {
            pos = start + 1;
            return;
        }
        pos = end; // move to next token
        tokenList.Add(TokenType::Value, start, end, TokenColor::Word);
    }
    void ParseForExpectKeyValueOrSection(uint8 chType)
    {
        uint32 next;
        switch (chType)
        {
        case CharType::Comment:
            next = text.ParseTillNextLine(pos);
            tokenList.Add(TokenType::Comment, pos, next, TokenColor::Comment);
            pos = next;
            break;
        case CharType::SectionOrArrayStart:
            next = text.Parse(pos, [](char16 ch) { return (ch != ']') && (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10); });
            if (text[next] == ']')
                next++;
            tokenList.Add(TokenType::Section, pos, next, TokenColor::Keyword);
            pos = next;
            break;
        case CharType::Word:
            next = text.Parse(
                  pos, [](char16 ch) { return (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10) && (ch != '=') && (ch != ':'); });
            tokenList.Add(TokenType::Key, pos, next, TokenColor::Word);
            pos   = next;
            state = ParserState::ExpectEqual;
            break;
        default:
            next = text.ParseTillNextLine(pos);
            tokenList.AddErrorToken(pos, next, "Invalid character (expecting either a key or a section)");
            pos = next;
            break;
        }
    }
    void ParseForExpectValueOrArray(uint8 chType)
    {
        uint32 next;
        switch (chType)
        {
        case CharType::Comment:
            next = text.ParseTillNextLine(pos);
            tokenList.Add(TokenType::Comment, pos, next, TokenColor::Comment);
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::String:
            next = text.ParseString(pos);
            tokenList.Add(TokenType::Value, pos, next, TokenColor::String);
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::Invalid:
            next = text.ParseTillNextLine(pos);
            tokenList.AddErrorToken(pos, next, "Invalid character (expecting either a avlue or an array)");
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::SectionOrArrayStart:
            tokenList.Add(TokenType::ArrayStart, pos, pos + 1, TokenColor::Operator);
            state = ParserState::ExpectArrayValue;
            pos++;
            break;
        default:
            // its an word
            next = text.Parse(pos, [](char16 ch) { return (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10); });
            next = text.ParseBackwards(next - 1, [](char16 ch) { return (ch == ' ') || (ch == '\t'); });
            next++;
            // we should check if next is a number or another special value
            AddValue(pos, next);
            state = ParserState::ExpectKeyValueOrSection;
            break;
        }
    }
    void ParseForExpectEqual(uint8 chType)
    {
        uint32 next;
        switch (chType)
        {
        case CharType::Comment:
            next = text.ParseTillNextLine(pos);
            tokenList.Add(TokenType::Comment, pos, next, TokenColor::Comment);
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::Equal:
            tokenList.Add(TokenType::Equal, pos, pos + 1, TokenColor::Operator);
            pos++;
            state = ParserState::ExpectValueOrArray;
            break;
        default:
            next = text.ParseTillNextLine(pos);
            tokenList.AddErrorToken(pos, next, "Invalid character (expecting either ':' or '=')");
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        }
    }
    void ParseForCommaOrEndOfArray(uint8 chType)
    {
        uint32 next;
        switch (chType)
        {
        case CharType::Comment:
            next = text.ParseTillNextLine(pos);
            tokenList.Add(TokenType::Comment, pos, next, TokenColor::Comment);
            pos = next;
            break;
        case CharType::Comma:
            tokenList.Add(TokenType::Comma, pos, pos + 1, TokenColor::Operator);
            pos++;
            state = ParserState::ExpectArrayValue;
            break;
        case CharType::SectionOrArrayEnd:
            tokenList.Add(TokenType::ArrayEnd, pos, pos + 1, TokenColor::Operator);
            state = ParserState::ExpectKeyValueOrSection;
            pos++;
        default:
            next = text.Parse(
                  pos, [](char16 ch) { return (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10) && (ch != ',') && (ch != ']'); });
            next = text.ParseBackwards(next - 1, [](char16 ch) { return (ch == ' ') || (ch == '\t'); });
            next++;
            tokenList.AddErrorToken(pos, next, "Invalid character (expecting either a comma (,) or the end of an array (])");
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        }
    }
    void ParseForExpectArrayValue(uint8 chType)
    {
        uint32 next;
        switch (chType)
        {
        case CharType::Comment:
            next = text.ParseTillNextLine(pos);
            tokenList.Add(TokenType::Comment, pos, next, TokenColor::Comment);
            pos = next;
            break;
        case CharType::String:
            next = text.ParseString(pos);
            tokenList.Add(TokenType::Value, pos, next, TokenColor::String);
            pos   = next;
            state = ParserState::ExpectCommaOrEndOfArray;
            break;
        case CharType::Invalid:
            next = text.ParseTillNextLine(pos);
            tokenList.AddErrorToken(pos, next, "Invalid character (expecting either a avlue or an array)");
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::SectionOrArrayEnd:
            tokenList.Add(TokenType::ArrayEnd, pos, pos + 1, TokenColor::Operator);
            state = ParserState::ExpectArrayValue;
            pos++;
            break;
        case CharType::SectionOrArrayStart:
            tokenList.Add(TokenType::ArrayStart, pos, pos + 1, TokenColor::Operator);
            state = ParserState::ExpectArrayValue;
            pos++;
            break;
        default:
            // its an word
            next = text.Parse(
                  pos, [](char16 ch) { return (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10) && (ch != ',') && (ch != ']'); });
            next = text.ParseBackwards(next - 1, [](char16 ch) { return (ch == ' ') || (ch == '\t'); });
            next++;
            // we should check if next is a number or another special value
            AddValue(pos, next);
            state = ParserState::ExpectCommaOrEndOfArray;
            break;
        }
    }
};

INIFile::INIFile()
{
}

bool INIFile::Update()
{
    return true;
}

void INIFile::AnalyzeText(const TextParser& text, TokensList& tokenList)
{
    ParserData p(text, tokenList);

    // Tokenization
    while (p.pos < p.len)
    {
        auto chType = CharType::GetCharType(text[p.pos]);
        if (chType == CharType::SpaceOrNewLine)
        {
            p.pos = text.ParseSpace(p.pos, SpaceType::All);
        }
        else
        {
            switch (p.state)
            {
            case ParserState::ExpectKeyValueOrSection:
                p.ParseForExpectKeyValueOrSection(chType);
                break;
            case ParserState::ExpectValueOrArray:
                p.ParseForExpectValueOrArray(chType);
                break;
            case ParserState::ExpectEqual:
                p.ParseForExpectEqual(chType);
                break;
            case ParserState::ExpectArrayValue:
                p.ParseForExpectArrayValue(chType);
                break;
            case ParserState::ExpectCommaOrEndOfArray:
                p.ParseForCommaOrEndOfArray(chType);
                break;
            default:
                // force exit
                p.pos = p.len;
                break;
            }
        }
    }

    // semantic process
    // search for a section and fold it :)
    uint32 len = tokenList.Len();
    uint32 idx = 0;
    while (idx < len)
    {
        while ((idx < len) && (tokenList[idx].GetTypeID() != TokenType::Section))
            idx++;
        if (idx < len)
        {
            // we have found a section
            uint32 next = idx + 1;
            while ((next < len) && (tokenList[next].GetTypeID() != TokenType::Section))
                next++;
            if (next < len)
            {
                // we have found another section
                tokenList.CreateBlock(idx, next - 1, false);
                // within each block --> search for arrays and create a block for them as well
                // TODO
            }
            idx = next;
        }
    }
}
} // namespace GView::Type::INI