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
    int32 arrayLevel;
    ParserData(const TextParser& _text, TokensList& _tokenList)
        : text(_text), tokenList(_tokenList), pos(0), state(ParserState::ExpectKeyValueOrSection)
    {
        len        = text.Len();
        arrayLevel = 0;
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
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(
                  TokenType::Comment,
                  pos,
                  next,
                  TokenColor::Comment,
                  TokenDataType::MetaInformation,
                  TokenAlignament::NewLineAfter | TokenAlignament::SpaceOnLeft);
            pos = next;
            break;
        case CharType::SectionOrArrayStart:
            next = text.Parse(pos, [](char16 ch) { return (ch != ']') && (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10); });
            if (text[next] == ']')
                next++;
            tokenList.Add(TokenType::Section, pos, next, TokenColor::Keyword, TokenAlignament::NewLineBefore|TokenAlignament::NewLineAfter);
            pos = next;
            break;
        case CharType::Word:
            next = text.Parse(
                  pos,
                  [](char16 ch) {
                      return (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10) && (ch != '=') && (ch != ':') && (ch != ' ') &&
                             (ch != '\t');
                  });
            tokenList.Add(TokenType::Key, pos, next, TokenColor::Word, TokenAlignament::StartsOnNewLine);
            pos   = next;
            state = ParserState::ExpectEqual;
            break;
        default:
            next = text.ParseUntillEndOfLine(pos);
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
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(
                  TokenType::Comment,
                  pos,
                  next,
                  TokenColor::Comment,
                  TokenDataType::MetaInformation,
                  TokenAlignament::NewLineAfter | TokenAlignament::SpaceOnLeft);
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
            next = text.ParseUntillEndOfLine(pos);
            tokenList.AddErrorToken(pos, next, "Invalid character (expecting either a avlue or an array)");
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::SectionOrArrayStart:
            tokenList.Add(TokenType::ArrayStart, pos, pos + 1, TokenColor::Operator);
            state = ParserState::ExpectArrayValue;
            this->arrayLevel++;
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
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(
                  TokenType::Comment,
                  pos,
                  next,
                  TokenColor::Comment,
                  TokenDataType::MetaInformation,
                  TokenAlignament::NewLineAfter | TokenAlignament::SpaceOnLeft);
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::Equal:
            tokenList.Add(
                  TokenType::Equal, pos, pos + 1, TokenColor::Operator, TokenAlignament::SpaceOnLeft | TokenAlignament::SpaceOnRight);
            pos++;
            state = ParserState::ExpectValueOrArray;
            break;
        default:
            next = text.ParseUntillEndOfLine(pos);
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
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(
                  TokenType::Comment,
                  pos,
                  next,
                  TokenColor::Comment,
                  TokenDataType::MetaInformation,
                  TokenAlignament::NewLineAfter | TokenAlignament::SpaceOnLeft);
            pos = next;
            break;
        case CharType::Comma:
            tokenList.Add(TokenType::Comma, pos, pos + 1, TokenColor::Operator);
            pos++;
            state = ParserState::ExpectArrayValue;
            break;
        case CharType::SectionOrArrayEnd:
            tokenList.Add(TokenType::ArrayEnd, pos, pos + 1, TokenColor::Operator);
            this->arrayLevel--;
            state = this->arrayLevel > 0 ? ParserState::ExpectCommaOrEndOfArray : ParserState::ExpectKeyValueOrSection;
            pos++;
            break;
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
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(
                  TokenType::Comment,
                  pos,
                  next,
                  TokenColor::Comment,
                  TokenDataType::MetaInformation,
                  TokenAlignament::NewLineAfter | TokenAlignament::SpaceOnLeft);
            pos = next;
            break;
        case CharType::String:
            next = text.ParseString(pos);
            tokenList.Add(TokenType::Value, pos, next, TokenColor::String);
            pos   = next;
            state = ParserState::ExpectCommaOrEndOfArray;
            break;
        case CharType::Invalid:
            next = text.ParseUntillEndOfLine(pos);
            tokenList.AddErrorToken(pos, next, "Invalid character (expecting either a avlue or an array)");
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::SectionOrArrayEnd:
            tokenList.Add(TokenType::ArrayEnd, pos, pos + 1, TokenColor::Operator);
            this->arrayLevel--;
            state = this->arrayLevel > 0 ? ParserState::ExpectCommaOrEndOfArray : ParserState::ExpectKeyValueOrSection;
            pos++;
            break;
        case CharType::SectionOrArrayStart:
            tokenList.Add(TokenType::ArrayStart, pos, pos + 1, TokenColor::Operator);
            state = ParserState::ExpectArrayValue;
            this->arrayLevel++;
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
    void Tokenize()
    {
        this->arrayLevel = 0;
        while (this->pos < this->len)
        {
            auto chType = CharType::GetCharType(text[this->pos]);
            if (chType == CharType::SpaceOrNewLine)
            {
                this->pos = text.ParseSpace(this->pos, SpaceType::All);
            }
            else
            {
                switch (this->state)
                {
                case ParserState::ExpectKeyValueOrSection:
                    this->ParseForExpectKeyValueOrSection(chType);
                    break;
                case ParserState::ExpectValueOrArray:
                    this->ParseForExpectValueOrArray(chType);
                    break;
                case ParserState::ExpectEqual:
                    this->ParseForExpectEqual(chType);
                    break;
                case ParserState::ExpectArrayValue:
                    this->ParseForExpectArrayValue(chType);
                    break;
                case ParserState::ExpectCommaOrEndOfArray:
                    this->ParseForCommaOrEndOfArray(chType);
                    break;
                default:
                    // force exit
                    this->pos = this->len;
                    break;
                }
            }
        }
    }
    uint32 CreateArrayBlock(uint32 start, uint32 end)
    {
        // starts points to an array '['...']'
        uint32 idx = start + 1;
        while (idx<end)
        {
            switch (tokenList[idx].GetTypeID())
            {
            case TokenType::ArrayStart:
                idx = CreateArrayBlock(idx, end);
                break;
            case TokenType::ArrayEnd:
                this->tokenList.CreateBlock(start, idx, BlockAlignament::AsBlockStartToken, true);
                return idx + 1;
            default:
                idx++;
                break;
            }
        }
        return end;
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
    p.Tokenize();

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
            // we have found another section
            tokenList.CreateBlock(idx, next - 1, BlockAlignament::AsCurrentBlock, false);
            // within each block --> search for arrays and create a block for them as well
            while (idx < next)
            {
                if (tokenList[idx].GetTypeID() == TokenType::ArrayStart)
                    idx = p.CreateArrayBlock(idx, next);
                else
                    idx++;
            }
            idx = next;
        }
    }
}
} // namespace GView::Type::INI