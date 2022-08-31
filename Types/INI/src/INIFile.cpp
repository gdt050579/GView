#include "ini.hpp"

namespace GView::Type::INI
{
using namespace GView::View::LexicalViewer;

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
namespace ConstantsHashes
{
    constexpr uint32 False = 0x0B069958;
    constexpr uint32 True  = 0x4DB211E5;
} // namespace ConstantsHashes
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
        pos       = end; // move to next token
        auto hash = text.ComputeHash32(start, end, true);
        if ((hash == ConstantsHashes::True) || (hash == ConstantsHashes::False))
        {
            tokenList.Add(TokenType::Value, start, end, TokenColor::Constant, TokenDataType::Boolean);
            return;
        }
        if (text.ParseNumber(start) == end)
        {
            tokenList.Add(TokenType::Value, start, end, TokenColor::Number, TokenDataType::Number);
            return;
        }
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
                  TokenAlignament::NewLineAfter | TokenAlignament::AddSpaceBefore,
                  true);
            pos = next;
            break;
        case CharType::SectionOrArrayStart:
            next = text.Parse(pos, [](char16 ch) { return (ch != ']') && (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10); });
            if (text[next] == ']')
                next++;
            tokenList.Add(
                  TokenType::Section,
                  pos,
                  next,
                  TokenColor::Keyword,
                  TokenDataType::None,
                  TokenAlignament::NewLineBefore | TokenAlignament::NewLineAfter,
                  true);
            pos = next;
            break;
        case CharType::Word:
            next = text.Parse(
                  pos,
                  [](char16 ch) {
                      return (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10) && (ch != '=') && (ch != ':') && (ch != ' ') &&
                             (ch != '\t');
                  });
            tokenList.Add(TokenType::Key, pos, next, TokenColor::Keyword2, TokenAlignament::StartsOnNewLine);
            pos   = next;
            state = ParserState::ExpectEqual;
            break;
        default:
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(TokenType::Invalid, pos, next, TokenColor::Word)
                  .SetError("Invalid character (expecting either a key or a section)");
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
                  TokenAlignament::NewLineAfter | TokenAlignament::AddSpaceBefore,
                  true);
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::String:
            next = text.ParseString(pos);
            tokenList.Add(TokenType::Value, pos, next, TokenColor::String, TokenDataType::String);
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::Invalid:
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(TokenType::Invalid, pos, next, TokenColor::Word)
                  .SetError("Invalid character (expecting either a avlue or an array)");
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::SectionOrArrayStart:
            tokenList.Add(TokenType::ArrayStart, pos, pos + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
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
                  TokenAlignament::NewLineAfter | TokenAlignament::AddSpaceBefore,
                  true);
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::Equal:
            tokenList.Add(
                  TokenType::Equal,
                  pos,
                  pos + 1,
                  TokenColor::Operator,
                  TokenDataType::None,
                  TokenAlignament::AddSpaceBefore | TokenAlignament::AddSpaceAfter | TokenAlignament::SameColumn,
                  true);
            pos++;
            state = ParserState::ExpectValueOrArray;
            break;
        default:
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(TokenType::Invalid, pos, next, TokenColor::Word).SetError("Invalid character (expecting either ':' or '=')");
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
                  TokenAlignament::NewLineAfter | TokenAlignament::AddSpaceBefore,
                  true);
            pos = next;
            break;
        case CharType::Comma:
            tokenList.Add(TokenType::Comma, pos, pos + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
            pos++;
            state = ParserState::ExpectArrayValue;
            break;
        case CharType::SectionOrArrayEnd:
            tokenList.Add(TokenType::ArrayEnd, pos, pos + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
            this->arrayLevel--;
            state = this->arrayLevel > 0 ? ParserState::ExpectCommaOrEndOfArray : ParserState::ExpectKeyValueOrSection;
            pos++;
            break;
        default:
            next = text.Parse(
                  pos, [](char16 ch) { return (ch != ';') && (ch != '#') && (ch != 13) && (ch != 10) && (ch != ',') && (ch != ']'); });
            next = text.ParseBackwards(next - 1, [](char16 ch) { return (ch == ' ') || (ch == '\t'); });
            next++;
            tokenList.Add(TokenType::Invalid, pos, next, TokenColor::Word)
                  .SetError("Invalid character (expecting either a comma (,) or the end of an array (])");
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
                  TokenAlignament::NewLineAfter | TokenAlignament::AddSpaceBefore,
                  true);
            pos = next;
            break;
        case CharType::String:
            next = text.ParseString(pos);
            tokenList.Add(TokenType::Value, pos, next, TokenColor::String, TokenDataType::String);
            pos   = next;
            state = ParserState::ExpectCommaOrEndOfArray;
            break;
        case CharType::Invalid:
            next = text.ParseUntillEndOfLine(pos);
            tokenList.Add(TokenType::Invalid, pos, next, TokenColor::Word)
                  .SetError("Invalid character (expecting either a avlue or an array)");
            pos   = next;
            state = ParserState::ExpectKeyValueOrSection;
            break;
        case CharType::SectionOrArrayEnd:
            tokenList.Add(TokenType::ArrayEnd, pos, pos + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
            this->arrayLevel--;
            state = this->arrayLevel > 0 ? ParserState::ExpectCommaOrEndOfArray : ParserState::ExpectKeyValueOrSection;
            pos++;
            break;
        case CharType::SectionOrArrayStart:
            tokenList.Add(TokenType::ArrayStart, pos, pos + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, true);
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
    uint32 CreateArrayBlock(uint32 start, uint32 end, bool firstArray, GView::View::LexicalViewer::BlocksList& blocks)
    {
        Block block;
        // starts points to an array '['...']'
        uint32 idx = start + 1;
        while (idx < end)
        {
            switch (tokenList[idx].GetTypeID(TokenType::Invalid))
            {
            case TokenType::ArrayStart:
                idx = CreateArrayBlock(idx, end, false, blocks);
                break;
            case TokenType::ArrayEnd:
                block = blocks.Add(start, idx, BlockAlignament::AsBlockStartToken, BlockFlags::EndMarker);
                if ((start >= 2) && (tokenList[start - 2].GetTypeID(TokenType::Invalid) == TokenType::Key))
                {
                    // make sure that key can also fold/unfold current block
                    tokenList[start - 2].SetBlock(block);
                }
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

void INIFile::PreprocessText(GView::View::LexicalViewer::TextEditor&)
{
    // nothing to do --> there is no pre-processing needed for an INI format
}
void INIFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
    switch (id)
    {
    case TokenType::Comment:
        str.Set("Comment");
        break;
    case TokenType::Section:
        str.Set("Section");
        break;
    case TokenType::Key:
        str.Set("Key");
        break;
    case TokenType::Value:
        str.Set("Value");
        break;
    case TokenType::ArrayStart:
        str.Set("Array start");
        break;
    case TokenType::ArrayEnd:
        str.Set("Array end");
        break;
    case TokenType::Comma:
        str.Set("Separator (comma)");
        break;
    case TokenType::Equal:
        str.Set("Asignament");
        break;
    case TokenType::Invalid:
        str.Set("Invalid/Error");
        break;
    default:
        str.SetFormat("Unknwon: 0x%08X", id);
        break;
    }
}
void INIFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    LocalString<64> tmp;
    ParserData p(syntax.text, syntax.tokens);

    // Tokenization
    p.Tokenize();

    // semantic process
    // search for a section and create a block around it
    uint32 len = syntax.tokens.Len();
    uint32 idx = 0;
    while (idx < len)
    {
        while ((idx < len) && (syntax.tokens[idx].GetTypeID(TokenType::Invalid) != TokenType::Section))
            idx++;
        if (idx < len)
        {
            // we have found a section
            uint32 next   = idx + 1;
            auto keyCount = 0;
            while (next < len)
            {
                auto tokID = syntax.tokens[next].GetTypeID(TokenType::Invalid);
                if (tokID == TokenType::Section)
                    break;
                if (tokID == TokenType::Key)
                    keyCount++;
                next++;
            }
            // we have found another section
            auto block = syntax.blocks.Add(idx, next - 1, BlockAlignament::AsCurrentBlock);
            if (keyCount == 0)
                block.SetFoldMessage("<Empty>");
            else
                block.SetFoldMessage(tmp.Format("<Keys: %d>", keyCount));
            // within each block --> search for arrays and create a block for them as well
            while (idx < next)
            {
                if (syntax.tokens[idx].GetTypeID(TokenType::Invalid) == TokenType::ArrayStart)
                    idx = p.CreateArrayBlock(idx, next, true, syntax.blocks);
                else
                    idx++;
            }
            idx = next;
        }
    }
}
} // namespace GView::Type::INI