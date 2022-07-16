#include <GView.hpp>

namespace GView::Utils::Tokenizer
{
#define HAS_FLAG(value, flag) (((value) & (flag)) == (flag))

Lexer::Lexer(const char16* _text, uint32 _size)
{
    this->text = _text;
    this->size = _size;
    if (this->text == nullptr)
        this->size = 0; // sanity check
}
Lexer::Lexer(u16string_view _text)
{
    if (_text.empty())
    {
        this->text = nullptr;
        this->size = 0;
    }
    else
    {
        if (_text.size() > 0x7FFFFFFF)
        {
            this->text = nullptr;
            this->size = 0;
        }
        else
        {
            this->text = _text.data();
            this->size = static_cast<uint32>(_text.size() & 0xFFFFFFFF);
        }
    }
    if (this->text == nullptr)
        this->size = 0; // sanity check
}
uint32 Lexer::ParseTillNextLine(uint32 index)
{
    if (index >= size)
        return size;
    auto* p = text + index;
    while ((index < size) && ((*p) != '\n') && ((*p) != '\r'))
    {
        index++;
        p++;
    }
    return index;
}
uint32 Lexer::Parse(uint32 index, bool (*validate)(char16 character))
{
    if (index >= size)
        return size;
    if (validate == nullptr)
        return index;
    auto* p = text + index;
    while ((index < size) && (validate(*p)))
    {
        index++;
        p++;
    }
    return index;
}
uint32 Lexer::ParseSameGroupID(uint32 index, uint32 (*charToGroupID)(char16 character))
{
    if (index >= size)
        return size;
    if (charToGroupID == nullptr)
        return index;
    auto* p = text + index;
    auto id = charToGroupID(*p);
    while ((index < size) && (charToGroupID(*p) == id))
    {
        index++;
        p++;
    }
    return index;
}
uint32 Lexer::ParseSpace(uint32 index, SpaceType type)
{
    if (index >= size)
        return size;
    auto* p = text + index;
    switch (type)
    {
    case SpaceType::Space:
        while ((index < size) && ((*p) == ' '))
        {
            index++;
            p++;
        }
        break;
    case SpaceType::Tabs:
        while ((index < size) && ((*p) == '\t'))
        {
            index++;
            p++;
        }
        break;
    case SpaceType::SpaceAndTabs:
        while ((index < size) && (((*p) == '\t') || ((*p) == ' ')))
        {
            index++;
            p++;
        }
        break;
    case SpaceType::NewLine:
        while ((index < size) && (((*p) == '\n') || ((*p) == '\r')))
        {
            index++;
            p++;
        }
        break;
    case SpaceType::All:
        while ((index < size) && (((*p) == '\n') || ((*p) == '\r') || ((*p) == ' ') || ((*p) == '\t')))
        {
            index++;
            p++;
        }
        break;
    }
    return index;
}

uint32 Lexer::ParseString(uint32 index, StringFormat format)
{
    if (index >= size)
        return size;
    auto ch = text[index];
    while (true)
    {
        if ((ch == '"') && (HAS_FLAG(format, StringFormat::DoubleQuotes)))
            break;
        if ((ch == '\'') && (HAS_FLAG(format, StringFormat::SingleQuotes)))
            break;
        // string does not starts with a valid string character
        return size;
    }
    // check if a tri-quotes string
    const auto supportsTripleQuoted  = HAS_FLAG(format, StringFormat::TripleQuotes);
    const auto allowEscapeChars      = HAS_FLAG(format, StringFormat::AllowEscapeSequences);
    const auto forbidMultiLine       = !(HAS_FLAG(format, StringFormat::MultiLine));
    const auto searchForTripleQuotes = (supportsTripleQuoted && (index + 3 < size) && (text[index + 1] == ch) && (text[index + 2] == ch));
    index                            = searchForTripleQuotes ? index + 3 : index + 1;
    auto validString                 = false;
    while (index < size)
    {
        const auto currentChar = text[index];
        if (currentChar == ch)
        {
            if (searchForTripleQuotes)
            {
                if ((index + 3 < size) && (text[index + 1] == ch) && (text[index + 2] == ch))
                {
                    validString = true;
                    index += 3;
                    break;
                }
            }
            else
            {
                index++;
                validString = true;
                break;
            }
        }
        if ((currentChar == '\\') && (allowEscapeChars))
        {
            index++;
        }
        else
        {
            if (((currentChar == '\n') || (currentChar == '\r')) && (forbidMultiLine))
                break; // invalid string (ended too fast)
        }
        // else --> move to next character
        index++;
    }

    return index;
}
uint32 Lexer::ParseNumber(uint32 index, NumberFormat format)
{
    if (index >= size)
        return size;

    if (HAS_FLAG(format, NumberFormat::AllowSignBeforeNumber))
    {
        if ((text[index] == '-') || (text[index] == '+'))
        {
            if (index + 1 >= size)
                return index;
            index++;
        }
    }
    uint8 base = 10;
    if ((index + 2 < size) && (text[index] == '0'))
    {
        switch (text[index + 1])
        {
        case 'x':
        case 'X':
            if (HAS_FLAG(format, NumberFormat::HexFormat0x))
            {
                base = 16;
                index += 2;
            }
            break;
        case 'b':
        case 'B':
            if (HAS_FLAG(format, NumberFormat::BinFormat0b))
            {
                base = 2;
                index += 2;
            }
            break;
        }
    }
    auto* p                   = text + index;
    const auto allowUnderline = HAS_FLAG(format, NumberFormat::AllowUnderline);
    bool validCharacter       = false;
    switch (base)
    {
    case 2:
        while (index < size)
        {
            validCharacter = (((*p) == '0') || ((*p) == '1'));
            if (((*p) == '_') && allowUnderline)
                validCharacter = true;

            if (validCharacter)
            {
                p++;
                index++;
                continue;
            }
            break;
        }
        break;
    case 16:
        while (index < size)
        {
            validCharacter = ((((*p) >= '0') && ((*p) <= '9')) || (((*p) >= 'a') && ((*p) <= 'f')) || (((*p) >= 'A') && ((*p) <= 'F')));
            if (((*p) == '_') && allowUnderline)
                validCharacter = true;

            if (validCharacter)
            {
                p++;
                index++;
                continue;
            }
            break;
        }
        break;
    case 10:
        while (index < size)
        {
            validCharacter = (((*p) >= '0') && ((*p) <= '9'));
            if (((*p) == '_') && allowUnderline)
                validCharacter = true;

            if (validCharacter)
            {
                p++;
                index++;
                continue;
            }
            break;
        }
        if ((index < size) && ((*p) == '.') && (HAS_FLAG(format, NumberFormat::FloatingPoint)))
        {
            index++;
            p++;
            while (index < size)
            {
                validCharacter = (((*p) >= '0') && ((*p) <= '9'));
                if (((*p) == '_') && allowUnderline)
                    validCharacter = true;

                if (validCharacter)
                {
                    p++;
                    index++;
                    continue;
                }
                break;
            }
        }
        break;
    }
    return index;
}
#undef HAS_FLAG
} // namespace GView::Utils::Tokenizer