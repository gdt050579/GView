#include <GView.hpp>

namespace GView::View::LexicalViewer
{
#define HAS_FLAG(value, flag) (((value) & (flag)) == (flag))
const uint8 lower_case_table[128] = { 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,
                                      19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,
                                      38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,
                                      57,  58,  59,  60,  61,  62,  63,  64,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107,
                                      108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 91,  92,  93,  94,
                                      95,  96,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
                                      114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127 };
uint32 TextParser_ComputeHash32(const uint8* p, const uint8* e, bool ignoreCase)
{
    // use FNV algorithm ==> https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
    uint32 hash = 0x811c9dc5;
    if (ignoreCase)
    {
        for (; p < e; p++)
        {
            if ((*p) == 0)
                continue;
            if ((*p) < 128)
                hash = hash ^ (lower_case_table[*p]);
            else
                hash = hash ^ (*p);
            hash = hash * 0x01000193;
        }
    }
    else
    {
        for (; p < e; p++)
        {
            if ((*p) == 0)
                continue;
            hash = hash ^ (*p);
            hash = hash * 0x01000193;
        }
    }
    return hash;
}
uint64 TextParser_ComputeHash64(const uint8* p, const uint8* e, bool ignoreCase)
{
    // use FNV algorithm ==> https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
    uint64 hash = 0xcbf29ce484222325ULL;
    if (ignoreCase)
    {
        for (; p < e; p++)
        {
            if ((*p) == 0)
                continue;
            if ((*p) < 128)
                hash = hash ^ (lower_case_table[*p]);
            else
                hash = hash ^ (*p);
            hash = hash * 0x00000100000001B3ULL;
        }
    }
    else
    {
        for (; p < e; p++)
        {
            if ((*p) == 0)
                continue;
            hash = hash ^ (*p);
            hash = hash * 0x00000100000001B3ULL;
        }
    }
    return hash;
}

TextParser::TextParser(const char16* _text, uint32 _size)
{
    this->text = _text;
    this->size = _size;
    if (this->text == nullptr)
        this->size = 0; // sanity check
}
TextParser::TextParser(u16string_view _text)
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
uint32 TextParser::ParseUntillEndOfLine(uint32 index) const
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
uint32 TextParser::ParseUntillStartOfNextLine(uint32 index) const
{
    if (index >= size)
        return size;
    auto* p = text + index;
    while ((index < size) && ((*p) != '\n') && ((*p) != '\r'))
    {
        index++;
        p++;
    }
    // skip new line
    if ((index < size) && (((*p == '\n')) || ((*p) == '\r')))
    {
        auto current = *p;
        index++;
        p++;
        if ((index < size) && (((*p == '\n')) || ((*p) == '\r')) && ((*p) != current))
            index++; // CRLF or LFCR cases
    }
    return index;
}
uint32 TextParser::Parse(uint32 index, bool (*validate)(char16 character)) const
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
uint32 TextParser::ParseBackwards(uint32 index, bool (*validate)(char16 character)) const
{
    if (index == 0)
        return 0;
    if (index >= size)
        return size;
    if (validate == nullptr)
        return index;
    auto* p = text + index;
    while ((index > 0) && (validate(*p)))
    {
        index--;
        p--;
    }
    return index;
}
uint32 TextParser::ParseSameGroupID(uint32 index, uint32 (*charToGroupID)(char16 character)) const
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
uint32 TextParser::ParseSpace(uint32 index, SpaceType type) const
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
uint32 TextParser::ParseUntillText(uint32 index, string_view textToFind, bool ignoreCase) const
{
    if (index >= size)
        return size;
    if (textToFind.size() + index > size)
        return size;
    if (textToFind.size() == 0)
        return index;
    const char16* p        = this->text + index;
    const char16* e        = (this->text + (size_t) size) - textToFind.size();
    const uint8* txt_start = (const uint8*) textToFind.data();
    const uint8* txt_end   = txt_start + textToFind.size();

    if (ignoreCase)
    {
        while (p < e)
        {
            if (((*p) < 128) && (lower_case_table[*p] == lower_case_table[*txt_start]))
            {
                const auto* t = txt_start;
                const auto* c = p;
                for (; (t < txt_end) && ((*c) < 128) && (lower_case_table[*c] == lower_case_table[*t]); t++, c++)
                    ;
                if (t == txt_end)
                {
                    // found one
                    return (uint32) (p - this->text);
                }
            }
            p++;
        }
    }
    else
    {
        while (p < e)
        {
            if ((*p) == (*txt_start))
            {
                const auto* t = txt_start;
                const auto* c = p;
                for (; (t < txt_end) && ((*c) == (*t)); t++, c++)
                    ;
                if (t == txt_end)
                {
                    // found one
                    return (uint32) (p - this->text);
                }
            }
            p++;
        }
    }
    // return end of the text
    return size;
}
uint32 TextParser::ParseUntilNextCharacterAfterText(uint32 index, string_view textToFind, bool ignoreCase) const
{
    auto pos = ParseUntillText(index, textToFind, ignoreCase);
    if (pos >= size)
        return size;
    return pos + (uint32) textToFind.size();
}
uint32 TextParser::ParseString(uint32 index, StringFormat format) const
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
uint32 TextParser::ParseNumber(uint32 index, NumberFormat format) const
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
            if ((index < size) && (((*p) | 0x20) == 'e') && (HAS_FLAG(format, NumberFormat::ExponentFormat)))
            {
                index++;
                p++;
                if ((index < size) && (((*p) == '+') || ((*p) == '-')))
                {
                    p++;
                    index++;
                }
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
        }
        break;
    }
    return index;
}
uint64 TextParser::ComputeHash64(uint32 start, uint32 end, bool ignoreCase) const
{
    // use FNV algorithm ==> https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
    if ((start >= end) || (end > size))
        return 0;
    return TextParser_ComputeHash64(reinterpret_cast<const uint8*>(text + start), reinterpret_cast<const uint8*>(text + end), ignoreCase);
}
uint32 TextParser::ComputeHash32(uint32 start, uint32 end, bool ignoreCase) const
{
    // use FNV algorithm ==> https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
    if ((start >= end) || (end > size))
        return 0;
    return TextParser_ComputeHash32(reinterpret_cast<const uint8*>(text + start), reinterpret_cast<const uint8*>(text + end), ignoreCase);
}
uint32 TextParser::ComputeHash32(u16string_view txt, bool ignoreCase)
{
    if (txt.empty())
        return 0;
    const uint8* p = reinterpret_cast<const uint8*>(txt.data());
    const uint8* e = reinterpret_cast<const uint8*>(txt.data() + txt.size());
    return TextParser_ComputeHash32(p, e, ignoreCase);
}
uint64 TextParser::ComputeHash64(u16string_view txt, bool ignoreCase)
{
    if (txt.empty())
        return 0;
    const uint8* p = reinterpret_cast<const uint8*>(txt.data());
    const uint8* e = reinterpret_cast<const uint8*>(txt.data() + txt.size());
    return TextParser_ComputeHash64(p, e, ignoreCase);
}
#undef HAS_FLAG
} // namespace GView::View::LexicalViewer