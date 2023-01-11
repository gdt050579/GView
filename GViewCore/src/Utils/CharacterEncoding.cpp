#include "Internal.hpp"

namespace GView::Utils::CharacterEncoding
{
bool ExpandedCharacter::FromUTF8Buffer(const uint8* p, const uint8* end)
{
    // unicode encoding (based on the code described in https://en.wikipedia.org/wiki/UTF-8)
    if (((*p) >> 5) == 6) // binary encoding 110xxxxx, followed by 10xxxxxx
    {
        CHECK(p + 1 < end, false, "Invalid unicode sequence (missing one extra character after 110xxxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (110xxxx should be followed by 10xxxxxx)");
        this->unicodeValue = (((uint16) ((*p) & 0x1F)) << 6) | ((uint16) ((*(p + 1)) & 63));
        this->length       = 2;
        return true;
    }
    if (((*p) >> 4) == 14) // binary encoding 1110xxxx, followed by 2 bytes with 10xxxxxx
    {
        CHECK(p + 2 < end, false, "Invalid unicode sequence (missing two extra characters after 1110xxxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (1110xxxx should be followed by 10xxxxxx)");
        CHECK((p[2] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        this->unicodeValue = (((uint16) ((*p) & 0x0F)) << 12) | (((uint16) ((*(p + 1)) & 63)) << 6) | ((uint16) ((*(p + 2)) & 63));
        this->length       = 3;
        return true;
    }
    if (((*p) >> 3) == 30) // binary encoding 11110xxx, followed by 3 bytes with 10xxxxxx
    {
        CHECK(p + 3 < end, false, "Invalid unicode sequence (missing two extra characters after 11110xxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (11110xxx should be followed by 10xxxxxx)");
        CHECK((p[2] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        CHECK((p[3] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        this->unicodeValue = (((uint16) ((*p) & 7)) << 18) | (((uint16) ((*(p + 1)) & 63)) << 12) | (((uint16) ((*(p + 2)) & 63)) << 6) |
                             ((uint16) ((*(p + 3)) & 63));
        this->length = 4;
        return true;
    }
    // invalid 16 bytes encoding
    RETURNERROR(false, "Invalid UTF-8 encoding ");
}
BufferView EncodedCharacter::ToUTF8(char16 ch)
{
    if (ch <= 0x80)
    {
        this->internalBuffer[0] = static_cast<uint8>(ch);
        return BufferView(this->internalBuffer, 2);
    }
    if (ch<=0x7FF)
    {
        this->internalBuffer[0] = static_cast<uint8>(0b11000000) | static_cast<uint8>(ch >> 6);
        this->internalBuffer[1] = static_cast<uint8>(0b10000000) | static_cast<uint8>(ch & 63);
        return BufferView(this->internalBuffer, 2);
    }
    // else rest of characters
    this->internalBuffer[0] = static_cast<uint8>(0b11100000) | static_cast<uint8>(ch >> 12);
    this->internalBuffer[1] = static_cast<uint8>(0b10000000) | static_cast<uint8>((ch >> 6) & 63);
    this->internalBuffer[2] = static_cast<uint8>(0b10000000) | static_cast<uint8>(ch & 63);
    return BufferView(this->internalBuffer, 3);
}
uint8 utf8BOM[] = {0xEF, 0xBB, 0xBf};
uint8 unicode16LEBOM[] = {0xFF, 0xFE};
uint8 unicode16BEBOM[] = {0xFE, 0xFF};
BufferView GetBOMForEncoding(Encoding encoding)
{
    switch (encoding)
    {
    case Encoding::Binary:
    case Encoding::Ascii:
        return BufferView();
    case Encoding::UTF8:
        return BufferView(utf8BOM, 3);
    case Encoding::Unicode16LE:
        return BufferView(unicode16LEBOM, 2);
    case Encoding::Unicode16BE:
        return BufferView(unicode16BEBOM, 2);
    }
    return BufferView();
}
inline bool IsTextCharacter(uint8 value)
{
    return ((value >= ' ') && (value < 127)) || (value == '\n') || (value == '\r') || (value == '\t');
}
Encoding AnalyzeBufferForEncoding(BufferView buf, bool checkForBOM, uint32& BOMLength)
{
    BOMLength = 0;
    if (checkForBOM)
    {
        if (buf.GetLength() >= 3)
        {
            if ((buf[0] == 0xEF) && (buf[1] == 0xBB) && (buf[2] == 0xBF))
            {
                BOMLength = 3;
                return Encoding::UTF8;
            }
        }
        if (buf.GetLength() >= 2)
        {
            if ((buf[0] == 0xFE) && (buf[1] == 0xFF))
            {
                BOMLength = 2;
                return Encoding::Unicode16BE;
            }
            if ((buf[0] == 0xFF) && (buf[1] == 0xFE))
            {
                BOMLength = 2;
                return Encoding::Unicode16LE;
            }
        }
    }
    // if NO BOOM is present - analyze the data and find the type
    // 1. check for Unicode LE/BE
    {
        size_t sz       = buf.GetLength();
        auto countU16LE = 0U;
        auto countU16BE = 0U;
        auto szUTF16    = sz - (sz & 1); // odd value
        for (size_t idx = 0; idx < szUTF16; idx += 2)
        {
            if ((IsTextCharacter(buf[idx])) && (buf[idx + 1] == 0))
                countU16LE++;
            if ((buf[idx] == 0) && (IsTextCharacter(buf[idx + 1])))
                countU16BE++;
        }
        szUTF16 >>= 2; // half the number of characters
        if (szUTF16 > 4)
        {
            // at least 4 unicode characters
            if (countU16LE >= szUTF16)
                return Encoding::Unicode16LE;
            if (countU16BE >= szUTF16)
                return Encoding::Unicode16BE;
        }
    }
    // 2. check for UTF-8
    {
        auto countUTF8    = 0U;
        auto countAscii   = 0U;
        auto countUnknown = 0U;
        auto p            = buf.begin();
        auto e            = buf.end();
        ExpandedCharacter ec;
        while (p < e)
        {
            if ((*p) >= 0x80)
            {
                if (ec.FromUTF8Buffer(p, e))
                {
                    countUTF8++;
                    p += ec.Length();
                    continue;
                }
            }
            if (IsTextCharacter(*p))
            {
                countAscii++;
                p++;
                continue;
            }
            // unknown encoding
            p++;
            countUnknown++;
        }
        auto total = countUnknown + countAscii + countUTF8;
        if ((total > 0) && ((((countAscii + countUTF8) * 100U) / total) >= 75))
        {
            // if at least 75% of the characters are in ascii or UTF8 format
            if (countUTF8 > 0)
                return Encoding::UTF8; // at least one UTF-8 encoding
            else
                return Encoding::Ascii;
        }
    }
    // 3. if no encoding was matched --> return binary
    return Encoding::Binary;
}
UnicodeString ConvertToUnicode16(BufferView buf)
{
    if (buf.Empty())
        return UnicodeString();
    if (buf.GetLength() > 0x80000000)
        return UnicodeString(); // buffer too big to be converted
    uint32 bomLength;
    auto enc    = AnalyzeBufferForEncoding(buf, true, bomLength);
    char16* ptr = new char16[buf.GetLength()];
    auto pos    = ptr;
    auto start  = buf.begin() + bomLength;
    auto end    = buf.end();

    ExpandedCharacter ch;
    while (start<end)
    {
        if (ch.FromEncoding(enc,start,end))
        {
            *pos = ch.GetChar();
            start += ch.Length();
        }
        else
        {
            *pos = *start;
            start++;
        }
        pos++;
    }
    return UnicodeString(ptr, static_cast<uint32>(pos - ptr), static_cast<uint32>(buf.GetLength()));
}

} // namespace GView::Utils::CharacterEncoding