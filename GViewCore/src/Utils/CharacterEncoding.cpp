#include "Internal.hpp"

namespace GView::Utils::CharacterEncoding
{
bool ExpandedCharacter::FromUTF8Buffer(const uint8* p, const uint8* end)
{
    // on failure the character stays empty (the caller treats the first byte as a binary character)
    this->codePoint = 0;
    this->length    = 0;
    // unicode encoding (based on the code described in https://en.wikipedia.org/wiki/UTF-8)
    // overlong forms, UTF-16 surrogates (U+D800..U+DFFF) and code points above U+10FFFF are invalid sequences
    if (((*p) >> 5) == 6) // binary encoding 110xxxxx, followed by 10xxxxxx
    {
        CHECK(p + 1 < end, false, "Invalid unicode sequence (missing one extra character after 110xxxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (110xxxx should be followed by 10xxxxxx)");
        const uint32 value = (static_cast<uint32>(p[0] & 0x1F) << 6) | static_cast<uint32>(p[1] & 63);
        CHECK(value >= 0x80, false, "Invalid unicode sequence (overlong 2 bytes encoding)");
        this->codePoint = value;
        this->length    = 2;
        return true;
    }
    if (((*p) >> 4) == 14) // binary encoding 1110xxxx, followed by 2 bytes with 10xxxxxx
    {
        CHECK(p + 2 < end, false, "Invalid unicode sequence (missing two extra characters after 1110xxxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (1110xxxx should be followed by 10xxxxxx)");
        CHECK((p[2] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        const uint32 value =
              (static_cast<uint32>(p[0] & 0x0F) << 12) | (static_cast<uint32>(p[1] & 63) << 6) | static_cast<uint32>(p[2] & 63);
        CHECK(value >= 0x800, false, "Invalid unicode sequence (overlong 3 bytes encoding)");
        CHECK((value < 0xD800) || (value > 0xDFFF), false, "Invalid unicode sequence (UTF-16 surrogate encoded in UTF-8)");
        this->codePoint = value;
        this->length    = 3;
        return true;
    }
    if (((*p) >> 3) == 30) // binary encoding 11110xxx, followed by 3 bytes with 10xxxxxx
    {
        CHECK(p + 3 < end, false, "Invalid unicode sequence (missing three extra characters after 11110xxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (11110xxx should be followed by 10xxxxxx)");
        CHECK((p[2] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        CHECK((p[3] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        const uint32 value = (static_cast<uint32>(p[0] & 7) << 18) | (static_cast<uint32>(p[1] & 63) << 12) |
                             (static_cast<uint32>(p[2] & 63) << 6) | static_cast<uint32>(p[3] & 63);
        CHECK(value >= 0x10000, false, "Invalid unicode sequence (overlong 4 bytes encoding)");
        CHECK(value <= UNICODE_MAX_CODE_POINT, false, "Invalid unicode sequence (code point above U+10FFFF)");
        this->codePoint = value;
        this->length    = 4;
        return true;
    }
    // invalid 16 bytes encoding
    RETURNERROR(false, "Invalid UTF-8 encoding ");
}

// writes the UTF-8 form of a code point (at most U+10FFFF) and returns the number of bytes written (1..4)
static uint32 WriteUTF8CodePoint(uint8* output, uint32 cp)
{
    if (cp < 0x80)
    {
        output[0] = static_cast<uint8>(cp);
        return 1;
    }
    if (cp <= 0x7FF)
    {
        output[0] = static_cast<uint8>(0b11000000 | (cp >> 6));
        output[1] = static_cast<uint8>(0b10000000 | (cp & 63));
        return 2;
    }
    if (cp <= 0xFFFF)
    {
        output[0] = static_cast<uint8>(0b11100000 | (cp >> 12));
        output[1] = static_cast<uint8>(0b10000000 | ((cp >> 6) & 63));
        output[2] = static_cast<uint8>(0b10000000 | (cp & 63));
        return 3;
    }
    output[0] = static_cast<uint8>(0b11110000 | (cp >> 18));
    output[1] = static_cast<uint8>(0b10000000 | ((cp >> 12) & 63));
    output[2] = static_cast<uint8>(0b10000000 | ((cp >> 6) & 63));
    output[3] = static_cast<uint8>(0b10000000 | (cp & 63));
    return 4;
}
BufferView EncodedCharacter::ToUTF8(char16 ch)
{
    uint32 size = 0;
    if (this->pendingHighSurrogate != 0)
    {
        const uint32 high          = this->pendingHighSurrogate;
        this->pendingHighSurrogate = 0;
        if (IsLowSurrogate(ch))
        {
            // high + low surrogate --> one 4 bytes sequence
            const uint32 cp = 0x10000 + ((high - 0xD800) << 10) + (static_cast<uint32>(ch) - 0xDC00);
            size            = WriteUTF8CodePoint(this->internalBuffer, cp);
            return BufferView(this->internalBuffer, size);
        }
        // the previous high surrogate is not followed by a low surrogate
        size = WriteUTF8CodePoint(this->internalBuffer, UNICODE_REPLACEMENT_CHARACTER);
    }
    if (IsHighSurrogate(ch))
    {
        // wait for the low surrogate (next call)
        this->pendingHighSurrogate = ch;
        return BufferView(this->internalBuffer, size);
    }
    // an unpaired low surrogate is not a valid character
    size += WriteUTF8CodePoint(this->internalBuffer + size, IsLowSurrogate(ch) ? UNICODE_REPLACEMENT_CHARACTER : static_cast<uint32>(ch));
    return BufferView(this->internalBuffer, size);
}
BufferView EncodedCharacter::Flush()
{
    if (this->pendingHighSurrogate == 0)
        return BufferView(this->internalBuffer, 0);
    // a high surrogate at the end of the text (not followed by a low surrogate)
    this->pendingHighSurrogate = 0;
    return BufferView(this->internalBuffer, WriteUTF8CodePoint(this->internalBuffer, UNICODE_REPLACEMENT_CHARACTER));
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
            // code points above U+FFFF become a surrogate pair; a decoded character always uses at least as many bytes
            // as the UTF-16 units it produces, so 'ptr' (one char16 per input byte) can not overflow
            pos += ch.ToUTF16(pos);
            start += ch.Length();
        }
        else
        {
            *pos = *start;
            start++;
            pos++;
        }
    }
    return UnicodeString(ptr, static_cast<uint32>(pos - ptr), static_cast<uint32>(buf.GetLength()));
}

} // namespace GView::Utils::CharacterEncoding