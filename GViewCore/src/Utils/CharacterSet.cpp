#include "Internal.hpp"

using namespace GView::Utils;

bool IsCharacterWriteable(int ch)
{
    if ((ch <= 32) || (ch >= 127))
        return false;
    if ((ch == '-') || (ch == '\\') || (ch == '"') || (ch == '\''))
        return false;
    return true;
}

CharacterSet::CharacterSet()
{
    SetAll();
}
CharacterSet::CharacterSet(bool asciiMask[256])
{
    memcpy(this->Ascii, asciiMask, sizeof(this->Ascii));
}
void CharacterSet::ClearAll()
{
    for (uint32 tr = 0; tr < 256; tr++)
        Ascii[tr] = false;
}
void CharacterSet::SetAll()
{
    for (uint32 tr = 0; tr < 256; tr++)
        Ascii[tr] = true;
}

bool CharacterSet::Set(uint32 start, uint32 end, bool value)
{
    if ((start < end) && (end <= 256))
    {
        while (start < end)
        {
            Ascii[start] = value;
            start++;
        }
        return true;
    }
    return false;
}
void CharacterSet::Set(uint8 position, bool value)
{
    Ascii[position] = value;
}
bool CharacterSet::Set(std::string_view stringRepresentation, bool value)
{
    uint32 start, end;
    bool startExpr, add;
    uint8 ch;
    // parsez stringul
    startExpr = true;
    auto p    = stringRepresentation.data();
    auto e    = p + stringRepresentation.length();
    for (; p < e; p++)
    {
        ch  = (*p);
        add = true;

        switch (ch)
        {
        case '\\':
            CHECK(p + 1 < e, false, "");

            switch (p[1])
            {
            case '\\':
                ch = '\\';
                p++;
                break;
            case '-':
                ch = '-';
                p++;
                break;
            case 'x':
            case 'X':
            {
                CHECK(p + 4 <= e, false, "");
                auto n = Number::ToUInt8(std::string_view{ p+2, (size_t) 2 }, NumberParseFlags::Base16);
                CHECK(n.has_value(), false, "");
                ch = n.value();
                p += 4;
            }
            break;
            default:
                RETURNERROR(false, "Unknwon character: %d", p[1]);
            };
            if (startExpr)
            {
                start = ch;
                end   = ch;
            }
            else
            {
                end       = ch;
                startExpr = true;
            }
            break;
        case ' ':
            add = false;
            break;
        case '-':
            startExpr = false;
            break;
        default:
            if (startExpr)
            {
                start = ch;
                end   = ch;
            }
            else
            {
                end       = ch;
                startExpr = true;
            }
            break;
        };
        // set
        if (add)
        {
            for (uint32 gr = start; gr <= end; gr++)
                Ascii[gr] = value;
        }
    }
    CHECK(startExpr, false, "");
    return true;
}
bool CharacterSet::GetStringRepresentation(String& str) const
{
    uint32 start, end;
    uint32 pzz;
    // caut pe rand blocurile libere
    start = 0;
    pzz   = 0;
    CHECK(str.Set(""), false, "");
    while (start < 256)
    {
        if (Ascii[start])
        {
            for (end = start + 1; (end < 256) && (Ascii[end]); end++)
                ;
            // atribui
            if (IsCharacterWriteable(start))
            {
                CHECK(str.AddChar(start), false, "");
            }
            else
            {
                CHECK(str.AddFormat("\\x%02X", start), false, "");
            }
            if (end - start > 1)
            {
                CHECK(str.AddChar('-'), false, "");
                end--;
                if (IsCharacterWriteable(end))
                {
                    CHECK(str.AddChar(end), false, "");
                }
                else
                {
                    CHECK(str.AddFormat("\\x%02X", end), false, "");
                }
            }
            start = end;
            CHECK(str.AddChar(' '), false, "");
        }
        start++;
    }
    return true;
}
void CharacterSet::CopySetTo(bool _ascii[256])
{
    memcpy(_ascii, Ascii, sizeof(Ascii));
}
