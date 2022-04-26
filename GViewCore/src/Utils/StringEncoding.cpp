#include "Internal.hpp"


namespace GView::Utils::StringEncoding
{
bool ExpandedCharacter::FromUTF8Buffer(const char8* p, const char8* end)
{
    // unicode encoding (based on the code described in https://en.wikipedia.org/wiki/UTF-8)
    if (((*p) >> 5) == 6) // binary encoding 110xxxxx, followed by 10xxxxxx
    {
        CHECK(p + 1 < end, false, "Invalid unicode sequence (missing one extra character after 110xxxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (110xxxx should be followed by 10xxxxxx)");
        this->unicodeValue = (((uint16) ((*p) & 0x1F)) << 6) | ((uint16) ((*(p + 1)) & 63));
        this->length = 2;
        return true;
    }
    if (((*p) >> 4) == 14) // binary encoding 1110xxxx, followed by 2 bytes with 10xxxxxx
    {
        CHECK(p + 2 < end, false, "Invalid unicode sequence (missing two extra characters after 1110xxxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (1110xxxx should be followed by 10xxxxxx)");
        CHECK((p[2] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        this->unicodeValue = (((uint16) ((*p) & 0x0F)) << 12) | (((uint16) ((*(p + 1)) & 63)) << 6) | ((uint16) ((*(p + 2)) & 63));
        this->length = 3;
        return true;
    }
    if (((*p) >> 3) == 30) // binary encoding 11110xxx, followed by 3 bytes with 10xxxxxx
    {
        CHECK(p + 3 < end, false, "Invalid unicode sequence (missing two extra characters after 11110xxx)");
        CHECK((p[1] >> 6) == 2, false, "Invalid unicode sequence (11110xxx should be followed by 10xxxxxx)");
        CHECK((p[2] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        CHECK((p[3] >> 6) == 2, false, "Invalid unicode sequence (10xxxxxx should be followed by 10xxxxxx)");
        this->unicodeValue= (((uint16) ((*p) & 7)) << 18) | (((uint16) ((*(p + 1)) & 63)) << 12) | (((uint16) ((*(p + 2)) & 63)) << 6) |
                       ((uint16) ((*(p + 3)) & 63));
        this->length = 4;
        return true;
    }
    // invalid 16 bytes encoding
    RETURNERROR(false, "Invalid UTF-8 encoding ");
}
} // namespace GView::Utils::StringEncoding