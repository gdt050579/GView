#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
/*
        => 32
    !   => 33
    ()  => 40-41
    "   => 42
    -   => 45
    .   => 46
    0-9 => 48-57
    <   => 60   => ignore
    >   => 62   => ignore
    ?   => 63
    @   => 64
    A-Z => 65-90
    _   => 95
    a-z => 97-122
    LF  => 10   => ignore
    CR  => 13   => ignore
    (32, 33, 40-42, 45, 46, 48-57, 63-90, 95, 97-122)
*/

// this would rather be a static matrix value <-> bool
static bool IsValidChar(char c)
{
    return (c == 32) || (c == 33) || (c >= 40 && c <= 42) || (c == 45) || (c == 46) || (c >= 48 && c <= 57) || (c >= 63 && c <= 90) || (c == 95) ||
           (c >= 97 && c <= 122);
}

Text::Text(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
}

const std::string_view Text::GetName() const
{
    return "Text";
}

const std::string_view Text::GetOutputExtension() const
{
    return "text";
}

Result Text::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(precachedBuffer.GetLength() > 0, Result::NotFound, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), Result::NotFound, "");
    CHECK(precachedBuffer.GetData()[0] != ' ', Result::NotFound, "");

    const auto isUnicode = precachedBuffer.GetData()[1] == 0;
    if (isUnicode) {
        CHECK(unicode, Result::NotFound, "");
    }

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= this->minLength * (isUnicode ? 2 : 1), Result::NotFound, "");

    start = offset;
    end   = offset;

    uint64 i = 0;
    while (end - start < this->maxLength) {
        const auto c = buffer.GetData()[i];
        CHECKBK(IsValidChar(c), "");

        if (isUnicode && unicode) {
            CHECKBK(buffer.GetData()[i + 1] == 0, "");
            end += 1;
            i++;
        }

        end += 1;
        i++;

        if (i + 1 >= buffer.GetLength()) {
            offset += i + 1;
            buffer = file.Get(offset, file.GetCacheSize() / 12, false);
            if (buffer.GetLength() == 0) {
                break;
            }
            i = 0;
        }
    }

    CHECK(start < end, Result::NotFound, "");

    if (isUnicode && unicode) {
        if ((end - start) / 2 > this->minLength) {
            return Result::Unicode;
        }
    } else {
        if ((end - start) > this->minLength) {
            return Result::Ascii;
        }
    }

    return Result::NotFound;
}

bool Text::SetMaxLength(uint32 maxLength)
{
    CHECK(this->minLength < maxLength, false, "");
    this->maxLength = maxLength;
    return true;
}

bool Text::SetMinLength(uint32 minLength)
{
    CHECK(minLength < this->maxLength, false, "");
    this->minLength = minLength;
    return true;
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
