#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
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

Subcategory Text::GetSubGroup() const
{
    return Subcategory::Text;
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

bool Text::SetAscii(bool value)
{
    if (!value) {
        CHECK(unicode, false, "");
    }
    this->ascii = value;
    return true;
}
bool Text::SetUnicode(bool value)
{
    if (!value) {
        CHECK(ascii, false, "");
    }
    this->unicode = value;
    return true;
}

void Text::SetMatrix(bool matrix[STRINGS_CHARSET_MATRIX_SIZE])
{
    memcpy(this->stringsCharSetMatrix, matrix, STRINGS_CHARSET_MATRIX_SIZE);
}

bool Text::IsValidChar(char c) const
{
    return this->stringsCharSetMatrix[c];
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
