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

Subcategory Text::GetSubcategory() const
{
    return Subcategory::Text;
}

bool Text::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(precachedBuffer.GetLength() > 0, false, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), false, "");
    CHECK(precachedBuffer.GetData()[0] != ' ', false, "");

    const auto isUnicode = precachedBuffer.GetData()[1] == 0;
    if (isUnicode) {
        CHECK(unicode, false, "");
    }

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= this->minLength * (isUnicode ? 2 : 1), false, "");

    finding.start = offset;
    finding.end   = offset;

    uint64 i = 0;
    while (finding.end - finding.start < this->maxLength) {
        const auto c = buffer.GetData()[i];
        CHECKBK(IsValidChar(c), "");

        if (isUnicode && unicode) {
            CHECKBK(buffer.GetData()[i + 1] == 0, "");
            finding.end += 1;
            i++;
        }

        finding.end += 1;
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

    CHECK(finding.start < finding.end, false, "");

    if (isUnicode && unicode) {
        if ((finding.end - finding.start) / 2 > this->minLength) {
            finding.result = Result::Unicode;
            return true;
        }
    } else {
        if ((finding.end - finding.start) > this->minLength) {
            finding.result = Result::Ascii;
            return true;
        }
    }

    return true;
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
