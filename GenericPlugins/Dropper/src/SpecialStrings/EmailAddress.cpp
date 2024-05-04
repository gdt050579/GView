#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
static constexpr std::string_view EMAIL_REGEX_ASCII{ R"(^([a-z0-9\_\.]+@[a-z\_]+\.[a-z]{2,5}))" };
static constexpr std::string_view EMAIL_REGEX_UNICODE{ R"(^(([a-z0-9\_\.]\x00)+@\x00([a-z\_]\x00)+\.\x00([a-z]\x00){2,5}))" };

EmailAddress::EmailAddress(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
    this->matcherAscii.Init(EMAIL_REGEX_ASCII, unicode, caseSensitive);
    this->matcherUnicode.Init(EMAIL_REGEX_UNICODE, unicode, caseSensitive);
}

const std::string_view EmailAddress::GetName() const
{
    return "Email Address";
}

const std::string_view EmailAddress::GetOutputExtension() const
{
    return "email";
}

Subcategory EmailAddress::GetSubGroup() const
{
    return Subcategory::Email;
}

Result EmailAddress::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(precachedBuffer.GetLength() > 0, Result::NotFound, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), Result::NotFound, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= 4, Result::NotFound, "");

    if (this->matcherAscii.Match(buffer, start, end)) {
        start += offset;
        end += offset;
        return Result::Ascii;
    }

    CHECK(unicode, Result::NotFound, "");
    CHECK(precachedBuffer.GetData()[1] == 0, Result::NotFound, ""); // we already checked ascii printable

    if (this->matcherUnicode.Match(buffer, start, end)) {
        start += offset;
        end += offset;
        return Result::Unicode;
    }

    return Result::NotFound;
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
