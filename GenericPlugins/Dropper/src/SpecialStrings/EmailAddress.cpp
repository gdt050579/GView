#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
static constexpr std::string_view EMAIL_REGEX_ASCII{ R"(([a-z0-9\_\.]+@[a-z\_]+\.[a-z]{2,5}))" };
static constexpr std::string_view EMAIL_REGEX_UNICODE{ R"(^(([a-z0-9\_\.]\x00)+@\x00([a-z\_]\x00)+\.\x00([a-z]\x00){2,5}))" };

EmailAddress::EmailAddress(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
    this->matcherAscii.Init(EMAIL_REGEX_ASCII, unicode, caseSensitive);
    this->matcherUnicode.Init(EMAIL_REGEX_UNICODE, unicode, caseSensitive);
}

const char* EmailAddress::GetName()
{
    return "Email Address";
}

ObjectCategory EmailAddress::GetGroup()
{
    return ObjectCategory::SpecialStrings;
}

const char* EmailAddress::GetOutputExtension()
{
    return "email";
}

Priority EmailAddress::GetPriority()
{
    return Priority::Text;
}

bool EmailAddress::ShouldGroupInOneFile()
{
    return true;
}

Result EmailAddress::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(precachedBuffer.GetLength() > 0, Result::NotFound, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), Result::NotFound, "");

    auto buffer = file.Get(offset, 39 * 2, false);         // IPv6 length in Unicode
    CHECK(buffer.GetLength() >= 14, Result::NotFound, ""); // not enough for IPv4 => length in ASCII

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
