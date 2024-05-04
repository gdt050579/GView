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

Subcategory EmailAddress::GetSubcategory() const
{
    return Subcategory::Email;
}

bool EmailAddress::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(precachedBuffer.GetLength() > 0, false, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), false, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= 4, false, "");

    if (this->matcherAscii.Match(buffer, finding.start, finding.end)) {
        finding.start += offset;
        finding.end += offset;
        finding.result = Result::Ascii;
        return true;
    }

    CHECK(unicode, false, "");
    CHECK(precachedBuffer.GetData()[1] == 0, false, ""); // we already checked ascii printable

    if (this->matcherUnicode.Match(buffer, finding.start, finding.end)) {
        finding.start += offset;
        finding.end += offset;
        finding.result = Result::Unicode;
        return true;
    }

    return true;
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
