#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
static const std::string_view IPS_REGEX_ASCII{ R"(^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\:[0-9]{1,5})*))" };
static const std::string_view IPS_REGEX_UNICODE{
    R"(^(([0-9]\x00){1,3}\.\x00([0-9]\x00){1,3}\.\x00([0-9]\x00){1,3}\.\x00([0-9]\x00){1,3}(\:\x00([0-9]\x00){1,5})*))"
};

IpAddress::IpAddress(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
    this->matcherAscii.Init(IPS_REGEX_ASCII, unicode, caseSensitive);
    this->matcherUnicode.Init(IPS_REGEX_UNICODE, unicode, caseSensitive);
}

const std::string_view IpAddress::GetName() const
{
    return "IP Address";
}

const std::string_view IpAddress::GetOutputExtension() const
{
    return "ip";
}

Subcategory IpAddress::GetSubcategory() const
{
    return Subcategory::IP;
}

bool IpAddress::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(precachedBuffer.GetLength() > 0, false, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), false, "");

    auto buffer = file.Get(offset, 39 * 2, false); // IPv6 length in Unicode
    CHECK(buffer.GetLength() >= 14, false, "");    // not enough for IPv4 => length in ASCII

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
