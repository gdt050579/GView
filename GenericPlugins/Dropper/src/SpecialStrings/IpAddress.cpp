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

const char* IpAddress::GetName()
{
    return "IP Address";
}

const char* IpAddress::GetOutputExtension()
{
    return "ip";
}

Result IpAddress::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
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
