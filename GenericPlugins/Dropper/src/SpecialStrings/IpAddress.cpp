#include "SpecialStrings.hpp"

#include <regex>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
inline static const std::string_view IPS_REGEX_ASCII{ R"(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\:[0-9]{1,5})*))" };
inline static const std::u16string_view IPS_REGEX_UNICODE{ uR"(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\:[0-9]{1,5})*))" };

IpAddress::IpAddress(bool caseSensitive, bool unicode)
{
    this->pattern_ascii = std::regex(
          IPS_REGEX_ASCII.data(),
          caseSensitive ? std::regex_constants::ECMAScript | std::regex_constants::optimize
                        : std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize);

    if (unicode) {
        this->pattern_unicode = std::wregex(
              reinterpret_cast<wchar_t const* const>(IPS_REGEX_UNICODE.data()),
              caseSensitive ? std::regex_constants::ECMAScript | std::regex_constants::optimize
                            : std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize);
    }
}

const char* IpAddress::GetName()
{
    return "IP Address";
}

ObjectCategory IpAddress::GetGroup()
{
    return ObjectCategory::SpecialStrings;
}

const char* IpAddress::GetOutputExtension()
{
    return "ip";
}

Priority IpAddress::GetPriority()
{
    return Priority::Text;
}

bool IpAddress::ShouldGroupInOneFile()
{
    return true;
}

Result IpAddress::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(precachedBuffer.GetLength() > 0, Result::NotFound, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), Result::NotFound, "");

    auto buffer = file.Get(offset, 39 * 2, false);         // IPv6 length in Unicode
    CHECK(buffer.GetLength() >= 14, Result::NotFound, ""); // not enough for IPv4 => length in ASCII

    // https://stackoverflow.com/questions/26696250/difference-between-stdregex-match-stdregex-search

    auto bStart     = reinterpret_cast<char const*>(buffer.GetData());
    const auto bEnd = reinterpret_cast<char const*>(bStart + buffer.GetLength());

    std::cmatch acm{};
    if (std::regex_search(bStart, bEnd, acm, this->pattern_ascii)) {
        start = offset + acm.position();
        end   = start + acm.length();
        return Result::Ascii;
    }

    CHECK(unicode, Result::NotFound, "");
    CHECK(precachedBuffer.GetData()[1] == 0, Result::NotFound, ""); // we already checked ascii printable

    auto b2Start     = reinterpret_cast<wchar_t const*>(buffer.GetData());
    const auto b2End = reinterpret_cast<wchar_t const*>(buffer.GetData() + buffer.GetLength());
    std::wcmatch wcm{};
    if (std::regex_search(b2Start, b2End, wcm, this->pattern_unicode)) {
        start = offset + wcm.position();
        end   = start + wcm.length();
        return Result::Unicode;
    }

    return Result::NotFound;
}

} // namespace GView::GenericPlugins::Droppper::SpecialStrings
