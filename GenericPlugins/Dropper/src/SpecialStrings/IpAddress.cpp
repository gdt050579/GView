#include "SpecialStrings.hpp"

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

Result IpAddress::Check(uint64 offset, DataCache& file, unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint64& start, uint64& end)
{
    return Result::NotFound;
}

} // namespace GView::GenericPlugins::Droppper::SpecialStrings
