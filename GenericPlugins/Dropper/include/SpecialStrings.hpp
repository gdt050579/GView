#pragma once

#include "IDrop.hpp"
#include <string>
#include <regex>

inline static const std::string_view IPS_REGEX_ASCII{ R"(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\:[0-9]{1,5})*))" };
inline static const std::u16string_view IPS_REGEX_UNICODE{ uR"(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\:[0-9]{1,5})*))" };

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
class IpAddress : public IDrop
{
  private:
    std::regex pattern_ascii;
    std::wregex pattern_unicode;
    bool unicode{ false };

  public:
    IpAddress(bool caseSensitive, bool unicode)
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

    virtual const char* GetName() override;
    virtual ObjectCategory GetGroup() override;
    virtual const char* GetOutputExtension() override;
    virtual Priority GetPriority() override;
    virtual bool ShouldGroupInOneFile() override;

    virtual Result Check(uint64 offset, DataCache& file, unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
