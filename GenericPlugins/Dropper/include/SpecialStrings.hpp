#pragma once

#include "IDrop.hpp"
#include <string>
#include <regex>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
class IpAddress : public IDrop
{
  private:
    std::regex pattern_ascii;
    std::wregex pattern_unicode;
    bool unicode{ false };

  public:
    IpAddress(bool caseSensitive, bool unicode);

    virtual const char* GetName() override;
    virtual ObjectCategory GetGroup() override;
    virtual const char* GetOutputExtension() override;
    virtual Priority GetPriority() override;
    virtual bool ShouldGroupInOneFile() override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
