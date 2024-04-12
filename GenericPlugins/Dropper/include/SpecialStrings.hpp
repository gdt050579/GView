#pragma once

#include "IDrop.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
class SpecialStrings : public IDrop
{
  protected:
    bool unicode{ false };
    bool caseSensitive{ false };
    GView::Regex::Matcher matcherAscii{};
    GView::Regex::Matcher matcherUnicode{};

  public:
    virtual ObjectCategory GetGroup() override;
    virtual Priority GetPriority() override;
    virtual bool ShouldGroupInOneFile() override;
};

class IpAddress : public SpecialStrings
{
  public:
    IpAddress(bool caseSensitive, bool unicode);

    virtual const char* GetName() override;
    virtual const char* GetOutputExtension() override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class EmailAddress : public SpecialStrings
{
  public:
    EmailAddress(bool caseSensitive, bool unicode);

    virtual const char* GetName() override;
    virtual const char* GetOutputExtension() override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Filepath : public SpecialStrings
{
  public:
    Filepath(bool caseSensitive, bool unicode);

    virtual const char* GetName() override;
    virtual const char* GetOutputExtension() override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
