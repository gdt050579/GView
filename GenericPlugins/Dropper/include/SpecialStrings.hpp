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
    virtual ObjectCategory GetGroup() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;
};

class IpAddress : public SpecialStrings
{
  public:
    IpAddress(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class EmailAddress : public SpecialStrings
{
  public:
    EmailAddress(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Filepath : public SpecialStrings
{
  public:
    Filepath(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class URL : public SpecialStrings
{
  public:
    URL(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Wallet : public SpecialStrings
{
  public:
    Wallet(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Registry : public SpecialStrings
{
  public:
    Registry(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Text : public SpecialStrings
{
  public:
    Text(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
