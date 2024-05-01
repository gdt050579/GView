#pragma once

#include "IDrop.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
enum class Types { Email, Filepath, IP, Registry, URL, Wallet };

static const std::map<Types, Metadata> TYPES_MAP{
    { Types::Email, { "Email address", "An email address identifies an email box to which messages are delivered.", true } },
    { Types::Filepath, { "Filepath", "A path is a string of characters used to uniquely identify a location in a directory structure.", true } },
    { Types::IP,
      { "IP address",
        "An Internet Protocol address is a numerical label such as 192.0.2.1 that is assigned to a device connected to a computer network that uses the "
        "Internet Protocol for communication.",
        true } },
    { Types::Registry,
      { "Registry entry",
        "The Windows Registry is a hierarchical database that stores low-level settings for the Microsoft Windows operating system and for applications that "
        "opt to use the registry.",
        true } },
    { Types::URL,
      { "URL",
        "A uniform resource locator, colloquially known as an address on the Web, is a reference to a resource that specifies its location on a computer "
        "network and a mechanism for retrieving it.",
        true } },
    { Types::Email,
      { "Wallet address",
        "A wallet address, a unique identifier in the blockchain, is a randomly generated series of alphanumeric characters that corresponds to a specific "
        "cryptocurrency stored in a blockchain wallet.",
        true } },
};

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

// text class has a separate purpose
class Text : public SpecialStrings
{
  private:
    uint32 minLength{ 8 };
    uint32 maxLength{ 128 };

  public:
    Text(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;

    bool SetMinLength(uint32 minLength);
    bool SetMaxLength(uint32 maxLength);
};
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
