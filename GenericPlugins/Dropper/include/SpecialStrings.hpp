#pragma once

#include "IDrop.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
constexpr std::string_view DEFAULT_STRINGS_CHARSET{ "\\x20-\\x7e" };
constexpr int32 STRINGS_CHARSET_MATRIX_SIZE{ 256 };

class SpecialStrings : public IDrop
{
  protected:
    bool unicode{ false };
    bool caseSensitive{ false };
    GView::Regex::Matcher matcherAscii{};
    GView::Regex::Matcher matcherUnicode{};

  public:
    virtual Category GetGroup() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;
};

class IpAddress : public SpecialStrings
{
  public:
    IpAddress(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubGroup() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class EmailAddress : public SpecialStrings
{
  public:
    EmailAddress(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubGroup() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Filepath : public SpecialStrings
{
  public:
    Filepath(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubGroup() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class URL : public SpecialStrings
{
  public:
    URL(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubGroup() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Wallet : public SpecialStrings
{
  public:
    Wallet(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubGroup() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Registry : public SpecialStrings
{
  public:
    Registry(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubGroup() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};

// text class has a separate purpose
class Text : public SpecialStrings
{
  private:
    bool ascii{ false };
    uint32 minLength{ 8 };
    uint32 maxLength{ 128 };
    bool stringsCharSetMatrix[STRINGS_CHARSET_MATRIX_SIZE]{};

  public:
    Text(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubGroup() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;

    bool SetMinLength(uint32 minLength);
    bool SetMaxLength(uint32 maxLength);
    bool SetAscii(bool value);
    bool SetUnicode(bool value);
    void SetMatrix(bool stringsCharSetMatrix[STRINGS_CHARSET_MATRIX_SIZE]);
    bool IsValidChar(char c) const;
};
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
