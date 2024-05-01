#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::HtmlObjects
{
enum class Types { IFrame, Script, XML };

static const std::map<Types, Metadata> TYPES_MAP{
    { Types::IFrame,
      { "IFrame",
        "An inline frame (iframe) is a HTML element that loads another HTML page within the document. It essentially puts another webpage within the parent "
        "page.",
        true } },
    { Types::Script,
      { "Script", "The <script> HTML element is used to embed executable code or data; this is typically used to embed or refer to JavaScript code. ", true } },
    { Types::XML,
      { "XML", "Extensible Markup Language (XML) is a markup language and file format for storing, transmitting, and reconstructing arbitrary data.", true } },
};

class IFrame : public IDrop
{
  public:
    IFrame() = default;

    virtual const std::string_view GetName() const override;
    virtual ObjectCategory GetGroup() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class Script : public IDrop
{
  public:
    Script() = default;

    virtual const std::string_view GetName() const override;
    virtual ObjectCategory GetGroup() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
class XML : public IDrop // TODO: maybe a proper XML parser
{
  public:
    XML() = default;

    virtual const std::string_view GetName() const override;
    virtual ObjectCategory GetGroup() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::HtmlObjects
