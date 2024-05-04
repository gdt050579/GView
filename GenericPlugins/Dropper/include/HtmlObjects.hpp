#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::HtmlObjects
{
class IFrame : public IDrop
{
  public:
    IFrame() = default;

    virtual const std::string_view GetName() const override;
    virtual Category GetCategory() const override;
    virtual Subcategory GetSubcategory() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};
class Script : public IDrop
{
  public:
    Script() = default;

    virtual const std::string_view GetName() const override;
    virtual Category GetCategory() const override;
    virtual Subcategory GetSubcategory() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};
class XML : public IDrop // TODO: maybe a proper XML parser
{
  public:
    XML() = default;

    virtual const std::string_view GetName() const override;
    virtual Category GetCategory() const override;
    virtual Subcategory GetSubcategory() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};
} // namespace GView::GenericPlugins::Droppper::HtmlObjects
