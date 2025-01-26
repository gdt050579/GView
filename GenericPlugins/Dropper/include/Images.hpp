#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::Images
{
class PNG : public IDrop
{
  private:
  public:
    PNG() = default;

    virtual const std::string_view GetName() const override;
    virtual Category GetCategory() const override;
    virtual Subcategory GetSubcategory() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};

class JPG : public IDrop
{
  private:
  public:
    JPG() = default;

    virtual const std::string_view GetName() const override;
    virtual Category GetCategory() const override;
    virtual Subcategory GetSubcategory() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};

class BMP : public IDrop
{
  private:
  public:
    BMP() = default;

    virtual const std::string_view GetName() const override;
    virtual Category GetCategory() const override;
    virtual Subcategory GetSubcategory() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};

} // namespace GView::GenericPlugins::Droppper::Images
