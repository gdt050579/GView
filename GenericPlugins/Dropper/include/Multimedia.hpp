#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::Multimedia
{
class SWF : public IDrop
{
  private:
  public:
    SWF() = default;

    virtual const std::string_view GetName() const override;
    virtual Category GetCategory() const override;
    virtual Subcategory GetSubcategory() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
    uint32 GetSwfSignature(BufferView precachedBuffer);
    uint8 GetSwfVersion(BufferView precachedBuffer);
    uint32 GetSwfFileLength(BufferView precachedBuffer);
    uint8 GetSwfNumberBytesRect(uint64 offset, DataCache& file);
    uint32 GetSwfTagLength(uint64 offset, DataCache& file);
};
} // namespace GView::GenericPlugins::Droppper::Multimedia
