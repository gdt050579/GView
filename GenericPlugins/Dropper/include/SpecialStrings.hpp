#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
class IpAddress : public IDrop
{
  public:
    IpAddress() = default;

    virtual const char* GetName() override;
    virtual ObjectCategory GetGroup() override;
    virtual const char* GetOutputExtension() override;
    virtual Priority GetPriority() override;
    virtual bool ShouldGroupInOneFile() override;

    virtual Result Check(uint64 offset, DataCache& file, unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
