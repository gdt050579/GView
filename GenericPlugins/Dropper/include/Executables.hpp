#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::Executables
{
class MZPE : public IDrop
{
  private:
  public:
    MZPE() = default;

    virtual const std::string_view GetName() const override;
    virtual ObjectCategory GetGroup() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::Executables
