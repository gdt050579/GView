#pragma once

#include <cassert>
#include <GView.hpp>

namespace GView::Type::JClass
{
class ClassViewer : public TypeInterface
{
  public:
    string_view GetTypeName() override;
    void RunCommand(std::string_view) override;
    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }
};
} // namespace GView::Type::JClass
