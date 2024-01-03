#pragma once

#include "class_parser.hpp"

using namespace AppCUI;
using namespace AppCUI::OS;
using namespace AppCUI::Controls;
using namespace AppCUI::Application;
using namespace GView::Type;
using namespace GView::View;

namespace GView::Type::JClass
{
class ClassViewer : public TypeInterface
{
  private:
    ClassParser parser;

  public:
    vector<ColoredArea> areas;
    vector<ConstPanel> const_panel;

    string_view GetTypeName() override;
    void RunCommand(std::string_view) override;

    bool Parse();
};
} // namespace GView::Type::JClass
