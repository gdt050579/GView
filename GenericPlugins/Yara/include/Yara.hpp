#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::Yara
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::View;

class YaraDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<GView::Object> object;
    Reference<Button> closeButton;

  public:
    YaraDialog(Reference<GView::Object> object);
    void OnButtonPressed(Reference<Button> b) override;
};

} // namespace GView::GenericPlugins::Yara
