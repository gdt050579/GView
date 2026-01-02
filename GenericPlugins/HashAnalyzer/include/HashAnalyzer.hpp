#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::HashAnalyzer
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;

// Placeholder dialog class for future implementation
class HashAnalyzerDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<GView::Object> object;
    Reference<Button> close;

  public:
    HashAnalyzerDialog(Reference<GView::Object> object);
    void OnButtonPressed(Reference<Button> b) override;
};

} // namespace GView::GenericPlugins::HashAnalyzer

