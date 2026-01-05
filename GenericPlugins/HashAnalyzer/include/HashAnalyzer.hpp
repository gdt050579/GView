#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::HashAnalyzer
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;

class HashAnalyzerDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<GView::Object> object;
    Reference<Button> close;
    
    Reference<RadioBox> computeForFile;
    Reference<RadioBox> computeForSelection;
    Reference<ListView> hashesList;
    Reference<Button> computeBtn;

    std::vector<TypeInterface::SelectionZone> selectedZones;

    void ComputeHash();

  public:
    HashAnalyzerDialog(Reference<GView::Object> object);
    void OnButtonPressed(Reference<Button> b) override;
};

} // namespace GView::GenericPlugins::HashAnalyzer

