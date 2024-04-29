#pragma once

#include "Dropper.hpp"

namespace GView::GenericPlugins::Droppper
{
class DropperUI : public Window
{
  private:
    Reference<GView::Object> object;
    Instance instance;
    Reference<Tab> tab;

    Reference<RadioBox> computeForFile;
    Reference<RadioBox> computeForSelection;

    Reference<TextField> binaryFilename;

  public:
    DropperUI(Reference<GView::Object> object);

    bool OnEvent(Reference<Control>, Event eventType, int32) override;
};
} // namespace GView::GenericPlugins::Droppper
