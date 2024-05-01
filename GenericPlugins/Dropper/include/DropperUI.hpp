#pragma once

#include "Dropper.hpp"

namespace GView::GenericPlugins::Droppper
{
struct ItemMetadata {
    std::optional<ListViewItem> parent;
    std::vector<ListViewItem> children;
    ObjectCategory category{ ObjectCategory::Archives };
    uint32 subcategory{ 0 };
};

class DropperUI : public Window
{
  private:
    Reference<Window> parentWindow{ nullptr };

    Reference<GView::Object> object;
    Instance instance;
    Reference<Tab> tab;

    Reference<RadioBox> computeForFile;
    Reference<RadioBox> computeForSelection;

    Reference<TextField> binaryFilename;
    Reference<TextField> includedCharset;
    Reference<TextField> excludedCharset;

    Reference<CheckBox> checkboxOpenDroppedFile;
    Reference<RadioBox> overwriteFile;
    Reference<RadioBox> appendToFile;

    Reference<ListView> objectsPlugins;
    std::vector<ItemMetadata> objectsMetadata;
    Reference<Label> currentObjectDescription;

  private:
    bool DropBinary();

  public:
    DropperUI(Reference<GView::Object> object);

    bool OnEvent(Reference<Control> control, Event eventType, int32 id) override;
    bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
};
} // namespace GView::GenericPlugins::Droppper
