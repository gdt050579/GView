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

    std::filesystem::path droppedFilename;

    Reference<RadioBox> computeForFile;
    Reference<RadioBox> computeForSelection;

    Reference<TextField> binaryFilename;
    Reference<TextField> binaryIncludedCharset;
    Reference<TextField> binaryExcludedCharset;

    Reference<CheckBox> checkboxOpenDroppedFile;
    Reference<RadioBox> overwriteFile;
    Reference<RadioBox> appendToFile;

    std::filesystem::path logFilename;
    Reference<ListView> objectsPlugins;
    std::vector<ItemMetadata> objectsMetadata;
    Reference<Label> currentObjectDescription;
    Reference<TextField> objectsFilename;
    Reference<TextField> objectsLogFilename;
    Reference<CheckBox> checkRecursiveInObjects;
    Reference<CheckBox> writeObjectsLog;
    Reference<CheckBox> openLogInView;
    Reference<CheckBox> openDroppedObjects;
    Reference<CheckBox> highlightObjects;

    std::filesystem::path stringsFilename;
    Reference<TextField> stringsLogFilename;
    Reference<CheckBox> dropAsciiStrings;
    Reference<CheckBox> dropUnicodeStrings;
    Reference<RadioBox> logDumpSimple;
    Reference<RadioBox> logDumpTabular;
    Reference<TextField> minimumStringSize;
    Reference<TextField> maximumStringSize;
    Reference<TextField> stringsCharset;
    Reference<CheckBox> identifyStringsArtefacts;
    Reference<CheckBox> openArtefactsInView;
    Reference<CheckBox> openStringsLogFile;

  private:
    bool DropBinary();
    const std::vector<PluginClassification> GetActivePlugins();

  public:
    DropperUI(Reference<GView::Object> object);

    bool OnEvent(Reference<Control> control, Event eventType, int32 id) override;
    bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
};
} // namespace GView::GenericPlugins::Droppper
