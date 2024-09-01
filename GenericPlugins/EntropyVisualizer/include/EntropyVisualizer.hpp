#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::EntropyVisualizer
{
static const SpecialChars BLOCK_SPECIAL_CHARACTER                   = SpecialChars::Block75;
static const Color CANVAS_ENTROPY_BACKGROUND                        = Color::Black;
static const uint32 SHANNON_ENTROPY_MAX_VALUE                       = 8;
static const uint32 SHANNON_ENTROPY_DATA_TYPE_MAX_VALUE             = 2;
static const uint32 SHANNON_ENTROPY_LEGEND_DATA_TYPE_HEIGHT         = 10;
static const uint32 SHANNON_ENTROPY_LEGEND_HEIGHT                   = 13;
static const std::string_view SHANNON_ENTROPY_OPTION_NAME           = "Shannon Entropy";
static const std::string_view SHANNON_ENTROPY_DATA_TYPE_OPTION_NAME = "Shannon Entropy Data Type";
static const uint32 EMBEDDED_OBJECTS_MAX_VALUE                      = 6;
static const uint32 EMBEDDED_OBJECTS_LEGEND_HEIGHT                  = 12 + 8;
static const std::string_view EMBEDDED_OBJECTS_OPTION_NAME          = "Embedded Objects";
static const uint32 MINIMUM_BLOCK_SIZE                              = 4;

static const uint32 COMBO_BOX_ITEM_SHANNON_ENTROPY           = 0;
static const uint32 COMBO_BOX_ITEM_SHANNON_ENTROPY_DATA_TYPE = 1;
static const uint32 COMBO_BOX_ITEM_EMBEDDED_OBJECTS          = 2;

class Plugin : public Window
{
  private:
    Reference<Control> parent; // hackish for retaining parent window

  private:
    Reference<Object> object;
    Reference<ComboBox> entropyComboBox;
    Reference<NumericSelector> blockSizeSelector;
    Reference<CanvasViewer> canvasEntropy;
    Reference<CanvasViewer> canvasLegend;

    Reference<NumericSelector> alphaSelector;

    uint32 blockSize = MINIMUM_BLOCK_SIZE;

  private:
    void ResizeLegendCanvas();
    static Color ShannonEntropyValueToColor(int32 value);
    static Color ShannonEntropyDataTypeValueToColor(double value, double epsilon);
    static Color ShannonEntropyDataTypeValueToColorName(std::string_view name);
    static double ComputeEpsilon(uint64 size);
    static Color EmbeddedObjectValueToColor(std::string_view name);
    bool InitializeBlocksForCanvas();

  public:
    Plugin(Reference<Object> object);

    bool DrawShannonEntropy(bool dataType);
    bool DrawShannonEntropyLegend(bool dataType);

    bool DrawEmbeddedObjects();
    bool DrawEmbeddedObjectsLegend();
    std::optional<GView::Utils::Zone> IsOffsetInZone(const GView::Utils::ZonesList& zones, uint64 offset) const;

    virtual void OnAfterResize(int newWidth, int newHeight) override;
    bool OnEvent(Reference<Control> sender, Event eventType, int controlID) override;
};
} // namespace GView::GenericPlugins::EntropyVisualizer
