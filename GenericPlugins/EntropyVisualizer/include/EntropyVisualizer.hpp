#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::EntropyVisualizer
{
static const SpecialChars BLOCK_SPECIAL_CHARACTER         = SpecialChars::Block75;
static const Color CANVAS_ENTROPY_BACKGROUND              = Color::Black;
static const uint32 SHANNON_ENTROPY_MAX_VALUE             = 8;
static const uint32 SHANNON_ENTROPY_LEGEND_HEIGHT         = 13;
static const std::string_view SHANNON_ENTROPY_OPTION_NAME = "Shannon Entropy";
static const uint32 MINIMUM_BLOCK_SIZE                    = 4;

static const uint32 COMBO_BOX_ITEM_SHANNON_ENTROPY = 0;

class Plugin : public Window
{
    Reference<Object> object;
    Reference<ComboBox> entropyComboBox;
    Reference<ComboBox> blockSizeComboBox;
    Reference<CanvasViewer> canvasEntropy;
    Reference<CanvasViewer> canvasLegend;

    uint32 blockSize = MINIMUM_BLOCK_SIZE;

  private:
    void ResizeLegendCanvas();
    static Color ShannonEntropyValueToColor(int32 value);
    bool InitializeBlocksForCanvas();

  public:
    Plugin(Reference<Object> object);

    bool DrawShannonEntropy();
    bool DrawShannonEntropyLegend();

    virtual void OnAfterResize(int newWidth, int newHeight) override;
    bool OnEvent(Reference<Control> sender, Event eventType, int controlID) override;
};
} // namespace GView::GenericPlugins::EntropyVisualizer
