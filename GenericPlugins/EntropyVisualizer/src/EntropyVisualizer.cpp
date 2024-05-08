#include "EntropyVisualizer.hpp"

namespace GView::GenericPlugins::EntropyVisualizer
{
extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "EntropyVisualizer") {
        auto p = Plugin(object);
        p.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["command.EntropyVisualizer"] = Input::Key::Ctrl | Input::Key::F10;
}
}

Color Plugin::ShannonEntropyValueToColor(int32 value)
{
    switch (value) {
    case 0:
        return Color::White;
    case 1:
        return Color::Silver;
    case 2:
        return Color::Gray;
    case 3:
        return Color::Olive;
    case 4:
        return Color::Yellow;
    case 5:
        return Color::DarkGreen;
    case 6:
        return Color::DarkRed;
    case 7:
        return Color::Magenta;
    case 8:
        return Color::Red;
    default:
        return Color::Black;
    }
}

Plugin::Plugin(Reference<Object> object) : Window("EntropyVisualizer", "d:c,w:95%,h:95%", WindowFlags::FixedPosition)
{
    this->object = object;
    {
        Factory::Label::Create(this, "Entropy type", "x:1, y:0,w:12,h:1");
        this->entropyComboBox = Factory::ComboBox::Create(this, "x:14, y:0,w:25,h:1", "");
        entropyComboBox->SetHotKey('E');
        entropyComboBox->AddItem(SHANNON_ENTROPY_OPTION_NAME, COMBO_BOX_ITEM_SHANNON_ENTROPY);
        // TODO: add the rest
        entropyComboBox->SetCurentItemIndex(0);
    }
    {
        Factory::Label::Create(this, "Block size", "x:40,y:0,w:10,h:1");
        this->blockSizeComboBox = Factory::ComboBox::Create(this, "x:51,y:0,w:12,h:1", "");
        blockSizeComboBox->SetHotKey('B');
    }
    {
        this->canvasEntropy = Factory::CanvasViewer::Create(this, "d:lb,w:90%,h:99%", this->GetWidth(), this->GetHeight(), Controls::ViewerFlags::Border);
        auto canvas         = this->canvasEntropy->GetCanvas();
        canvas->Resize(this->canvasEntropy->GetWidth(), this->canvasEntropy->GetHeight());
        canvas->SetCursor(0, 0);
    }
    {
        this->canvasLegend = Factory::CanvasViewer::Create(this, "d:tr,w:10%,h:20%", this->GetWidth(), this->GetHeight(), Controls::ViewerFlags::Border);
        auto canvas        = this->canvasLegend->GetCanvas();
        canvas->Resize(this->canvasLegend->GetWidth(), this->canvasLegend->GetHeight());
    }

    this->InitializeBlocksForCanvas();
    // raise events after all children are initialized
    this->entropyComboBox->RaiseEvent(Event::ComboBoxClosed);

    this->canvasEntropy->SetFocus();
}

bool Plugin::DrawShannonEntropy()
{
    CHECK(this->canvasEntropy.IsValid(), false, "");
    auto canvas = this->canvasEntropy->GetCanvas();

    auto& cache              = object->GetData();
    const auto size          = cache.GetSize();
    const uint32 blocksCount = static_cast<uint32>(size / this->blockSize + 1);

    uint32 x         = 0;
    uint32 y         = 0;
    uint32 maxX      = canvas->GetWidth();
    uint32 maxY      = std::max<uint32>(blocksCount / maxX + 1 + 1, canvas->GetHeight());
    const auto color = ColorPair{ Color::White, this->GetConfig()->Window.Background.Normal };
    canvas->Resize(maxX, maxY, 'X', color);
    canvas->ClearEntireSurface('X', color);

    for (uint32 i = 0; i < blocksCount; i++) {
        auto bf                 = cache.Get(i * static_cast<uint64>(this->blockSize), this->blockSize, false);
        const auto value        = GView::Entropy::ShannonEntropy(bf);
        const auto roundedValue = static_cast<uint32>(std::llround(value));
        const auto fColor       = ShannonEntropyValueToColor(roundedValue);

        canvas->WriteSpecialCharacter(x++, y, BLOCK_SPECIAL_CHARACTER, ColorPair{ fColor, CANVAS_ENTROPY_BACKGROUND });
        if (x == maxX) {
            x = 0;
            y++;
        }
    }

    return true;
}

bool Plugin::DrawShannonEntropyLegend()
{
    CHECK(this->canvasLegend.IsValid(), false, "");
    ResizeLegendCanvas();

    auto canvas = this->canvasLegend->GetCanvas();

    const auto color = ColorPair{ Color::White, this->GetConfig()->Window.Background.Normal };

    uint32 x = 0;
    uint32 y = 0;
    canvas->Clear(' ', color);

    canvas->WriteSingleLineText(x, y++, "Shanon Legend [0-8]", color);
    canvas->FillHorizontalLineWithSpecialChar(x, y++, canvas->GetWidth(), SpecialChars::BoxHorizontalSingleLine, color);
    x = 0;

    for (uint32 i = 0; i <= SHANNON_ENTROPY_MAX_VALUE; i++) {
        canvas->WriteCharacter(x++, y, i + '0', color);
        canvas->WriteCharacter(x++, y, ' ', color);
        canvas->WriteCharacter(x++, y, '=', color);
        canvas->WriteCharacter(x++, y, '>', color);
        canvas->WriteCharacter(x++, y, ' ', color);

        while (x < canvas->GetWidth()) {
            canvas->WriteSpecialCharacter(x++, y, BLOCK_SPECIAL_CHARACTER, ColorPair{ ShannonEntropyValueToColor(i), CANVAS_ENTROPY_BACKGROUND });
        }
        y++;
        x = 0;
    }

    return true;
}

void Plugin::OnAfterResize(int newWidth, int newHeight)
{
    ResizeLegendCanvas();
}

void Plugin::ResizeLegendCanvas()
{
    CHECKRET(canvasLegend.IsValid(), "");
    CHECKRET(canvasEntropy.IsValid(), "");
    this->canvasLegend->MoveTo(this->canvasLegend->GetX(), this->canvasEntropy->GetY());

    uint32 newHeight   = this->canvasLegend->GetHeight();
    const auto entropy = this->entropyComboBox->GetCurrentItemUserData(-1);
    if (entropy == COMBO_BOX_ITEM_SHANNON_ENTROPY) {
        newHeight = SHANNON_ENTROPY_LEGEND_HEIGHT;
    }

    this->canvasLegend->Resize(this->canvasLegend->GetWidth(), newHeight);
    auto canvas = this->canvasLegend->GetCanvas();
    canvas->Resize(this->canvasLegend->GetWidth(), newHeight);
}

bool Plugin::OnEvent(Reference<Control> sender, Event eventType, int controlID)
{
    if (Window::OnEvent(sender, eventType, controlID)) {
        return true;
    }

    switch (eventType) {
    case AppCUI::Controls::Event::ComboBoxSelectedItemChanged:
        /* nothing, it is to costly computing entropy each time / on the fly */
        break;
    case AppCUI::Controls::Event::ComboBoxClosed:
        if (sender == this->entropyComboBox.ToBase<Control>()) {
            const auto entropy = this->entropyComboBox->GetCurrentItemUserData(-1);
            if (entropy == COMBO_BOX_ITEM_SHANNON_ENTROPY) {
                this->DrawShannonEntropy();
                this->DrawShannonEntropyLegend();
            }
            return true;
        }
        if (sender == this->blockSizeComboBox.ToBase<Control>()) {
            this->blockSize = static_cast<uint32>(this->blockSizeComboBox->GetCurrentItemUserData(-1));
            this->entropyComboBox->RaiseEvent(Event::ComboBoxClosed);
            return true;
        }
        break;
    default:
        break;
    }

    return false;
}

bool Plugin::InitializeBlocksForCanvas()
{
    CHECK(this->object.IsValid(), false, "");
    CHECK(this->canvasEntropy.IsValid(), false, "");

    const auto size         = this->object->GetData().GetSize();
    auto canvas             = this->canvasEntropy->GetCanvas();
    const auto canvasWidth  = canvas->GetWidth();
    const auto canvasHeight = canvas->GetHeight();

    uint32 blocksRows = 0;
    do {
        uint32 blocksCount = static_cast<uint32>(size / this->blockSize);
        blocksRows         = blocksCount / canvasWidth + 1;
        blockSizeComboBox->AddItem(std::to_string(this->blockSize), this->blockSize);
        this->blockSize *= 2;
    } while (blocksRows > canvasHeight);
    this->blockSize /= 2;

    blockSizeComboBox->SetCurentItemIndex(blockSizeComboBox->GetItemsCount() - 1);

    return true;
}
} // namespace GView::GenericPlugins::EntropyVisualizer
