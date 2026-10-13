#include "GridViewer.hpp"
#include <array>
using namespace GView::View::GridViewer;
using namespace GView::View::GridViewer::Commands;
using namespace AppCUI::Input;

void Config::Update(IniSection)
{
    // keys are handled by the key bindings registry ([Keys.View.Grid], "Keyboard shortcuts" window)
}

void Config::Initialize()
{
    loaded = true;
}

void GView::View::GridViewer::Commands::RegisterKeys(KeyboardControlsInterface* interface)
{
    for (auto cmd : AllGridCommands)
        interface->RegisterKey(cmd);
    // keys handled by the AppCUI grid control (not configurable)
    interface->BeginCategory("Navigation & editing");
    interface->RegisterKeyText("Arrows", "MoveCursor", "Move the current cell");
    interface->RegisterKeyText("Shift+Arrows", "ExtendSelection", "Select a range of cells");
    interface->RegisterKeyText("Ctrl+Arrows", "Scroll", "Scroll the grid");
    interface->RegisterKeyText("Ctrl+Alt+Arrows", "ResizeCells", "Change the size of the cells");
    interface->RegisterKeyText("Ctrl+Space", "ResetLayout", "Reset the cells layout");
    interface->RegisterKeyText("Ctrl+C", "CopyCells", "Copy the selected cells");
    interface->RegisterKeyText("Escape", "ClearSelection", "Clear the selection");
}
