#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection)
{
    // keys are handled by the key bindings registry ([Keys.View.Image], "Keyboard shortcuts" window)
}
void Config::Initialize()
{
    this->Loaded = true;
}
void GView::View::ImageViewer::Commands::RegisterKeys(KeyboardControlsInterface* interface)
{
    for (auto cmd : ImageViewCommands)
        interface->RegisterKey(cmd);
    interface->BeginCategory("Navigation & editing");
    interface->RegisterKeyText("+ / =", "ZoomInChar", "Zoom in the picture");
    interface->RegisterKeyText("- / _", "ZoomOutChar", "Zoom out the picture");
}
