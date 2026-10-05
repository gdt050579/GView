#include "TextViewer.hpp"

using namespace GView::View::TextViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection)
{
    // keys are handled by the key bindings registry ([Keys.View.Text], "Keyboard shortcuts" window)
}
void Config::Initialize()
{
    this->Loaded = true;
}
void GView::View::TextViewer::Commands::RegisterKeys(KeyboardControlsInterface* interface)
{
    interface->RegisterKey(&WordWrap);
    interface->BeginCategory("Navigation & editing");
    for (auto k : NavigationKeys)
        interface->RegisterKey(k);
}
void GView::View::TextViewer::Commands::OnKeysChanged()
{
    Map.Build(NavigationKeys);
}
