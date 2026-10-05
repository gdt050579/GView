#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection)
{
    // keys are handled by the key bindings registry ([Keys.View.Lexical], "Keyboard shortcuts" window)
}
void Config::Initialize()
{
    this->Loaded = true;
}
void GView::View::LexicalViewer::Commands::RegisterKeys(KeyboardControlsInterface* interface)
{
    for (auto cmd : LexicalViewerCommands)
        interface->RegisterKey(cmd);
    interface->BeginCategory("Navigation & editing");
    for (auto cmd : NavigationKeys)
        interface->RegisterKey(cmd);
    interface->RegisterKeyText("[ / ]", "TokenWidth", "Decrease / increase the maximum width of the sizeable tokens");
    interface->RegisterKeyText("{ / }", "TokenHeight", "Decrease / increase the maximum height of the sizeable tokens");
}
void GView::View::LexicalViewer::Commands::OnKeysChanged()
{
    Map.Build(NavigationKeys);
}
