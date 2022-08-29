#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK      = 1;
constexpr int32 BTN_ID_CANCEL  = 2;
constexpr int32 APPLY_GROUP_ID = 1;

PluginDialog::PluginDialog(PluginData& data, Reference<SettingsData> settings)
    : Window("Plugins", "d:c,w:70,h:12", WindowFlags::ProcessReturn), pluginData(data)
{
    this->lstPlugins        = Factory::ListView::Create(this, "l:1,t:1,r:1,b:4", { "w:200,a:l,n:Name" }, ListViewFlags::HideColumns);
    this->cbOpenInNewWindow = Factory::CheckBox::Create(this, "Open result in &new window", "l:1,b:2,w:60");

    // buttons
    Factory::Button::Create(this, "&Delete", "l:21,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);
}
bool PluginDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    switch (eventType)
    {
    case Event::ButtonClicked:
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            Exit(Dialogs::Result::Ok);
            return true;
        }
        break;

    case Event::WindowAccept:
        Exit(Dialogs::Result::Ok);
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
} // namespace GView::View::LexicalViewer