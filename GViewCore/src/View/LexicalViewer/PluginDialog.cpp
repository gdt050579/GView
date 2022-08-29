#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_RUN    = 1;
constexpr int32 BTN_ID_CANCEL = 2;

PluginDialog::PluginDialog(PluginData& data, Reference<SettingsData> _settings)
    : Window("Plugins", "d:c,w:70,h:24", WindowFlags::ProcessReturn), pluginData(data), settings(_settings)
{
    this->lstPlugins        = Factory::ListView::Create(this, "l:1,t:1,r:1,b:4", { "w:25,a:l,n:Name", "w:200,a:l,n:Descrition" });
    this->cbOpenInNewWindow = Factory::CheckBox::Create(this, "Open result in &new window", "l:1,b:3,w:60");

    // populate
    auto index = 0;
    for (auto& p : settings->plugins)
    {
        auto item = this->lstPlugins->AddItem({ p->GetName(), p->GetDescription() });
        if (p->CanBeAppliedOn(pluginData) == false)
            item.SetType(ListViewItem::Type::GrayedOut);
        else
            item.SetType(ListViewItem::Type::Normal);
        item.SetData(index);
        index++;
    }

    // buttons
    Factory::Button::Create(this, "&Run", "l:21,b:0,w:13", BTN_ID_RUN);
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);
}
void PluginDialog::RunPlugin()
{
    Exit(Dialogs::Result::Ok);
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
        case BTN_ID_RUN:
            RunPlugin();
            return true;
        }
        break;
    case Event::ListViewItemPressed:
    case Event::WindowAccept:
        RunPlugin();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
} // namespace GView::View::LexicalViewer