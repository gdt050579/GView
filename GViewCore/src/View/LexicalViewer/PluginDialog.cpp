#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_RUN      = 1;
constexpr int32 BTN_ID_CANCEL   = 2;
constexpr int32 APPLY_GROUP_ID  = 1234;
constexpr uint64 INVALID_PLUGIN = 0xFFFFFFFFFFFFFFFFULL;

PluginDialog::PluginDialog(PluginData& data, Reference<SettingsData> _settings)
    : Window("Plugins", "d:c,w:70,h:24", WindowFlags::ProcessReturn), pluginData(data), settings(_settings),
      afterActionRequest(PluginAfterActionRequest::None)
{
    this->lstPlugins        = Factory::ListView::Create(this, "l:1,t:1,r:1,b:8", { "w:25,a:l,n:Name", "w:200,a:l,n:Descrition" });
    this->rbRunOnEntireFile = Factory::RadioBox::Create(this, "Run the plugin for the entire &program", "l:1,b:6,w:60", APPLY_GROUP_ID);
    this->rbRunOnSelection  = Factory::RadioBox::Create(this, "Run the plugin over the &selected tokens", "l:1,b:5,w:60", APPLY_GROUP_ID);
    this->cbOpenInNewWindow = Factory::CheckBox::Create(this, "Open result in &new window", "l:1,b:3,w:60");

    this->cbOpenInNewWindow->SetEnabled(false); // for the moment

    // populate
    auto index = 0;
    for (auto& p : settings->plugins)
    {
        auto item = this->lstPlugins->AddItem({ p->GetName(), p->GetDescription() });
        if (p->CanBeAppliedOn(pluginData) == false)
        {
            item.SetType(ListViewItem::Type::GrayedOut);
            item.SetData(INVALID_PLUGIN);
        }
        else
        {
            item.SetType(ListViewItem::Type::Normal);
            item.SetData(index);
        }
        index++;
    }

    // buttons
    Factory::Button::Create(this, "&Run", "l:21,b:0,w:13", BTN_ID_RUN);
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);
}
void PluginDialog::RunPlugin()
{
    auto item = lstPlugins->GetCurrentItem();
    if (item.IsValid() == false)
        return;
    if (item.GetData(INVALID_PLUGIN) == INVALID_PLUGIN)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Selected plugin can not be applied for current file/selection or token !");
        return;
    }
    // run the plugin
    auto idx = static_cast<size_t>(item.GetData(INVALID_PLUGIN));
    if (idx >= this->settings->plugins.size())
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Internal error -> invalid plugin index");
        return;
    }
    this->afterActionRequest = this->settings->plugins[idx]->Execute(this->pluginData);
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