#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_RUN      = 1;
constexpr int32 BTN_ID_CANCEL   = 2;
constexpr int32 APPLY_GROUP_ID  = 1234;
constexpr uint64 INVALID_PLUGIN = 0xFFFFFFFFFFFFFFFFULL;

PluginDialog::PluginDialog(
      PluginData& data,
      Reference<SettingsData> _settings,
      uint32 _selectionStart,
      uint32 _selectionEnd,
      uint32 _blockStart,
      uint32 _blockEnd)
    : Window("Plugins", "d:c,w:70,h:24", WindowFlags::ProcessReturn), pluginData(data), settings(_settings),
      afterActionRequest(PluginAfterActionRequest::None), selectionStart(_selectionStart), selectionEnd(_selectionEnd),
      blockStart(_blockStart), blockEnd(_blockEnd)
{
    this->lstPlugins          = Factory::ListView::Create(this, "l:1,t:1,r:1,b:9", { "w:25,a:l,n:Name","w:3,a:c,n:#", "w:200,a:l,n:Descrition" });
    this->rbRunOnEntireFile   = Factory::RadioBox::Create(this, "Run the plugin for the entire &program", "l:1,b:7,w:60", APPLY_GROUP_ID);
    this->rbRunOnCurrentBlock = Factory::RadioBox::Create(this, "Run the plugin for current &block", "l:1,b:6,w:60", APPLY_GROUP_ID);
    this->rbRunOnSelection    = Factory::RadioBox::Create(this, "Run the plugin over the &selected tokens", "l:1,b:5,w:60", APPLY_GROUP_ID);
    this->cbOpenInNewWindow   = Factory::CheckBox::Create(this, "Open result in &new window", "l:1,b:3,w:60");

    this->cbOpenInNewWindow->SetEnabled(false); // for the moment

    this->rbRunOnSelection->SetEnabled(selectionEnd > selectionStart);
    this->rbRunOnCurrentBlock->SetEnabled(blockEnd > blockStart);
    if (selectionEnd > selectionStart)
        this->rbRunOnSelection->SetChecked(true);
    else
        this->rbRunOnEntireFile->SetChecked(true);

    // populate
    for (auto& p : settings->plugins)
    {
        this->lstPlugins->AddItem({ p->GetName(), "", p->GetDescription() });
    }

    // buttons
    Factory::Button::Create(this, "&Run", "l:21,b:0,w:13", BTN_ID_RUN);
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);
    
    // update plugin data
    UpdatePluginData();
}
void PluginDialog::UpdatePluginData()
{
    if (rbRunOnEntireFile->IsChecked())
    {
        pluginData.startIndex = 0;
        pluginData.endIndex   = pluginData.tokens.Len();
    }
    if (rbRunOnSelection->IsChecked())
    {
        pluginData.startIndex = selectionStart;
        pluginData.endIndex   = selectionEnd;
    }
    if (rbRunOnCurrentBlock->IsChecked())
    {
        pluginData.startIndex = blockStart;
        pluginData.endIndex   = blockEnd;
    }
    // update plugin status
    auto index = 0;
    char16 status[2] = { 0 };
    for (auto& p : settings->plugins)
    {
        auto item = this->lstPlugins->GetItem(index);
        if (p->CanBeAppliedOn(pluginData) == false)
        {
            item.SetType(ListViewItem::Type::GrayedOut);
            item.SetData(INVALID_PLUGIN);
            status[0] = '-';
        }
        else
        {
            item.SetType(ListViewItem::Type::Normal);
            item.SetData(index);
            status[0] = '+';

        }
        item.SetText(1, u16string_view{ status, (size_t)2 });
        index++;
    }
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
    case Event::CheckedStatusChanged:
        UpdatePluginData();
        return true;
    }

    return false;
}
} // namespace GView::View::LexicalViewer