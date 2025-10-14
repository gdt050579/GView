#include "Internal.hpp"

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

class KeyConfigDisplayWindow : public Controls::Window
{
  public:
    KeyConfigDisplayWindow(const std::vector<KeyboardControlsImplementation::OwnedKeyboardControl>& keys)
        : Window("Available keys", "d:c", Controls::WindowFlags::Sizeable)
    {
        auto list = Factory::ListView::Create(
              this, "x:1,y:1,w:99%,h:99%", { "n:Caption,w:30%", "n:Description,w:50%", "n:Key,w:20%" }, ListViewFlags::PopupSearchBar);

        LocalString<32> buffer;

        for (const auto& key : keys) {
            buffer.Clear();
            if (!KeyUtils::ToString(key.Key, buffer))
                buffer.SetFormat("Failed to convert key");
            const std::initializer_list<ConstString> items = { key.Caption.c_str(), key.Explanation.c_str(), buffer.GetText() };
            list->AddItem(items);
        }
    }
    virtual bool OnEvent(AppCUI::Utils::Reference<Control>, AppCUI::Controls::Event eventType, int ID) override
    {
        switch (eventType) {
        case Event::ButtonClicked:
        case Event::WindowAccept:
        case Event::WindowClose:
            Exit(Dialogs::Result::Cancel);
            return true;
        }

        return false;
    }
};

void GView::App::FileWindow::ShowKeyConfiguratorWindow()
{
    KeyboardControlsImplementation impl;

    auto pluginTypeInstance = obj->GetContentType();
    pluginTypeInstance->UpdateKeys(&impl);

    GetCurrentView()->UpdateKeys(&impl);
    UpdateKeys(&impl);

    KeyConfigDisplayWindow window(impl.keys);
    window.Show();
}

bool GView::App::KeyboardControlsImplementation::RegisterKey(KeyboardControl* key)
{
    keys.emplace_back(key);
    return true;
}