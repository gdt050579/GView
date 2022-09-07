#include "CharacterTable.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

constexpr int CMD_BUTTON_CLOSE = 1;

class CharacterTableExample : public Window, public Handlers::OnButtonPressedInterface
{
  public:
    CharacterTableExample() : Window("Character Table", "d:c,w:70,h:20", WindowFlags::Sizeable | WindowFlags::Maximized)
    {
        Factory::CharacterTable::Create(this, "l:1,t:1,r:1,b:3");
        Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE)->Handlers()->OnButtonPressed = this;
    }
    void OnButtonPressed(Reference<Button>) override
    {
        this->Exit(AppCUI::Dialogs::Result::None);
    }
};

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
    {
        // all good
        if (command == "CharacterTable")
        {
            CharacterTableExample dlg;
            dlg.Show();
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.CharacterTable"] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::Shift | Input::Key::F1;
    }
}
