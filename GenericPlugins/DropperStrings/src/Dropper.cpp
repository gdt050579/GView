#include "Dropper.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

namespace GView::GenericPlugins::DroppperStrings
{
    constexpr int CMD_BUTTON_CLOSE = 1;

    class Dropper : public Window, public Handlers::OnButtonPressedInterface
    {
    public:
        Dropper() : Window("Strings", "d:c,w:70,h:20", WindowFlags::Sizeable | WindowFlags::Maximized)
        {
            Factory::CharacterTable::Create(this, "l:1,t:1,r:1,b:3");
            Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE)->Handlers()->OnButtonPressed = this;
        }

        void OnButtonPressed(Reference<Button>) override
        {
            this->Exit();
        }
    };

    extern "C"
    {
        PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
        {
            // all good
            if (command == "DropperStrings")
            {
                Dropper dlg;
                dlg.Show();
                return true;
            }
            return false;
        }

        PLUGIN_EXPORT void UpdateSettings(IniSection sect)
        {
            sect["command.DropperStrings"] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::Shift | Input::Key::F2;
        }
    }
}
