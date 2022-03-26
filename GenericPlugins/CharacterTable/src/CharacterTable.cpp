#include "CharacterTable.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command)
    {
        // all good
        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.CharacterTable"] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::Shift | Input::Key::F1;
    }
}

int main()
{
    return 0;
}
