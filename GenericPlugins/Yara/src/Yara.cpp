#include "Yara.hpp"

namespace GView::GenericPlugins::Yara
{

constexpr int32 CMD_BUTTON_CLOSE = 1;

YaraDialog::YaraDialog(Reference<GView::Object> object) : Window("Yara Scanner", "d:c,w:60,h:10", WindowFlags::ProcessReturn)
{
    this->object = object;

    Factory::Label::Create(this, "Yara plugin", "x:1,y:2,w:58");

    closeButton                              = Factory::Button::Create(this, "&Close", "x:50%,y:5,w:12", CMD_BUTTON_CLOSE);
    closeButton->Handlers()->OnButtonPressed = this;
    closeButton->SetFocus();
}

void YaraDialog::OnButtonPressed(Reference<Button> b)
{
    if (b->GetControlID() == CMD_BUTTON_CLOSE)
    {
        Exit();
    }
}

} // namespace GView::GenericPlugins::Yara

extern "C"
{
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "Yara")
    {
        GView::GenericPlugins::Yara::YaraDialog dlg(object);
        dlg.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.Yara"] = Input::Key::F11;
}
}