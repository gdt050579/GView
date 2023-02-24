#include "SyncCompare.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

constexpr int CMD_BUTTON_CLOSE = 1;

class SyncCompareExample : public Window, public Handlers::OnButtonPressedInterface
{
  public:
    SyncCompareExample() : Window("SyncCompare", "d:c,w:70,h:20", WindowFlags::Sizeable | WindowFlags::Maximized)
    {
        auto list = Factory::ListView::Create(
              this, "x:5,y:1,w:85%,h:80%", { "n:Window,w:30%", "n:View Name,w:30%", "n:Type Name,w:50%" }, ListViewFlags::AllowMultipleItemsSelection);
        list->SetFocus();

        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();
        for (uint32 i = 0; i < windowsNo; i++)
        {
            auto window    = desktop->GetChild(i);
            auto interface = window.ToObjectRef<GView::View::WindowInterface>();

            auto currentView    = interface->GetCurrentView();
            const auto viewName = currentView->GetName();

            auto object         = interface->GetObject();
            const auto typeName = object->GetContentType()->GetTypeName();

            LocalString<64> tmp;
            list->AddItem({ tmp.Format("#%i", i), viewName, typeName });
        }

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
        if (command == "SyncCompare")
        {
            SyncCompareExample dlg;
            dlg.Show();
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.SyncCompare"] = Input::Key::Ctrl | Input::Key::Space;
    }
}
