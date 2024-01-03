#include "Internal.hpp"

using namespace GView::App;
using namespace GView::View;

constexpr int32 BUTTON_ID_CLOSE = 1;
constexpr int32 BUTTON_ID_GOTO  = 2;

FileWindowProperties::FileWindowProperties(Reference<Tab> viewContainer) : Window("Properties", "d:c,w:78,h:24", WindowFlags::None)
{
    auto t = Factory::Tab::Create(this, "l:1,t:1,r:1,b:3", TabFlags::LeftTabs | TabFlags::TabsBar);

    Factory::TabPage::Create(t, "General");

    // process all view modes
    for (uint32 idx = 0; idx < viewContainer->GetChildrenCount(); idx++)
    {
        auto viewObject = viewContainer->GetChild(idx).ToObjectRef<ViewControl>();
        if (viewObject)
        {
            auto tp_view = Factory::TabPage::Create(t, viewObject->GetName());
            Factory::PropertyList::Create(tp_view, "d:c", viewObject.ToBase<PropertiesInterface>(), PropertyListFlags::Border);
        }
    }

    Factory::Button::Create(this, "&Close", "x:40%,y:22,a:b,w:12", BUTTON_ID_CLOSE);
    Factory::Button::Create(this, "&Go To", "x:60%,y:22,a:b,w:12", BUTTON_ID_GOTO);
}
bool FileWindowProperties::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (Window::OnEvent(control, eventType, ID))
        return true;
    if (eventType == Event::ButtonClicked)
    {
        if (ID == BUTTON_ID_CLOSE)
        {
            this->Exit(Dialogs::Result::Ok);
            return true;
        }
        if (ID == BUTTON_ID_GOTO)
        {
            //GDT: switch to that particular view
            this->Exit(Dialogs::Result::Ok);
            return true;
        }
    }
    return false;
}
