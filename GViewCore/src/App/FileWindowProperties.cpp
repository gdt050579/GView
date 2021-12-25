#include "Internal.hpp"

using namespace GView::App;
using namespace GView::View;

FileWindowProperties::FileWindowProperties(Reference<Tab> viewContainer) : Window("Properties", "d:c,w:78,h:24", WindowFlags::None)
{
    auto t = Factory::Tab::Create(this, "l:1,t:1,r:1,b:3", TabFlags::LeftTabs | TabFlags::TabsBar);

    auto tp1 = Factory::TabPage::Create(t, "General");

    // process all view modes
    for (uint32 idx = 0; idx < viewContainer->GetChildernCount(); idx++)
    {
        auto viewObject = viewContainer->GetChild(idx).DownCast<ViewControl>();
        if (viewObject)
        {
            auto tp_view = Factory::TabPage::Create(t, viewObject->GetName());
            Factory::PropertyList::Create(tp_view, "d:c", viewObject.UpCast<PropertiesInterface>(), PropertyListFlags::Border);
        }
    }

    Factory::Button::Create(this, "&Close", "x:40%,y:22,a:b,w:12", 1234);
    Factory::Button::Create(this, "&Go To", "x:60%,y:22,a:b,w:12", 1234);
}