#include "Internal.hpp"

using namespace GView::App;
using namespace GView::View;

FileWindowProperties::FileWindowProperties() : Window("Properties", "d:c,w:78,h:24", WindowFlags::None)
{
    auto t = Factory::Tab::Create(this, "l:1,t:1,r:1,b:3", TabFlags::LeftTabs|TabFlags::TabsBar);

    auto tp1 = Factory::TabPage::Create(t, "General");

    Factory::Button::Create(this, "&Close", "x:40%,y:22,a:b,w:12", 1234);
    Factory::Button::Create(this, "&Go To", "x:60%,y:22,a:b,w:12", 1234);
}