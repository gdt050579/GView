#include "Internal.hpp"

namespace GView::App
{
ErrorDialog::ErrorDialog(const GView::Utils::ErrorList& errList) : Window("Errors", "d:c,w:80,h:16",WindowFlags::ErrorWindow)
{
    auto lv = Factory::ListView::Create(this, "l:1,t:1,r:1,b:3", ListViewFlags::HideSearchBar | ListViewFlags::HideColumns);
    lv->AddColumn("", TextAlignament::Left, 255);
    LocalString<64> tmp;
    lv->AddItem(tmp.Format("Errors   : %u", errList.GetErrorsCount()));
    lv->AddItem(tmp.Format("Warnings : %u", errList.GetWarningsCount()));
    // add items
    if (errList.GetErrorsCount()>0)
    {
        lv->SetItemType(lv->AddItem("Errors"), ListViewItemType::Category);
        auto cnt = errList.GetErrorsCount();
        for (auto i = 0U; i < cnt; i++)
            lv->AddItem(errList.GetError(i));
    }
    if (errList.GetWarningsCount() > 0)
    {
        lv->SetItemType(lv->AddItem("Warnings"), ListViewItemType::Category);
        auto cnt = errList.GetWarningsCount();
        for (auto i = 0U; i < cnt; i++)
            lv->AddItem(errList.GetWarning(i));
    }
    Factory::Button::Create(this,"&Close", "d:b,w:10");
}
bool ErrorDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (Window::OnEvent(control, eventType, ID))
        return true;
    if (eventType == Event::ButtonClicked)
    {
        Exit(0);
        return true;
    }
    return false;
}
} // namespace GView::App