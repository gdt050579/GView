#include "GViewApp.hpp"

using namespace GView::App;
using namespace GView::View;

constexpr int HORIZONTA_PANEL_ID         = 100000;
constexpr int CMD_SHOW_VIEW_CONFIG_PANEL = 2000000;

FileWindow::FileWindow(const AppCUI::Utils::ConstString& name) : Window(name, "d:c", WindowFlags::Sizeable)
{
    // create splitters
    horizontal = this->CreateChildControl<Splitter>("d:c", false);
    vertical   = horizontal->CreateChildControl<Splitter>("d:c", true);

    // create tabs
    view             = vertical->CreateChildControl<Tab>("d:c", TabFlags::HideTabs, 16);
    verticalPanels   = vertical->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);
    horizontalPanels = horizontal->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);

    // configuration menu
    char16_t menuSymbol = 0x2261;
    this->GetControlBar(WindowControlsBarLayout::TopBarFromLeft)
          .AddCommandItem(std::u16string_view(&menuSymbol, 1), CMD_SHOW_VIEW_CONFIG_PANEL ,"Click to open view configuration panel !");
}
Reference<GView::Object> FileWindow::GetObject()
{
    return Reference<GView::Object>(&this->obj);
}
bool FileWindow::AddPanel(Pointer<TabPage> page, bool verticalPosition)
{
    if (verticalPosition)
        return !this->verticalPanels->AddControl(std::move(page)).Emptry();
    else
        return !this->horizontalPanels->AddControl(std::move(page)).Emptry();
}
Reference<BufferViewInterface> FileWindow::AddBufferView(const std::string_view& name)
{
    return this->view->CreateChildControl<BufferView>(name, &this->obj).To<BufferViewInterface>();
}
bool FileWindow::OnEvent(Control* ctrl, Event eventType, int ID)
{
    if (Window::OnEvent(ctrl, eventType, ID))
        return true;
    if (eventType == Event::Command)
    {
        if (ID == CMD_SHOW_VIEW_CONFIG_PANEL)
        {
            // a call to default view 
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Not implemented yet !");
            return true;
        }
    }
}