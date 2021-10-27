#include "GViewApp.hpp"

using namespace GView::App;
using namespace GView::View;

constexpr int HORIZONTA_PANEL_ID         = 100000;
constexpr int CMD_SHOW_VIEW_CONFIG_PANEL = 2000000;
constexpr int CMD_SHOW_HORIZONTAL_PANEL  = 2001000;

class CursorInformation: public UserControl
{
    Reference<FileWindow> win;
  public:
    CursorInformation(Reference<FileWindow> _win) : UserControl("d:c"), win(_win)
    {
    }
    void Paint(Renderer& renderer) override
    {
        auto v = win->GetCurrentView();
        if (v)
            v->PaintCursorInformation(renderer, this->GetWidth(), this->GetHeight());
    }
};

FileWindow::FileWindow(const AppCUI::Utils::ConstString& name) : Window(name, "d:c", WindowFlags::Sizeable)
{
    // create splitters
    horizontal = this->CreateChildControl<Splitter>("d:c", false);
    vertical   = horizontal->CreateChildControl<Splitter>("d:c", true);
    horizontal->SetSecondPanelSize(1);

    // create tabs
    view             = vertical->CreateChildControl<Tab>("d:c", TabFlags::HideTabs, 16);
    verticalPanels   = vertical->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);
    horizontalPanels = horizontal->CreateChildControl<Tab>("d:c", TabFlags::HideTabs | TabFlags::TransparentBackground, 16);

    // CursorInformation
    horizontalPanels->CreateChildControl<CursorInformation>(this);
    horizontalPanels->SetCurrentTabPage(0);

    // configuration menu
    char16_t menuSymbol = 0x2261;
    this->GetControlBar(WindowControlsBarLayout::TopBarFromLeft)
          .AddCommandItem(std::u16string_view(&menuSymbol, 1), CMD_SHOW_VIEW_CONFIG_PANEL, "Click to open view configuration panel !");

    // cursor information
    this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft)
          .AddSingleChoiceItem("<->", CMD_SHOW_HORIZONTAL_PANEL,true, "Show cursor and selection information");
}
Reference<GView::Object> FileWindow::GetObject()
{
    return Reference<GView::Object>(&this->obj);
}
bool FileWindow::AddPanel(Pointer<TabPage> page, bool verticalPosition)
{
    if (verticalPosition)
        return !this->verticalPanels->AddControl(std::move(page)).Empty();
    else
        return !this->horizontalPanels->AddControl(std::move(page)).Empty();
}
Reference<BufferViewInterface> FileWindow::AddBufferView(const std::string_view& name)
{
    return this->view->CreateChildControl<BufferView>(name, &this->obj).To<BufferViewInterface>();
}
Reference<ViewControl> FileWindow::GetCurrentView()
{
    return view->GetCurrentTab().DownCast<ViewControl>();
}
bool FileWindow::OnEvent(Reference<Control> ctrl, Event eventType, int ID)
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
    return false;
}