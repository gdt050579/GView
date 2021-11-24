#include "GViewApp.hpp"

using namespace GView::App;
using namespace GView::View;

constexpr int HORIZONTA_PANEL_ID         = 100000;
constexpr int CMD_SHOW_VIEW_CONFIG_PANEL = 2000000;
constexpr int CMD_SHOW_HORIZONTAL_PANEL  = 2001000;

class CursorInformation : public UserControl
{
    Reference<FileWindow> win;

  public:
    CursorInformation(Reference<FileWindow> _win) : UserControl("d:c"), win(_win)
    {
    }
    void Paint(Renderer& renderer) override
    {
        auto v = win->GetCurrentView();
        if (v.IsValid())
            v->PaintCursorInformation(renderer, this->GetWidth(), this->GetHeight());
    }
};

FileWindow::FileWindow(const AppCUI::Utils::ConstString& name, Instance* instanceContext)
    : Window(name, "d:c", WindowFlags::Sizeable), instanceContext(instanceContext)
{
    cursorInfoHandle = ItemHandle{};
    // create splitters
    horizontal = this->CreateChildControl<Splitter>("d:c", false);
    vertical   = horizontal->CreateChildControl<Splitter>("d:c", true);
    horizontal->SetSecondPanelSize(1);

    // create tabs
    view                      = vertical->CreateChildControl<Tab>("d:c", TabFlags::HideTabs, 16);
    verticalPanels            = vertical->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);
    horizontalPanels          = horizontal->CreateChildControl<Tab>("d:c", TabFlags::HideTabs | TabFlags::TransparentBackground, 16);
    view->Handlers()->OnFocus = this;
    verticalPanels->Handlers()->OnFocus   = this;
    horizontalPanels->Handlers()->OnFocus = this;

    // CursorInformation
    horizontalPanels->CreateChildControl<CursorInformation>(this);
    horizontalPanels->SetCurrentTabPageByIndex(0);

    // configuration menu
    char16_t menuSymbol = 0x2261;
    this->GetControlBar(WindowControlsBarLayout::TopBarFromLeft)
          .AddCommandItem(std::u16string_view(&menuSymbol, 1), CMD_SHOW_VIEW_CONFIG_PANEL, "Click to open view configuration panel !");

    // cursor information
    cursorInfoHandle = this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft)
                             .AddSingleChoiceItem("<->", CMD_SHOW_HORIZONTAL_PANEL, true, "Show cursor and selection information");

    // sizes
    this->defaultCursorViewSize       = 2;
    this->defaultVerticalPanelsSize   = 8;
    this->defaultHorizontalPanelsSize = 40;
}
Reference<GView::Object> FileWindow::GetObject()
{
    return Reference<GView::Object>(&this->obj);
}
bool FileWindow::AddPanel(Pointer<TabPage> page, bool verticalPosition)
{
    if (verticalPosition)
        return this->verticalPanels->AddControl(std::move(page)).IsValid();
    else
    {
        auto p = this->horizontalPanels->AddControl(std::move(page));
        if (p.IsValid())
        {
            this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft)
                  .AddSingleChoiceItem((CharacterView) p->GetText(), CMD_SHOW_HORIZONTAL_PANEL, true, "");
            return true;
        }
        return false;
    }
}
Reference<BufferViewerInterface> FileWindow::AddBufferViewer(const std::string_view& name)
{
    return this->view->CreateChildControl<BufferViewer>(name, &this->obj).To<BufferViewerInterface>();
}
Reference<ViewControl> FileWindow::GetCurrentView()
{
    return view->GetCurrentTab().DownCast<ViewControl>();
}
bool FileWindow::OnKeyEvent(AppCUI::Input::Key keyCode, char16_t unicode)
{
    if (Window::OnKeyEvent(keyCode, unicode))
        return true;
    // check vertical panel
    if (verticalPanels->OnKeyEvent(keyCode, unicode))
        return true;
    // check horizontal panel
    if (horizontalPanels->OnKeyEvent(keyCode, unicode))
        return true;
    // if Alt+F is pressed --> enable view
    if (keyCode == (AppCUI::Input::Key::Alt | AppCUI::Input::Key::F))
    {
        if (!view->HasFocus())
            view->SetFocus();
        return true;
    }
    return false;
}
void FileWindow::UpdateDefaultPanelsSizes(Reference<Splitter> splitter)
{
    // logic is as follows
    // horizontal|vertical view are only updated when those panels are resized and have the focus
    if ((!horizontalPanels.IsValid()) || (!verticalPanels.IsValid()))
        return;
    // if the resized is done when the view is active, only the cursor size is stored
    if (view->HasFocus())
    {
        if (splitter == horizontal)
        {
            defaultCursorViewSize = horizontal->GetSecondPanelSize();
        }
    }
    else
    {
        if (verticalPanels->HasFocus())
        {
            defaultHorizontalPanelsSize = vertical->GetSecondPanelSize();
        }
        if (horizontalPanels->HasFocus())
        {
            defaultVerticalPanelsSize = horizontal->GetSecondPanelSize();
        }
    }
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
    if (eventType == Event::SplitterPositionChanged)
    {
        UpdateDefaultPanelsSizes(ctrl.DownCast<Splitter>());
        return true;
    }
    return false;
}
void FileWindow::OnFocus(Reference<Control> control)
{
    if (control == view)
    {
        // minimize vertical and horizontal panels
        if (vertical.IsValid())
            vertical->SetSecondPanelSize(0);
        if (horizontal.IsValid())
            horizontal->SetSecondPanelSize(defaultCursorViewSize);
        horizontalPanels->SetCurrentTabPageByIndex(0); // force cursor information show when
        this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft).SetItemCheck(cursorInfoHandle, true);
        // test
    }
    if (control == verticalPanels)
    {
        vertical->SetSecondPanelSize(defaultHorizontalPanelsSize);
    }
    if (control == horizontalPanels)
    {
        horizontal->SetSecondPanelSize(defaultVerticalPanelsSize);
    }
}
bool GView::App::FileWindow::AddFileWindow(const std::filesystem::path& path)
{
    if (!instanceContext)
        return false;
    return instanceContext->AddFileWindow(path);
}
bool GView::App::FileWindow::AddNewGenericFileWindow(const std::filesystem::path& path)
{
    return AddFileWindow(path);
}
bool FileWindow::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return true;
}
void FileWindow::Start()
{
    this->view->SetCurrentTabPageByIndex(0);
    this->view->SetFocus();
}