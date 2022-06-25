#include "Internal.hpp"
#include "BufferViewer.hpp"
#include "ImageViewer.hpp"
#include "GridViewer.hpp"
#include "DissasmViewer.hpp"
#include "TextViewer.hpp"
#include "ContainerViewer.hpp"

using namespace GView::App;
using namespace GView::View;

constexpr int HORIZONTA_PANEL_ID         = 100000;
constexpr int CMD_SHOW_VIEW_CONFIG_PANEL = 2000000;
constexpr int CMD_SHOW_HORIZONTAL_PANEL  = 2001000;
constexpr int CMD_NEXT_VIEW              = 30012345;
constexpr int CMD_GOTO                   = 30012346;
constexpr int CMD_FIND                   = 30012347;

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

FileWindow::FileWindow(std::unique_ptr<GView::Object> _obj, Reference<GView::App::Instance> _gviewApp)
    : Window("", "d:c", WindowFlags::Sizeable), gviewApp(_gviewApp), obj(std::move(_obj))
{
    cursorInfoHandle = ItemHandle{};
    // create splitters
    horizontal = this->CreateChildControl<Splitter>("d:c", SplitterFlags::Horizontal | SplitterFlags::AutoCollapsePanel2);
    vertical   = horizontal->CreateChildControl<Splitter>("d:c", SplitterFlags::Vertical | SplitterFlags::AutoCollapsePanel2);
    horizontal->SetPanel2Bounderies(1); // minim size (1 line)
    horizontal->SetSecondPanelSize(1);
    vertical->SetDefaultPanelSize(64);   // default panel upon extension
    horizontal->SetDefaultPanelSize(10); // default h-splitter size upon extension

    // create tabs
    view             = vertical->CreateChildControl<Tab>("d:c", TabFlags::HideTabs | TabFlags::TransparentBackground, 16);
    verticalPanels   = vertical->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);
    horizontalPanels = horizontal->CreateChildControl<Tab>("d:c", TabFlags::HideTabs | TabFlags::TransparentBackground, 16);

    // CursorInformation
    horizontalPanels->CreateChildControl<CursorInformation>(this);
    horizontalPanels->SetCurrentTabPageByIndex(0);

    // configuration menu
    char16_t menuSymbol = 0x2261;
    this->GetControlBar(WindowControlsBarLayout::TopBarFromLeft)
          .AddCommandItem(std::u16string_view(&menuSymbol, 1), CMD_SHOW_VIEW_CONFIG_PANEL, "Click to open view configuration panel !");

    // cursor information
    lastHorizontalPanelID = CMD_SHOW_HORIZONTAL_PANEL + 1;
    cursorInfoHandle      = this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft)
                             .AddSingleChoiceItem("<->", CMD_SHOW_HORIZONTAL_PANEL, true, "Show cursor and selection information");

    // sizes
    this->defaultCursorViewSize       = 2;
    this->defaultVerticalPanelsSize   = 8;
    this->defaultHorizontalPanelsSize = 40;

    // set the name
    this->SetText(obj->GetName());
    this->SetTag(obj->GetContentType()->GetTypeName(), "");
}
Reference<GView::Object> FileWindow::GetObject()
{
    return Reference<GView::Object>(this->obj.get());
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
            auto bar  = this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft);
            auto item = bar.AddSingleChoiceItem((CharacterView) p->GetText(), lastHorizontalPanelID++, true, "");
            bar.SetItemTextWithHotKey(item, (CharacterView) p->GetText(), p->GetHotKeyTextOffset());
            return true;
        }
        return false;
    }
}
bool FileWindow::CreateViewer(const std::string_view& name, GView::View::BufferViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::BufferViewer::Instance>(name, Reference<GView::Object>(this->obj.get()), &settings)
          .IsValid();
}
bool FileWindow::CreateViewer(const std::string_view& name, GView::View::TextViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::TextViewer::Instance>(name, Reference<GView::Object>(this->obj.get()), &settings)
          .IsValid();
}
bool FileWindow::CreateViewer(const std::string_view& name, GView::View::ImageViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::ImageViewer::Instance>(name, Reference<GView::Object>(this->obj.get()), &settings)
          .IsValid();
}
bool FileWindow::CreateViewer(const std::string_view& name, View::GridViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::GridViewer::Instance>(name, Reference<GView::Object>(this->obj.get()), &settings)
          .IsValid();
}
bool FileWindow::CreateViewer(const std::string_view& name, View::ContainerViewer::Settings& settings)
{
    return this->view
          ->CreateChildControl<GView::View::ContainerViewer::Instance>(name, Reference<GView::Object>(this->obj.get()), &settings)
          .IsValid();
}
bool FileWindow::CreateViewer(const std::string_view& name, GView::View::DissasmViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::DissasmViewer::Instance>(name, Reference<GView::Object>(this->obj.get()), &settings)
          .IsValid();
}
Reference<ViewControl> FileWindow::GetCurrentView()
{
    return view->GetCurrentTab().ToObjectRef<ViewControl>();
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
    if (keyCode == gviewApp->GetSwitchToViewKey())
    {
        if (!view->HasFocus())
            view->SetFocus();
        return true;
    }
    return false;
}
bool FileWindow::OnEvent(Reference<Control> ctrl, Event eventType, int ID)
{
    if (Window::OnEvent(ctrl, eventType, ID))
        return true;
    switch (eventType)
    {
    case Event::Command:
        if (ID == CMD_SHOW_VIEW_CONFIG_PANEL)
        {
            FileWindowProperties dlg(view);
            dlg.Show();
            return true;
        }
        if (ID == CMD_NEXT_VIEW)
        {
            this->view->GoToNextTabPage();
            return true;
        }
        if (ID == CMD_GOTO)
        {
            if (this->view->GetCurrentTab().ToObjectRef<ViewControl>()->ShowGoToDialog()==false)
            {
                AppCUI::Dialogs::MessageBox::ShowError("Error", "This view has no implementation for GoTo command !");
            }
            return true;
        }
        if (ID == CMD_FIND)
        {
            if (this->view->GetCurrentTab().ToObjectRef<ViewControl>()->ShowFindDialog() == false)
            {
                AppCUI::Dialogs::MessageBox::ShowError("Error", "This view has no implementation for Find command !");
            }
            return true;
        }
        if ((ID >= CMD_SHOW_HORIZONTAL_PANEL) && (ID <= CMD_SHOW_HORIZONTAL_PANEL + 100))
        {
            horizontalPanels->SetCurrentTabPageByIndex(ID - CMD_SHOW_HORIZONTAL_PANEL, true);
            horizontalPanels->SetFocus();
            return true;
        }
        break;
    case Event::SplitterPanelAutoCollapsed:
        if (ctrl == horizontal)
        {
            horizontalPanels->SetCurrentTabPageByIndex(0);
            this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft).SetItemCheck(cursorInfoHandle, true);
        }
        return true;
    }

    return false;
}

bool FileWindow::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(
          this->gviewApp->GetChangeViewesKey(), this->view->GetCurrentTab().ToObjectRef<ViewControl>()->GetName(), CMD_NEXT_VIEW);
    commandBar.SetCommand(this->gviewApp->GetGoToKey(), "GoTo", CMD_GOTO);
    commandBar.SetCommand(this->gviewApp->GetFindKey(), "Find", CMD_FIND);
    // add all generic plugins
    this->gviewApp->UpdateCommandBar(commandBar);
    return true;
}
void FileWindow::Start()
{
    this->view->SetCurrentTabPageByIndex(0);
    this->view->SetFocus();
}
