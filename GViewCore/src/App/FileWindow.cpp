#include "Internal.hpp"
#include "BufferViewer.hpp"
#include "ImageViewer.hpp"
#include "GridViewer.hpp"
#include "DissasmViewer.hpp"
#include "TextViewer.hpp"
#include "ContainerViewer.hpp"
#include "LexicalViewer.hpp"

using namespace GView::App;
using namespace GView::App::InstanceCommands;
using namespace GView::View;
using namespace AppCUI::Input;

// constexpr int HORIZONTA_PANEL_ID         = 100000;
constexpr int CMD_SHOW_VIEW_CONFIG_PANEL = 2000000;
constexpr int CMD_SHOW_HORIZONTAL_PANEL  = 2001000;
constexpr int CMD_FOR_TYPE_PLUGIN_START  = 50000000;

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

FileWindow::FileWindow(std::unique_ptr<GView::Object> _obj, Reference<GView::App::Instance> _gviewApp, Reference<Type::Plugin> _typePlugin)
: Window("", "d:c", WindowFlags::Sizeable), gviewApp(_gviewApp), typePlugin(_typePlugin), obj(std::move(_obj))
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

    // set the name (+ course watermark when Learning and Evaluation Mode is active)
    RefreshTitle();
    this->SetTag(obj->GetContentType()->GetTypeName(), "");

    queryInterface.fileWindow = this;

    // push the configured keys into the keys registered by the type plugin instance
    if (this->gviewApp.IsValid())
        ApplyKeyBindings(this->gviewApp->GetKeyBindings());
    // binds the window to the learning item being opened (if any)
    GView::Security::Learning::Hooks::OnFileWindowCreated(this->obj.get());
}
std::string FileWindow::GetTypePluginKeysSection() const
{
    auto plugin = this->typePlugin;
    if (!plugin.IsValid())
        return {};
    return plugin->GetKeysSection();
}
void FileWindow::ApplyKeyBindings(const Keys::Registry& registry)
{
    const auto section = GetTypePluginKeysSection();
    if (section.empty() || (!this->obj) || (this->obj->GetContentType() == nullptr))
        return;
    Keys::ApplyPass pass(registry, section);
    this->obj->GetContentType()->UpdateKeys(&pass);
}
FileWindow::~FileWindow()
{
    GView::Security::Learning::Hooks::OnFileWindowClosed(this->obj.get());
}
void FileWindow::RefreshTitle()
{
    const auto watermark = GView::Security::RestrictedMode::Internal::GetWatermark();
    if (watermark.empty())
    {
        this->SetText(obj->GetName());
        return;
    }
    LocalUnicodeStringBuilder<512> title;
    title.Set(obj->GetName());
    title.Add(u" - ");
    title.Add(std::u8string_view(reinterpret_cast<const char8_t*>(watermark.data()), watermark.size()));
    this->SetText(title);
}
std::string_view FileWindow::GetCurrentViewerKind()
{
    // closed set of names (telemetry never reports custom viewer captions)
    auto v = GetCurrentView();
    if (!v.IsValid())
        return "Other";
    ViewControl* p = v.operator->();
    if (dynamic_cast<GView::View::DissasmViewer::Instance*>(p))
        return "Dissasm";
    if (dynamic_cast<GView::View::BufferViewer::Instance*>(p))
        return "Buffer";
    if (dynamic_cast<GView::View::LexicalViewer::Instance*>(p))
        return "Lexical";
    if (dynamic_cast<GView::View::TextViewer::Instance*>(p))
        return "Text";
    if (dynamic_cast<GView::View::ImageViewer::Instance*>(p))
        return "Image";
    if (dynamic_cast<GView::View::GridViewer::Instance*>(p))
        return "Grid";
    if (dynamic_cast<GView::View::ContainerViewer::Instance*>(p))
        return "Container";
    return "Other";
}
bool FileWindow::OnFrameUpdate()
{
    GView::Security::Learning::Hooks::OnFileWindowFrame(this->obj.get(), GetCurrentViewerKind(), this->HasFocus());
    return false; // never request a repaint by itself (keeps idle detection meaningful)
}
void FileWindow::Paint(Renderer& renderer)
{
    Window::Paint(renderer);
    // GView only repaints in response to user input: a repaint is the activity signal used for idle detection
    GView::Security::Learning::Hooks::NoteUserActivity();
}
Reference<GView::Object> FileWindow::GetObject()
{
    return Reference<GView::Object>(this->obj.get());
}

void FileWindow::ShowGoToDialog()
{
    GView::Security::Learning::Hooks::OnSimpleEvent(this->obj.get(), GView::Security::Learning::Hooks::SimpleEvent::GotoDialog);
    if (this->view->GetCurrentTab().ToObjectRef<ViewControl>()->ShowGoToDialog() == false)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "This view has no implementation for GoTo command !");
    }
}
void FileWindow::ShowFindDialog()
{
    if (this->view->GetCurrentTab().ToObjectRef<ViewControl>()->ShowFindDialog() == false)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "This view has no implementation for Find command !");
    }
}
void FileWindow::ShowCopyDialog()
{
    if (GView::App::IsBlockedByPolicy(GView::Security::RestrictedMode::Feature::Copy, "copying from the viewer"))
        return;
    if (this->view->GetCurrentTab().ToObjectRef<ViewControl>()->ShowCopyDialog() == false)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "This view has no implementation for Copy command !");
    }
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

bool FileWindow::CreateViewer(GView::View::BufferViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::BufferViewer::Instance>(Reference<GView::Object>(this->obj.get()), &settings).IsValid();
}

Reference<GView::Utils::SelectionZoneInterface> FileWindow::GetSelectionZoneInterfaceFromViewerCreation(GView::View::BufferViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::BufferViewer::Instance>(Reference<GView::Object>(this->obj.get()), &settings)
          .ToBase<GView::Utils::SelectionZoneInterface>();
}

bool FileWindow::CreateViewer(GView::View::TextViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::TextViewer::Instance>(Reference<GView::Object>(this->obj.get()), &settings).IsValid();
}
bool FileWindow::CreateViewer(GView::View::ImageViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::ImageViewer::Instance>(Reference<GView::Object>(this->obj.get()), &settings).IsValid();
}
bool FileWindow::CreateViewer(View::GridViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::GridViewer::Instance>(Reference<GView::Object>(this->obj.get()), &settings).IsValid();
}
bool FileWindow::CreateViewer(View::ContainerViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::ContainerViewer::Instance>(Reference<GView::Object>(this->obj.get()), &settings)
          .IsValid();
}
bool FileWindow::CreateViewer(GView::View::DissasmViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::DissasmViewer::Instance>(Reference<GView::Object>(this->obj.get()), &settings).IsValid();
}
bool FileWindow::CreateViewer(GView::View::LexicalViewer::Settings& settings)
{
    return this->view->CreateChildControl<GView::View::LexicalViewer::Instance>(Reference<GView::Object>(this->obj.get()), &settings)
          .IsValid();
}

Reference<ViewControl> FileWindow::GetCurrentView()
{
    return view->GetCurrentTab().ToObjectRef<ViewControl>();
}

uint32 FileWindow::GetViewsCount()
{
    return view->GetChildrenCount();
}

Reference<ViewControl> FileWindow::GetViewByIndex(uint32 index)
{
    return view->GetChild(index).ToObjectRef<ViewControl>();
}

bool FileWindow::SetViewByIndex(uint32 index)
{
    CHECK(index < view->GetChildrenCount(), false, "");
    return view->SetCurrentTabPageByIndex(index, true);
}

bool FileWindow::OnKeyEvent(AppCUI::Input::Key keyCode, char16_t unicode)
{
    if (INSTANCE_FOCUS_VIEWER.Matches(keyCode) && !view->HasFocus()) {
        view->SetFocus();
        return true;
    }
    if (Window::OnKeyEvent(keyCode, unicode))
        return true;
    // check vertical panel
    if (verticalPanels->OnKeyEvent(keyCode, unicode))
        return true;
    // check horizontal panel
    if (horizontalPanels->OnKeyEvent(keyCode, unicode))
        return true;
    // if Alt+F is pressed --> enable view
    if (INSTANCE_SWITCH_TO_VIEW.Matches(keyCode))
    {
        if (!view->HasFocus())
            view->SetFocus();
        return true;
    }

    // the primary GoTo/Find keys are command bar commands, the alternative ones are handled here
    if (FILE_WINDOW_COMMAND_GOTO.Matches(keyCode)) {
        ShowGoToDialog();
        return true;
    }
    if (FILE_WINDOW_COMMAND_FIND.Matches(keyCode)) {
        ShowFindDialog();
        return true;
    }
    if (FILE_WINDOW_COMMAND_COPY.Matches(keyCode) || FILE_WINDOW_COMMAND_INSERT.Matches(keyCode)) {
        ShowCopyDialog();
        return true;
    }
    if (INSTANCE_LEARNING_SUBMIT_FLAG.Matches(keyCode) && GView::Security::Learning::Hooks::IsLearningProblem(this->obj.get())) {
        GView::Security::Learning::Hooks::ShowSubmitDialogForObject(this->obj.get());
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
        switch (ID)
        {
        case CMD_SHOW_VIEW_CONFIG_PANEL:
            ShowFilePropertiesDialog();
            return true;
        case CMD_NEXT_VIEW:
            this->view->GoToNextTabPage();
            return true;
        case CMD_GOTO:
            ShowGoToDialog();
            return true;
        case CMD_FIND:
            ShowFindDialog();
            return true;
        case CMD_CHOSE_NEW_TYPE:
            if (this->obj->GetObjectType() == Object::Type::File)
            {
                GView::App::OpenFile(this->obj->GetPath(), OpenMethod::Select);
            }
            else
            {
                AppCUI::Dialogs::MessageBox::ShowError("Error", "Not implemented yet for this type of object (buffer/PID/Folder)");
            }
            return true;
        case CMD_SHOW_KEY_CONFIGURATOR:
            ShowKeyboardShortcutsWindow(this->gviewApp, this);
            return true;
        case CMD_OPEN_ADD_NOTE:
            GView::App::ShowAddNoteDialog();
            return true;
        case CMD_LEARNING_SUBMIT_FLAG:
            GView::Security::Learning::Hooks::ShowSubmitDialogForObject(this->obj.get());
            return true;
        }
        if ((ID >= CMD_SHOW_HORIZONTAL_PANEL) && (ID <= CMD_SHOW_HORIZONTAL_PANEL + 100))
        {
            horizontalPanels->SetCurrentTabPageByIndex(ID - CMD_SHOW_HORIZONTAL_PANEL, true);
            horizontalPanels->SetFocus();
            return true;
        }
        if (((ID >= CMD_FOR_TYPE_PLUGIN_START) && (ID <= CMD_FOR_TYPE_PLUGIN_START + 1000)) && (this->typePlugin.IsValid()))
        {
            this->obj->GetContentType()->RunCommand(this->typePlugin->GetCommands()[static_cast<size_t>(ID) - CMD_FOR_TYPE_PLUGIN_START].name);
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
    if (INSTANCE_CHANGE_VIEW.Key != Key::None)
        commandBar.SetCommand(INSTANCE_CHANGE_VIEW.Key, this->view->GetCurrentTab().ToObjectRef<ViewControl>()->GetName(), CMD_NEXT_VIEW);
    if (INSTANCE_COMMAND_GOTO.Key != Key::None)
        commandBar.SetCommand(INSTANCE_COMMAND_GOTO.Key, "GoTo", CMD_GOTO);
    if (INSTANCE_COMMAND_FIND.Key != Key::None)
        commandBar.SetCommand(INSTANCE_COMMAND_FIND.Key, "Find", CMD_FIND);
    commandBar.SetCommand(INSTANCE_CHOOSE_TYPE, CMD_CHOSE_NEW_TYPE);
    if (INSTANCE_KEY_CONFIGURATOR.Key != Key::None)
        commandBar.SetCommand(INSTANCE_KEY_CONFIGURATOR.Key, "Keys", CMD_SHOW_KEY_CONFIGURATOR);
    commandBar.SetCommand(INSTANCE_OPEN_ADD_NOTE, CMD_OPEN_ADD_NOTE);
    if (GView::Security::Learning::Hooks::IsLearningProblem(this->obj.get()) && INSTANCE_LEARNING_SUBMIT_FLAG.Key != Key::None)
        commandBar.SetCommand(INSTANCE_LEARNING_SUBMIT_FLAG.Key, "SubmitFlag", CMD_LEARNING_SUBMIT_FLAG);
    // add commands from type plugin
    if (this->typePlugin.IsValid())
    {
        auto idx = 0;
        for (auto& cmd : typePlugin->GetCommands())
        {
            if (cmd.key != Key::None) // unassigned in the key bindings
                commandBar.SetCommand(cmd.key, cmd.name, CMD_FOR_TYPE_PLUGIN_START + idx);
            idx++;
        }
    }
    // add all generic plugins
    this->gviewApp->UpdateCommandBar(commandBar);
    return true;
}
void FileWindow::Start()
{
    this->view->SetCurrentTabPageByIndex(0);
    this->view->SetFocus();

    queryInterface.Start();
}

void GView::App::InstanceCommands::RegisterGViewKeys(KeyboardControlsInterface* interface)
{
    for (auto key : GViewKeys)
        interface->RegisterKey(key);
    interface->BeginCategory("Menus");
    interface->RegisterKeyText("Alt+<letter>", "OpenMenu", "Open the menu whose name has that letter underlined (File, Options, Windows, Help)");
#ifdef GVIEW_ENABLE_REMOTE
    interface->BeginCategory("Remote");
    interface->RegisterKey(&REMOTE_LOCAL_KEY);
#endif
}
