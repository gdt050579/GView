#include "Internal.hpp"

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

constexpr uint32 DEFAULT_CACHE_SIZE    = 0x100000; // 1 MB
constexpr uint32 MIN_CACHE_SIZE        = 0x10000;  // 64 K
constexpr uint32 GENERIC_PLUGINS_CMDID = 40000000;
constexpr uint32 GENERIC_PLUGINS_FRAME = 100;

struct _MenuCommand_
{
    std::string_view name;
    int commandID;
    Key shortCutKey;
};
constexpr _MenuCommand_ menuFileList[] = {
    { "&Open file", MenuCommands::OPEN_FILE, Key::None },
    { "Open &folder", MenuCommands::OPEN_FOLDER, Key::None },
    { "", 0, Key::None },
    { "Open &process", MenuCommands::OPEN_PID, Key::None },
    { "Open process &tree", MenuCommands::OPEN_PROCESS_TREE, Key::None },
    { "", 0, Key::None },
    { "E&xit", MenuCommands::EXIT_GVIEW, Key::Shift | Key::Escape },
};
constexpr _MenuCommand_ menuWindowList[] = {
    { "Arrange &Vertically", MenuCommands::ARRANGE_VERTICALLY, Key::None },
    { "Arrange &Horizontally", MenuCommands::ARRANGE_HORIZONTALLY, Key::None },
    { "&Cascade mode", MenuCommands::ARRANGE_CASCADE, Key::None },
    { "&Grid", MenuCommands::ARRANGE_GRID, Key::None },
    { "", 0, Key::None },
    { "Close", MenuCommands::CLOSE, Key::None },
    { "Close &All", MenuCommands::CLOSE_ALL, Key::None },
    { "Close All e&xcept current", MenuCommands::CLOSE_ALL, Key::None },
    { "", 0, Key::None },
    { "&Windows manager", MenuCommands::SHOW_WINDOW_MANAGER, Key::Alt | Key::N0 },
};
constexpr _MenuCommand_ menuHelpList[] = {
    { "Check for &updates", MenuCommands::CHECK_FOR_UPDATES, Key::None },
    { "&About", MenuCommands::ABOUT, Key::None },
};

bool AddMenuCommands(Menu* mnu, const _MenuCommand_* list, size_t count)
{
    while (count > 0)
    {
        if (list->name.empty())
        {
            CHECK(mnu->AddSeparator() != InvalidItemHandle, false, "Fail to add separator !");
        }
        else
        {
            CHECK(mnu->AddCommandItem(list->name, list->commandID, list->shortCutKey) != InvalidItemHandle,
                  false,
                  "Fail to add %s to menu !",
                  list->name.data());
        }
        count--;
        list++;
    }
    return true;
}

Instance::Instance()
{
    this->defaultCacheSize = DEFAULT_CACHE_SIZE; // 1 MB
    this->keyToChangeViews = Key::F4;
    this->mnuWindow        = nullptr;
    this->mnuHelp          = nullptr;
    this->mnuFile          = nullptr;
}
bool Instance::LoadSettings()
{
    auto ini = AppCUI::Application::GetAppSettings();
    CHECK(ini, false, "");

    // check plugins
    // for (auto section : *ini)
    for (auto section : ini->GetSections())
    {
        auto sectionName = section.GetName();
        if (String::StartsWith(sectionName, "type.", true))
        {
            GView::Type::Plugin p;
            if (p.Init(section))
            {
                this->typePlugins.push_back(p);
            }
            else
            {
                errList.AddWarning("Fail to load type plugin (%s)", sectionName.data());
            }
        }
        if (String::StartsWith(sectionName, "generic.", true))
        {
            GView::Generic::Plugin p;
            if (p.Init(section))
            {
                this->genericPlugins.push_back(p);
            }
            else
            {
                errList.AddWarning("Fail to load generic plugin (%s)", sectionName.data());
            }
        }
    }

    // sort all plugins based on their priority
    std::sort(this->typePlugins.begin(), this->typePlugins.end());

    // read instance settings
    auto sect               = ini->GetSection("GView");
    this->defaultCacheSize  = std::min<>(sect.GetValue("CacheSize").ToUInt32(DEFAULT_CACHE_SIZE), MIN_CACHE_SIZE);
    this->keyToChangeViews  = sect.GetValue("ChangeView").ToKey(Key::F4);
    this->keyToSwitchToView = sect.GetValue("SwitchToView").ToKey(Key::F | Key::Alt);

    return true;
}
bool Instance::BuildMainMenus()
{
    CHECK(mnuFile = AppCUI::Application::AddMenu("File"), false, "Unable to create 'File' menu");
    CHECK(AddMenuCommands(mnuFile, menuFileList, ARRAY_LEN(menuFileList)), false, "");
    CHECK(mnuWindow = AppCUI::Application::AddMenu("&Windows"), false, "Unable to create 'Windows' menu");
    CHECK(AddMenuCommands(mnuWindow, menuWindowList, ARRAY_LEN(menuWindowList)), false, "");
    CHECK(mnuHelp = AppCUI::Application::AddMenu("&Help"), false, "Unable to create 'Help' menu");
    CHECK(AddMenuCommands(mnuHelp, menuHelpList, ARRAY_LEN(menuHelpList)), false, "");
    return true;
}

bool Instance::Init()
{
    InitializationData initData;
    initData.Flags = InitializationFlags::Menu | InitializationFlags::CommandBar | InitializationFlags::LoadSettingsFile |
                     InitializationFlags::AutoHotKeyForWindow;

    CHECK(AppCUI::Application::Init(initData), false, "Fail to initialize AppCUI framework !");
    // reserve some space fo type
    this->typePlugins.reserve(128);
    CHECK(LoadSettings(), false, "Fail to load settings !");
    CHECK(BuildMainMenus(), false, "Fail to create bundle menus !");
    this->defaultPlugin.Init();
    // set up handlers
    auto dsk                 = AppCUI::Application::GetDesktop();
    dsk->Handlers()->OnEvent = this;
    dsk->Handlers()->OnStart = this;
    return true;
}
bool Instance::Add(std::unique_ptr<AppCUI::OS::IFile> file, const AppCUI::Utils::ConstString& name, std::string_view ext)
{
    auto win = std::make_unique<FileWindow>(name, this);
    auto obj = win->GetObject();
    CHECK(obj->cache.Init(std::move(file), this->defaultCacheSize), false, "Fail to instantiate window");

    auto buf  = obj->cache.Get(0, 4096, false); // first 4k
    auto* plg = &this->defaultPlugin;
    // iterate from existing types
    for (auto& pType : this->typePlugins)
    {
        if (pType.Validate(buf, ext))
        {
            plg = &pType;
            break;
        }
    }

    // create an instance of that type
    obj->type = plg->CreateInstance(Reference<GView::Utils::FileCache>(&obj->cache));

    // validate type
    CHECK(obj->type, false, "`CreateInstance` returned a null pointer to a type object !");

    // instantiate window
    while (true)
    {
        CHECKBK(plg->PopulateWindow(win.get()), "Fail to populate file window !");
        win->Start(); // starts the window and set focus
        // set window TAG (based on type)
        win->SetTag(obj->type->GetTypeName(), "");
        auto res = AppCUI::Application::AddWindow(std::move(win));
        CHECKBK(res != InvalidItemHandle, "Fail to add newly created window to desktop");

        return true;
    }
    // error case
    delete obj->type;
    obj->type = nullptr;
    return false;
}
void Instance::ShowErrors()
{
    if (errList.Empty())
        return;
    ErrorDialog err(errList);
    err.Show();
    errList.Clear();
}
bool Instance::AddFileWindow(const std::filesystem::path& path)
{
    auto f = std::make_unique<AppCUI::OS::File>();
    if (f->OpenRead(path) == false)
    {
        errList.AddError("Fail to open file: %s", path.u8string().c_str());
        RETURNERROR(false, "Fail to open file: %s", path.u8string().c_str());
    }
    return Add(std::move(f), path.u16string(), path.extension().string());
}
void Instance::OpenFile()
{
    auto res = Dialogs::FileDialog::ShowOpenFileWindow("", "", ".");
    if (res.has_value())
    {
        if (AddFileWindow(res.value()) == false)
            ShowErrors();
    }
}
void Instance::UpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    auto idx = GENERIC_PLUGINS_CMDID;
    for (auto& p : this->genericPlugins)
    {
        p.UpdateCommandBar(commandBar, idx);
        idx += GENERIC_PLUGINS_FRAME;
    }
}
Reference<GView::Object> Instance::GetObject(uint32 index)
{
    auto dsk = AppCUI::Application::GetDesktop();
    CHECK(dsk.IsValid(), nullptr, "Fail to get Desktop object from AppCUI !");
    return dsk->GetChild(index).ToObjectRef<FileWindow>()->GetObject();
}
Reference<GView::Object> Instance::GetCurrentObject()
{
    auto dsk = AppCUI::Application::GetDesktop();
    CHECK(dsk.IsValid(), nullptr, "Fail to get Desktop object from AppCUI !");
    return dsk->GetFocusedChild().ToObjectRef<FileWindow>()->GetObject();
}
//===============================[APPCUI HANDLERS]==============================
bool Instance::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (eventType == Event::Command)
    {
        switch (ID)
        {
        case MenuCommands::ARRANGE_CASCADE:
            AppCUI::Application::ArrangeWindows(AppCUI::Application::ArrangeWindowsMethod::Cascade);
            return true;
        case MenuCommands::ARRANGE_GRID:
            AppCUI::Application::ArrangeWindows(AppCUI::Application::ArrangeWindowsMethod::Grid);
            return true;
        case MenuCommands::ARRANGE_HORIZONTALLY:
            AppCUI::Application::ArrangeWindows(AppCUI::Application::ArrangeWindowsMethod::Horizontal);
            return true;
        case MenuCommands::ARRANGE_VERTICALLY:
            AppCUI::Application::ArrangeWindows(AppCUI::Application::ArrangeWindowsMethod::Vertical);
            return true;
        case MenuCommands::SHOW_WINDOW_MANAGER:
            AppCUI::Dialogs::WindowManager::Show();
            return true;
        case MenuCommands::EXIT_GVIEW:
            AppCUI::Application::Close();
            return true;
        case MenuCommands::OPEN_FILE:
            OpenFile();
            return true;
        }
        if ((ID >= GENERIC_PLUGINS_CMDID) && (ID < GENERIC_PLUGINS_CMDID + GENERIC_PLUGINS_FRAME * 1000))
        {
            auto packedValue = ((uint32) ID) - GENERIC_PLUGINS_CMDID;
            // get current focused object

            this->genericPlugins[packedValue / GENERIC_PLUGINS_FRAME].Run(packedValue % GENERIC_PLUGINS_FRAME, this->GetCurrentObject());
            return true;
        }
    }
    return true;
}
void Instance::OnStart(Reference<Control> control)
{
    ShowErrors();
}
//===============================[PROPERTIES]==================================
bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value)
{
    NOT_IMPLEMENTED(false);
}
bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error)
{
    NOT_IMPLEMENTED(false);
}
void Instance::SetCustomPropertyValue(uint32 propertyID)
{
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    NOT_IMPLEMENTED(false);
}
const vector<Property> Instance::GetPropertiesList()
{
    return {};
}
