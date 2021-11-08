#include <GViewApp.hpp>

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

struct _MenuCommand_
{
    std::string_view name;
    int commandID;
    Key shortCutKey;
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
    this->defaultCacheSize = 0x100000; // 1 MB
}
bool Instance::LoadSettings()
{
    auto ini = AppCUI::Application::GetAppSettings();
    CHECK(ini, false, "");
    // check plugins
    for (auto section : ini->GetSections())
    {
        if (String::StartsWith(section.GetName(), std::string_view("type."), true))
        {
            GView::Type::Plugin p;
            CHECK(p.Init(section), false, "Fail to initialize pluggin !");
            this->typePlugins.push_back(p);
        }
    }
    // sort all plugins based on their priority
    std::sort(this->typePlugins.begin(), this->typePlugins.end());

    return true;
}
bool Instance::BuildMainMenus()
{
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

    return true;
}
bool Instance::Add(std::unique_ptr<AppCUI::OS::IFile> file, const AppCUI::Utils::ConstString& name, std::string_view ext)
{
    auto win = std::make_unique<FileWindow>(name);
    auto obj = win->GetObject();
    CHECK(obj->cache.Init(std::move(file), this->defaultCacheSize), false, "Fail to instantiate window");

    auto buf  = obj->cache.Get(0, 4096); // first 4k
    auto& plg = this->defaultPlugin;
    // iterate from existing types
    for (auto& pType : this->typePlugins)
    {
        if (pType.Validate(buf, ext))
        {
            plg = pType;
            break;
        }
    }

    // create an instance of that type
    obj->type = plg.CreateInstance(Reference<GView::Utils::FileCache>(&obj->cache));

    // instantiate window
    while (true)
    {
        CHECKBK(plg.PopulateWindow(win.get()), "Fail to populate file window !");
        auto res = AppCUI::Application::AddWindow(std::move(win));
        CHECKBK(res != InvalidItemHandle, "Fail to add newly created window to desktop");
        return true;
    }
    // error case
    delete obj->type;
    obj->type = nullptr;
    return false;
}
bool Instance::AddFileWindow(const std::filesystem::path& path)
{
    auto f = std::make_unique<AppCUI::OS::File>();
    CHECK(f->OpenRead(path), false, "Fail to open file: %s", path.u8string().c_str());
    return Add(std::move(f), path.u16string(), path.extension().string());
}
void Instance::Run()
{
    AppCUI::Application::Run();
}