#include <GViewApp.hpp>

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

struct _MenuCommand_
{
    std::string_view name;
    int commandID;
    Key shortCutKey;
};
constexpr _MenuCommand_ menuWindowList[] = {
    {"Arrange &Vertically", MenuCommands::ARRANGE_VERTICALLY, Key::None},
    {"Arrange &Horizontally", MenuCommands::ARRANGE_HORIZONTALLY, Key::None},
    {"&Cascade mode", MenuCommands::ARRANGE_CASCADE, Key::None},
    {"&Grid", MenuCommands::ARRANGE_GRID, Key::None},
    {"",0,Key::None},
    {"Close", MenuCommands::CLOSE, Key::None},
    {"Close &All", MenuCommands::CLOSE_ALL, Key::None},
    {"Close All e&xcept current", MenuCommands::CLOSE_ALL, Key::None},
    {"",0,Key::None},
    {"&Windows manager", MenuCommands::SHOW_WINDOW_MANAGER, Key::Alt|Key::N0},
};
constexpr _MenuCommand_ menuHelpList[] = {
    {"Check for &updates", MenuCommands::CHECK_FOR_UPDATES, Key::None},
    {"&About", MenuCommands::ABOUT, Key::None},
};

bool AddMenuCommands(Menu* mnu, const _MenuCommand_* list, size_t count)
{
    while (count > 0)
    {
        if (list->name.empty())
        {
            CHECK(mnu->AddSeparator() != InvalidItemHandle, false, "Fail to add separator !");
        }
        else {
            CHECK(mnu->AddCommandItem(list->name, list->commandID, list->shortCutKey) != InvalidItemHandle, false, "Fail to add %s to menu !", list->name.data());
        }
        count--;
        list++;
    }
    return true;
}

bool Instance::LoadSettings()
{
    // process all settings and set up plugins
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
    initData.Flags = InitializationFlags::Menu | InitializationFlags::CommandBar |
        InitializationFlags::LoadSettingsFile | InitializationFlags::AutoHotKeyForWindow;

    CHECK(AppCUI::Application::Init(initData), false, "Fail to initialize AppCUI framework !");
    // reserve some space fo type
    this->typePlugins.reserve(128);
    CHECK(LoadSettings(), false, "Fail to load settings !");
    CHECK(BuildMainMenus(), false, "Fail to create bundle menus !");
    return true;
}
void Instance::Run()
{
    AppCUI::Application::Run();
}