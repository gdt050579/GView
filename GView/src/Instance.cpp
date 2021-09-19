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
constexpr _MenuCommand_ menuArrange[] = {
    {"Arrange &Vertically", MenuCommands::ARRANGE_VERTICALLY, Key::None},
    {"Arrange &Horizontally", MenuCommands::ARRANGE_HORIZONTALLY, Key::None},
    {"&Cascade mode", MenuCommands::ARRANGE_CASCADE, Key::None},
    {"&Grid", MenuCommands::ARRANGE_GRID, Key::None},
};

bool AddMenuCommands(Menu* mnu, const _MenuCommand_* list, size_t count, bool addSeperatorAfterList)
{
    while (count > 0)
    {
        CHECK(mnu->AddCommandItem(list->name, list->commandID, list->shortCutKey) != InvalidItemHandle, false, "Fail to add %s to menu !", list->name.data());
        count--;
        list++;
    }
    if (addSeperatorAfterList)
    {
        CHECK(mnu->AddSeparator() != InvalidItemHandle, false, "Fail to add separator !");
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
    CHECK(mnuWindow = AppCUI::Application::AddMenu("&Windows"), false, "Unable to create `Windows` menu");
    CHECK(AddMenuCommands(mnuWindow, menuArrange, 4, false), false, "");
    return true;
}

bool Instance::Init()
{
    InitializationData initData;
    initData.Flags = InitializationFlags::Menu | InitializationFlags::CommandBar;
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