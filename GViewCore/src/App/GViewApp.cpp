#include "Internal.hpp"
#include "BufferViewer.hpp"
#include "ImageViewer.hpp"
#include "GridViewer.hpp"
#include "DissasmViewer.hpp"

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

GView::App::Instance* gviewAppInstance = nullptr;

bool UpdateSettingsForTypePlugin(AppCUI::Utils::IniObject& ini, const std::filesystem::path& pluginPath)
{
    // First load the plugin
    AppCUI::OS::Library lib;
    CHECK(lib.Load(pluginPath), false, "Fail to load: %s", pluginPath.string().c_str());
    void (*fnUpdateSettings)(AppCUI::Utils::IniSection sect);
    fnUpdateSettings = lib.GetFunction<decltype(fnUpdateSettings)>("UpdateSettings");
    CHECK(fnUpdateSettings, false, "'UpdateSettings' export was not located in: %s", pluginPath.string().c_str());
    auto nm = pluginPath.filename().string();
    // format is lib<....>.tpl
    auto sect = ini["Type." + nm.substr(3, nm.length() - 7)];
    fnUpdateSettings(sect);
    return true;
}
bool UpdateSettingsForGenericPlugin(AppCUI::Utils::IniObject& ini, const std::filesystem::path& pluginPath)
{
    // First load the plugin
    AppCUI::OS::Library lib;
    CHECK(lib.Load(pluginPath), false, "Fail to load: %s", pluginPath.string().c_str());
    void (*fnUpdateSettings)(AppCUI::Utils::IniSection sect);
    fnUpdateSettings = lib.GetFunction<decltype(fnUpdateSettings)>("UpdateSettings");
    CHECK(fnUpdateSettings, false, "'UpdateSettings' export was not located in: %s", pluginPath.string().c_str());
    auto nm = pluginPath.filename().string();
    // format is lib<....>.tpl
    auto sect = ini["Generic." + nm.substr(3, nm.length() - 7)];
    fnUpdateSettings(sect);
    return true;
}
bool GView::App::Init()
{
    gviewAppInstance = new GView::App::Instance();
    if (!gviewAppInstance->Init())
    {
        delete gviewAppInstance;
        RETURNERROR(false, "Fail to initialize GView app");
    }
    return true;
}
void GView::App::Run()
{
    if (gviewAppInstance)
    {
        AppCUI::Application::Run();
    }
}
bool GView::App::ResetConfiguration()
{
    IniObject ini;

    // for AppCUI
    AppCUI::Application::UpdateAppCUISettings(ini, true);
    // for viewers
    GView::View::BufferViewer::Config::Update(ini["BufferView"]);
    GView::View::ImageViewer::Config::Update(ini["ImageView"]);
    GView::View::GridViewer::Config::Update(ini["GridView"]);
    GView::View::DissasmViewer::Config::Update(ini["DissasmView"]);

    // parse types and add specs
    auto typesPath = AppCUI::OS::GetCurrentApplicationPath();
    typesPath.remove_filename();
    typesPath += "Types";
    for (const auto& fileEntry : std::filesystem::directory_iterator(typesPath))
    {
        if ((fileEntry.path().extension() == ".tpl") && (fileEntry.path().filename().string().starts_with("lib")))
            UpdateSettingsForTypePlugin(ini, fileEntry.path());
    }

    // parse generic plugins and add specs
    auto genericPluginsPath = AppCUI::OS::GetCurrentApplicationPath();
    genericPluginsPath.remove_filename();
    genericPluginsPath += "GenericPlugins";
    for (const auto& fileEntry : std::filesystem::directory_iterator(genericPluginsPath))
    {
        if ((fileEntry.path().extension() == ".gpl") && (fileEntry.path().filename().string().starts_with("lib")))
            UpdateSettingsForGenericPlugin(ini, fileEntry.path());
    }

    // generic GView settings
    ini["GView"]["CacheSize"]    = 0x100000;
    ini["GView"]["ChangeView"]   = Key::F4;
    ini["GView"]["SwitchToView"] = Key::Alt | Key::F;

    // all good (save config)
    return ini.Save(AppCUI::Application::GetAppSettingsFile());
}
void GView::App::OpenFile(const char* path)
{
    if (gviewAppInstance)
        gviewAppInstance->AddFileWindow(path);
}
void GView::App::OpenItem(View::ExtractItem item, Reference<View::ViewControl> view, uint64 size, string_view name)
{
    // simple form --> just write it to a file and open it
    AppCUI::OS::File f;
    if (!f.Create(name, true))
        return;
    if (view->ExtractTo(&f, item, size) == false)
        return;
    f.Close();
    // API to OpenFile has to be changed (remove that cont char* path)
    OpenFile(name.data());
}
