#include "Internal.hpp"
#include "BufferViewer.hpp"
#include "TextViewer.hpp"
#include "ImageViewer.hpp"
#include "GridViewer.hpp"
#include "DissasmViewer.hpp"
#include "LexicalViewer.hpp"

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

GView::App::Instance* gviewAppInstance = nullptr;

constexpr uint32 DEFAULT_CACHE_SIZE = 0xA00000; // 10 MB // sync this with the one from App/Instance.cpp

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
    GView::View::BufferViewer::Config::Update(ini["View.Buffer"]);
    GView::View::TextViewer::Config::Update(ini["View.Text"]);
    GView::View::ImageViewer::Config::Update(ini["View.Image"]);
    GView::View::GridViewer::Config::Update(ini["View.Grid"]);
    GView::View::DissasmViewer::Config::Update(ini["DissasmView"]);
    GView::View::LexicalViewer::Config::Update(ini["View.Lexical"]);

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
    ini["GView"]["CacheSize"]        = DEFAULT_CACHE_SIZE;
    ini["GView"]["Key.ChangeView"]   = Key::F4;
    ini["GView"]["Key.SwitchToView"] = Key::Alt | Key::F;
    ini["GView"]["Key.GoTo"]         = Key::F5;
    ini["GView"]["Key.Find"]         = Key::Alt | Key::F7;
    ini["GView"]["Key.ChoseType"]    = Key::Alt | Key::F1;

    // all good (save config)
    return ini.Save(AppCUI::Application::GetAppSettingsFile());
}

void GView::App::OpenFile(const std::filesystem::path& path, std::string_view typeName)
{
    OpenFile(path, OpenMethod::ForceType, typeName);
}
void GView::App::OpenFile(const std::filesystem::path& path, OpenMethod method, std::string_view typeName)
{
    if (gviewAppInstance)
    {
        try
        {
            if (path.is_absolute())
            {
                gviewAppInstance->AddFileWindow(path, method, typeName);
            }
            else
            {
                const auto absPath = std::filesystem::canonical(path);
                gviewAppInstance->AddFileWindow(absPath, method, typeName);
            }
        }
        catch (std::filesystem::filesystem_error /* e */)
        {
            gviewAppInstance->AddFileWindow(path, method, typeName);
        }
    }
}
void GView::App::OpenBuffer(BufferView buf, const ConstString& name, OpenMethod method, std::string_view typeName)
{
    if (gviewAppInstance)
        gviewAppInstance->AddBufferWindow(buf, name, "", method, typeName);
}
void GView::App::OpenBuffer(BufferView buf, const ConstString& name, const ConstString& path, OpenMethod method, std::string_view typeName)
{
    if (gviewAppInstance)
        gviewAppInstance->AddBufferWindow(buf, name, path, method, typeName);
}

Reference<GView::Object> GView::App::GetObject(uint32 index)
{
    CHECK(gviewAppInstance, nullptr, "GView was not initialized !");
    return gviewAppInstance->GetObject(index);
}
uint32 GView::App::GetObjectsCount()
{
    CHECK(gviewAppInstance, 0U, "GView was not initialized !");
    return gviewAppInstance->GetObjectsCount();
}
std::string_view GView::App::GetTypePluginName(uint32 index)
{
    CHECK(gviewAppInstance, nullptr, "GView was not initialized !");
    return gviewAppInstance->GetTypePluginName(index);
}
std::string_view GView::App::GetTypePluginDescription(uint32 index)
{
    CHECK(gviewAppInstance, nullptr, "GView was not initialized !");
    return gviewAppInstance->GetTypePluginDescription(index);
}
uint32 CORE_EXPORT GView::App::GetTypePluginsCount()
{
    CHECK(gviewAppInstance, 0, "GView was not initialized !");
    return gviewAppInstance->GetTypePluginsCount();
}