#include "Internal.hpp"
#include "BufferViewer.hpp"
#include "TextViewer.hpp"
#include "ImageViewer.hpp"
#include "GridViewer.hpp"
#include "DissasmViewer.hpp"
#include "LexicalViewer.hpp"
#ifdef GVIEW_ENABLE_REMOTE
#    include "../Remote/RemoteConfig.hpp"
#endif
#include "../Update/Installer.hpp"
#include "../Update/UpdateService.hpp"

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
bool GView::App::Init(bool isTestingEnabled)
{
    gviewAppInstance = new GView::App::Instance();
    if (!gviewAppInstance->Init(isTestingEnabled))
    {
        delete gviewAppInstance;
        RETURNERROR(false, "Fail to initialize GView app");
    }
    return true;
}
void GView::App::Run(std::string_view testing_script)
{
    if (gviewAppInstance)
    {
        if (testing_script.empty())
            AppCUI::Application::Run();
        else
            AppCUI::Application::RunTestScript(testing_script);
    }
    // learning session: final session_end + bounded telemetry flush, remove restrictions, wipe secrets
    GView::Security::Learning::Hooks::Shutdown();
    // auto-updater: cancel a running background check (an accepted update is installed by FinishPendingUpdate)
    GView::Update::Service::Shutdown();
}
int GView::App::FinishPendingUpdate()
{
    return GView::Update::Installer::Execute();
}
#ifdef BUILD_FOR_WINDOWS
void GView::App::SetCommandLineArguments(int argc, const wchar_t** argv)
#else
void GView::App::SetCommandLineArguments(int argc, const char** argv)
#endif
{
    std::vector<GView::Update::Installer::NativeString> args;
    for (int i = 1; i < argc && argv != nullptr && argv[i] != nullptr; i++)
        args.emplace_back(argv[i]);
    GView::Update::Installer::SetRelaunchArguments(std::move(args));
}
bool GView::App::ResetConfiguration()
{
    IniObject ini = {};
    ini.CreateFromFile(GetAppSettingsFile());

    // for AppCUI
    AppCUI::Application::UpdateAppCUISettings(ini, true);
    // for viewers
    GView::View::BufferViewer::Config::Update(ini["View.Buffer"]);
    GView::View::TextViewer::Config::Update(ini["View.Text"]);
    GView::View::ImageViewer::Config::Update(ini["View.Image"]);
    GView::View::GridViewer::Config::Update(ini["View.Grid"]);
    GView::View::DissasmViewer::Config::Update(ini["View.Dissasm"]);
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

    // Learning and Evaluation Mode (see docs/source/learning_mode_protocol.rst)
    //   ServerConnectionString          - saved after the first verified connect
    //   PolicyPublicKey                 - 64 hex chars, used when the connection string has no public key (v1)
    //   LearningAllowPlainHttpLocalhost - allow http:// for localhost/127.0.0.1 only (teacher-laptop labs)
    //   LearningDownloadFolder          - default folder for file-mode deliveries (empty = <Documents>/GView/<week>)
    ini["GView"]["PolicyPublicKey"]                 = "";
    ini["GView"]["LearningAllowPlainHttpLocalhost"] = false;
    ini["GView"]["LearningDownloadFolder"]          = "";

#ifdef GVIEW_ENABLE_REMOTE
    // remote TUI (see docs/source/remote_protocol.rst)
    GView::Remote::WriteDefaultRemoteConfig(ini);
#endif

    // Auto-updater (see docs/source/updates.rst)
    //   UpdateCheck              - daily background check for a newer GView release
    //   UpdateIncludePreReleases - also offer GitHub pre-releases (every GView release so far is a pre-release)
    //   UpdateFeedUrl            - GitHub "list releases" API URL (https only)
    //   UpdateCheckIntervalHours - minimum delay between two automatic checks
    //   UpdateRemindAfterDays    - "Remind me later" delay (0 = never remind about the same version again)
    //   UpdateProxy              - optional proxy for the update requests (https_proxy is honoured as well)
    //   UpdateLastCheck, UpdateLastSeenVersion, UpdateRemindAt, UpdateSkippedVersion, UpdateETag,
    //   UpdateCachedFeedVersion  - state written by GView
    GView::Update::UpdateSettings::WriteDefaults(ini);

    // key bindings: only the user changes are stored ([Keys.*] sections, written by the "Keyboard shortcuts" window).
    // A reset restores the built-in keys -> saving an empty registry removes every [Keys.*] section and the legacy
    // Key.* values of [GView] / [View.*] (the keyboard profile is reset with the [AppCUI] section above).
    Keys::Registry{}.Save(ini);

    // all good (save config)
    return ini.Save(AppCUI::Application::GetAppSettingsFile());
}

void GView::App::OpenFile(const std::filesystem::path& path, std::string_view typeName, Reference<Window> parent, const ConstString& creationProcess)
{
    OpenFile(path, OpenMethod::ForceType, typeName, parent, creationProcess);
}

void GView::App::OpenFile(
      const std::filesystem::path& path, OpenMethod method, std::string_view typeName, Reference<Window> parent, const ConstString& creationProcess)
{
    if (gviewAppInstance)
    {
        try
        {
            if (path.is_absolute())
            {
                gviewAppInstance->AddFileWindow(path, method, typeName, parent, creationProcess);
            }
            else
            {
                const auto absPath = std::filesystem::canonical(path);
                gviewAppInstance->AddFileWindow(absPath, method, typeName, parent, creationProcess);
            }
        }
        catch (std::filesystem::filesystem_error /* e */)
        {
            gviewAppInstance->AddFileWindow(path, method, typeName, parent, creationProcess);
        }
    }
}
void GView::App::OpenBuffer(
      BufferView buf,
      const ConstString& name,
      const ConstString& path,
      OpenMethod method,
      std::string_view typeName,
      Reference<Window> parent,
      const ConstString& creationProcess)
{
    if (gviewAppInstance)
        gviewAppInstance->AddBufferWindow(buf, name, path, method, typeName, parent, creationProcess);
}
static std::string g_startupConnectionString;
void GView::App::OpenLearningModeOnStart(std::string_view connectionString)
{
    g_startupConnectionString.assign(connectionString);
}
bool GView::App::TakeStartupLearningConnection(std::string& out)
{
    if (g_startupConnectionString.empty())
        return false;
    out = std::move(g_startupConnectionString);
    g_startupConnectionString.clear();
    return true;
}
bool GView::App::OpenDataObject(
      std::unique_ptr<AppCUI::OS::DataObject> data,
      const ConstString& name,
      const ConstString& path,
      OpenMethod method,
      std::string_view typeName,
      Reference<Window> parent,
      const ConstString& creationProcess)
{
    CHECK(gviewAppInstance, false, "GView was not initialized !");
    return gviewAppInstance->AddDataObjectWindow(std::move(data), name, path, method, typeName, parent, creationProcess);
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

void FileWindow::ShowFilePropertiesDialog()
{
    FileWindowProperties dlg(view, gviewAppInstance);
    dlg.Show();
}

class AddNoteWindow : public Controls::Window
{
    constexpr static int BUTTON_ID_OK    = 10000;
    constexpr static int BUTTON_ID_CLOSE = 10001;

    CharacterBuffer data;
    Reference<TextField> input;

  public:
    AddNoteWindow() : Window("Add note", "d:c,w:30,h:8", WindowFlags::Sizeable)
    {
        input = Factory::TextField::Create(this, data, "l:1,t:1,r:1", TextFieldFlags::None);
        Factory::Button::Create(this, "OK", "l:6,b:0,w:10", BUTTON_ID_OK);
        Factory::Button::Create(this, "Close", "l:16,b:0,w:10", BUTTON_ID_CLOSE);
        input->SetFocus();
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::WindowClose || eventType == Event::WindowAccept) {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        if (eventType != Event::ButtonClicked)
            return true;
        switch (id) {
        case BUTTON_ID_OK:
            if (input->GetText().Len() > 0) {
                data = input->GetText();
                Exit(Dialogs::Result::Ok);
            } else
                Dialogs::MessageBox::ShowError("Error", "Note cannot be empty !");
            return true;
        case BUTTON_ID_CLOSE:
            Exit(Dialogs::Result::Cancel);
            return true;
        default:
            return true;
        }
    }

    const CharacterBuffer& GetNote() const
    {
        return data;
    }
};

bool CORE_EXPORT GView::App::ShowAddNoteDialog()
{
    CHECK(gviewAppInstance, false, "GView was not initialized !");

    AddNoteWindow win;
    const auto result = win.Show();
    if (result != Dialogs::Result::Ok)
        return false;
    std::u16string newNodeStr;
    if (!win.GetNote().ToString(newNodeStr))
        return false;
    auto current = GetCurrentWindow();
    current->AddNote(newNodeStr);
    // telemetry records only that a note was added (never its content)
    if (auto* fw = dynamic_cast<FileWindow*>(current.operator->()); fw != nullptr)
        GView::Security::Learning::Hooks::OnSimpleEvent(fw->GetObject(), GView::Security::Learning::Hooks::SimpleEvent::NoteAdd);
    return true;
}
