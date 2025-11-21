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

    const std::array<std::reference_wrapper<KeyboardControl>, 6> localKeys = {
        InstanceCommands::INSTANCE_CHANGE_VIEW,     InstanceCommands::INSTANCE_SWITCH_TO_VIEW, InstanceCommands::INSTANCE_COMMAND_GOTO,
        InstanceCommands::FILE_WINDOW_COMMAND_FIND, InstanceCommands::INSTANCE_CHOOSE_TYPE,    InstanceCommands::INSTANCE_KEY_CONFIGURATOR
    };

    LocalString<64> keyCommand;
    for (auto& k : localKeys) {
        keyCommand.SetFormat("Key.%s", k.get().Caption);
        ini["GView"][keyCommand.GetText()] = k.get().Key;
    }

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
    GetCurrentWindow()->AddNote(newNodeStr);
    return true;
}
