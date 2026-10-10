#include "Internal.hpp"
#include "Learning/SecureMemory.hpp"
#ifdef GVIEW_ENABLE_REMOTE
#    include "../Remote/RemoteConfig.hpp"
#endif
#include "../Update/Stager.hpp"
#include "../Update/UpdateService.hpp"
#include <array>

using namespace GView::App;
using namespace GView::App::InstanceCommands;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

constexpr uint32 DEFAULT_CACHE_SIZE    = 0xA00000; // 10 MB
constexpr uint32 MIN_CACHE_SIZE        = 0x10000;  // 64 K
constexpr uint32 GENERIC_PLUGINS_CMDID = 40000000;
constexpr uint32 GENERIC_PLUGINS_FRAME = 100;

constexpr uint32 CACHE_SIZE_PROPERTY_ID = 1;

struct GViewMenuCommand {
    std::string_view name;
    int commandID;
    Key shortCutKey;
    const GView::KeyboardControl* binding = nullptr; // when set, the shortcut is the (configurable) key of this binding
};
constexpr GViewMenuCommand menuFileList[] = {
    { "&Open file", MenuCommands::OPEN_FILE, Key::None },
    { "Open &folder", MenuCommands::OPEN_FOLDER, Key::None },
    { "", 0, Key::None },
    { "Open &process", MenuCommands::OPEN_PID, Key::None },
    { "Open process &tree", MenuCommands::OPEN_PROCESS_TREE, Key::None },
    { "", 0, Key::None },
#ifdef GVIEW_ENABLE_REMOTE
    { "Connect to a &remote GView", MenuCommands::REMOTE_CONNECT, Key::None },
    { "&Wait for a reverse connection", MenuCommands::REMOTE_LISTEN, Key::None },
    { "", 0, Key::None },
#endif
    { "E&xit", MenuCommands::EXIT_GVIEW, Key::None, &INSTANCE_EXIT },
};
constexpr ItemHandle menuFileDisabledCommandsList[] = { 3, 4 };

constexpr GViewMenuCommand menuOptionsList[] = { 
    { "&Change theme", MenuCommands::CHANGE_THEME, Key::None },
    { "Op&en Theme Editor", MenuCommands::OPEN_THEME_EDITOR, Key::None },
    { "", 0, Key::None },
    { "&Learning and Evaluation Mode", MenuCommands::OPEN_RESTRICTED_MODE, Key::None },
};

constexpr GViewMenuCommand menuWindowList[] = {
    { "Arrange &Vertically", MenuCommands::ARRANGE_VERTICALLY, Key::None },
    { "Arrange &Horizontally", MenuCommands::ARRANGE_HORIZONTALLY, Key::None },
    { "&Cascade mode", MenuCommands::ARRANGE_CASCADE, Key::None },
    { "&Grid", MenuCommands::ARRANGE_GRID, Key::None },
    { "", 0, Key::None },
    { "Close", MenuCommands::CLOSE, Key::None },
    { "Close &All", MenuCommands::CLOSE_ALL, Key::None },
    { "Close All e&xcept current", MenuCommands::CLOSE_ALL, Key::None },
    { "", 0, Key::None },
    { "&Windows manager", MenuCommands::SHOW_WINDOW_MANAGER, Key::None, &INSTANCE_WINDOWS_MANAGER },
};
constexpr GViewMenuCommand menuHelpList[] = {
    { "Check for &updates", MenuCommands::CHECK_FOR_UPDATES, Key::None },
    { "&Keyboard shortcuts", MenuCommands::AVAILABLE_KEYS, Key::None, &INSTANCE_KEY_CONFIGURATOR },
    { "&About", MenuCommands::ABOUT, Key::None },
};

bool AddMenuCommands(Menu* mnu, const GViewMenuCommand* list, size_t count)
{
    while (count > 0) {
        if (list->name.empty()) {
            CHECK(mnu->AddSeparator() != InvalidItemHandle, false, "Fail to add separator !");
        } else {
            const auto key = list->binding ? list->binding->Key : list->shortCutKey;
            CHECK(mnu->AddCommandItem(list->name, list->commandID, key) != InvalidItemHandle,
                  false,
                  "Fail to add %s to menu !",
                  list->name.data());
        }
        count--;
        list++;
    }
    return true;
}

// set by the remote server before Init (GView::App::SetHeadlessFrontend)
static AppCUI::Application::CustomFrontendInterface* headlessFrontend = nullptr;
void GView::App::SetHeadlessFrontend(AppCUI::Application::CustomFrontendInterface* frontend)
{
    headlessFrontend = frontend;
}

Instance::Instance()
{
    this->defaultCacheSize         = DEFAULT_CACHE_SIZE;
    this->mnuWindow                = nullptr;
    this->mnuHelp                  = nullptr;
    this->mnuFile                  = nullptr;
    this->lastOpenedFolderLocation = ".";
}
bool Instance::LoadSettings()
{
    auto ini = AppCUI::Application::GetAppSettings();
    CHECK(ini, false, "");
    CHECK(ini->GetSectionsCount() > 0, false, "");
    // check plugins
    for (auto section : *ini) {
        auto sectionName = section.GetName();
        if (String::StartsWith(sectionName, "type.", true)) {
            GView::Type::Plugin p;
            if (p.Init(section)) {
                this->typePlugins.push_back(p);
            } else {
                errList.AddWarning("Fail to load type plugin (%s)", sectionName.data());
            }
        }
        if (String::StartsWith(sectionName, "generic.", true)) {
            GView::Generic::Plugin p;
            if (p.Init(section)) {
                this->genericPlugins.push_back(p);
            } else {
                errList.AddWarning("Fail to load generic plugin (%s)", sectionName.data());
            }
        }
    }

    // sort all plugins based on their priority
    std::sort(this->typePlugins.begin(), this->typePlugins.end());

    // read instance settings
    auto sect                                  = ini->GetSection("GView");
    this->defaultCacheSize                     = std::max<>(sect.GetValue("Config.CacheSize").ToUInt32(DEFAULT_CACHE_SIZE), MIN_CACHE_SIZE);

    // key bindings (must be applied before the menus and the first window are created)
    this->keyBindings.Load(*ini);
    ApplyKeyBindings();
    return true;
}
void Instance::ApplyKeyBindings()
{
    // GView keys
    Keys::ApplyPass gviewPass(this->keyBindings, Keys::SECTION_GVIEW);
    RegisterGViewKeys(&gviewPass);
    // viewers (static keys -> one pass per viewer type)
    for (const auto& viewer : Keys::GetAllViewerKeys()) {
        Keys::ApplyPass pass(this->keyBindings, viewer.section);
        viewer.registerKeys(&pass);
        if (viewer.onKeysChanged)
            viewer.onKeysChanged();
    }
    // plugin commands (command bar)
    for (auto& p : this->typePlugins)
        p.ApplyKeyBindings(this->keyBindings);
    for (auto& p : this->genericPlugins)
        p.ApplyKeyBindings(this->keyBindings);
    // keys registered by the type plugin instances of the opened windows
    auto dsk = AppCUI::Application::GetDesktop();
    if (dsk.IsValid()) {
        const auto count = dsk->GetChildrenCount();
        for (uint32 i = 0; i < count; i++) {
            auto child = dsk->GetChild(i);
            if (!child.IsValid())
                continue;
            if (auto fileWindow = dynamic_cast<FileWindow*>(&static_cast<Control&>(child)))
                fileWindow->ApplyKeyBindings(this->keyBindings);
        }
    }
}
Reference<FileWindow> Instance::GetCurrentFileWindow()
{
    auto dsk = AppCUI::Application::GetDesktop();
    if (!dsk.IsValid())
        return nullptr;
    auto focused = dsk->GetFocusedChild();
    if (!focused.IsValid())
        return nullptr;
    return dynamic_cast<FileWindow*>(&static_cast<Control&>(focused));
}
void Instance::ShowKeyboardShortcuts()
{
    ShowKeyboardShortcutsWindow(this, GetCurrentFileWindow());
}
bool Instance::BuildMainMenus()
{
    CHECK(mnuFile = AppCUI::Application::AddMenu("File"), false, "Unable to create 'File' menu");
    CHECK(AddMenuCommands(mnuFile, menuFileList, ARRAY_LEN(menuFileList)), false, "");
    for (auto itemHandle : menuFileDisabledCommandsList) {
        CHECK(mnuFile->SetEnable(itemHandle, false), false, "Fail to disable menu item");
    }
    CHECK(mnuOptions = AppCUI::Application::AddMenu("&Options"), false, "Unable to create 'Options' menu");
    CHECK(AddMenuCommands(mnuOptions, menuOptionsList, ARRAY_LEN(menuOptionsList)), false, "");

    CHECK(mnuWindow = AppCUI::Application::AddMenu("&Windows"), false, "Unable to create 'Windows' menu");
    CHECK(AddMenuCommands(mnuWindow, menuWindowList, ARRAY_LEN(menuWindowList)), false, "");
    CHECK(mnuHelp = AppCUI::Application::AddMenu("&Help"), false, "Unable to create 'Help' menu");
    CHECK(AddMenuCommands(mnuHelp, menuHelpList, ARRAY_LEN(menuHelpList)), false, "");
    return true;
}

bool Instance::Init(bool isTestingEnabled)
{
    InitializationData initData;
    // EnableFPSMode: AppCUI only delivers OnFrameUpdate (~30 Hz) in FPS mode. Learning and Evaluation Mode relies on
    // it to apply background network results on the UI thread without blocking. No GView control requests a repaint
    // from OnFrameUpdate unless its state changed, so idle CPU usage stays negligible.
    initData.Flags = InitializationFlags::Menu | InitializationFlags::CommandBar | InitializationFlags::LoadSettingsFile |
                     InitializationFlags::AutoHotKeyForWindow | InitializationFlags::EnableFPSMode;
    // A remote server never updates itself: the update dialog would be shown to the remote analysts, and installing
    // replaces the binaries and restarts the process the analysts are connected to.
    const bool isRemoteServer = headlessFrontend != nullptr;
    if (headlessFrontend) {
        // remote server: the screen is streamed to remote analysts and must stay up even when every window is closed
        initData.Frontend       = FrontendType::Custom;
        initData.CustomFrontend = headlessFrontend;
        initData.Flags |= InitializationFlags::DisableAutoCloseDesktop;
        headlessFrontend = nullptr;
    }
    // the GView desktop runs the background update check (see Update/UpdateService.hpp)
    if (!isTestingEnabled && !isRemoteServer)
        initData.CustomDesktopConstructor = GView::App::CreateDesktop;

    const auto settingsPath = AppCUI::Application::GetAppSettingsFile();
    AppCUI::OS::File settingsFile;

    bool showTutorial = false;
    // no .ini file found
    if (!settingsFile.OpenRead(settingsPath)) {
        CHECK(GView::App::ResetConfiguration(), false, "");
        if (!isTestingEnabled)
            showTutorial = true;
    }
    settingsFile.Close();

    if (isTestingEnabled) {
        CHECK(AppCUI::Application::InitForTests(initData.Width, initData.Height, initData.Flags, false),
              false,
              "Fail to initialize AppCUI framework for tests!");
    } else {
        CHECK(AppCUI::Application::Init(initData), false, "Fail to initialize AppCUI framework !");
    }
    // reserve some space fo type
    this->typePlugins.reserve(128);
    if (!LoadSettings()) {
        auto preservedSettingsNewPath = settingsPath;
        preservedSettingsNewPath.replace_extension(".ini.bak");
        std::filesystem::rename(settingsPath, preservedSettingsNewPath);
        AppCUI::Log::Report(
              AppCUI::Log::Severity::Warning, __FILE__, __FUNCTION__, "!LoadSettings()", __LINE__, "found an invalid ini file, will generate a new one");
        CHECK(GView::App::ResetConfiguration(), false, "");

        AppCUI::Dialogs::MessageBox::ShowError(
              "Error reading configuration",
              "Found an invalid configuration, it will be renamed as \".ini.bak\". Will generated a new one! Please restart GView.");
    }

    if (showTutorial) {
        ShowTutorial();
    }

    CHECK(BuildMainMenus(), false, "Fail to create bundle menus !");
    this->defaultPlugin.InitDefaultPlugin();

    if (!isTestingEnabled) {
        // leftovers of a previous update (staging folders, replaced files of a completed update)
        GView::Update::CleanupWorkDir(AppCUI::OS::GetCurrentApplicationPath().parent_path());
        if (!isRemoteServer)
            GView::Update::Service::Enable(); // also gates Help > Check for updates
    }

    // set up handlers
    auto dsk                 = AppCUI::Application::GetDesktop();
    dsk->Handlers()->OnEvent = this;
    dsk->Handlers()->OnStart = this;
    return true;
}
Reference<GView::Type::Plugin> Instance::IdentifyTypePlugin_WithSelectedType(
      const AppCUI::Utils::ConstString& name,
      const AppCUI::Utils::ConstString& path,
      uint64 dataSize,
      AppCUI::Utils::BufferView buf,
      GView::Type::Matcher::TextParser& textParser,
      uint64 extensionHash,
      std::string_view typeName,
      std::u16string& newName)
{
    GView::Type::Plugin* plg = nullptr;
    // search for the plugin
    auto sz = typeName.size();
    for (auto& pType : this->typePlugins) {
        auto pName = pType.GetName();
        if (pName.size() != sz)
            continue;
        if (AppCUI::Utils::String::StartsWith(pName, typeName, true)) {
            plg = &pType;
            break;
        }
    }
    if (plg != nullptr && !Security::RestrictedMode::Internal::IsPluginAllowed(plg->GetName())) {
        GView::App::IsBlockedByPolicy(Security::RestrictedMode::Feature::Plugins, "this type plugin is not allowed by the course policy");
        return IdentifyTypePlugin_Select(name, path, dataSize, buf, textParser, extensionHash, newName);
    }

    // plugin was not found
    if (plg == nullptr) {
        LocalString<128> temp;
        temp.Set("Unable to find any registered plugin for type: ");
        temp.Add(typeName);
        AppCUI::Dialogs::MessageBox::ShowError("Error", temp);
        // default to selection mode
        return IdentifyTypePlugin_Select(name, path, dataSize, buf, textParser, extensionHash, newName);
    }
    // check if the parser accepts it
    if (plg->IsOfType(buf, textParser) == false) {
        LocalString<128> temp;
        temp.Set("Current file/buffer can not be matched plugin registered for type : ");
        temp.Add(typeName);
        AppCUI::Dialogs::MessageBox::ShowError("Error", temp);
        // default to selection mode
        return IdentifyTypePlugin_Select(name, path, dataSize, buf, textParser, extensionHash, newName);
    }
    // all good return the type plugin
    return plg;
}
Reference<GView::Type::Plugin> Instance::IdentifyTypePlugin_Select(
      const AppCUI::Utils::ConstString& name,
      const AppCUI::Utils::ConstString& path,
      uint64 dataSize,
      AppCUI::Utils::BufferView buf,
      GView::Type::Matcher::TextParser& textParser,
      uint64 extensionHash,
      std::u16string& newName)
{
    SelectTypeDialog dlg(name, path, dataSize, this->typePlugins, buf, textParser, extensionHash);
    if (dlg.Show() == Dialogs::Result::Ok) {
        newName = dlg.GetFilename();
        return dlg.GetSelectedPlugin(&this->defaultPlugin);
    }
    return nullptr;
}
Reference<GView::Type::Plugin> Instance::IdentifyTypePlugin_FirstMatch(
      const string_view& extension, AppCUI::Utils::BufferView buf, GView::Type::Matcher::TextParser& textParser, uint64 extensionHash)
{
    // check for extension first
    // (plugins outside the course policy whitelist are skipped at runtime: the policy may arrive after startup)
    if (extensionHash != 0) {
        for (auto& pType : this->typePlugins) {
            if (!Security::RestrictedMode::Internal::IsPluginAllowed(pType.GetName()))
                continue;
            if (pType.MatchExtension(extensionHash)) {
                if (pType.IsOfType(buf, textParser, extension))
                    return &pType;
            }
        }
    }

    // check the content
    for (auto& pType : this->typePlugins) {
        if (!Security::RestrictedMode::Internal::IsPluginAllowed(pType.GetName()))
            continue;
        if (pType.MatchContent(buf, textParser)) {
            if (pType.IsOfType(buf, textParser))
                return &pType;
        }
    }

    // nothing matched => return the default plugin
    return &this->defaultPlugin;
}
Reference<GView::Type::Plugin> Instance::IdentifyTypePlugin_BestMatch(
      const AppCUI::Utils::ConstString& name,
      const AppCUI::Utils::ConstString& path,
      uint64 dataSize,
      AppCUI::Utils::BufferView buf,
      GView::Type::Matcher::TextParser& textParser,
      uint64 extensionHash,
      std::u16string& newName)
{
    auto plg   = &this->defaultPlugin;
    auto count = 0;
    if (extensionHash != 0) {
        for (auto& pType : this->typePlugins) {
            if (!Security::RestrictedMode::Internal::IsPluginAllowed(pType.GetName()))
                continue;
            if (pType.MatchExtension(extensionHash)) {
                if (pType.IsOfType(buf, textParser)) {
                    count++;
                    plg = &pType;
                    if (count > 1) // at least two options
                        return IdentifyTypePlugin_Select(name, path, dataSize, buf, textParser, extensionHash, newName);
                }
            }
        }
    }

    // check the content
    for (auto& pType : this->typePlugins) {
        if (!Security::RestrictedMode::Internal::IsPluginAllowed(pType.GetName()))
            continue;
        if (pType.MatchContent(buf, textParser)) {
            if (pType.IsOfType(buf, textParser)) {
                count++;
                plg = &pType;
                if (count > 1) // at least two options
                    return IdentifyTypePlugin_Select(name, path, dataSize, buf, textParser, extensionHash, newName);
            }
        }
    }

    // nothing matched => return the default plugin
    return plg;
}
Reference<GView::Type::Plugin> Instance::IdentifyTypePlugin(
      const AppCUI::Utils::ConstString& name,
      const AppCUI::Utils::ConstString& path,
      GView::Utils::DataCache& cache,
      uint64 extensionHash,
      OpenMethod method,
      std::string_view typeName,
      std::u16string& newName)
{
    auto buf    = cache.Get(0, 0x8800, false);
    auto bomLen = 0U;
    auto enc    = GView::Utils::CharacterEncoding::AnalyzeBufferForEncoding(buf, true, bomLen);
    auto text =
          enc != GView::Utils::CharacterEncoding::Encoding::Binary ? GView::Utils::CharacterEncoding::ConvertToUnicode16(buf) : GView::Utils::UnicodeString();
    auto tp = GView::Type::Matcher::TextParser(text.text, text.size);
    auto sz = cache.GetSize();

    LocalUnicodeStringBuilder<256> temp;
    temp.Set(name);
    auto pos = temp.ToStringView().find_last_of('.');

    // Get extension as UTF-16 and convert it to UTF-8
    auto u16Extension             = pos != u16string_view::npos ? (temp.ToStringView().substr(pos)) : std::u16string_view();
    std::string extensionAsString = { u16Extension.begin(), u16Extension.end() };
    std::string_view extension(extensionAsString.c_str(), extensionAsString.size());

    switch (method) {
    case OpenMethod::FirstMatch:
        return IdentifyTypePlugin_FirstMatch(extension, buf, tp, extensionHash);
    case OpenMethod::BestMatch:
        return IdentifyTypePlugin_BestMatch(name, path, sz, buf, tp, extensionHash, newName);
    case OpenMethod::Select:
        return IdentifyTypePlugin_Select(name, path, sz, buf, tp, extensionHash, newName);
    case OpenMethod::ForceType:
        return IdentifyTypePlugin_WithSelectedType(name, path, sz, buf, tp, extensionHash, typeName, newName);
    }

    // for other methods --> return the default plugin
    return &this->defaultPlugin;
}
bool Instance::Add(
      GView::Object::Type objType,
      std::unique_ptr<AppCUI::OS::DataObject> data,
      const AppCUI::Utils::ConstString& name,
      const AppCUI::Utils::ConstString& path,
      uint32 PID,
      OpenMethod method,
      std::string_view typeName,
      Reference<Window> parent,
      const ConstString& creationProcess)
{
    GView::Utils::DataCache cache;
    CHECK(cache.Init(std::move(data), this->defaultCacheSize), false, "Fail to instantiate cache object");

    // extract extension
    LocalUnicodeStringBuilder<256> temp;
    CHECK(temp.Set(path), false, "Fail to get path object");
    // search for the last "."
    auto pos = temp.ToStringView().find_last_of('.');
    auto extHash =
          pos != u16string_view::npos ? GView::Type::Plugin::ExtensionToHash(temp.ToStringView().substr(pos)) : GView::Type::Plugin::ExtensionToHash("");

    CHECK(temp.Set(name), false, "Fail to get filename object");
    std::u16string newName{ temp.ToStringView() };
    auto plg = IdentifyTypePlugin(name, path, cache, extHash, method, typeName, newName);
    CHECK(plg, false, "Unable to identify a valid plugin open canceled !");
    // defence in depth: whatever the identification path, a plugin outside the course whitelist never runs
    if (plg != static_cast<const void*>(&this->defaultPlugin) && !Security::RestrictedMode::Internal::IsPluginAllowed(plg->GetName()))
        plg = &this->defaultPlugin;

    // create an instance of that object type
    auto contentType = plg->CreateInstance();
    CHECK(contentType, false, "'CreateInstance' returned a null pointer to a content type object !");

    auto win = std::make_unique<FileWindow>(std::make_unique<GView::Object>(objType, std::move(cache), contentType, newName, path, PID), this, plg);

    // instantiate window
    while (true) {
        CHECKBK(plg->PopulateWindow(win.get()), "Failed to populate file window!");
        // LLM hints disabled by the course policy => no Smart Assistants tab (prompts are also gated centrally)
        if (!Security::RestrictedMode::IsFeatureDisabled(Security::RestrictedMode::Feature::LLMHints)) {
            CHECKBK(Type::InterfaceTabs::PopulateWindowSmartAssistantsTab(win.get()), "Failed to populate file window!");
        }
        win->Start(); // starts the window and set focus

        auto res = AppCUI::Application::AddWindow(std::move(win), GetCurrentWindow(), creationProcess);
        CHECKBK(res != InvalidItemHandle, "Fail to add newly created window to desktop");

        return true;
    }
    // error case
    return false;
}
bool Instance::AddFolder(const std::filesystem::path& path, const ConstString& creationProcess)
{
    auto contentType = GView::Type::FolderViewPlugin::CreateInstance(path);
    CHECK(contentType, false, "`CreateInstance` returned a null pointer to a type object !");

    GView::Utils::DataCache cache;
    auto win = std::make_unique<FileWindow>(
          std::make_unique<GView::Object>(GView::Object::Type::Folder, std::move(cache), contentType, path.filename().u16string(), path.u16string(), 0),
          this,
          nullptr);

    // instantiate window
    while (true) {
        GView::Type::FolderViewPlugin::PopulateWindow(win.get());
        win->Start(); // starts the window and set focus
        auto res = AppCUI::Application::AddWindow(std::move(win), nullptr, creationProcess);
        CHECKBK(res != InvalidItemHandle, "Fail to add newly created window to desktop");

        return true;
    }
    // error case
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
bool Instance::AddFileWindow(
      const std::filesystem::path& path, OpenMethod method, string_view typeName, Reference<Window> parent, const ConstString& creationProcess)
{
    try {
        if (std::filesystem::is_directory(path)) {
            return AddFolder(path);
        } else {
            auto f = std::make_unique<AppCUI::OS::File>();
            if (f->OpenRead(path) == false) {
                errList.AddError("Fail to open file: %s", path.u8string().c_str());
                RETURNERROR(false, "Fail to open file: %s", path.u8string().c_str());
            }
            return Add(Object::Type::File, std::move(f), path.filename().u16string(), path.u16string(), 0, method, typeName, parent, creationProcess);
        }
    } catch (const std::filesystem::filesystem_error& /* e */) {
        errList.AddError("Fail to open file: %s", path.u8string().c_str());
        RETURNERROR(false, "Fail to open file: %s", path.u8string().c_str());
    }
}
bool Instance::AddBufferWindow(
      BufferView buf,
      const ConstString& name,
      const ConstString& path,
      OpenMethod method,
      string_view typeName,
      Reference<Window> parent,
      const ConstString& creationProcess)
{
    auto f = std::make_unique<AppCUI::OS::MemoryFile>();
    if (f->Create(buf.GetData(), buf.GetLength()) == false) {
        errList.AddError("Fail to open memory buffer of size: %llu", buf.GetLength());
        RETURNERROR(false, "Fail to open memory buffer of size: %llu", buf.GetLength());
    }
    return Add(Object::Type::MemoryBuffer, std::move(f), name, path, 0, method, typeName, parent, creationProcess);
}
bool Instance::AddDataObjectWindow(
      std::unique_ptr<AppCUI::OS::DataObject> data,
      const ConstString& name,
      const ConstString& path,
      OpenMethod method,
      string_view typeName,
      Reference<Window> parent,
      const ConstString& creationProcess)
{
    CHECK(data, false, "Expecting a valid data object");
    return Add(Object::Type::MemoryBuffer, std::move(data), name, path, 0, method, typeName, parent, creationProcess);
}
void Instance::OpenFile()
{
    auto res = Dialogs::FileDialog::ShowOpenFileWindow("", "", this->lastOpenedFolderLocation);
    if (res.has_value()) {
        if (!AddFileWindow(res.value(), OpenMethod::BestMatch, "")) {
            ShowErrors();
        }else {
            this->lastOpenedFolderLocation = res.value().parent_path().u8string();
        }
    }
}
void Instance::OpenFolder()
{
    auto res = Dialogs::FileDialog::ShowOpenFileWindow("", "GVIEW:IGNORE-EVERYTHING", this->lastOpenedFolderLocation);
    if (res.has_value()) {
        {
            if (!AddFileWindow(res.value(), OpenMethod::BestMatch, ""))
                ShowErrors();
            else {
                this->lastOpenedFolderLocation = res.value().parent_path().u8string();
            }
        }
    }
}
void Instance::UpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    auto idx = GENERIC_PLUGINS_CMDID;
    for (auto& p : this->genericPlugins) {
        // plugins outside the course whitelist are not offered (the student sees the policy instead of fighting it)
        if (Security::RestrictedMode::Internal::IsPluginAllowed(p.GetName()))
            p.UpdateCommandBar(commandBar, idx);
        idx += GENERIC_PLUGINS_FRAME;
    }
}

// Objects are the file windows of the desktop; other windows (e.g. remote screens) are skipped.
uint32 Instance::GetObjectsCount()
{
    auto dsk = AppCUI::Application::GetDesktop();
    CHECK(dsk.IsValid(), 0, "Fail to get Desktop object from AppCUI !");
    uint32 count     = 0;
    const auto total = dsk->GetChildrenCount();
    for (uint32 i = 0; i < total; i++)
        if (dsk->GetChild(i).ToObjectRef<FileWindow>().IsValid())
            count++;
    return count;
}
Reference<GView::Object> Instance::GetObject(uint32 index)
{
    auto dsk = AppCUI::Application::GetDesktop();
    CHECK(dsk.IsValid(), nullptr, "Fail to get Desktop object from AppCUI !");
    const auto total = dsk->GetChildrenCount();
    for (uint32 i = 0; i < total; i++) {
        auto fw = dsk->GetChild(i).ToObjectRef<FileWindow>();
        if (!fw.IsValid())
            continue;
        if (index == 0)
            return fw->GetObject();
        index--;
    }
    return nullptr;
}
Reference<GView::Object> Instance::GetCurrentObject()
{
    auto dsk = AppCUI::Application::GetDesktop();
    CHECK(dsk.IsValid(), nullptr, "Fail to get Desktop object from AppCUI !");
    auto fw = dsk->GetFocusedChild().ToObjectRef<FileWindow>();
    return fw.IsValid() ? fw->GetObject() : nullptr;
}
uint32 Instance::GetTypePluginsCount()
{
    return static_cast<uint32>(this->typePlugins.size());
}
std::string_view Instance::GetTypePluginName(uint32 index)
{
    if (index >= this->typePlugins.size())
        return "";
    return this->typePlugins[index].GetName();
}
std::string_view Instance::GetTypePluginDescription(uint32 index)
{
    if (index >= this->typePlugins.size())
        return "";
    return this->typePlugins[index].GetDescription();
}

//===============================[APPCUI HANDLERS]==============================
bool Instance::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (eventType == Event::Command) {
        switch (ID) {
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
        case MenuCommands::OPEN_FOLDER:
            OpenFolder();
            return true;
        case MenuCommands::ABOUT:
            ShowAboutWindow();
            return true;
        case MenuCommands::CHECK_FOR_UPDATES:
            GView::Update::Service::CheckInteractive();
            return true;
        case MenuCommands::AVAILABLE_KEYS:
            ShowKeyboardShortcuts();
            return true;
        case MenuCommands::CHANGE_THEME:
            ShowChangeThemeWindow();
            return true;
        case MenuCommands::OPEN_THEME_EDITOR:
            AppCUI::Dialogs::ThemeEditor::Show();
            return true;
        case MenuCommands::OPEN_RESTRICTED_MODE:
            ShowRestrictedModeWindow();
            return true;
#ifdef GVIEW_ENABLE_REMOTE
        case MenuCommands::REMOTE_CONNECT:
            GView::Remote::ShowConnectDialog();
            return true;
        case MenuCommands::REMOTE_LISTEN:
            GView::Remote::ShowListenDialog();
            return true;
#endif
        }
        if ((ID >= GENERIC_PLUGINS_CMDID) && (ID < GENERIC_PLUGINS_CMDID + GENERIC_PLUGINS_FRAME * 1000)) {
            auto packedValue       = ((uint32) ID) - GENERIC_PLUGINS_CMDID;
            const auto pluginIndex = packedValue / GENERIC_PLUGINS_FRAME;
            if (pluginIndex >= this->genericPlugins.size())
                return true;
            auto& plugin = this->genericPlugins[pluginIndex];
            if (!Security::RestrictedMode::Internal::IsPluginAllowed(plugin.GetName())) {
                GView::App::IsBlockedByPolicy(Security::RestrictedMode::Feature::Plugins, "this generic plugin is not allowed by the course policy");
                return true;
            }
            // get current focused object
            auto object = this->GetCurrentObject();
            if (object.IsValid())
                plugin.Run(packedValue % GENERIC_PLUGINS_FRAME, object);
            return true;
        }
    }
    return true;
}
void Instance::OnStart(Reference<Control> control)
{
    ShowErrors();
    std::string connectionString;
    if (GView::App::TakeStartupLearningConnection(connectionString)) {
        GView::App::ShowLearningModeWindow(connectionString, true);
        GView::Security::Learning::WipeString(connectionString);
    }
}
//===============================[PROPERTIES]==================================
bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value)
{
    if (propertyID == CACHE_SIZE_PROPERTY_ID) 
    {
        value = this->defaultCacheSize;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error)
{
    if (propertyID == CACHE_SIZE_PROPERTY_ID) {
        const uint32 newCacheSize    = std::get<uint32>(value);
        if (newCacheSize < MIN_CACHE_SIZE) {
            error.SetFormat("Cache size must be at least %u bytes", MIN_CACHE_SIZE);
            return false;
        }
        this->defaultCacheSize = newCacheSize;
        return true;
    }
    return true;
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
    std::vector<Property> properties = {
        { CACHE_SIZE_PROPERTY_ID, "Config", "CacheSize", PropertyType::UInt32 },
    };

    // keys are configured from the "Keyboard shortcuts" window (Help menu / F1)
    return properties;
}
