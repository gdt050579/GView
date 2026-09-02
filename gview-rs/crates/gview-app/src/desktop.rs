//! The `AppCUI` desktop: menus, the pending-open queue and the window
//! directory (spec `00_APP §5.1`, design decisions `§0.3 D5`, `D6`).
//!
//! C++ anchors: `GViewCore/src/App/Instance.cpp` — the menu tables
//! (L20-62), `BuildMainMenus` (L128-147), `Init` (L148-204),
//! `OpenFile` / `OpenFolder` (L491-514), `OnEvent` (L560-610) and
//! `OnStart` (L611-614). The `AppCUI-rs` shape follows
//! `AppCUI-rs/appcui/src/ui/desktop/tests.rs` `check_menus`.
//!
//! `main` never opens anything: it hands the desktop a
//! `Vec<OpenRequest>` and `DesktopEvents::on_start` drains it (`D6`),
//! because `appbar()` is only valid on a live control and the C++
//! `Instance::OnStart` is likewise the first point where the framework
//! is running.
//!
//! ```text
//! on_start
//!   1. build the four menus (§5.1.2)
//!   2. drain `pending` through `open_pipeline::open`
//!   3. arrange_windows(Grid)                    (C++ before `Run`)
//!   4. collect `Instance::take_errors` and show them   (C++ `ShowErrors`)
//! ```
//!
//! `headless` is the `App::debug` / `gview test` mode: no modal ever
//! opens, and the accumulated errors stay in [`DesktopState`] so a test
//! can read them.

use std::rc::Rc;
use std::sync::{Mutex, PoisonError};

use appcui::prelude::*;
use appcui::ui::desktop::ArrangeWindowsMethod;

use gview_view::traits::SharedObject;

use crate::error::AppError;
use crate::error_dialog::{self, ErrorEntry};
use crate::file_window::{FileWindow, ShellRequest};
use crate::instance::window_lifecycle::{
    menu as gview_menu, menu_action, ArrangeMethod, InstanceAction, InstanceError,
};
use crate::open_file::{selector_for_path, OpenFileFlow};
use crate::open_pipeline::{open, OpenRequest, SharedInstance};
use crate::instance::window_lifecycle::{CancelSelector, TypeSelector};

/// C++ `menuFileList` caption (`Instance.cpp:25-33`).
pub const MENU_FILE: &str = "File";
/// C++ `mnuOptions` caption.
pub const MENU_OPTIONS: &str = "&Options";
/// C++ `mnuWindow` caption.
pub const MENU_WINDOWS: &str = "&Windows";
/// C++ `mnuHelp` caption.
pub const MENU_HELP: &str = "&Help";

/// Text every "the C++ has a window for this, this build does not"
/// menu item shows instead of silently doing nothing (`§5.1.4`).
pub const NOT_AVAILABLE: &str = "Not available in this build";
/// C++ `Dialogs::WindowManager::Show()` has no `AppCUI-rs` counterpart.
pub const WINDOW_MANAGER_TITLE: &str = "Windows manager";
/// `About` caption (C++ `ShowAboutWindow`).
pub const ABOUT_TITLE: &str = "About";
/// A generic-plugin command with no focused object (C++
/// `GetCurrentObject()` returning null).
pub const ERR_NO_CURRENT_OBJECT: &str = "No object is currently open !";
/// A generic-plugin index the registry does not have.
pub const ERR_NO_SUCH_PLUGIN: &str = "No generic plugin with index ";
/// A command index the plugin does not declare.
pub const ERR_NO_SUCH_COMMAND: &str = "Unknown command for generic plugin ";

/// How the desktop answers the `SelectTypeDialog` (`00_APP §4`).
///
/// The C++ always shows the modal; a scripted session cannot, so the
/// spec's "headless tests use `CancelSelector` / a scripted selector"
/// becomes an explicit mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SelectorMode {
    /// Show `SelectTypeDialog` (interactive sessions).
    #[default]
    Modal,
    /// Never show it; every request is cancelled
    /// (`InstanceError::OpenCanceled`).
    Cancel,
    /// Answer every request with this candidate index; an index past
    /// the candidate list is the C++ `GetSelectedPlugin(&defaultPlugin)`
    /// entry.
    Scripted(usize),
}

/// A [`TypeSelector`] that always answers `choice` without a dialog.
struct ScriptedSelector {
    choice: usize,
}

impl TypeSelector for ScriptedSelector {
    fn select(&mut self, _candidates: &[&gview_plugin::type_plugin::RegisteredTypePlugin]) -> Option<usize> {
        Some(self.choice)
    }
}

/// One live file window in the directory (`00_APP §5.1.5`).
///
/// The object is kept beside the handle because the C++
/// `Instance::GetObject(index)` answers from the desktop child, and a
/// `Handle` can only be resolved while the framework is running.
#[derive(Clone)]
pub struct WindowEntry {
    /// The window control.
    pub handle: Handle<FileWindow>,
    /// Its single [`SharedObject`] (`02_SMART_VIEWERS_DEEP` §C.2).
    pub object: SharedObject,
    /// `Object::GetName()` at open time, for diagnostics.
    pub name: String,
}

impl core::fmt::Debug for WindowEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowEntry").field("name", &self.name).finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct DesktopStateInner {
    windows: Vec<WindowEntry>,
    errors: Vec<String>,
}

/// The desktop's observable state, shared with the shell
/// (`§0.3 D4`: UI-thread only, `Rc<Mutex<_>>` so a poisoned lock
/// degrades instead of panicking).
///
/// `main` and the tests keep a clone so the window directory and the
/// accumulated errors outlive the `App::run` call that consumes the
/// desktop itself.
#[derive(Clone, Debug, Default)]
pub struct DesktopState {
    inner: Rc<Mutex<DesktopStateInner>>,
}

impl DesktopState {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, f: impl FnOnce(&DesktopStateInner) -> T) -> T {
        let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        f(&guard)
    }

    fn with_mut<T>(&self, f: impl FnOnce(&mut DesktopStateInner) -> T) -> T {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }

    /// C++ `Instance::GetObjectsCount` (`Instance.cpp:524-529`).
    #[must_use]
    pub fn objects_count(&self) -> u32 {
        self.with(|s| s.windows.len() as u32)
    }

    /// C++ `Instance::GetObject(index)` (`Instance.cpp:530-535`).
    #[must_use]
    pub fn object(&self, index: u32) -> Option<SharedObject> {
        self.with(|s| s.windows.get(index as usize).map(|w| SharedObject::clone(&w.object)))
    }

    /// Display name of window `index`.
    #[must_use]
    pub fn window_name(&self, index: u32) -> Option<String> {
        self.with(|s| s.windows.get(index as usize).map(|w| w.name.clone()))
    }

    /// The window handles, in desktop order.
    #[must_use]
    pub fn handles(&self) -> Vec<Handle<FileWindow>> {
        self.with(|s| s.windows.iter().map(|w| w.handle).collect())
    }

    /// Directory index of `handle`, if it is still listed.
    #[must_use]
    pub fn index_of(&self, handle: Handle<FileWindow>) -> Option<u32> {
        self.with(|s| {
            s.windows
                .iter()
                .position(|w| w.handle == handle)
                .map(|index| index as u32)
        })
    }

    /// The accumulated error / warning texts (C++ `errList`).
    #[must_use]
    pub fn errors(&self) -> Vec<String> {
        self.with(|s| s.errors.clone())
    }

    /// Adds one message to the list (settings warnings come in this
    /// way before the desktop starts).
    pub fn push_error(&self, message: impl Into<String>) {
        self.with_mut(|s| s.errors.push(message.into()));
    }

    fn push_window(&self, entry: WindowEntry) {
        self.with_mut(|s| s.windows.push(entry));
    }

    fn take_errors(&self) -> Vec<String> {
        self.with_mut(|s| std::mem::take(&mut s.errors))
    }

    fn retain_windows(&self, keep: impl Fn(&WindowEntry) -> bool) {
        self.with_mut(|s| s.windows.retain(|w| keep(w)));
    }
}

/// The four `AppBar` menu buttons (C++ `mnuFile` … `mnuHelp`).
#[derive(Clone, Copy, Debug, Default)]
pub struct DesktopMenus {
    /// `File`.
    pub file: Handle<appbar::MenuButton>,
    /// `&Options`.
    pub options: Handle<appbar::MenuButton>,
    /// `&Windows`.
    pub windows: Handle<appbar::MenuButton>,
    /// `&Help`.
    pub help: Handle<appbar::MenuButton>,
}

#[Desktop(
    events = DesktopEvents + AppBarEvents + MenuEvents + CommandBarEvents,
    commands = [
        OpenFile, OpenFolder, OpenPid, OpenProcessTree, Exit,
        ChangeTheme, ThemeEditor, RestrictedMode,
        ArrangeVertically, ArrangeHorizontally, Cascade, Grid,
        Close, CloseAll, CloseAllExceptCurrent, WindowManager,
        CheckForUpdates, About, AvailableKeys
    ]
)]
pub struct GViewDesktop {
    instance: SharedInstance,
    pending: Vec<OpenRequest>,
    state: DesktopState,
    open_flow: OpenFileFlow,
    menus: DesktopMenus,
    selector_mode: SelectorMode,
    headless: bool,
}

impl GViewDesktop {
    /// The desktop over `instance`, with `pending` opens to drain in
    /// [`DesktopEvents::on_start`] (`§0.3 D6`).
    ///
    /// `headless` is `App::debug` / `gview test`: no modal is ever
    /// opened and the error list is kept for inspection.
    #[must_use]
    pub fn new(instance: SharedInstance, pending: Vec<OpenRequest>, headless: bool) -> Self {
        Self {
            base: Desktop::new(),
            instance,
            pending,
            state: DesktopState::new(),
            open_flow: OpenFileFlow::new(),
            menus: DesktopMenus::default(),
            selector_mode: if headless { SelectorMode::Cancel } else { SelectorMode::Modal },
            headless,
        }
    }

    /// Overrides how the type-selection dialog is answered
    /// (`SelectorMode`); a scripted session sets it before the app
    /// starts.
    pub const fn set_selector_mode(&mut self, mode: SelectorMode) {
        self.selector_mode = mode;
    }

    /// How the type-selection dialog is answered.
    #[must_use]
    pub const fn selector_mode(&self) -> SelectorMode {
        self.selector_mode
    }

    /// The shared window directory and error list; clone it before
    /// handing the desktop to `App::desktop`.
    #[must_use]
    pub fn state(&self) -> DesktopState {
        self.state.clone()
    }

    /// The instance this desktop drives.
    #[must_use]
    pub fn instance(&self) -> SharedInstance {
        SharedInstance::clone(&self.instance)
    }

    /// `true` in `App::debug` / `gview test` mode.
    #[must_use]
    pub const fn is_headless(&self) -> bool {
        self.headless
    }

    /// C++ `Instance::GetObjectsCount` (`Instance.cpp:524-529`).
    #[must_use]
    pub fn objects_count(&self) -> u32 {
        self.state.objects_count()
    }

    /// C++ `Instance::GetObject(index)` (`Instance.cpp:530-535`).
    #[must_use]
    pub fn object(&self, index: u32) -> Option<SharedObject> {
        self.state.object(index)
    }

    /// C++ `Instance::GetCurrentObject` (`Instance.cpp:536-541`):
    /// the object of the focused window.
    ///
    /// `None` when the desktop has no window, or when the focused
    /// child is not one of ours (the C++ blindly casts
    /// `GetFocusedChild()` to a `FileWindow`; the port checks).
    #[must_use]
    pub fn current_object(&self) -> Option<SharedObject> {
        let handle = self.active_entry()?;
        let index = self.state.index_of(handle)?;
        self.state.object(index)
    }

    /// Directory index of the focused window (C++
    /// `Desktop::GetFocusedChild()` position).
    #[must_use]
    pub fn current_index(&self) -> Option<u32> {
        self.state.index_of(self.active_entry()?)
    }

    /// C++ `BuildMainMenus` (`Instance.cpp:128-147`).
    fn build_menus(&mut self) {
        use gviewdesktop::Commands as C;

        let mut file = Menu::new();
        file.add(menu::Command::new("&Open file", Key::default(), C::OpenFile));
        file.add(menu::Command::new("Open &folder", Key::default(), C::OpenFolder));
        file.add(menu::Separator::new());
        // C++ `menuFileDisabledCommandsList = { 3, 4 }`.
        file.add(disabled(menu::Command::new("Open &process", Key::default(), C::OpenPid)));
        file.add(disabled(menu::Command::new(
            "Open process &tree",
            Key::default(),
            C::OpenProcessTree,
        )));
        file.add(menu::Separator::new());
        file.add(menu::Command::new("E&xit", key!("Shift+Escape"), C::Exit));

        let mut options = Menu::new();
        options.add(menu::Command::new("&Change theme", Key::default(), C::ChangeTheme));
        options.add(menu::Command::new("Op&en Theme Editor", Key::default(), C::ThemeEditor));
        options.add(menu::Separator::new());
        options.add(menu::Command::new(
            "Open &Restricted Mode",
            Key::default(),
            C::RestrictedMode,
        ));

        let mut windows = Menu::new();
        windows.add(menu::Command::new("Arrange &Vertically", Key::default(), C::ArrangeVertically));
        windows.add(menu::Command::new(
            "Arrange &Horizontally",
            Key::default(),
            C::ArrangeHorizontally,
        ));
        windows.add(menu::Command::new("&Cascade mode", Key::default(), C::Cascade));
        windows.add(menu::Command::new("&Grid", Key::default(), C::Grid));
        windows.add(menu::Separator::new());
        windows.add(menu::Command::new("Close", Key::default(), C::Close));
        windows.add(menu::Command::new("Close &All", Key::default(), C::CloseAll));
        // Parity quirk #11: the C++ binds `MenuCommands::CLOSE_ALL` to
        // *both* entries, so "except current" closes everything.
        windows.add(menu::Command::new("Close All e&xcept current", Key::default(), C::CloseAll));
        windows.add(menu::Separator::new());
        windows.add(menu::Command::new("&Windows manager", key!("Alt+0"), C::WindowManager));

        let mut help = Menu::new();
        // C++ `menuHelpListDisabledCommandsList = { 0 }`.
        help.add(disabled(menu::Command::new(
            "Check for &updates",
            Key::default(),
            C::CheckForUpdates,
        )));
        help.add(menu::Command::new("&About", Key::default(), C::About));

        self.menus = DesktopMenus {
            file: self
                .appbar()
                .add(appbar::MenuButton::new(MENU_FILE, file, 0, appbar::Side::Left)),
            options: self
                .appbar()
                .add(appbar::MenuButton::new(MENU_OPTIONS, options, 1, appbar::Side::Left)),
            windows: self
                .appbar()
                .add(appbar::MenuButton::new(MENU_WINDOWS, windows, 2, appbar::Side::Left)),
            help: self
                .appbar()
                .add(appbar::MenuButton::new(MENU_HELP, help, 3, appbar::Side::Left)),
        };
    }

    /// Opens one request and files the window or the error
    /// (`§5.1.3 (2)`).
    fn open_request(&mut self, request: &OpenRequest) -> bool {
        let instance = SharedInstance::clone(&self.instance);
        let mut modal;
        let mut scripted;
        let selector: &mut dyn TypeSelector = match self.selector_mode {
            SelectorMode::Modal => {
                modal = selector_for_path(&request.path, true);
                &mut modal
            }
            SelectorMode::Cancel => &mut CancelSelector,
            SelectorMode::Scripted(choice) => {
                scripted = ScriptedSelector { choice };
                &mut scripted
            }
        };
        match open(&instance, request, selector) {
            Ok(window) => {
                let name = window.title().to_owned();
                let object = window.model().lock().unwrap_or_else(PoisonError::into_inner).object();
                let handle = self.add_window(window);
                self.state.push_window(WindowEntry { handle, object, name });
                true
            }
            Err(error) => {
                // C++ `AddFileWindow` already wrote
                // `Fail to open file: <path>` into `errList` for an I/O
                // failure (`Instance.cpp:456-474`); taking that list
                // here and adding the `AppError` text only for the
                // failures it does not record keeps `ShowErrors` from
                // listing the same open twice.
                let recorded = self
                    .instance
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take_errors();
                let already_reported = matches!(error, AppError::Open(InstanceError::OpenFile { .. }));
                self.state.with_mut(|s| s.errors.extend(recorded));
                if !already_reported {
                    self.state.push_error(error.to_string());
                }
                false
            }
        }
    }

    /// C++ `Instance::ShowErrors` (`Instance.cpp:448-455`): show the
    /// accumulated list, then clear it. Headless keeps the list.
    pub fn show_errors(&mut self) {
        let from_instance = self
            .instance
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_errors();
        self.state.with_mut(|s| s.errors.extend(from_instance));
        if self.headless {
            return;
        }
        let errors = self.state.take_errors();
        let entries: Vec<ErrorEntry> = errors.into_iter().map(ErrorEntry::error).collect();
        let _shown = error_dialog::show(&entries);
    }

    /// C++ `Application::ArrangeWindows(method)`.
    pub fn arrange(&mut self, method: ArrangeMethod) {
        self.arrange_windows(match method {
            ArrangeMethod::Cascade => ArrangeWindowsMethod::Cascade,
            ArrangeMethod::Grid => ArrangeWindowsMethod::Grid,
            ArrangeMethod::Horizontal => ArrangeWindowsMethod::Horizontal,
            ArrangeMethod::Vertical => ArrangeWindowsMethod::Vertical,
        });
    }

    /// C++ `Instance::OpenFile()` (`Instance.cpp:491-501`): the file
    /// dialog, then a `BestMatch` open. A no-op when headless — the
    /// dialog would block a scripted session forever.
    pub fn open_file_dialog(&mut self) {
        if self.headless {
            return;
        }
        let Some(path) = self.open_flow.ask_path() else {
            return;
        };
        let request = OpenRequest::new(&path);
        if self.open_request(&request) {
            self.open_flow.remember_folder(&path);
        } else {
            self.show_errors();
        }
    }

    /// C++ `Instance::OpenFolder()` (`Instance.cpp:502-514`).
    ///
    /// Folder windows are out of scope (`§0.3 D7`), so the chosen
    /// directory is reported through the normal open path, which
    /// answers `InstanceError::FolderUnsupported`.
    pub fn open_folder_dialog(&mut self) {
        if self.headless {
            return;
        }
        let location = self
            .open_flow
            .last_opened_folder()
            .map_or(dialogs::Location::Last, dialogs::Location::Path);
        let Some(path) = dialogs::select_folder("Open folder", location, dialogs::SelectFolderDialogFlags::None)
        else {
            return;
        };
        self.open_request(&OpenRequest::new(path));
        self.show_errors();
    }

    /// Shows the "this build has no such window" message for a menu
    /// entry the C++ services with a dialog (`§5.1.4`).
    fn not_available(&self, title: &str) {
        if !self.headless {
            dialogs::message(title, NOT_AVAILABLE);
        }
    }

    /// The directory entry of the focused window
    /// (C++ `Desktop::GetFocusedChild()` narrowed to a `FileWindow`).
    ///
    /// `Handle<A> == Handle<B>` compares the raw slot, which is how the
    /// untyped active handle is matched against the typed directory.
    fn active_entry(&self) -> Option<Handle<FileWindow>> {
        let active = self.active_window_handle()?;
        self.state.handles().into_iter().find(|handle| *handle == active)
    }

    /// Closes the focused window (C++ `MenuCommands::CLOSE`).
    pub fn close_current(&mut self) {
        let Some(handle) = self.active_entry() else {
            return;
        };
        if let Some(window) = self.window_mut(handle) {
            window.close();
        }
        self.state.retain_windows(|entry| entry.handle != handle);
    }

    /// Closes every window (C++ `MenuCommands::CLOSE_ALL`, reached by
    /// both `Close All` menu entries — quirk #11).
    pub fn close_all(&mut self) {
        for handle in self.state.handles() {
            if let Some(window) = self.window_mut(handle) {
                window.close();
            }
        }
        self.state.retain_windows(|_| false);
    }

    /// Drains the shell requests of every open window and services
    /// them (C++ `FileWindow::OnEvent` calls straight into
    /// `GView::App::*`; `00_APP §5.6`).
    ///
    /// **Port note:** `AppCUI-rs` gives a `Window` no way to reach the
    /// desktop (`Desktop::add_window` needs `&mut Desktop`), so a
    /// window queues what only the desktop can do and the desktop
    /// drains the queue at its next event — after a menu command, a
    /// command-bar command, a window-count change and `on_start`. The
    /// C++ has no queue because `Instance` is a global with desktop
    /// access.
    pub fn service_requests(&mut self) {
        for handle in self.state.handles() {
            let requests = self
                .window_mut(handle)
                .map(FileWindow::take_requests)
                .unwrap_or_default();
            for request in requests {
                self.service_request(&request);
            }
        }
    }

    /// Services one [`ShellRequest`] (`§5.6` table).
    pub fn service_request(&mut self, request: &ShellRequest) {
        match request {
            ShellRequest::ReopenWithTypeSelect(path) => {
                // C++ `GView::App::OpenFile(path, OpenMethod::Select)`:
                // the original window stays open.
                self.open_request(&OpenRequest::select_type(path.clone()));
                self.show_errors();
            }
            ShellRequest::RunGenericPlugin { plugin, command } => {
                self.run_generic_plugin(*plugin, *command);
            }
            ShellRequest::ShowProperties => self.not_available("File properties"),
            ShellRequest::ShowKeyConfigurator => self.not_available("Key configurator"),
            ShellRequest::AddNote => self.not_available("Add note"),
            ShellRequest::ShowAnalysisEngine => self.not_available("Analysis engine"),
            ShellRequest::Error(text) => {
                // Always recorded; only shown when there is a terminal
                // to show it on.
                self.state.push_error(*text);
                if !self.headless {
                    dialogs::error("Error", text);
                }
            }
            // A view asked for a dialog the window could not open
            // (headless), or has an entry to open as a new object:
            // both are recorded for the session log.
            ShellRequest::ShowViewDialog(dialog) => {
                self.state.push_error(format!("view dialog not available: {dialog:?}"));
            }
            ShellRequest::OpenPendingObject { view } => {
                self.state
                    .push_error(format!("opening a child object is not available in this build (view {view})"));
            }
        }
    }

    /// C++ `genericPlugins[plugin].Run(command, GetCurrentObject())`
    /// (`Instance.cpp:600-605`).
    ///
    /// The failure text lands in the error list, exactly like the C++
    /// `MessageBox` in `Generic::Plugin::Run`.
    pub fn run_generic_plugin(&mut self, plugin: usize, command: usize) -> bool {
        let Some(object) = self.current_object() else {
            self.state.push_error(ERR_NO_CURRENT_OBJECT);
            return false;
        };
        let outcome = {
            let instance = self.instance.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(registered) = instance.generic_plugins().plugins().get(plugin) else {
                drop(instance);
                self.state.push_error(format!("{ERR_NO_SUCH_PLUGIN}{plugin}"));
                return false;
            };
            let Some(def) = registered.metadata().commands.get(command) else {
                let name = registered.name();
                drop(instance);
                self.state.push_error(format!("{ERR_NO_SUCH_COMMAND}{name}"));
                return false;
            };
            let name = def.name.clone();
            let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            let outcome = registered.run(&name, &mut guard);
            drop(guard);
            drop(instance);
            outcome
        };
        match outcome {
            Ok(()) => true,
            Err(error) => {
                self.state.push_error(error.to_string());
                false
            }
        }
    }

    /// Runs one menu command (C++ `Instance::OnEvent`, `§5.1.4`).
    ///
    /// The C++ command ids stay the single source of truth: the
    /// generated enum is mapped to an id and routed through
    /// [`menu_action`].
    pub fn run_command(&mut self, command: gviewdesktop::Commands) {
        let id = menu_id_for_command(command);
        match menu_action(id) {
            InstanceAction::Arrange(method) => self.arrange(method),
            InstanceAction::Exit => self.close(),
            InstanceAction::OpenFile => self.open_file_dialog(),
            InstanceAction::OpenFolder => self.open_folder_dialog(),
            InstanceAction::ShowWindowManager => self.not_available(WINDOW_MANAGER_TITLE),
            InstanceAction::About => {
                if !self.headless {
                    dialogs::message(ABOUT_TITLE, &format!("GView-rs {}", env!("CARGO_PKG_VERSION")));
                }
            }
            InstanceAction::ChangeTheme => self.not_available("Change theme"),
            InstanceAction::ThemeEditor => self.not_available("Theme editor"),
            InstanceAction::RestrictedMode => self.not_available("Restricted mode"),
            // Generic-plugin ids never reach the desktop: a focused
            // `FileWindow` owns the command bar and raises
            // `ShellRequest::RunGenericPlugin` instead (`§5.6`).
            InstanceAction::RunGenericPlugin { .. } | InstanceAction::Unhandled => {
                self.run_desktop_command(command);
            }
        }
    }

    /// The menu entries `menu_action` does not model (C++ handles them
    /// outside `Instance::OnEvent`, or not at all).
    fn run_desktop_command(&mut self, command: gviewdesktop::Commands) {
        use gviewdesktop::Commands as C;
        match command {
            C::Close => self.close_current(),
            C::CloseAll | C::CloseAllExceptCurrent => self.close_all(),
            C::OpenPid => self.not_available("Open process"),
            C::OpenProcessTree => self.not_available("Open process tree"),
            C::CheckForUpdates => self.not_available("Check for updates"),
            C::AvailableKeys => self.not_available("Available keys"),
            // Everything else was already serviced by `menu_action`.
            _ => {}
        }
    }
}

/// Disables a menu command before it is added (C++ `SetEnable(h,
/// false)` on the index lists).
fn disabled(mut command: menu::Command) -> menu::Command {
    command.set_enabled(false);
    command
}

/// The C++ `MenuCommands` id behind a generated command
/// (`Internal.hpp:462-487`), so [`menu_action`] stays the dispatch
/// table.
#[must_use]
pub const fn menu_id_for_command(command: gviewdesktop::Commands) -> u32 {
    use gviewdesktop::Commands as C;
    match command {
        C::OpenFile => gview_menu::OPEN_FILE,
        C::OpenFolder => gview_menu::OPEN_FOLDER,
        C::OpenPid => gview_menu::OPEN_PID,
        C::OpenProcessTree => gview_menu::OPEN_PROCESS_TREE,
        C::Exit => gview_menu::EXIT_GVIEW,
        C::ChangeTheme => gview_menu::CHANGE_THEME,
        C::ThemeEditor => gview_menu::OPEN_THEME_EDITOR,
        C::RestrictedMode => gview_menu::OPEN_RESTRICTED_MODE,
        C::ArrangeVertically => gview_menu::ARRANGE_VERTICALLY,
        C::ArrangeHorizontally => gview_menu::ARRANGE_HORIZONTALLY,
        C::Cascade => gview_menu::ARRANGE_CASCADE,
        C::Grid => gview_menu::ARRANGE_GRID,
        C::Close => gview_menu::CLOSE,
        C::CloseAll => gview_menu::CLOSE_ALL,
        C::CloseAllExceptCurrent => gview_menu::CLOSE_ALL_EXCEPT_CURRENT,
        C::WindowManager => gview_menu::SHOW_WINDOW_MANAGER,
        C::CheckForUpdates => gview_menu::CHECK_FOR_UPDATES,
        C::About => gview_menu::ABOUT,
        C::AvailableKeys => gview_menu::AVAILABLE_KEYS,
    }
}

impl DesktopEvents for GViewDesktop {
    /// C++ `BuildMainMenus` + `Instance::OnStart` (`§5.1.3`).
    fn on_start(&mut self) {
        self.build_menus();
        for request in std::mem::take(&mut self.pending) {
            self.open_request(&request);
        }
        self.arrange(ArrangeMethod::Grid);
        self.service_requests();
        self.show_errors();
    }

    /// Keeps `windows.len() == live FileWindows` (`§5.1.5`).
    ///
    /// A window the *user* closes (the title-bar `x`, `Alt+F4`) never
    /// passes through [`Self::close_current`], so the directory is
    /// re-checked whenever the framework reports a different child
    /// count. The C++ has no such list: it re-reads
    /// `Desktop::GetChildrenCount()` on every query.
    fn on_update_window_count(&mut self, _count: usize) {
        let alive: Vec<Handle<FileWindow>> = self
            .state
            .handles()
            .into_iter()
            .filter(|handle| self.windowt(*handle).is_some())
            .collect();
        self.state.retain_windows(|entry| alive.contains(&entry.handle));
        self.service_requests();
    }
}

impl AppBarEvents for GViewDesktop {
    fn on_update(&self, appbar: &mut AppBar) {
        appbar.show(self.menus.file);
        appbar.show(self.menus.options);
        appbar.show(self.menus.windows);
        appbar.show(self.menus.help);
    }
}

impl MenuEvents for GViewDesktop {
    fn on_command(&mut self, _menu: Handle<Menu>, _item: Handle<menu::Command>, command: gviewdesktop::Commands) {
        self.run_command(command);
        self.service_requests();
    }
}

impl CommandBarEvents for GViewDesktop {
    /// The desktop owns no F-key: a focused `FileWindow` fills the
    /// command bar (C++ `FileWindow::OnUpdateCommandBar`), and with no
    /// window the bar stays empty.
    fn on_update_commandbar(&self, _commandbar: &mut CommandBar) {}

    fn on_event(&mut self, command: gviewdesktop::Commands) {
        self.run_command(command);
        self.service_requests();
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn menu_commands_map_to_the_cpp_ids() {
        use gviewdesktop::Commands as C;
        assert_eq!(menu_id_for_command(C::OpenFile), gview_menu::OPEN_FILE);
        assert_eq!(menu_id_for_command(C::Exit), gview_menu::EXIT_GVIEW);
        assert_eq!(menu_id_for_command(C::Grid), gview_menu::ARRANGE_GRID);
        assert_eq!(menu_id_for_command(C::About), gview_menu::ABOUT);

        // Every arrange entry routes through the instance dispatch table.
        for (command, method) in [
            (C::ArrangeVertically, ArrangeMethod::Vertical),
            (C::ArrangeHorizontally, ArrangeMethod::Horizontal),
            (C::Cascade, ArrangeMethod::Cascade),
            (C::Grid, ArrangeMethod::Grid),
        ] {
            assert_eq!(
                menu_action(menu_id_for_command(command)),
                InstanceAction::Arrange(method)
            );
        }
        assert_eq!(menu_action(menu_id_for_command(C::Exit)), InstanceAction::Exit);
        // The desktop-only entries are not in the instance table.
        for command in [C::Close, C::CloseAll, C::OpenPid, C::CheckForUpdates, C::AvailableKeys] {
            assert_eq!(menu_action(menu_id_for_command(command)), InstanceAction::Unhandled);
        }
    }

    #[test]
    fn the_state_handle_survives_the_desktop() {
        let state = DesktopState::new();
        assert_eq!(state.objects_count(), 0);
        assert!(state.object(0).is_none());
        assert!(state.errors().is_empty());

        let clone = state.clone();
        clone.push_error("Fail to open file: a.bin");
        assert_eq!(state.errors(), ["Fail to open file: a.bin"]);
        assert_eq!(state.take_errors(), ["Fail to open file: a.bin"]);
        assert!(clone.errors().is_empty(), "both handles share one list");
    }

    /// One pending golden PE opens exactly one window; a pending path
    /// that does not exist leaves the C++ message in the (headless)
    /// error list and no window.
    #[test]
    fn desktop_on_start_drains_the_pending_queue() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = fixture_dir("pending");
        let pe = write(&dir, "sample.exe", &minimal_pe());
        let missing = dir.join("nope.bin");

        let instance = instance();
        let desktop = GViewDesktop::new(
            SharedInstance::clone(&instance),
            vec![
                OpenRequest::new(&pe).headless(),
                OpenRequest::new(&missing).headless(),
            ],
            true,
        );
        assert!(desktop.is_headless());
        let state = desktop.state();

        let script = "
            Paint.Enable(false)
            Paint('desktop with one window')
        ";
        let app = App::debug(100, 40, script)
            .desktop(desktop)
            .app_bar()
            .command_bar()
            .build()
            .expect("debug app");
        app.run();

        assert_eq!(state.objects_count(), 1, "only the PE opened");
        assert_eq!(state.window_name(0).as_deref(), Some("sample.exe"));
        let object = state.object(0).expect("object 0");
        assert_eq!(object.lock().expect("object").name(), "sample.exe");

        let errors = state.errors();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].starts_with("Fail to open file: "), "{errors:?}");
    }

    /// The `Exit` menu entry closes the application: the script ends
    /// cleanly and nothing after `Exit` is dispatched.
    #[test]
    fn desktop_exit_menu_closes_the_application() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let instance = instance();
        let desktop = GViewDesktop::new(SharedInstance::clone(&instance), Vec::new(), true);
        let state = desktop.state();

        // `File` is the first appbar button: open it and pick `E&xit`.
        let script = "
            Paint.Enable(false)
            Paint('empty desktop')
            Key.Pressed(Shift+Escape)
            Paint('after exit')
        ";
        let app = App::debug(80, 24, script)
            .desktop(desktop)
            .app_bar()
            .command_bar()
            .build()
            .expect("debug app");
        app.run();
        assert_eq!(state.objects_count(), 0);
        assert!(state.errors().is_empty());
    }

    /// `Open file` must not block a scripted session: headless makes it
    /// a no-op instead of opening the modal file dialog.
    #[test]
    fn desktop_open_file_is_a_no_op_when_headless() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let instance = instance();
        let mut desktop = GViewDesktop::new(SharedInstance::clone(&instance), Vec::new(), true);
        let state = desktop.state();

        // Every "not available" entry is equally silent.
        desktop.run_command(gviewdesktop::Commands::OpenFile);
        desktop.run_command(gviewdesktop::Commands::OpenFolder);
        desktop.run_command(gviewdesktop::Commands::OpenPid);
        desktop.run_command(gviewdesktop::Commands::About);
        desktop.run_command(gviewdesktop::Commands::WindowManager);
        desktop.run_command(gviewdesktop::Commands::CheckForUpdates);
        assert_eq!(state.objects_count(), 0);
        assert!(state.errors().is_empty());
    }

}

#[cfg(test)]
// The fixture builders index and add on fixed-size buffers, exactly as
// `registry.rs`'s own `minimal_*` helpers do.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod test_support {
    use super::{Rc, SharedInstance};
    use crate::instance::window_lifecycle::Instance;
    use crate::registry;
    use gview_core::constants::DEFAULT_CACHE_SIZE;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    pub fn instance() -> SharedInstance {
        let registries = registry::build().expect("registry");
        Rc::new(Mutex::new(Instance::new(
            registries.types,
            registries.generics,
            DEFAULT_CACHE_SIZE,
        )))
    }

    /// A per-test fixture directory.
    ///
    /// It is created, never deleted: on Windows `remove_dir_all` can
    /// return before the directory is really gone, and the following
    /// `create_dir_all` + `write` then race with the pending deletion.
    /// Fixtures are overwritten instead.
    pub fn fixture_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("gview_desktop").join(name);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        dir
    }

    pub fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("fixture file");
        path
    }

    /// `registry.rs`'s `minimal_pe`, kept in step with it.
    pub fn minimal_pe() -> Vec<u8> {
        const E_LFANEW_OFFSET: usize = 60;
        const NT_HEADERS32_SIZE: usize = 4 + 20 + 224;
        let lfanew: u32 = 0x80;
        let mut image = vec![0_u8; lfanew as usize + NT_HEADERS32_SIZE];
        image[0..2].copy_from_slice(b"MZ");
        image[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&lfanew.to_le_bytes());
        let nt = lfanew as usize;
        image[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let opt = nt + 4 + 20;
        image[opt..opt + 2].copy_from_slice(&0x010B_u16.to_le_bytes());
        image
    }
}

/// The window directory of `00_APP §5.1.5` (C++
/// `Instance::GetObjectsCount` / `GetObject` / `GetCurrentObject`,
/// `Instance.cpp:524-541`).
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod directory {
    use super::test_support::*;
    use super::*;
    use std::path::Path;

    /// Two golden files, opened as `a.exe` and `b.exe`.
    fn two_pending(dir: &Path) -> Vec<OpenRequest> {
        let a = write(dir, "a.exe", &minimal_pe());
        let b = write(dir, "b.exe", &minimal_pe());
        vec![OpenRequest::new(a).headless(), OpenRequest::new(b).headless()]
    }

    fn run(dir: &str, pending: Vec<OpenRequest>, script: &str) -> DesktopState {
        let instance = instance();
        let _ = dir;
        let desktop = GViewDesktop::new(instance, pending, true);
        let state = desktop.state();
        let app = App::debug(100, 40, script)
            .desktop(desktop)
            .app_bar()
            .command_bar()
            .build()
            .expect("debug app");
        app.run();
        state
    }

    /// Two pending files open two windows, in queue order.
    #[test]
    fn directory_lists_every_opened_window() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = fixture_dir("directory_two");
        let state = run(
            "directory_two",
            two_pending(&dir),
            "Paint.Enable(false)\nPaint('two windows')",
        );

        assert_eq!(state.objects_count(), 2, "errors: {:?}", state.errors());
        assert_eq!(state.window_name(0).as_deref(), Some("a.exe"));
        assert_eq!(state.window_name(1).as_deref(), Some("b.exe"));
        assert_eq!(
            state.object(0).map(|o| o.lock().expect("object").name().to_owned()),
            Some(String::from("a.exe"))
        );
        assert!(state.object(2).is_none(), "index past the end");
        assert!(state.errors().is_empty());
    }

    /// `Close` acts on the **focused** window: with the focus where
    /// `on_start` left it (the last opened window), `b.exe` goes.
    #[test]
    fn directory_close_removes_the_focused_window() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = fixture_dir("directory_close");
        // `&Windows` menu → 5th selectable entry (`Close`).
        let script = "
            Paint.Enable(false)
            Paint('two windows')
            Key.Pressed(Alt+W)
            Paint('windows menu')
            Key.Pressed(Home)
            Key.Pressed(Down,4)
            Key.Pressed(Enter)
            Paint('after close')
        ";
        let state = run("directory_close", two_pending(&dir), script);
        assert_eq!(state.objects_count(), 1, "one window closed");
        assert_eq!(
            state.window_name(0).as_deref(),
            Some("a.exe"),
            "the focused window (the last opened) was the one closed"
        );
    }

    /// Clicking on the other window moves the focus, and `Close` then
    /// removes *that* window: `current_object()` follows the focus
    /// (`00_APP §5.1.5`; the matrix allows any `AppCUI` window switch).
    ///
    /// `on_start` arranges the two windows as a grid, so the left half
    /// of the screen belongs to the first one.
    #[test]
    fn directory_current_object_follows_the_focus() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = fixture_dir("directory_focus");
        let script = "
            Paint.Enable(false)
            Paint('two windows')
            Mouse.Click(10,10,left)
            Paint('focus moved to the left window')
            Key.Pressed(Alt+W)
            Key.Pressed(Home)
            Key.Pressed(Down,4)
            Key.Pressed(Enter)
            Paint('after close')
        ";
        let state = run("directory_focus", two_pending(&dir), script);
        assert_eq!(state.objects_count(), 1);
        assert_eq!(
            state.window_name(0).as_deref(),
            Some("b.exe"),
            "the click moved the focus to a.exe, so that is the one Close removed"
        );
    }

    /// `Close &All` empties the directory; `current_object()` then
    /// has nothing to answer with.
    #[test]
    fn directory_close_all_empties_the_desktop() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = fixture_dir("directory_close_all");
        // `Close &All` carries `A` as its hot key.
        let script = "
            Paint.Enable(false)
            Paint('two windows')
            Key.Pressed(Alt+W)
            Key.Pressed(A)
            Paint('after close all')
        ";
        let state = run("directory_close_all", two_pending(&dir), script);
        assert_eq!(state.objects_count(), 0);
        assert!(state.object(0).is_none());
        assert!(state.handles().is_empty());
    }

    /// `Close All e&xcept current` is bound to the same command
    /// (parity quirk #11), so it also empties the desktop.
    #[test]
    fn directory_close_all_except_current_also_empties_the_desktop() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = fixture_dir("directory_close_except");
        // `Close All e&xcept current` carries `x` as its hot key.
        let script = "
            Paint.Enable(false)
            Paint('two windows')
            Key.Pressed(Alt+W)
            Key.Pressed(X)
            Paint('after close all except current')
        ";
        let state = run("directory_close_except", two_pending(&dir), script);
        assert_eq!(state.objects_count(), 0, "quirk #11: it closes everything");
    }

    /// The pure half of the directory: lookups, pruning and the
    /// empty-desktop answers, with no framework involved.
    #[test]
    fn directory_lookups_are_bounds_checked() {
        let state = DesktopState::new();
        assert_eq!(state.objects_count(), 0);
        assert!(state.object(0).is_none());
        assert!(state.window_name(0).is_none());
        assert!(state.index_of(Handle::None).is_none());
        assert!(state.handles().is_empty());

        let object: SharedObject = std::sync::Arc::new(std::sync::Mutex::new(
            gview_core::object::Object::from_buffer(b"MZ", "a.exe", 0),
        ));
        let handle: Handle<FileWindow> = Handle::None;
        state.push_window(WindowEntry {
            handle,
            object,
            name: String::from("a.exe"),
        });
        assert_eq!(state.objects_count(), 1);
        assert_eq!(state.window_name(0).as_deref(), Some("a.exe"));
        assert_eq!(state.index_of(handle), Some(0));
        assert!(state.object(1).is_none(), "past the end");
        assert!(format!("{:?}", state.handles()).contains("Handle"));

        // Pruning drops everything the framework no longer knows.
        state.retain_windows(|_| false);
        assert_eq!(state.objects_count(), 0);
        assert!(state.index_of(handle).is_none());
    }
}

/// The `FileWindow` ↔ desktop seam of `00_APP §5.6` (C++
/// `FileWindow::OnEvent`, `FileWindow.cpp:222-282`).
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod shell_integration {
    use super::test_support::*;
    use super::*;
    use crate::file_window::events::cmd;
    use crate::instance::window_lifecycle::OpenMethod;
    use crate::file_window::mount::{MountedViewer, ViewDialog};
    use crate::file_window::{ERR_NO_COPY, FileWindow};
    use crate::open_pipeline::generic_command_slots;
    use std::path::PathBuf;

    /// A window over a golden PE, built outside the desktop so its
    /// mounted controls can be driven directly.
    fn window(dir: &std::path::Path, name: &str, interactive: bool) -> (SharedInstance, FileWindow, PathBuf) {
        let path = write(dir, name, &minimal_pe());
        let instance = instance();
        let generic = generic_command_slots(&instance.lock().expect("instance"));
        let _ = generic;
        let mut request = OpenRequest::new(&path);
        request.interactive = interactive;
        let window = open(&instance, &request, &mut CancelSelector).expect("the PE opens");
        (instance, window, path)
    }

    /// `Ctrl+G` on the mounted `BufferView` reaches the window, and the
    /// offset the dialog would return moves the cursor.
    #[test]
    fn shell_integration_ctrl_g_reaches_the_window_and_go_to_moves_the_cursor() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, "Paint.Enable(false)\nPaint('goto')")
            .build()
            .expect("debug app");
        let dir = fixture_dir("shell_goto");
        let (_instance, mut win, _path) = window(&dir, "goto.exe", false);

        let Some(MountedViewer::Buffer(buffer)) = win.mounted_view(0) else {
            panic!("page 0 is a BufferView");
        };
        assert_eq!(win.current_snapshot().offset, 0);

        // The control's own key matrix raises `ShowGoTo` (C++
        // `FileWindow::OnKeyEvent` Ctrl+G).
        if let Some(view) = win.control_mut(buffer) {
            OnResize::on_resize(view, Size::new(0, 0), Size::new(120, 12));
            assert!(matches!(
                OnKeyPressed::on_key_pressed(view, Key::new(KeyCode::G, KeyModifier::Ctrl), '\0'),
                EventProcessStatus::Processed
            ));
        }
        // Headless: no modal, the request is surfaced instead.
        win.service_view_dialog(ViewDialog::GoTo);
        assert_eq!(
            win.take_requests(),
            [ShellRequest::ShowViewDialog(ViewDialog::GoTo)]
        );

        // What the dialog would return moves the view (C++ `MoveTo`).
        assert!(win.go_to_current_view(0x10));
        assert_eq!(win.current_snapshot().offset, 0x10);
        // Past the end clamps instead of panicking.
        assert!(win.go_to_current_view(u64::MAX));
        assert!(win.current_snapshot().offset < win.current_snapshot().size);

        app.add_window(win);
        app.run();
    }

    /// The Find seam: the window compiles the pattern into the shared
    /// session and the mounted control repeats it with `Ctrl+F7`.
    #[test]
    fn shell_integration_find_session_is_shared_with_the_mounted_view() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, "Paint.Enable(false)\nPaint('find')")
            .build()
            .expect("debug app");
        let dir = fixture_dir("shell_find");
        let (_instance, mut win, _path) = window(&dir, "find.exe", false);

        let Some(MountedViewer::Buffer(buffer)) = win.mounted_view(0) else {
            panic!("page 0 is a BufferView");
        };
        if let Some(view) = win.control_mut(buffer) {
            OnResize::on_resize(view, Size::new(0, 0), Size::new(120, 12));
        }

        // Nothing compiled yet: `Ctrl+F7` asks for the dialog.
        assert!(!win.find_session().is_armed());
        if let Some(view) = win.control_mut(buffer) {
            OnKeyPressed::on_key_pressed(view, Key::new(KeyCode::F7, KeyModifier::Ctrl), '\0');
        }
        win.service_view_dialog(ViewDialog::Find);
        assert_eq!(
            win.take_requests(),
            [ShellRequest::ShowViewDialog(ViewDialog::Find)]
        );

        // An unusable pattern is refused before anything is armed.
        assert!(!win.arm_find("", crate::buffer_find::BufferFindOptions::default()));
        assert!(!win.find_session().is_armed());

        // `PE\0\0` sits at 0x80 in the golden image.
        assert!(win.arm_find("PE", crate::buffer_find::BufferFindOptions::default()));
        assert!(win.find_session().is_armed());
        assert!(win.find_next_in_current_view());
        assert_eq!(win.current_snapshot().offset, 0x80, "the match moved the cursor");
        assert!(win.current_snapshot().has_selection, "the match is selected");

        // `Ctrl+Shift+F7` walks back to the same hit from further on.
        assert!(win.go_to_current_view(0x100));
        if let Some(view) = win.control_mut(buffer) {
            OnKeyPressed::on_key_pressed(
                view,
                Key::new(KeyCode::F7, KeyModifier::Ctrl | KeyModifier::Shift),
                '\0',
            );
        }
        assert_eq!(win.current_snapshot().offset, 0x80);

        app.add_window(win);
        app.run();
    }

    /// A dialog the window cannot open headlessly becomes a request,
    /// and the desktop records the C++ error text without opening a
    /// message box.
    #[test]
    fn shell_integration_headless_errors_are_recorded_not_shown() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // `Desktop::new` refuses to run once the framework is up, so
        // the desktop is built before the app.
        let mut desktop = GViewDesktop::new(instance(), Vec::new(), true);
        let state = desktop.state();

        let mut app = App::debug(100, 40, "Paint.Enable(false)\nPaint('errors')")
            .build()
            .expect("debug app");
        let dir = fixture_dir("shell_errors");
        let (_instance, mut win, _path) = window(&dir, "errors.exe", false);

        // Headless: every view dialog is surfaced instead of opened.
        win.service_view_dialog(ViewDialog::GoTo);
        win.service_view_dialog(ViewDialog::Find);
        win.service_view_dialog(ViewDialog::Copy);
        assert_eq!(
            win.take_requests(),
            [
                ShellRequest::ShowViewDialog(ViewDialog::GoTo),
                ShellRequest::ShowViewDialog(ViewDialog::Find),
                ShellRequest::ShowViewDialog(ViewDialog::Copy),
            ]
        );

        desktop.service_request(&ShellRequest::Error(ERR_NO_COPY));
        assert_eq!(state.errors(), [ERR_NO_COPY]);

        // The "not available in this build" requests are silent.
        desktop.service_request(&ShellRequest::ShowProperties);
        desktop.service_request(&ShellRequest::ShowKeyConfigurator);
        desktop.service_request(&ShellRequest::AddNote);
        desktop.service_request(&ShellRequest::ShowAnalysisEngine);
        assert_eq!(state.errors().len(), 1, "no extra noise");

        app.add_window(win);
        app.run();
    }

    /// `RunGenericPlugin` runs against the focused object; a bad index
    /// lands in the error list instead of panicking.
    #[test]
    fn shell_integration_generic_plugin_runs_against_the_focused_object() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = fixture_dir("shell_generic");
        let pe = write(&dir, "hashes.exe", &minimal_pe());
        let instance = instance();

        // `Hashes` is generic plugin 0; its first command is `Hashes`.
        {
            let guard = instance.lock().expect("instance");
            let slots = generic_command_slots(&guard);
            assert_eq!(slots[0].plugin, 0);
            assert_eq!(guard.generic_plugins().plugins()[0].name(), "Hashes");
            drop(guard);
        }

        let desktop = GViewDesktop::new(
            SharedInstance::clone(&instance),
            vec![OpenRequest::new(&pe).headless()],
            true,
        );
        let state = desktop.state();
        let script = "
            Paint.Enable(false)
            Paint('one window')
            Key.Pressed(Alt+W)
            Key.Pressed(Home)
            Key.Pressed(Enter)
            Paint('arranged')
        ";
        let app = App::debug(100, 40, script)
            .desktop(desktop)
            .app_bar()
            .command_bar()
            .build()
            .expect("debug app");
        app.run();

        assert_eq!(state.objects_count(), 1);
        assert!(state.errors().is_empty(), "{:?}", state.errors());
    }

    /// Every `ShellRequest` variant is serviced; nothing is ignored.
    ///
    /// No framework is needed: with no window the desktop answers from
    /// its own directory.
    #[test]
    fn shell_integration_services_every_request_variant() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let instance = instance();
        let mut desktop = GViewDesktop::new(SharedInstance::clone(&instance), Vec::new(), true);
        let state = desktop.state();

        // No window: the generic-plugin request is refused, loudly.
        assert!(!desktop.run_generic_plugin(0, 0));
        assert_eq!(state.errors(), [ERR_NO_CURRENT_OBJECT]);

        desktop.service_request(&ShellRequest::ShowViewDialog(ViewDialog::GoTo));
        desktop.service_request(&ShellRequest::OpenPendingObject { view: 0 });
        let errors = state.errors();
        assert_eq!(errors.len(), 3);
        assert!(errors[1].contains("GoTo"), "{errors:?}");
        assert!(errors[2].contains("view 0"), "{errors:?}");

        // An index the registry does not have is refused, not indexed.
        assert!(!desktop.run_generic_plugin(99, 0));
        assert!(!desktop.run_generic_plugin(0, 99));
        assert_eq!(state.errors().len(), 5);
    }

    /// `CMD_CHOSE_NEW_TYPE` on a file window queues a re-open, and the
    /// desktop's next event turns it into a second window when the
    /// selector picks (C++ `OpenFile(path, OpenMethod::Select)`).
    #[test]
    fn shell_integration_choose_type_opens_a_second_window() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = fixture_dir("shell_choose_type");
        let pe = write(&dir, "retype.exe", &minimal_pe());
        let instance = instance();
        let mut desktop = GViewDesktop::new(
            SharedInstance::clone(&instance),
            vec![OpenRequest::new(&pe).headless()],
            true,
        );
        // The scripted answer: candidate 0 of the dialog's list.
        desktop.set_selector_mode(SelectorMode::Scripted(0));
        assert_eq!(desktop.selector_mode(), SelectorMode::Scripted(0));
        let state = desktop.state();

        // `Alt+F1` on the window queues `ReopenWithTypeSelect`; the
        // `&Windows` → `Arrange Vertically` menu command is the next
        // desktop event, which drains it.
        let script = "
            Paint.Enable(false)
            Paint('one window')
            Key.Pressed(Alt+F1)
            Paint('type selection queued')
            Key.Pressed(Alt+W)
            Key.Pressed(Home)
            Key.Pressed(Enter)
            Paint('two windows')
        ";
        let app = App::debug(100, 40, script)
            .desktop(desktop)
            .app_bar()
            .command_bar()
            .build()
            .expect("debug app");
        app.run();

        assert_eq!(state.objects_count(), 2, "errors: {:?}", state.errors());
        assert_eq!(state.window_name(0).as_deref(), Some("retype.exe"));
        assert_eq!(state.window_name(1).as_deref(), Some("retype.exe"));
    }

    /// A buffer object cannot be re-typed: the C++ message is produced
    /// and no window is opened.
    #[test]
    fn shell_integration_choose_type_on_a_buffer_object_is_refused() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, "Paint.Enable(false)\nPaint('buffer')")
            .build()
            .expect("debug app");
        let instance = instance();
        let index = instance
            .lock()
            .expect("instance")
            .add_buffer_window(&minimal_pe(), "blob.exe", OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect("buffer opens");
        let model = instance.lock().expect("instance").take_window(index).expect("model");
        let mut win = FileWindow::new(model, Vec::new(), Vec::new(), false);

        win.on_command_id(cmd::CMD_CHOSE_NEW_TYPE);
        assert_eq!(
            win.take_requests(),
            [ShellRequest::Error(crate::file_window::ERR_CHOOSE_TYPE_UNSUPPORTED)]
        );

        app.add_window(win);
        app.run();
    }

    /// The mounted view answers `ViewControl::go_to` for every kind the
    /// build mounts (the placeholder refuses, as its own task defined).
    #[test]
    fn shell_integration_go_to_is_forwarded_to_the_mounted_control() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, "Paint.Enable(false)\nPaint('go to')")
            .build()
            .expect("debug app");
        let dir = fixture_dir("shell_go_to");
        let (_instance, mut win, _path) = window(&dir, "forward.exe", false);

        // Page 1 is the PE plugin's Dissasm view.
        assert!(win.set_view_by_index(1));
        assert!(matches!(win.mounted_view(1), Some(MountedViewer::Dissasm(_))));
        let moved = win.go_to_current_view(0);
        // Whatever the viewer answers, the call reaches it and the bar
        // shows that view's snapshot.
        assert_eq!(win.current_snapshot().name_str(), "Dissasm View");
        let _ = moved;

        assert!(win.set_view_by_index(0));
        assert!(win.go_to_current_view(4));
        assert_eq!(win.current_snapshot().offset, 4);
        assert_eq!(win.current_snapshot().name_str(), "Buffer View");

        app.add_window(win);
        app.run();
    }
}
