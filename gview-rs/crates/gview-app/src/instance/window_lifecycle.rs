//! Window lifecycle: identify the type plugin, populate the window,
//! add it to the desktop model.
//!
//! C++ anchors: `Instance::Add` (`Instance.cpp:369-421`),
//! `AddFileWindow`, `AddBufferWindow`, `IdentifyTypePlugin*`,
//! `GetObject*`, and the `OnEvent` menu / arrange dispatch; spec
//! `02_SMART_VIEWERS_DEEP` §B.3, §F, §G; `03_DUAL_PLUGIN` §3.4.
//!
//! `Instance::Add` pipeline (§B.3), reproduced by [`Instance::add`]:
//!
//! 1. build the `DataCache` (the caller hands in the [`Object`]);
//! 2. hash the path's extension (`find_last_of('.')`, FNV-1a);
//! 3. `IdentifyTypePlugin` on the `0x8800`-byte probe and its UTF-16
//!    text (when the encoding is not binary), per [`OpenMethod`];
//!    the `SelectTypeDialog` is abstracted as [`TypeSelector`]
//!    (spec §F.2), which the shell implements with the real dialog;
//! 4. `CreateInstance` on the plugin (or the default fallback);
//! 5. `PopulateWindow` through [`WindowHandle`] — a failure aborts
//!    the open (C++ `CHECKBK`, the window is dropped);
//! 6. `Start()`: view tab 0 becomes current and focused;
//! 7. `AddWindow`: the window joins the desktop model and takes
//!    focus.
//!
//! [`DefaultTypePlugin`] is the `GENERIC` fallback (§F.3,
//! `DefaultTypePlugin.cpp`): an Information panel, a text viewer when
//! the probe is not binary, then a buffer viewer.
//!
//! The desktop is modelled in-process ([`Instance::windows`],
//! [`Instance::current_object`] = `GetFocusedChild()`); the `AppCUI`
//! `Desktop` / `App::add_window` wiring, the Smart Assistants tab and
//! the analysis-engine subject linkage are composed by the shell task.
//! Folder windows (`AddFolder`, `FolderViewPlugin`) have no matrix
//! task and are not part of this deliverable.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use appcui::graphics::Surface;
use gview_core::constants::TYPE_IDENTIFICATION_PROBE_SIZE;
use gview_core::object::Object;
use gview_plugin::generic_plugin::GenericPluginRegistry;
use gview_plugin::matcher::{utf16, TextParser};
use gview_plugin::type_plugin::{
    PanelRequest, PluginError, RegisteredTypePlugin, TypePlugin, TypePluginRegistry, ViewerKind, ViewerRequest,
    WindowHandle,
};
use gview_view::text_viewer::line_index::{analyze_encoding, Encoding};
use gview_view::traits::{SharedObject, SmartViewer, ViewerSettings};
use gview_view::view_control::ViewControl;

use crate::file_window::panels::PanelDock;
use crate::file_window::view_container::ViewContainer;

/// C++ `GView::App::OpenMethod`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMethod {
    /// First extension or content match wins.
    FirstMatch,
    /// All matches; the selector decides when more than one.
    BestMatch,
    /// Always ask the selector.
    Select,
    /// The named type, falling back to selection when it does not
    /// exist or rejects the data.
    ForceType,
}

/// C++ `Application::ArrangeWindowsMethod`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrangeMethod {
    /// Cascade.
    Cascade,
    /// Grid.
    Grid,
    /// Side by side.
    Horizontal,
    /// Stacked.
    Vertical,
}

/// C++ `MenuCommands` IDs (`Internal.hpp:462-487`).
pub mod menu {
    /// Arrange vertically.
    pub const ARRANGE_VERTICALLY: u32 = 100_000;
    /// Arrange horizontally.
    pub const ARRANGE_HORIZONTALLY: u32 = 100_001;
    /// Cascade.
    pub const ARRANGE_CASCADE: u32 = 100_002;
    /// Grid.
    pub const ARRANGE_GRID: u32 = 100_003;
    /// Close.
    pub const CLOSE: u32 = 100_004;
    /// Close all.
    pub const CLOSE_ALL: u32 = 100_005;
    /// Close all except current.
    pub const CLOSE_ALL_EXCEPT_CURRENT: u32 = 100_006;
    /// Window manager dialog.
    pub const SHOW_WINDOW_MANAGER: u32 = 100_007;
    /// Exit.
    pub const EXIT_GVIEW: u32 = 100_008;
    /// Check for updates.
    pub const CHECK_FOR_UPDATES: u32 = 110_000;
    /// About.
    pub const ABOUT: u32 = 110_001;
    /// Available keys.
    pub const AVAILABLE_KEYS: u32 = 110_002;
    /// Open file.
    pub const OPEN_FILE: u32 = 120_000;
    /// Open folder.
    pub const OPEN_FOLDER: u32 = 120_001;
    /// Open PID.
    pub const OPEN_PID: u32 = 120_002;
    /// Open process tree.
    pub const OPEN_PROCESS_TREE: u32 = 120_003;
    /// Change theme.
    pub const CHANGE_THEME: u32 = 130_000;
    /// Theme editor.
    pub const OPEN_THEME_EDITOR: u32 = 130_001;
    /// Restricted mode window.
    pub const OPEN_RESTRICTED_MODE: u32 = 130_002;
    /// First generic-plugin command ID (`Instance.cpp:15`).
    pub const GENERIC_PLUGINS_CMDID: u32 = 40_000_000;
    /// Command IDs reserved per generic plugin (`Instance.cpp:16`).
    pub const GENERIC_PLUGINS_FRAME: u32 = 100;
    /// Generic plugins addressable by the ID range (`FRAME * 1000`).
    pub const GENERIC_PLUGINS_MAX: u32 = 1000;
}

/// What the shell must do for a menu command
/// (C++ `Instance::OnEvent` `Event::Command` switch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceAction {
    /// `Application::ArrangeWindows(method)`.
    Arrange(ArrangeMethod),
    /// `Dialogs::WindowManager::Show()`.
    ShowWindowManager,
    /// `Application::Close()`.
    Exit,
    /// `OpenFile()` dialog.
    OpenFile,
    /// `OpenFolder()` dialog.
    OpenFolder,
    /// `ShowAboutWindow()`.
    About,
    /// `ShowChangeThemeWindow()`.
    ChangeTheme,
    /// `Dialogs::ThemeEditor::Show()`.
    ThemeEditor,
    /// `ShowRestrictedModeWindow()`.
    RestrictedMode,
    /// `genericPlugins[plugin].Run(command, GetCurrentObject())`.
    RunGenericPlugin {
        /// Index into the generic-plugin registry.
        plugin: usize,
        /// Command index within that plugin.
        command: usize,
    },
    /// Not a menu command handled by the instance (C++ still returns
    /// `true`).
    Unhandled,
}

/// Maps a command ID to the instance action (`Instance::OnEvent`).
#[must_use]
pub const fn menu_action(id: u32) -> InstanceAction {
    match id {
        menu::ARRANGE_CASCADE => InstanceAction::Arrange(ArrangeMethod::Cascade),
        menu::ARRANGE_GRID => InstanceAction::Arrange(ArrangeMethod::Grid),
        menu::ARRANGE_HORIZONTALLY => InstanceAction::Arrange(ArrangeMethod::Horizontal),
        menu::ARRANGE_VERTICALLY => InstanceAction::Arrange(ArrangeMethod::Vertical),
        menu::SHOW_WINDOW_MANAGER => InstanceAction::ShowWindowManager,
        menu::EXIT_GVIEW => InstanceAction::Exit,
        menu::OPEN_FILE => InstanceAction::OpenFile,
        menu::OPEN_FOLDER => InstanceAction::OpenFolder,
        menu::ABOUT => InstanceAction::About,
        menu::CHANGE_THEME => InstanceAction::ChangeTheme,
        menu::OPEN_THEME_EDITOR => InstanceAction::ThemeEditor,
        menu::OPEN_RESTRICTED_MODE => InstanceAction::RestrictedMode,
        _ => {
            let end = menu::GENERIC_PLUGINS_CMDID.saturating_add(
                menu::GENERIC_PLUGINS_FRAME.saturating_mul(menu::GENERIC_PLUGINS_MAX),
            );
            if id >= menu::GENERIC_PLUGINS_CMDID && id < end {
                let packed = id.wrapping_sub(menu::GENERIC_PLUGINS_CMDID);
                InstanceAction::RunGenericPlugin {
                    plugin: (packed / menu::GENERIC_PLUGINS_FRAME) as usize,
                    command: (packed % menu::GENERIC_PLUGINS_FRAME) as usize,
                }
            } else {
                InstanceAction::Unhandled
            }
        }
    }
}

/// The `SelectTypeDialog` seam (spec §F.2): asked to pick among
/// `candidates`; `None` cancels the open. `Select` mode passes every
/// registered plugin, as the dialog lists them all.
pub trait TypeSelector {
    /// Returns the index into `candidates` of the chosen plugin, or
    /// `None` to cancel.
    fn select(&mut self, candidates: &[&RegisteredTypePlugin]) -> Option<usize>;
}

/// A selector that never picks (`Dialogs::Result::Cancel`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CancelSelector;

impl TypeSelector for CancelSelector {
    fn select(&mut self, _candidates: &[&RegisteredTypePlugin]) -> Option<usize> {
        None
    }
}

/// Failures of the open pipeline (`Instance::Add` `CHECK` messages).
#[derive(Debug)]
pub enum InstanceError {
    /// `Unable to identify a valid plugin open canceled !`
    OpenCanceled,
    /// `Failed to populate file window!`
    PopulateFailed(PluginError),
    /// `Fail to open file: <path>`
    OpenFile {
        /// The path.
        path: PathBuf,
        /// I/O error.
        source: std::io::Error,
    },
    /// Folder windows are outside this deliverable.
    FolderUnsupported(PathBuf),
}

impl core::fmt::Display for InstanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OpenCanceled => write!(f, "Unable to identify a valid plugin open canceled !"),
            Self::PopulateFailed(e) => write!(f, "Failed to populate file window! ({e})"),
            Self::OpenFile { path, source } => {
                write!(f, "Fail to open file: {} ({source})", path.display())
            }
            Self::FolderUnsupported(path) => write!(f, "folder windows unsupported: {}", path.display()),
        }
    }
}

impl std::error::Error for InstanceError {}

/// Settings for a [`ViewerSlot`]: the plugin's [`ViewerRequest`].
#[derive(Debug, Default)]
pub struct ViewerSlotSettings {
    request: Option<ViewerRequest>,
    custom_name: Option<String>,
}

impl ViewerSlotSettings {
    /// Settings carrying the plugin's request
    /// (C++ `CreateViewer(Settings&)`).
    #[must_use]
    pub const fn for_request(request: ViewerRequest) -> Self {
        Self {
            request: Some(request),
            custom_name: None,
        }
    }

    /// Replaces the carried request.
    pub fn set_request(&mut self, request: ViewerRequest) {
        self.request = Some(request);
    }
}

impl ViewerSettings for ViewerSlotSettings {
    fn custom_name(&self) -> Option<&str> {
        self.custom_name.as_deref()
    }
    fn set_custom_name(&mut self, name: &str) {
        self.custom_name = Some(name.to_owned());
    }
}

/// A viewer as the window model holds it: the request that created
/// it plus its tab name (C++ `ViewControl(name)` — `"Buffer View"`,
/// …). The concrete `AppCUI` viewer controls are attached by the shell.
#[derive(Debug)]
pub struct ViewerSlot {
    kind: ViewerKind,
    name: String,
    request: Option<ViewerRequest>,
}

impl ViewerSlot {
    /// C++ `ViewControl` names per viewer.
    #[must_use]
    pub const fn default_name(kind: ViewerKind) -> &'static str {
        match kind {
            ViewerKind::Buffer => "Buffer View",
            ViewerKind::Text => "Text View",
            ViewerKind::Lexical => "Lexical View",
            ViewerKind::Image => "Image View",
            ViewerKind::Grid => "Grid View",
            ViewerKind::Dissasm => "Dissasm View",
            ViewerKind::Container => "Container View",
        }
    }

    /// Viewer type.
    #[must_use]
    pub const fn kind(&self) -> ViewerKind {
        self.kind
    }

    /// The creating request (settings the shell needs when it builds
    /// the real control); `None` once the mounting step took it.
    #[must_use]
    pub const fn request(&self) -> Option<&ViewerRequest> {
        self.request.as_ref()
    }

    /// Moves the creating request out, leaving the slot empty
    /// (`00_APP §5.3.1`).
    ///
    /// The C++ `CreateViewer` moves its `SettingsData` into the viewer
    /// instance; mounting does the same here, so a plugin's
    /// `ZonesList` is handed over instead of cloned. A second call
    /// yields `None`, which mounts the control with its defaults.
    pub const fn take_request(&mut self) -> Option<ViewerRequest> {
        self.request.take()
    }
}

impl ViewControl for ViewerSlot {
    fn name(&self) -> &str {
        &self.name
    }
    fn go_to(&mut self, _offset: u64) -> bool {
        false
    }
    fn select(&mut self, _offset: u64, _size: u64) -> bool {
        false
    }
    fn show_goto_dialog(&mut self) -> bool {
        false
    }
    fn show_find_dialog(&mut self) -> bool {
        false
    }
    fn show_copy_dialog(&mut self) -> bool {
        false
    }
    fn paint_cursor_information(&mut self, _surface: &mut Surface, _width: u32, _height: u32) {}

    /// The mounting step downcasts to this type to take the request.
    fn as_any_mut(&mut self) -> Option<&mut dyn core::any::Any> {
        Some(self)
    }
}

impl SmartViewer for ViewerSlot {
    type Settings = ViewerSlotSettings;

    fn from_settings(_object: SharedObject, settings: Self::Settings) -> Self {
        let kind = settings.request.as_ref().map_or(ViewerKind::Buffer, |r| r.kind);
        let name = settings
            .custom_name
            .clone()
            .or_else(|| settings.request.as_ref().and_then(|r| r.custom_name.clone()))
            .unwrap_or_else(|| Self::default_name(kind).to_owned());
        Self {
            kind,
            name,
            request: settings.request,
        }
    }
}

/// The per-object window model (C++ `FileWindow` state without the
/// controls): object, type instance, viewers and panels.
pub struct FileWindowModel {
    object: SharedObject,
    type_plugin: Option<&'static str>,
    content: Box<dyn TypePlugin>,
    views: ViewContainer,
    panels: PanelDock,
}

impl core::fmt::Debug for FileWindowModel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileWindowModel")
            .field("type_plugin", &self.type_plugin)
            .field("content", &self.content.name())
            .field("views", &self.views.views_count())
            .finish_non_exhaustive()
    }
}

impl FileWindowModel {
    fn new(object: Object, type_plugin: Option<&'static str>, content: Box<dyn TypePlugin>) -> Self {
        let object: SharedObject = Arc::new(Mutex::new(object));
        Self {
            views: ViewContainer::new(SharedObject::clone(&object)),
            object,
            type_plugin,
            content,
            panels: PanelDock::new(),
        }
    }

    /// The window's object (`GetObject()`).
    #[must_use]
    pub fn object(&self) -> SharedObject {
        SharedObject::clone(&self.object)
    }

    /// Registered plugin name, `None` for the default fallback.
    #[must_use]
    pub const fn type_plugin_name(&self) -> Option<&'static str> {
        self.type_plugin
    }

    /// The type instance (`Object::GetContentType`).
    #[must_use]
    pub fn content(&self) -> &dyn TypePlugin {
        self.content.as_ref()
    }

    /// Mutable type instance (for `RunCommand`).
    pub fn content_mut(&mut self) -> &mut dyn TypePlugin {
        self.content.as_mut()
    }

    /// The viewers.
    #[must_use]
    pub const fn views(&self) -> &ViewContainer {
        &self.views
    }

    /// Mutable viewers (F4 cycling etc.).
    pub const fn views_mut(&mut self) -> &mut ViewContainer {
        &mut self.views
    }

    /// The panel dock.
    #[must_use]
    pub const fn panels(&self) -> &PanelDock {
        &self.panels
    }

    /// Mutable panel dock (bottom-bar switching).
    pub const fn panels_mut(&mut self) -> &mut PanelDock {
        &mut self.panels
    }

    /// C++ `FileWindow::Start()`: view tab 0 current (focus is the
    /// shell's job).
    pub fn start(&mut self) -> bool {
        self.views.set_view_by_index(0)
    }
}

impl WindowHandle for FileWindowModel {
    fn object(&self) -> SharedObject {
        SharedObject::clone(&self.object)
    }

    fn add_panel(&mut self, panel: PanelRequest, vertical: bool) -> bool {
        self.panels.add_panel(&panel.caption, &panel.panel_id, vertical)
    }

    fn create_viewer(&mut self, request: ViewerRequest) -> Result<u32, PluginError> {
        let kind = request.kind;
        let settings = ViewerSlotSettings::for_request(request);
        if !self.views.create_viewer::<ViewerSlot>(settings) {
            return Err(PluginError::Window(format!(
                "cannot create {kind:?} viewer: view tab is full"
            )));
        }
        let index = self.views.views_count().saturating_sub(1);
        self.views.set_view_by_index(index);
        Ok(index as u32)
    }

    fn views_count(&self) -> u32 {
        self.views.views_count() as u32
    }

    fn set_view_by_index(&mut self, index: u32) -> bool {
        self.views.set_view_by_index(index as usize)
    }

    fn current_view(&self) -> Option<u32> {
        (self.views.views_count() > 0).then(|| self.views.current_index() as u32)
    }
}

/// The `GENERIC` fallback (C++ `DefaultTypePlugin.cpp`), owned by the
/// plugin crate.
pub use gview_plugin::default_type::DefaultTypePlugin;

/// C++ `Instance` orchestration state (spec §G.4).
pub struct Instance {
    type_plugins: TypePluginRegistry,
    generic_plugins: GenericPluginRegistry,
    default_cache_size: u32,
    windows: Vec<FileWindowModel>,
    focused: Option<usize>,
    errors: Vec<String>,
}

impl core::fmt::Debug for Instance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Instance")
            .field("type_plugins", &self.type_plugins.len())
            .field("generic_plugins", &self.generic_plugins.len())
            .field("default_cache_size", &self.default_cache_size)
            .field("windows", &self.windows.len())
            .field("focused", &self.focused)
            .finish_non_exhaustive()
    }
}

impl Instance {
    /// An instance with the given plugin tables and cache size.
    #[must_use]
    pub const fn new(type_plugins: TypePluginRegistry, generic_plugins: GenericPluginRegistry, default_cache_size: u32) -> Self {
        Self {
            type_plugins,
            generic_plugins,
            default_cache_size,
            windows: Vec::new(),
            focused: None,
            errors: Vec::new(),
        }
    }

    /// The type-plugin table.
    #[must_use]
    pub const fn type_plugins(&self) -> &TypePluginRegistry {
        &self.type_plugins
    }

    /// The generic-plugin table.
    #[must_use]
    pub const fn generic_plugins(&self) -> &GenericPluginRegistry {
        &self.generic_plugins
    }

    /// `defaultCacheSize`.
    #[must_use]
    pub const fn default_cache_size(&self) -> u32 {
        self.default_cache_size
    }

    /// Desktop children (`GetObjectsCount`).
    #[must_use]
    pub const fn objects_count(&self) -> u32 {
        self.windows.len() as u32
    }

    /// `GetObject(index)`.
    #[must_use]
    pub fn object(&self, index: u32) -> Option<SharedObject> {
        self.windows.get(index as usize).map(FileWindowModel::object)
    }

    /// `GetCurrentObject()` — the focused window's object.
    #[must_use]
    pub fn current_object(&self) -> Option<SharedObject> {
        self.current_window().map(FileWindowModel::object)
    }

    /// All windows in desktop order.
    #[must_use]
    pub fn windows(&self) -> &[FileWindowModel] {
        &self.windows
    }

    /// Window by desktop index.
    #[must_use]
    pub fn window(&self, index: u32) -> Option<&FileWindowModel> {
        self.windows.get(index as usize)
    }

    /// Mutable window by desktop index.
    pub fn window_mut(&mut self, index: u32) -> Option<&mut FileWindowModel> {
        self.windows.get_mut(index as usize)
    }

    /// The focused window (`GetFocusedChild`).
    #[must_use]
    pub fn current_window(&self) -> Option<&FileWindowModel> {
        self.focused.and_then(|i| self.windows.get(i))
    }

    /// Mutable focused window.
    pub fn current_window_mut(&mut self) -> Option<&mut FileWindowModel> {
        self.focused.and_then(|i| self.windows.get_mut(i))
    }

    /// Index of the focused window.
    #[must_use]
    pub const fn focused_index(&self) -> Option<usize> {
        self.focused
    }

    /// Focus change (desktop child focus); `false` when out of range.
    pub const fn set_focus(&mut self, index: u32) -> bool {
        if (index as usize) < self.windows.len() {
            self.focused = Some(index as usize);
            true
        } else {
            false
        }
    }

    /// Moves window `index` out of the desktop model (the shell wraps
    /// it in an `AppCUI` window, which then owns it). Focus is
    /// adjusted as for [`Self::close`].
    pub fn take_window(&mut self, index: u32) -> Option<FileWindowModel> {
        let index = index as usize;
        if index >= self.windows.len() {
            return None;
        }
        let model = self.windows.remove(index);
        self.focused = if self.windows.is_empty() {
            None
        } else {
            Some(index.min(self.windows.len().saturating_sub(1)))
        };
        Some(model)
    }

    /// Closes window `index` (`MenuCommands::CLOSE`); focus moves to
    /// the previous window, like the desktop does.
    pub fn close(&mut self, index: u32) -> bool {
        let index = index as usize;
        if index >= self.windows.len() {
            return false;
        }
        self.windows.remove(index);
        self.focused = if self.windows.is_empty() {
            None
        } else {
            Some(index.min(self.windows.len().saturating_sub(1)))
        };
        true
    }

    /// Errors accumulated since the last call (`errList` /
    /// `ShowErrors`).
    pub fn take_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.errors)
    }

    /// C++ `AddFileWindow(path, method, typeName)`.
    ///
    /// # Errors
    ///
    /// [`InstanceError::OpenFile`] (also recorded in the error list),
    /// [`InstanceError::FolderUnsupported`], or the errors of
    /// [`Self::add`].
    pub fn add_file_window(
        &mut self,
        path: &Path,
        method: OpenMethod,
        type_name: &str,
        selector: &mut dyn TypeSelector,
    ) -> Result<u32, InstanceError> {
        if path.is_dir() {
            return Err(InstanceError::FolderUnsupported(path.to_path_buf()));
        }
        let object = match Object::open_file(path, self.default_cache_size) {
            Ok(object) => object,
            Err(source) => {
                self.errors.push(format!("Fail to open file: {}", path.display()));
                return Err(InstanceError::OpenFile {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        self.add(object, method, type_name, selector)
    }

    /// C++ `AddBufferWindow(buf, name, path, method, typeName)`.
    ///
    /// # Errors
    ///
    /// As [`Self::add`].
    pub fn add_buffer_window(
        &mut self,
        buf: &[u8],
        name: &str,
        method: OpenMethod,
        type_name: &str,
        selector: &mut dyn TypeSelector,
    ) -> Result<u32, InstanceError> {
        let object = Object::from_buffer(buf, name, self.default_cache_size);
        self.add(object, method, type_name, selector)
    }

    /// C++ `Instance::Add`: identify → create instance → populate →
    /// start → add to the desktop (focused). Returns the new window's
    /// desktop index.
    ///
    /// # Errors
    ///
    /// [`InstanceError::OpenCanceled`] when the selector cancels,
    /// [`InstanceError::PopulateFailed`] when the plugin's
    /// `PopulateWindow` fails (the window is discarded).
    pub fn add(
        &mut self,
        mut object: Object,
        method: OpenMethod,
        type_name: &str,
        selector: &mut dyn TypeSelector,
    ) -> Result<u32, InstanceError> {
        // C++ hashes the extension of `path`; a memory-buffer window
        // (`AddBufferWindow`) has no path here, so its name stands in.
        let extension = extension_of_path(object.path())
            .or_else(|| gview_plugin::fnv::extension_of(object.name()).map(str::to_owned))
            .unwrap_or_default();
        let probe = object
            .data_mut()
            .copy_to_vec(0, TYPE_IDENTIFICATION_PROBE_SIZE, false)
            .unwrap_or_default();
        let text = probe_text(&probe);
        let mut parser = TextParser::new(&text);

        let plugin = self.identify_type_plugin(&probe, &mut parser, &extension, method, type_name, selector)?;
        let (name, content): (Option<&'static str>, Box<dyn TypePlugin>) = plugin.map_or_else(
            || (None, DefaultTypePlugin::create_instance() as Box<dyn TypePlugin>),
            |p| (Some(p.name()), p.create_instance()),
        );

        let mut window = FileWindowModel::new(object, name, content);
        // `PopulateWindow` goes through the type instance, which the
        // model owns: take it out for the call and put it back.
        let content = std::mem::replace(&mut window.content, DefaultTypePlugin::create_instance());
        let populated = content.populate_window(&mut window);
        window.content = content;
        populated.map_err(InstanceError::PopulateFailed)?;
        window.start();

        self.windows.push(window);
        let index = self.windows.len().saturating_sub(1);
        self.focused = Some(index);
        Ok(index as u32)
    }

    /// C++ `IdentifyTypePlugin` (§F.2): `None` means the default
    /// plugin.
    fn identify_type_plugin(
        &self,
        probe: &[u8],
        parser: &mut TextParser<'_>,
        extension: &str,
        method: OpenMethod,
        type_name: &str,
        selector: &mut dyn TypeSelector,
    ) -> Result<Option<&RegisteredTypePlugin>, InstanceError> {
        match method {
            OpenMethod::FirstMatch => Ok(self
                .type_plugins
                .candidates(probe, parser, extension)
                .first()
                .copied()),
            OpenMethod::BestMatch => {
                let candidates = self.type_plugins.candidates(probe, parser, extension);
                match candidates.len() {
                    0 => Ok(None),
                    1 => Ok(candidates.first().copied()),
                    _ => Self::select_from(&candidates, selector),
                }
            }
            OpenMethod::Select => self.select_any(selector),
            OpenMethod::ForceType => {
                // Exact-length, case-insensitive name match.
                let forced = self
                    .type_plugins
                    .plugins()
                    .iter()
                    .find(|p| p.name().len() == type_name.len() && p.name().eq_ignore_ascii_case(type_name));
                match forced {
                    Some(p) if p.is_of_type(probe, extension) => Ok(Some(p)),
                    _ => self.select_any(selector),
                }
            }
        }
    }

    fn select_any(&self, selector: &mut dyn TypeSelector) -> Result<Option<&RegisteredTypePlugin>, InstanceError> {
        let all: Vec<&RegisteredTypePlugin> = self.type_plugins.plugins().iter().collect();
        Self::select_from(&all, selector)
    }

    fn select_from<'a>(
        candidates: &[&'a RegisteredTypePlugin],
        selector: &mut dyn TypeSelector,
    ) -> Result<Option<&'a RegisteredTypePlugin>, InstanceError> {
        // An index past the list means "the default plugin"
        // (`GetSelectedPlugin(&defaultPlugin)`).
        selector
            .select(candidates)
            .map_or(Err(InstanceError::OpenCanceled), |index| {
                Ok(candidates.get(index).copied())
            })
    }

    /// C++ `Instance::OnEvent` for menu commands; generic-plugin
    /// commands run against the current object here, everything else
    /// is returned for the shell.
    pub fn on_menu_command(&mut self, id: u32) -> InstanceAction {
        let action = menu_action(id);
        if let InstanceAction::RunGenericPlugin { plugin, command } = action {
            self.run_generic_plugin(plugin, command);
        }
        action
    }

    /// `genericPlugins[plugin].Run(command, GetCurrentObject())`.
    pub fn run_generic_plugin(&mut self, plugin: usize, command: usize) -> bool {
        let Some(object) = self.current_object() else {
            return false;
        };
        let Some(registered) = self.generic_plugins.plugins().get(plugin) else {
            return false;
        };
        let Some(def) = registered.metadata().commands.get(command) else {
            return false;
        };
        let name = def.name.clone();
        let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
        match registered.run(&name, &mut guard) {
            Ok(()) => true,
            Err(e) => {
                self.errors.push(e.to_string());
                false
            }
        }
    }
}

/// `find_last_of('.')` on the path text (extension with its dot).
fn extension_of_path(path: &Path) -> Option<String> {
    let text = path.to_string_lossy();
    gview_plugin::fnv::extension_of(&text).map(str::to_owned)
}

/// C++ `IdentifyTypePlugin`: the probe as UTF-16 when it is text,
/// empty when binary (`ConvertToUnicode16`).
fn probe_text(probe: &[u8]) -> Vec<u16> {
    let info = analyze_encoding(probe);
    let body = probe.get(info.bom_size as usize..).unwrap_or(&[]);
    match info.encoding {
        Encoding::Binary => Vec::new(),
        Encoding::Ascii | Encoding::Utf8 => utf16(&String::from_utf8_lossy(body)),
        Encoding::Utf16Le => body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect(),
        Encoding::Utf16Be => body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_plugin::type_plugin::{KeyRegistry, PluginMetadata};
    use serde_json::Value as JsonValue;
    use gview_core::constants::DEFAULT_CACHE_SIZE;
    use gview_core::object::ObjectType;
    use gview_plugin::type_plugin::{CommandDef, Pattern};

    struct MockPe;

    impl TypePlugin for MockPe {
        fn name(&self) -> &'static str {
            "PE"
        }
        fn validate(buf: &[u8], _extension: &str) -> bool {
            buf.starts_with(b"MZ")
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata {
                pattern: vec![Pattern::Magic(vec![0x4D, 0x5A])],
                extensions: vec![String::from("exe")],
                ..PluginMetadata::default()
            }
        }
        fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            win.add_panel(
                PanelRequest {
                    caption: String::from("&Information"),
                    panel_id: String::from("pe.info"),
                },
                true,
            );
            win.create_viewer(ViewerRequest::new(ViewerKind::Buffer))?;
            win.create_viewer(ViewerRequest::new(ViewerKind::Dissasm).named("Code"))?;
            Ok(())
        }
        fn run_command(&mut self, _command: &str) {}
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _p: &str, _d: &str) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }
    }

    struct MockScript;

    impl TypePlugin for MockScript {
        fn name(&self) -> &'static str {
            "SCRIPT"
        }
        fn validate(_buf: &[u8], _extension: &str) -> bool {
            true
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata {
                pattern: vec![Pattern::LineStartsWith(String::from("#!"))],
                extensions: vec![String::from("sh")],
                ..PluginMetadata::default()
            }
        }
        fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            win.create_viewer(ViewerRequest::new(ViewerKind::Text))?;
            Ok(())
        }
        fn run_command(&mut self, _command: &str) {}
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _p: &str, _d: &str) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }
    }

    struct Broken;

    impl TypePlugin for Broken {
        fn name(&self) -> &'static str {
            "BROKEN"
        }
        fn validate(_buf: &[u8], _extension: &str) -> bool {
            true
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata {
                pattern: vec![Pattern::Magic(vec![0xCA, 0xFE])],
                ..PluginMetadata::default()
            }
        }
        fn populate_window(&self, _win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            Err(PluginError::Window(String::from("boom")))
        }
        fn run_command(&mut self, _command: &str) {}
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _p: &str, _d: &str) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }
    }

    #[derive(Default)]
    struct Hashes;

    impl gview_plugin::generic_plugin::GenericPlugin for Hashes {
        fn name(&self) -> &'static str {
            "Hashes"
        }
        fn metadata() -> gview_plugin::generic_plugin::GenericPluginMetadata {
            gview_plugin::generic_plugin::GenericPluginMetadata {
                description: String::new(),
                commands: vec![CommandDef::new(
                    "Hashes",
                    appcui::input::Key::new(appcui::input::KeyCode::F5, appcui::input::KeyModifier::Ctrl),
                    "",
                    0,
                )],
            }
        }
        fn run(&self, _command: &str, object: &mut Object) -> Result<(), PluginError> {
            if object.data().size() == 0 {
                return Err(PluginError::Unsupported(String::from("empty")));
            }
            Ok(())
        }
    }

    struct PickFirst;

    impl TypeSelector for PickFirst {
        fn select(&mut self, candidates: &[&RegisteredTypePlugin]) -> Option<usize> {
            (!candidates.is_empty()).then_some(0)
        }
    }

    struct PickDefault;

    impl TypeSelector for PickDefault {
        fn select(&mut self, candidates: &[&RegisteredTypePlugin]) -> Option<usize> {
            Some(candidates.len())
        }
    }

    fn instance() -> Instance {
        let mut types = TypePluginRegistry::new();
        types.register_type::<MockPe>("PE").expect("pe");
        types.register_type::<MockScript>("SCRIPT").expect("script");
        types.register_type::<Broken>("BROKEN").expect("broken");
        let mut generics = GenericPluginRegistry::new();
        generics.register_type::<Hashes>("Hashes").expect("hashes");
        Instance::new(types, generics, DEFAULT_CACHE_SIZE)
    }

    fn golden_file(name: &str, data: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gview-lifecycle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(name);
        std::fs::write(&path, data).expect("write");
        path
    }

    #[test]
    fn open_golden_file_yields_one_object_and_pe_window() {
        let mut inst = instance();
        let path = golden_file("golden.exe", b"MZ\x90\x00\x03\x00");
        let index = inst
            .add_file_window(&path, OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect("open");
        assert_eq!(index, 0);
        assert_eq!(inst.objects_count(), 1);
        let win = inst.window(0).expect("window");
        assert_eq!(win.type_plugin_name(), Some("PE"));
        assert_eq!(win.content().name(), "PE");
        assert_eq!(win.views().views_count(), 2);
        assert_eq!(win.views().current_index(), 0);
        assert_eq!(win.views().view_by_index(0).map(ViewControl::name), Some("Buffer View"));
        assert_eq!(win.views().view_by_index(1).map(ViewControl::name), Some("Code"));
        assert_eq!(win.panels().vertical_count(), 1);
        let object = inst.current_object().expect("object");
        let guard = object.lock().expect("lock");
        assert_eq!(guard.name(), "golden.exe");
        assert_eq!(guard.object_type(), ObjectType::File);
        assert_eq!(guard.data().size(), 6);
        assert!(inst.take_errors().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn current_object_follows_focus_changes() {
        let mut inst = instance();
        inst.add_buffer_window(b"MZ1", "first.exe", OpenMethod::FirstMatch, "", &mut CancelSelector)
            .expect("first");
        inst.add_buffer_window(b"plain text", "second.txt", OpenMethod::FirstMatch, "", &mut CancelSelector)
            .expect("second");
        assert_eq!(inst.objects_count(), 2);
        assert_eq!(inst.focused_index(), Some(1));
        let name = |o: Option<SharedObject>| o.map(|o| o.lock().expect("lock").name().to_owned());
        assert_eq!(name(inst.current_object()), Some(String::from("second.txt")));
        assert!(inst.set_focus(0));
        assert_eq!(name(inst.current_object()), Some(String::from("first.exe")));
        assert_eq!(name(inst.object(1)), Some(String::from("second.txt")));
        assert!(!inst.set_focus(7));
        assert!(inst.object(7).is_none());
        assert!(inst.close(0));
        assert_eq!(name(inst.current_object()), Some(String::from("second.txt")));
        assert!(inst.close(0));
        assert!(inst.current_object().is_none());
        assert!(!inst.close(0));
    }

    #[test]
    fn default_type_fallback_creates_buffer_viewer() {
        let mut inst = instance();
        inst.add_buffer_window(&[0x00, 0x01, 0x02, 0xFF], "blob.bin", OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect("open");
        let win = inst.current_window().expect("window");
        assert_eq!(win.type_plugin_name(), None);
        assert_eq!(win.content().name(), "GENERIC");
        assert_eq!(win.views().views_count(), 1);
        assert_eq!(win.views().view_by_index(0).map(ViewControl::name), Some("Buffer View"));
        assert_eq!(win.panels().vertical_count(), 1);
        let ctx = win.content().smart_assistant_context("", "").expect("ctx");
        assert_eq!(ctx["Name"], "blob.bin");
        assert_eq!(ctx["ContentSize"], 4);

        // Text content gets a Text viewer first, then the Buffer viewer.
        inst.add_buffer_window(b"hello world\n", "note.txt", OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect("open");
        let win = inst.current_window().expect("window");
        assert_eq!(win.content().name(), "GENERIC");
        let names: Vec<&str> = (0..win.views().views_count())
            .filter_map(|i| win.views().view_by_index(i).map(ViewControl::name))
            .collect();
        assert_eq!(names, ["Text View", "Buffer View"]);
        // Start() made view 0 current.
        assert_eq!(win.views().current_index(), 0);
    }

    #[test]
    fn best_match_asks_selector_when_ambiguous() {
        // ".exe" matches PE by extension but its Validate rejects (no
        // MZ); the "#!" line matches SCRIPT by content: unambiguous.
        let mut inst = instance();
        let data = b"#!/bin/sh\n";
        inst.add_buffer_window(data, "run.exe", OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect("open");
        assert_eq!(inst.current_window().map(FileWindowModel::type_plugin_name), Some(Some("SCRIPT")));

        // MZ content + ".sh": SCRIPT (extension) and PE (content) both
        // match → selector; cancel aborts the open.
        let err = inst
            .add_buffer_window(b"MZxx", "two.sh", OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect_err("canceled");
        assert!(matches!(err, InstanceError::OpenCanceled));
        assert_eq!(inst.objects_count(), 1);

        // Extension matches are listed first (SCRIPT), then content (PE).
        inst.add_buffer_window(b"MZxx", "two.sh", OpenMethod::BestMatch, "", &mut PickFirst)
            .expect("picked");
        assert_eq!(inst.current_window().map(FileWindowModel::type_plugin_name), Some(Some("SCRIPT")));

        // Choosing past the list means the default plugin.
        inst.add_buffer_window(b"MZxx", "two.sh", OpenMethod::BestMatch, "", &mut PickDefault)
            .expect("default");
        assert_eq!(inst.current_window().map(FileWindowModel::type_plugin_name), Some(None));
    }

    #[test]
    fn first_match_select_and_force_type() {
        struct Count(usize);
        impl TypeSelector for Count {
            fn select(&mut self, c: &[&RegisteredTypePlugin]) -> Option<usize> {
                self.0 = c.len();
                Some(1)
            }
        }
        let mut inst = instance();
        inst.add_buffer_window(b"MZxx", "a.exe", OpenMethod::FirstMatch, "", &mut CancelSelector)
            .expect("first");
        assert_eq!(inst.current_window().map(FileWindowModel::type_plugin_name), Some(Some("PE")));

        // Select always asks, over every registered plugin.
        let mut count = Count(0);
        inst.add_buffer_window(b"zzz", "b.bin", OpenMethod::Select, "", &mut count)
            .expect("select");
        assert_eq!(count.0, 3);
        assert_eq!(inst.current_window().map(FileWindowModel::type_plugin_name), Some(Some("SCRIPT")));

        // ForceType: case-insensitive exact-length name, must validate.
        inst.add_buffer_window(b"MZxx", "c.bin", OpenMethod::ForceType, "pe", &mut CancelSelector)
            .expect("forced");
        assert_eq!(inst.current_window().map(FileWindowModel::type_plugin_name), Some(Some("PE")));
        // Unknown or rejecting type falls back to selection (canceled).
        assert!(matches!(
            inst.add_buffer_window(b"MZxx", "d.bin", OpenMethod::ForceType, "P", &mut CancelSelector),
            Err(InstanceError::OpenCanceled)
        ));
        assert!(matches!(
            inst.add_buffer_window(b"nope", "e.bin", OpenMethod::ForceType, "PE", &mut CancelSelector),
            Err(InstanceError::OpenCanceled)
        ));
    }

    #[test]
    fn populate_failure_discards_the_window() {
        let mut inst = instance();
        let err = inst
            .add_buffer_window(&[0xCA, 0xFE, 0x00], "x.bin", OpenMethod::FirstMatch, "", &mut CancelSelector)
            .expect_err("populate fails");
        assert!(matches!(err, InstanceError::PopulateFailed(PluginError::Window(_))));
        assert_eq!(inst.objects_count(), 0);
        assert!(inst.current_object().is_none());
    }

    #[test]
    fn missing_file_is_reported_in_error_list() {
        let mut inst = instance();
        let missing = std::env::temp_dir().join("gview-does-not-exist-12345.bin");
        let err = inst
            .add_file_window(&missing, OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect_err("missing");
        assert!(matches!(err, InstanceError::OpenFile { .. }));
        let errors = inst.take_errors();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("Fail to open file: "));
        assert!(inst.take_errors().is_empty());
        let dir = std::env::temp_dir();
        assert!(matches!(
            inst.add_file_window(&dir, OpenMethod::BestMatch, "", &mut CancelSelector),
            Err(InstanceError::FolderUnsupported(_))
        ));
    }

    #[test]
    fn menu_commands_map_like_cpp_on_event() {
        assert_eq!(menu_action(menu::ARRANGE_CASCADE), InstanceAction::Arrange(ArrangeMethod::Cascade));
        assert_eq!(menu_action(menu::ARRANGE_GRID), InstanceAction::Arrange(ArrangeMethod::Grid));
        assert_eq!(
            menu_action(menu::ARRANGE_HORIZONTALLY),
            InstanceAction::Arrange(ArrangeMethod::Horizontal)
        );
        assert_eq!(menu_action(menu::ARRANGE_VERTICALLY), InstanceAction::Arrange(ArrangeMethod::Vertical));
        assert_eq!(menu_action(menu::EXIT_GVIEW), InstanceAction::Exit);
        assert_eq!(menu_action(menu::OPEN_FILE), InstanceAction::OpenFile);
        assert_eq!(menu_action(menu::OPEN_RESTRICTED_MODE), InstanceAction::RestrictedMode);
        assert_eq!(menu_action(menu::CLOSE), InstanceAction::Unhandled);
        assert_eq!(menu_action(0), InstanceAction::Unhandled);
        assert_eq!(
            menu_action(menu::GENERIC_PLUGINS_CMDID + 2 * menu::GENERIC_PLUGINS_FRAME + 7),
            InstanceAction::RunGenericPlugin { plugin: 2, command: 7 }
        );
        assert_eq!(
            menu_action(menu::GENERIC_PLUGINS_CMDID + menu::GENERIC_PLUGINS_FRAME * menu::GENERIC_PLUGINS_MAX),
            InstanceAction::Unhandled
        );
    }

    #[test]
    fn generic_plugin_commands_run_on_the_current_object() {
        let mut inst = instance();
        // No window: nothing to run on.
        assert_eq!(
            inst.on_menu_command(menu::GENERIC_PLUGINS_CMDID),
            InstanceAction::RunGenericPlugin { plugin: 0, command: 0 }
        );
        assert!(!inst.run_generic_plugin(0, 0));

        inst.add_buffer_window(b"MZxx", "a.exe", OpenMethod::FirstMatch, "", &mut CancelSelector)
            .expect("open");
        assert!(inst.run_generic_plugin(0, 0));
        assert!(!inst.run_generic_plugin(0, 1));
        assert!(!inst.run_generic_plugin(3, 0));
        assert!(inst.take_errors().is_empty());

        inst.add_buffer_window(b"", "empty.bin", OpenMethod::FirstMatch, "", &mut CancelSelector)
            .expect("open empty");
        assert!(!inst.run_generic_plugin(0, 0));
        assert_eq!(inst.take_errors().len(), 1);
    }

    #[test]
    fn probe_text_follows_encoding() {
        assert!(probe_text(&[0x00, 0xFF, 0x10]).is_empty());
        assert_eq!(probe_text(b"ab"), utf16("ab"));
        assert_eq!(probe_text(&[0xEF, 0xBB, 0xBF, b'x']), utf16("x"));
        assert_eq!(probe_text(&[0xFF, 0xFE, b'y', 0x00]), utf16("y"));
        assert_eq!(probe_text(&[0xFE, 0xFF, 0x00, b'z']), utf16("z"));
        assert_eq!(extension_of_path(Path::new("dir/a.tar.gz")).as_deref(), Some(".gz"));
        assert_eq!(extension_of_path(Path::new("noext")), None);
    }

    #[test]
    fn viewer_slot_defaults_and_window_handle_contract() {
        let mut inst = instance();
        inst.add_buffer_window(b"MZxx", "a.exe", OpenMethod::FirstMatch, "", &mut CancelSelector)
            .expect("open");
        let win = inst.current_window_mut().expect("window");
        assert_eq!(WindowHandle::views_count(win), 2);
        assert_eq!(WindowHandle::current_view(win), Some(0));
        assert!(WindowHandle::set_view_by_index(win, 1));
        assert!(!WindowHandle::set_view_by_index(win, 9));
        assert_eq!(WindowHandle::current_view(win), Some(1));
        assert!(win.views_mut().next_view());
        assert_eq!(win.views().current_index(), 0);
        win.content_mut().run_command("noop");
        assert!(format!("{win:?}").contains("PE"));
        assert!(format!("{inst:?}").contains("windows"));
        for kind in [
            ViewerKind::Buffer,
            ViewerKind::Text,
            ViewerKind::Lexical,
            ViewerKind::Image,
            ViewerKind::Grid,
            ViewerKind::Dissasm,
            ViewerKind::Container,
        ] {
            assert!(ViewerSlot::default_name(kind).ends_with(" View"));
        }
    }
}
