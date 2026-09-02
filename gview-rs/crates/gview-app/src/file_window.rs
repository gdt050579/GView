//! `FileWindow`: the per-object `AppCUI` window hosting the smart
//! viewers.
//!
//! C++ anchors: `GViewCore/src/App/FileWindow.cpp`,
//! `Internal.hpp:746-797`; spec `02_SMART_VIEWERS_DEEP` §B–§E, §H;
//! `APPCUI_RS_UI_AND_ASYNC_GUIDE` §1, §5.4, §6.7.
//!
//! The shell composes the pieces the earlier tasks modelled:
//! [`layout`] builds the splitter / tab tree, [`view_container`] and
//! [`panels`] hold the viewers and panel dock (owned through the
//! [`FileWindowModel`] the lifecycle task populates), [`events`] routes
//! keys and command IDs, and [`command_bar`] lists the F-key entries.
//!
//! Composition (C++ constructor + `Start()`):
//!
//! 1. `Window(name, "d:c", Sizeable)` titled with the object name and
//!    tagged with the type name (`SetText` / `SetTag`);
//! 2. the §B.2 control tree ([`layout::build_layout`]);
//! 3. one mounted viewer control ([`mount`]) per viewer in the hidden
//!    `view` tab and one page per plugin panel in the
//!    `verticalPanels` / `horizontalPanels` tabs, with
//!    [`CursorInformation`] as horizontal page 0;
//! 4. `Start()`: view page 0 current and focused.
//!
//! Key routing: `AppCUI` windows cannot override raw key handling
//! (`OnKeyPressed` is fixed for `#[Window]`), so the C++
//! `FileWindow::OnKeyEvent` shortcuts (Ctrl+G / Ctrl+F / Ctrl+C /
//! Ctrl+Insert / Alt+F / Escape) are evaluated by the focused viewer
//! control (each one applies [`events::route_key`] internally) and
//! forwarded to the window as custom events — the same "children
//! first, then the window" precedence as the C++ chain. Command-bar
//! commands go through the generated `Commands` enum and
//! [`events::dispatch_command`].
//!
//! Dialogs and windows that belong to later tasks (properties, key
//! configurator, add-note, analysis engine, re-open with type
//! selection, generic-plugin execution) are surfaced as
//! [`ShellRequest`]s for the instance / shell loop to fulfil; the
//! Smart Assistants tab (`queryInterface.Start()`) is a no-op until
//! the assistant crate exists.

pub mod command_bar;
pub mod events;
pub mod layout;
pub mod mount;
pub mod panel_mount;
pub mod panels;
pub mod view_container;

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Mutex, PoisonError};

use appcui::prelude::*;
use gview_core::object::ObjectType;
use gview_plugin::type_plugin::{CommandDef, TypePlugin, ViewerKind};
use gview_view::buffer_viewer::color::PositionToColorCallback;
use gview_view::container_viewer::open::OpenItemInterface;
use gview_view::container_viewer::tree::EnumerateInterface;
use gview_view::view_control::ViewControl;
use gview_viewers::buffer_view::{bufferview, BufferView};
use gview_viewers::container_view::{containerview, ContainerView};
use gview_viewers::dissasm_view::{dissasmview, DissasmView};
use gview_viewers::text_view::{textview, TextView};
use gview_viewers::{CursorSnapshot, SharedCursorInfo};

use crate::instance::window_lifecycle::{FileWindowModel, ViewerSlot};
use command_bar::{build_command_bar, TypePluginCommand};
use events::{cmd, dispatch_command, CommandAction};
use layout::{
    build_layout, FileWindowLayout, CMD_FOR_TYPE_PLUGIN_START, CMD_SHOW_HORIZONTAL_PANEL,
    CMD_SHOW_VIEW_CONFIG_PANEL,
};
use mount::{mount_viewer, MountContext, MountedViewer};
use panel_mount::{mount_panel, InformationFallback, MountedPanel};
use panels::PanelEntry;

pub use mount::ViewDialog;

/// The window model shared with its child controls.
///
/// C++ children hold `Reference<FileWindow>`. UI-thread only, hence
/// `Rc`; the `Mutex` gives interior mutability without `RefCell`
/// borrow panics (poisoning is tolerated).
pub type SharedModel = Rc<Mutex<FileWindowModel>>;

/// Command-bar slots reserved for type-plugin commands
/// (`CMD_FOR_TYPE_PLUGIN_START + idx`; the C++ range allows 1000, the
/// generated `Commands` enum needs a fixed count).
pub const MAX_TYPE_PLUGIN_COMMANDS: usize = 16;
/// Command-bar slots reserved for generic-plugin commands
/// (`Instance::UpdateCommandBar`).
pub const MAX_GENERIC_PLUGIN_COMMANDS: usize = 16;
/// Bottom-panel switch commands (`CMD_SHOW_HORIZONTAL_PANEL + n`).
pub const MAX_HORIZONTAL_PANELS: usize = 8;

/// Bottom-bar caption of the cursor-information page
/// (C++ `AddSingleChoiceItem("<->", …)`, `FileWindow.cpp:53-66`).
pub const CURSOR_INFO_CAPTION: &str = "<->";

/// C++ `FileWindow` error texts (`ShowGoToDialog` & co.).
pub const ERR_NO_GOTO: &str = "This view has no implementation for GoTo command !";
/// Find counterpart.
pub const ERR_NO_FIND: &str = "This view has no implementation for Find command !";
/// Copy counterpart.
pub const ERR_NO_COPY: &str = "This view has no implementation for Copy command !";
/// `CMD_CHOSE_NEW_TYPE` on a non-file object (`FileWindow.cpp:244-246`).
pub const ERR_CHOOSE_TYPE_UNSUPPORTED: &str = "Not implemented yet for this type of object (buffer/PID/Folder)";

/// One generic-plugin command-bar slot (`Instance::UpdateCommandBar`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericCommandSlot {
    /// Bound key.
    pub key: Key,
    /// Caption.
    pub caption: String,
    /// Generic-plugin index.
    pub plugin: usize,
    /// Command index within the plugin.
    pub command: usize,
}

/// Work the window hands back to the instance / shell loop
/// (C++ calls into `GView::App::*` or other windows).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellRequest {
    /// `ShowFilePropertiesDialog()`.
    ShowProperties,
    /// `ShowKeyConfiguratorWindow()`.
    ShowKeyConfigurator,
    /// `GView::App::ShowAddNoteDialog()`.
    AddNote,
    /// `analysisEngine->ShowAnalysisEngineWindow()`.
    ShowAnalysisEngine,
    /// `GView::App::OpenFile(path, OpenMethod::Select)`.
    ReopenWithTypeSelect(PathBuf),
    /// `genericPlugins[plugin].Run(command, GetCurrentObject())`.
    RunGenericPlugin {
        /// Generic-plugin index.
        plugin: usize,
        /// Command index.
        command: usize,
    },
    /// `MessageBox::ShowError("Error", text)`.
    Error(&'static str),
    /// The current view asked the window for one of its dialogs
    /// (C++ `FileWindow::ShowGoToDialog` / `ShowFindDialog` /
    /// `ShowCopyDialog` after the view accepted the request). The
    /// dialogs themselves are built by `file-window-shell-integration`
    /// (`00_APP §5.6`).
    ShowViewDialog(ViewDialog),
    /// The view on page `view` holds a pending "open this selection /
    /// entry as a new object" request (C++ `GView::App::OpenBuffer`,
    /// reached from `TextViewer`'s `Enter` and from activating a
    /// `ContainerViewer` item). The shell drains it from the control
    /// with `take_pending_open()`.
    OpenPendingObject {
        /// View-tab page index of the control holding the request.
        view: usize,
    },
}

/// Widest bar [`CursorInformation`] formats without allocating.
const CURSOR_BAR_CAPACITY: usize = 128;

/// C++ `CursorInformation`: the one-line bottom bar
/// (`FileWindow.cpp:26-34`).
///
/// C++ paints it with
/// `win->GetCurrentView()->PaintCursorInformation(...)` — it reaches
/// straight into the live viewer. `AppCUI-rs` controls are siblings
/// inside a `Tab` and cannot borrow one another, so each mounted
/// viewer publishes a [`CursorSnapshot`] into its own slot
/// (`00_APP §5.3.5`) and this control formats the slot belonging to
/// the current page. Formatting writes into an inline buffer, so
/// `on_paint` allocates nothing (`§6.3`).
#[CustomControl(overwrite = OnPaint)]
pub struct CursorInformation {
    model: SharedModel,
    /// One slot per view page, in view-tab order.
    slots: Vec<SharedCursorInfo>,
    /// Paint scratch; `on_paint` takes `&self`, hence the (uncontended)
    /// `Mutex` — a poisoned lock degrades instead of panicking
    /// (`§0.3 D4`).
    bar: Mutex<[u8; CURSOR_BAR_CAPACITY]>,
}

impl CursorInformation {
    /// Bound to the window model and the mounted views' cursor slots.
    #[must_use]
    pub fn new(model: SharedModel, slots: Vec<SharedCursorInfo>) -> Self {
        Self {
            base: ControlBase::new(layout!("d:f"), false),
            model,
            slots,
            bar: Mutex::new([b' '; CURSOR_BAR_CAPACITY]),
        }
    }

    /// The snapshot the bar currently shows.
    #[must_use]
    pub fn snapshot(&self) -> CursorSnapshot {
        let index = self
            .model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .views()
            .current_index();
        self.slots.get(index).map(SharedCursorInfo::read).unwrap_or_default()
    }
}

impl OnPaint for CursorInformation {
    fn on_paint(&self, surface: &mut Surface, theme: &Theme) {
        surface.clear(Character::with_attributes(' ', theme.window.normal));
        let snapshot = self.snapshot();
        let mut bar = self.bar.lock().unwrap_or_else(PoisonError::into_inner);
        let len = write_cursor_bar(&mut bar, &snapshot);
        let text = bar.get(..len).unwrap_or(&[]);
        surface.write_ascii(0, 0, text, theme.window.normal, false);
        drop(bar);
    }
}

/// Formats one [`CursorSnapshot`] into `out`, returning the byte
/// count.
///
/// Layout (C++ `PrintCursorPosInfo`, `ViewControl.cpp`, plus the view
/// name, which the C++ never needs because it calls the live control):
/// `"<view>  Sel:<start>,<len>  Pos:<offset>  <pct>%"`, with
/// `"NO Selection"` and `"----"` for the empty cases. ASCII only and
/// allocation-free.
fn write_cursor_bar(out: &mut [u8; CURSOR_BAR_CAPACITY], snapshot: &CursorSnapshot) -> usize {
    let mut len = 0_usize;
    push_bytes(out, &mut len, snapshot.name_str().as_bytes());
    push_bytes(out, &mut len, b"  ");
    if snapshot.has_selection {
        push_bytes(out, &mut len, b"Sel:");
        push_base(out, &mut len, snapshot.selection_start, 16);
        push_bytes(out, &mut len, b",");
        push_base(out, &mut len, snapshot.selection_len(), 16);
    } else {
        push_bytes(out, &mut len, b"NO Selection");
    }
    push_bytes(out, &mut len, b"  Pos:");
    push_base(out, &mut len, snapshot.offset, u64::from(snapshot.base.max(2)));
    push_bytes(out, &mut len, b"  ");
    if let Some(percent) = snapshot.percent() {
        push_base(out, &mut len, percent, 10);
        push_bytes(out, &mut len, b"%");
    } else {
        push_bytes(out, &mut len, b"----");
    }
    len
}

/// Appends `src` to `out`, stopping at the buffer end.
fn push_bytes(out: &mut [u8; CURSOR_BAR_CAPACITY], len: &mut usize, src: &[u8]) {
    for byte in src {
        let Some(slot) = out.get_mut(*len) else {
            return;
        };
        *slot = *byte;
        *len = len.saturating_add(1);
    }
}

/// Appends `value` in `base` (2..=16), upper-case, no padding.
fn push_base(out: &mut [u8; CURSOR_BAR_CAPACITY], len: &mut usize, value: u64, base: u64) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let base = base.clamp(2, 16);
    // 64 binary digits is the widest possible rendering.
    let mut scratch = [b'0'; 64];
    let mut count = 0_usize;
    let mut left = value;
    while left > 0 && count < scratch.len() {
        let digit = left.checked_rem(base).unwrap_or(0) as usize;
        if let (Some(slot), Some(ch)) = (scratch.get_mut(count), DIGITS.get(digit)) {
            *slot = *ch;
        }
        count = count.saturating_add(1);
        left = left.checked_div(base).unwrap_or(0);
    }
    if count == 0 {
        push_bytes(out, len, b"0");
        return;
    }
    while count > 0 {
        count = count.saturating_sub(1);
        let byte = scratch.get(count).copied().unwrap_or(b'0');
        push_bytes(out, len, &[byte]);
    }
}

#[Window(
    events = CommandBarEvents,
    custom_events = BufferViewEvents + TextViewEvents + ContainerViewEvents + DissasmViewEvents,
    commands = [
        NextView, GoTo, Find, ChooseType, KeyConfigurator, AddNote, AnalysisEngine, ShowViewConfig,
        HPanel0, HPanel1, HPanel2, HPanel3, HPanel4, HPanel5, HPanel6, HPanel7,
        Plugin0, Plugin1, Plugin2, Plugin3, Plugin4, Plugin5, Plugin6, Plugin7,
        Plugin8, Plugin9, Plugin10, Plugin11, Plugin12, Plugin13, Plugin14, Plugin15,
        Generic0, Generic1, Generic2, Generic3, Generic4, Generic5, Generic6, Generic7,
        Generic8, Generic9, Generic10, Generic11, Generic12, Generic13, Generic14, Generic15
    ]
)]
pub struct FileWindow {
    model: SharedModel,
    layout: FileWindowLayout,
    /// The mounted viewer controls, in view-tab order (`00_APP §5.3`).
    view_hosts: Vec<MountedViewer>,
    /// Bottom-bar slot of each mounted view (`§5.3.5`).
    cursor_slots: Vec<SharedCursorInfo>,
    /// Mounted sidebar panels, in `verticalPanels` tab order (`§5.4`).
    vertical_panel_hosts: Vec<MountedPanel>,
    /// Mounted bottom panels, in `horizontalPanels` tab order; index 0
    /// is the window's own [`CursorInformation`] and has no entry here.
    horizontal_panel_hosts: Vec<MountedPanel>,
    plugin_commands: Vec<CommandDef>,
    generic_commands: Vec<GenericCommandSlot>,
    requests: Vec<ShellRequest>,
    interactive: bool,
    started: bool,
}

const HPANEL_COMMANDS: [filewindow::Commands; MAX_HORIZONTAL_PANELS] = [
    filewindow::Commands::HPanel0,
    filewindow::Commands::HPanel1,
    filewindow::Commands::HPanel2,
    filewindow::Commands::HPanel3,
    filewindow::Commands::HPanel4,
    filewindow::Commands::HPanel5,
    filewindow::Commands::HPanel6,
    filewindow::Commands::HPanel7,
];

const PLUGIN_COMMANDS: [filewindow::Commands; MAX_TYPE_PLUGIN_COMMANDS] = [
    filewindow::Commands::Plugin0,
    filewindow::Commands::Plugin1,
    filewindow::Commands::Plugin2,
    filewindow::Commands::Plugin3,
    filewindow::Commands::Plugin4,
    filewindow::Commands::Plugin5,
    filewindow::Commands::Plugin6,
    filewindow::Commands::Plugin7,
    filewindow::Commands::Plugin8,
    filewindow::Commands::Plugin9,
    filewindow::Commands::Plugin10,
    filewindow::Commands::Plugin11,
    filewindow::Commands::Plugin12,
    filewindow::Commands::Plugin13,
    filewindow::Commands::Plugin14,
    filewindow::Commands::Plugin15,
];

const GENERIC_COMMANDS: [filewindow::Commands; MAX_GENERIC_PLUGIN_COMMANDS] = [
    filewindow::Commands::Generic0,
    filewindow::Commands::Generic1,
    filewindow::Commands::Generic2,
    filewindow::Commands::Generic3,
    filewindow::Commands::Generic4,
    filewindow::Commands::Generic5,
    filewindow::Commands::Generic6,
    filewindow::Commands::Generic7,
    filewindow::Commands::Generic8,
    filewindow::Commands::Generic9,
    filewindow::Commands::Generic10,
    filewindow::Commands::Generic11,
    filewindow::Commands::Generic12,
    filewindow::Commands::Generic13,
    filewindow::Commands::Generic14,
    filewindow::Commands::Generic15,
];

/// Maps a C++ command ID to the command-bar enum, when one exists.
#[must_use]
pub fn command_for_id(id: u32) -> Option<filewindow::Commands> {
    use filewindow::Commands;
    match id {
        cmd::CMD_NEXT_VIEW => Some(Commands::NextView),
        cmd::CMD_GOTO => Some(Commands::GoTo),
        cmd::CMD_FIND => Some(Commands::Find),
        cmd::CMD_CHOSE_NEW_TYPE => Some(Commands::ChooseType),
        cmd::CMD_SHOW_KEY_CONFIGURATOR => Some(Commands::KeyConfigurator),
        cmd::CMD_OPEN_ADD_NOTE => Some(Commands::AddNote),
        cmd::CMD_ANALYSIS_ENGINE => Some(Commands::AnalysisEngine),
        CMD_SHOW_VIEW_CONFIG_PANEL => Some(Commands::ShowViewConfig),
        _ => {
            if let Some(n) = id.checked_sub(CMD_SHOW_HORIZONTAL_PANEL) {
                if let Some(c) = HPANEL_COMMANDS.get(n as usize) {
                    return Some(*c);
                }
            }
            id.checked_sub(CMD_FOR_TYPE_PLUGIN_START)
                .and_then(|n| PLUGIN_COMMANDS.get(n as usize).copied())
        }
    }
}

/// Maps a command-bar enum value back to its C++ command ID
/// (generic slots have no C++ ID and yield `None`).
#[must_use]
pub fn id_for_command(command: filewindow::Commands) -> Option<u32> {
    use filewindow::Commands;
    match command {
        Commands::NextView => Some(cmd::CMD_NEXT_VIEW),
        Commands::GoTo => Some(cmd::CMD_GOTO),
        Commands::Find => Some(cmd::CMD_FIND),
        Commands::ChooseType => Some(cmd::CMD_CHOSE_NEW_TYPE),
        Commands::KeyConfigurator => Some(cmd::CMD_SHOW_KEY_CONFIGURATOR),
        Commands::AddNote => Some(cmd::CMD_OPEN_ADD_NOTE),
        Commands::AnalysisEngine => Some(cmd::CMD_ANALYSIS_ENGINE),
        Commands::ShowViewConfig => Some(CMD_SHOW_VIEW_CONFIG_PANEL),
        other => {
            if let Some(n) = HPANEL_COMMANDS.iter().position(|c| *c == other) {
                return Some(CMD_SHOW_HORIZONTAL_PANEL.saturating_add(n as u32));
            }
            PLUGIN_COMMANDS
                .iter()
                .position(|c| *c == other)
                .map(|n| CMD_FOR_TYPE_PLUGIN_START.saturating_add(n as u32))
        }
    }
}

/// Generic slot index for a `Generic<n>` command.
#[must_use]
pub fn generic_slot_for_command(command: filewindow::Commands) -> Option<usize> {
    GENERIC_COMMANDS.iter().position(|c| *c == command)
}

impl FileWindow {
    /// C++ constructor: wraps a populated [`FileWindowModel`] in an
    /// `AppCUI` window. `plugin_commands` are the type plugin's
    /// commands (`typePlugin->GetCommands()`), `generic_commands` the
    /// instance's generic-plugin slots. `interactive = false` keeps
    /// error dialogs as [`ShellRequest::Error`] only (headless tests).
    #[must_use]
    pub fn new(
        model: FileWindowModel,
        plugin_commands: Vec<CommandDef>,
        generic_commands: Vec<GenericCommandSlot>,
        interactive: bool,
    ) -> Self {
        let (title, tag, view_names, vertical_entries, horizontal_entries) = {
            let object = model.object();
            let guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            let title = guard.name().to_owned();
            drop(guard);
            let tag = model.content().name().to_owned();
            let views = model.views();
            let names: Vec<String> = (0..views.views_count())
                .filter_map(|i| views.view_by_index(i).map(|v| v.name().to_owned()))
                .collect();
            (
                title,
                tag,
                names,
                model.panels().vertical_panels().to_vec(),
                model.panels().horizontal_panels().to_vec(),
            )
        };

        let model: SharedModel = Rc::new(Mutex::new(model));
        let mut base = Window::new(&title, layout!("d:f"), window::Flags::Sizeable);
        base.set_tag(&tag);
        let layout = build_layout(&mut base);

        let mut win = Self {
            base,
            model: SharedModel::clone(&model),
            layout,
            view_hosts: Vec::new(),
            cursor_slots: Vec::new(),
            vertical_panel_hosts: Vec::new(),
            horizontal_panel_hosts: Vec::new(),
            plugin_commands,
            generic_commands,
            requests: Vec::new(),
            interactive,
            started: false,
        };

        // View pages (hidden tab bar): the real viewer controls.
        win.mount_views(&view_names);
        let cursor_slots = win.cursor_slots.clone();

        // Plugin side panels (captions carry `&` hot keys).
        let vertical_tab = win.layout.vertical_panels;
        win.vertical_panel_hosts = win.mount_panels(vertical_tab, &vertical_entries);

        // Bottom panels: cursor information first, then plugin panels.
        let horizontal_tab = win.layout.horizontal_panels;
        let cursor_info = CursorInformation::new(model, cursor_slots);
        if let Some(tab) = win.control_mut(horizontal_tab) {
            let page = tab.add_tab(
                horizontal_entries
                    .first()
                    .map_or(CURSOR_INFO_CAPTION, |entry| entry.caption.as_str()),
            );
            tab.add(page, cursor_info);
        }
        win.horizontal_panel_hosts =
            win.mount_panels(horizontal_tab, horizontal_entries.get(1..).unwrap_or(&[]));
        if let Some(tab) = win.control_mut(horizontal_tab) {
            tab.set_current_tab(0);
        }
        win
    }

    /// The window's control tree handles (C++ `FileWindow` members).
    #[must_use]
    pub const fn layout(&self) -> &FileWindowLayout {
        &self.layout
    }

    /// The shared window model.
    #[must_use]
    pub fn model(&self) -> SharedModel {
        SharedModel::clone(&self.model)
    }

    /// C++ `FileWindow::Start()`: view page 0 current and focused
    /// (`queryInterface.Start()` is a no-op until the assistant crate
    /// exists).
    pub fn start(&mut self) {
        self.model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .start();
        let view_tab = self.layout.view;
        if let Some(tab) = self.control_mut(view_tab) {
            tab.set_current_tab(0);
        }
        self.focus_mounted(0);
        self.started = true;
    }

    /// `true` after [`Self::start`].
    #[must_use]
    pub const fn is_started(&self) -> bool {
        self.started
    }

    /// Number of viewer pages (`GetViewsCount`).
    #[must_use]
    pub const fn views_count(&self) -> usize {
        self.view_hosts.len()
    }

    /// Index of the current viewer.
    #[must_use]
    pub fn current_view_index(&self) -> usize {
        self.model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .views()
            .current_index()
    }

    /// Name of the current viewer (the F4 caption).
    #[must_use]
    pub fn current_view_name(&self) -> String {
        self.model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .views()
            .current_view()
            .map(|v| v.name().to_owned())
            .unwrap_or_default()
    }

    /// Pending shell requests, drained.
    pub fn take_requests(&mut self) -> Vec<ShellRequest> {
        std::mem::take(&mut self.requests)
    }

    /// Pending shell requests, without draining.
    #[must_use]
    pub fn requests(&self) -> &[ShellRequest] {
        &self.requests
    }

    /// C++ ctor + `CreateViewer`: one real viewer control per page
    /// (`00_APP §5.2 (1)`, `§5.3`).
    ///
    /// The plugin's `ViewerRequest` is *moved* into each control, and
    /// each control gets its own bottom-bar slot (`§5.3.5`).
    fn mount_views(&mut self, names: &[String]) {
        let model = SharedModel::clone(&self.model);
        let view_tab = self.layout.view;
        let mut mounted = Vec::with_capacity(names.len());
        let mut slots = Vec::with_capacity(names.len());
        for (index, name) in names.iter().enumerate() {
            let Some(kind) = ({
                let mut guard = model.lock().unwrap_or_else(PoisonError::into_inner);
                slot_at(&mut guard, index).map(|slot| slot.kind())
            }) else {
                continue;
            };
            // The hooks are fetched before the slot is borrowed: the
            // plugin and the viewers live in the same model.
            let (colorizer, enumerator, opener) = {
                let guard = model.lock().unwrap_or_else(PoisonError::into_inner);
                plugin_hooks(guard.content(), kind)
            };
            let cursor = SharedCursorInfo::new();
            let mut guard = model.lock().unwrap_or_else(PoisonError::into_inner);
            let object = guard.object();
            let Some(slot) = slot_at(&mut guard, index) else {
                continue;
            };
            let Some(tab) = self.control_mut(view_tab) else {
                break;
            };
            let page = tab.add_tab(name);
            let context = MountContext {
                object: &object,
                colorizer,
                enumerator,
                opener,
                cursor: cursor.clone(),
                index,
            };
            mounted.push(mount_viewer(tab, page, slot, context));
            slots.push(cursor);
            drop(guard);
        }
        self.view_hosts = mounted;
        self.cursor_slots = slots;
    }

    /// C++ `AddPanel`: one `ListView` per plugin panel (`§5.4.2`).
    ///
    /// The content comes from `TypePlugin::panel_content(panel_id)`;
    /// a plugin that does not implement the id gets the generic
    /// `Information` fallback instead.
    fn mount_panels(&mut self, tab_handle: Handle<Tab>, entries: &[PanelEntry]) -> Vec<MountedPanel> {
        let model = SharedModel::clone(&self.model);
        let mut mounted = Vec::with_capacity(entries.len());
        for entry in entries {
            let (content, fallback) = {
                let guard = model.lock().unwrap_or_else(PoisonError::into_inner);
                let content = guard.content().panel_content(&entry.panel_id);
                let object = guard.object();
                let type_name = guard.content().name();
                drop(guard);
                let object = object.lock().unwrap_or_else(PoisonError::into_inner);
                let fallback = InformationFallback::new(&object, type_name);
                drop(object);
                (content, fallback)
            };
            let Some(tab) = self.control_mut(tab_handle) else {
                break;
            };
            let page = tab.add_tab(&entry.caption);
            mounted.push(mount_panel(tab, page, content, &fallback));
        }
        mounted
    }

    /// The mounted sidebar panels, in `verticalPanels` tab order.
    #[must_use]
    pub fn vertical_panels(&self) -> &[MountedPanel] {
        &self.vertical_panel_hosts
    }

    /// The mounted bottom panels, in `horizontalPanels` tab order after
    /// the cursor-information page.
    #[must_use]
    pub fn horizontal_panels(&self) -> &[MountedPanel] {
        &self.horizontal_panel_hosts
    }

    /// Gives the keyboard focus to the control on page `index`
    /// (C++ `view->SetFocus()`).
    fn focus_mounted(&mut self, index: usize) {
        match self.view_hosts.get(index).copied() {
            Some(MountedViewer::Buffer(handle)) => self.request_focus_for_control(handle),
            Some(MountedViewer::Text(handle)) => self.request_focus_for_control(handle),
            Some(MountedViewer::Container(handle)) => self.request_focus_for_control(handle),
            Some(MountedViewer::Dissasm(handle)) => self.request_focus_for_control(handle),
            Some(MountedViewer::Unavailable(handle)) => self.request_focus_for_control(handle),
            None => {}
        }
    }

    /// Asks the mounted control on page `index` to open `dialog`
    /// (`00_APP §5.6`: `self.control_mut(handle).show_*_dialog()`).
    ///
    /// A control that implements the dialog raises its own event, which
    /// comes back through the `<control>Events` impls below; one that
    /// does not returns `false` and the caller prints the C++ error.
    fn ask_view_dialog(&mut self, index: usize, dialog: ViewDialog) -> bool {
        match self.view_hosts.get(index).copied() {
            Some(MountedViewer::Buffer(handle)) => self
                .control_mut(handle)
                .is_some_and(|view| request_dialog(view, dialog)),
            Some(MountedViewer::Text(handle)) => self
                .control_mut(handle)
                .is_some_and(|view| request_dialog(view, dialog)),
            Some(MountedViewer::Container(handle)) => self
                .control_mut(handle)
                .is_some_and(|view| request_dialog(view, dialog)),
            Some(MountedViewer::Dissasm(handle)) => self
                .control_mut(handle)
                .is_some_and(|view| request_dialog(view, dialog)),
            Some(MountedViewer::Unavailable(handle)) => self
                .control_mut(handle)
                .is_some_and(|view| request_dialog(view, dialog)),
            None => false,
        }
    }

    /// View-tab page of the control addressed by `handle`.
    fn view_index_of<T>(&self, handle: Handle<T>) -> Option<usize> {
        self.view_hosts.iter().position(|view| view.matches(handle))
    }

    /// The mounted control on page `index` (tests and the shell task).
    #[must_use]
    pub fn mounted_view(&self, index: usize) -> Option<MountedViewer> {
        self.view_hosts.get(index).copied()
    }

    /// The bottom-bar slot of page `index`.
    #[must_use]
    pub fn cursor_slot(&self, index: usize) -> Option<&SharedCursorInfo> {
        self.cursor_slots.get(index)
    }

    /// A view accepted a dialog request; the shell opens it (`§5.6`).
    fn on_view_dialog_requested(&mut self, dialog: ViewDialog) {
        self.requests.push(ShellRequest::ShowViewDialog(dialog));
    }

    /// A view holds a pending "open as a new object" request.
    fn on_open_requested<T>(&mut self, handle: Handle<T>) {
        let view = self.view_index_of(handle).unwrap_or_else(|| self.current_view_index());
        self.requests.push(ShellRequest::OpenPendingObject { view });
    }

    fn sync_view_tab(&mut self) {
        let index = self.current_view_index();
        let view_tab = self.layout.view;
        if let Some(tab) = self.control_mut(view_tab) {
            tab.set_current_tab(index);
        }
        // C++ `GoToNextTabPage` / `SetViewByIndex` leave the focus on
        // the view; the mounted control must take it so its key matrix
        // keeps working.
        self.focus_mounted(index);
    }

    /// C++ `CMD_NEXT_VIEW` (`view->GoToNextTabPage()`): F4 cycling.
    pub fn next_view(&mut self) -> bool {
        let moved = self
            .model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .views_mut()
            .next_view();
        if moved {
            self.sync_view_tab();
        }
        moved
    }

    /// C++ `SetViewByIndex`.
    pub fn set_view_by_index(&mut self, index: usize) -> bool {
        let ok = self
            .model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .views_mut()
            .set_view_by_index(index);
        if ok {
            self.sync_view_tab();
        }
        ok
    }

    fn error(&mut self, text: &'static str) {
        self.requests.push(ShellRequest::Error(text));
        if self.interactive {
            dialogs::error("Error", text);
        }
    }

    /// C++ `FileWindow::ShowGoToDialog` / `ShowFindDialog` /
    /// `ShowCopyDialog`: asks the current view, and prints the C++
    /// error text when the view has no such dialog (a dialog too, when
    /// interactive).
    pub fn show_view_dialog(&mut self, dialog: ViewDialog) {
        if self.view_hosts.is_empty() {
            return;
        }
        let index = self.current_view_index();
        if !self.ask_view_dialog(index, dialog) {
            self.error(match dialog {
                ViewDialog::GoTo => ERR_NO_GOTO,
                ViewDialog::Find => ERR_NO_FIND,
                ViewDialog::Copy => ERR_NO_COPY,
            });
        }
    }

    /// Focuses the view tab (Escape / Alt+F, `view->SetFocus()`).
    pub fn focus_view(&mut self) {
        let index = self.current_view_index();
        self.focus_mounted(index);
    }

    /// Switches the bottom panel (`CMD_SHOW_HORIZONTAL_PANEL + n`).
    pub fn show_horizontal_panel(&mut self, index: usize) -> bool {
        let id = CMD_SHOW_HORIZONTAL_PANEL.saturating_add(index as u32);
        let known = {
            let mut model = self.model.lock().unwrap_or_else(PoisonError::into_inner);
            let count = model.panels().horizontal_count();
            model.panels_mut().handle_command(id);
            drop(model);
            index < count
        };
        if !known {
            return false;
        }
        let horizontal_tab = self.layout.horizontal_panels;
        if let Some(tab) = self.control_mut(horizontal_tab) {
            tab.set_current_tab(index);
        }
        self.request_focus_for_control(horizontal_tab);
        true
    }

    /// Executes one routed command (`FileWindow::OnEvent`).
    pub fn apply(&mut self, action: CommandAction) {
        match action {
            CommandAction::NextView => {
                self.next_view();
            }
            CommandAction::ShowGoTo => self.show_view_dialog(ViewDialog::GoTo),
            CommandAction::ShowFind => self.show_view_dialog(ViewDialog::Find),
            CommandAction::ShowProperties => self.requests.push(ShellRequest::ShowProperties),
            CommandAction::ShowKeyConfigurator => self.requests.push(ShellRequest::ShowKeyConfigurator),
            CommandAction::AddNote => self.requests.push(ShellRequest::AddNote),
            CommandAction::ShowAnalysisEngine => self.requests.push(ShellRequest::ShowAnalysisEngine),
            CommandAction::ChooseNewType => {
                let object = self.model.lock().unwrap_or_else(PoisonError::into_inner).object();
                let path = object
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .path()
                    .to_path_buf();
                self.requests.push(ShellRequest::ReopenWithTypeSelect(path));
            }
            CommandAction::ChooseNewTypeUnsupported => self.error(ERR_CHOOSE_TYPE_UNSUPPORTED),
            CommandAction::ShowHorizontalPanel(n) => {
                self.show_horizontal_panel(n);
            }
            CommandAction::RunTypePluginCommand(idx) => {
                if let Some(name) = self.plugin_commands.get(idx).map(|c| c.name.clone()) {
                    self.model
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .content_mut()
                        .run_command(&name);
                }
            }
            CommandAction::NotHandled => {}
        }
    }

    /// Routes a C++ command ID (`FileWindow::OnEvent`).
    pub fn on_command_id(&mut self, id: u32) -> CommandAction {
        let (is_file, has_plugin) = {
            let model = self.model.lock().unwrap_or_else(PoisonError::into_inner);
            let object = model.object();
            let guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            (
                guard.object_type() == ObjectType::File,
                model.type_plugin_name().is_some(),
            )
        };
        let action = dispatch_command(id, is_file, has_plugin);
        self.apply(action);
        action
    }
}

impl CommandBarEvents for FileWindow {
    fn on_update_commandbar(&self, commandbar: &mut CommandBar) {
        let plugin: Vec<TypePluginCommand> = self
            .plugin_commands
            .iter()
            .take(MAX_TYPE_PLUGIN_COMMANDS)
            .map(|c| TypePluginCommand {
                key: c.key,
                name: c.name.clone(),
            })
            .collect();
        for entry in build_command_bar(&self.current_view_name(), &plugin) {
            if let Some(command) = command_for_id(entry.command_id) {
                commandbar.set(entry.key, &entry.caption, command);
            }
        }
        for (slot, command) in self.generic_commands.iter().zip(GENERIC_COMMANDS) {
            commandbar.set(slot.key, &slot.caption, command);
        }
    }

    fn on_event(&mut self, command_id: filewindow::Commands) {
        if let Some(id) = id_for_command(command_id) {
            self.on_command_id(id);
        } else if let Some(slot) = generic_slot_for_command(command_id)
            .and_then(|n| self.generic_commands.get(n))
        {
            self.requests.push(ShellRequest::RunGenericPlugin {
                plugin: slot.plugin,
                command: slot.command,
            });
        }
    }
}

impl BufferViewEvents for FileWindow {
    fn on_event(&mut self, _handle: Handle<BufferView>, event: bufferview::Events) -> EventProcessStatus {
        match event {
            bufferview::Events::ShowGoTo => self.on_view_dialog_requested(ViewDialog::GoTo),
            bufferview::Events::ShowFind => self.on_view_dialog_requested(ViewDialog::Find),
            bufferview::Events::ShowCopy => self.on_view_dialog_requested(ViewDialog::Copy),
            bufferview::Events::FocusView => self.focus_view(),
        }
        EventProcessStatus::Processed
    }
}

impl TextViewEvents for FileWindow {
    fn on_event(&mut self, handle: Handle<TextView>, event: textview::Events) -> EventProcessStatus {
        match event {
            textview::Events::ShowGoTo => self.on_view_dialog_requested(ViewDialog::GoTo),
            textview::Events::ShowFind => self.on_view_dialog_requested(ViewDialog::Find),
            textview::Events::ShowCopy => self.on_view_dialog_requested(ViewDialog::Copy),
            textview::Events::FocusView => self.focus_view(),
            textview::Events::OpenSelection => self.on_open_requested(handle),
        }
        EventProcessStatus::Processed
    }
}

impl ContainerViewEvents for FileWindow {
    fn on_event(&mut self, handle: Handle<ContainerView>, event: containerview::Events) -> EventProcessStatus {
        match event {
            containerview::Events::OpenEntry => self.on_open_requested(handle),
            containerview::Events::FocusView => self.focus_view(),
        }
        EventProcessStatus::Processed
    }
}

impl DissasmViewEvents for FileWindow {
    fn on_event(&mut self, handle: Handle<DissasmView>, event: dissasmview::Events) -> EventProcessStatus {
        match event {
            dissasmview::Events::ShowGoTo => self.on_view_dialog_requested(ViewDialog::GoTo),
            dissasmview::Events::ShowFind => self.on_view_dialog_requested(ViewDialog::Find),
            dissasmview::Events::ShowCopy => self.on_view_dialog_requested(ViewDialog::Copy),
            dissasmview::Events::FocusView => self.focus_view(),
            dissasmview::Events::OpenSelection => self.on_open_requested(handle),
        }
        EventProcessStatus::Processed
    }
}

/// The concrete [`ViewerSlot`] behind view page `index`, if any.
///
/// Every viewer the lifecycle created is a `ViewerSlot`; the downcast
/// exists only so the mounting step can *move* the plugin request out
/// (`00_APP §5.3.1`).
fn slot_at(model: &mut FileWindowModel, index: usize) -> Option<&mut ViewerSlot> {
    model
        .views_mut()
        .view_by_index_mut(index)?
        .as_any_mut()?
        .downcast_mut::<ViewerSlot>()
}

/// The three `Settings::Set*Callback` hooks of `00_APP §5.3.3`, in the
/// order [`MountContext`] takes them: colourer, enumerator, opener.
type ViewerHooks = (
    Option<Box<dyn PositionToColorCallback + Send>>,
    Option<Box<dyn EnumerateInterface + Send>>,
    Option<Box<dyn OpenItemInterface + Send>>,
);

/// The plugin hooks a viewer of `kind` consumes (`00_APP §5.3.3`).
///
/// Only the kinds the C++ `Settings` objects carry callbacks for ask
/// the plugin, so a `Text` or `Dissasm` page never triggers a colour
/// snapshot build.
fn plugin_hooks(content: &dyn TypePlugin, kind: ViewerKind) -> ViewerHooks {
    match kind {
        ViewerKind::Buffer => (content.position_to_color(), None, None),
        ViewerKind::Container => (None, content.container_enumerator(), content.container_opener()),
        ViewerKind::Text | ViewerKind::Lexical | ViewerKind::Image | ViewerKind::Grid | ViewerKind::Dissasm => {
            (None, None, None)
        }
    }
}

/// Calls the view's C++ `Show*Dialog` counterpart.
fn request_dialog<V: ViewControl + ?Sized>(view: &mut V, dialog: ViewDialog) -> bool {
    match dialog {
        ViewDialog::GoTo => view.show_goto_dialog(),
        ViewDialog::Find => view.show_find_dialog(),
        ViewDialog::Copy => view.show_copy_dialog(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::window_lifecycle::{CancelSelector, Instance, OpenMethod};
    use gview_core::constants::DEFAULT_CACHE_SIZE;
    use gview_plugin::generic_plugin::GenericPluginRegistry;
    use gview_plugin::type_plugin::{
        KeyRegistry, PanelRequest, Pattern, PluginError, PluginMetadata, TypePlugin, TypePluginRegistry,
        ViewerKind, ViewerRequest, WindowHandle,
    };
    use serde_json::Value as JsonValue;
    use std::sync::Mutex as StdMutex;

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
                commands: vec![CommandDef::new(
                    "DigitalSignature",
                    Key::new(KeyCode::F8, KeyModifier::Alt),
                    "Validate digital signature",
                    0,
                )],
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
            win.add_panel(
                PanelRequest {
                    caption: String::from("&Sections"),
                    panel_id: String::from("pe.sections"),
                },
                false,
            );
            win.create_viewer(ViewerRequest::new(ViewerKind::Buffer))?;
            win.create_viewer(ViewerRequest::new(ViewerKind::Dissasm))?;
            Ok(())
        }
        fn run_command(&mut self, command: &str) {
            RUN_LOG.lock().expect("log").push(command.to_owned());
        }
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _p: &str, _d: &str) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }
    }

    static RUN_LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

    /// A plugin whose only viewer is a kind this build has no control
    /// for, so the window mounts the `§5.3.4` placeholder.
    struct MockGrid;

    impl TypePlugin for MockGrid {
        fn name(&self) -> &'static str {
            "GRID"
        }
        fn validate(buf: &[u8], _extension: &str) -> bool {
            buf.starts_with(b"GRID")
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata {
                pattern: vec![Pattern::Magic(b"GRID".to_vec())],
                ..PluginMetadata::default()
            }
        }
        fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            for kind in KINDS.lock().expect("kinds").iter() {
                win.create_viewer(ViewerRequest::new(*kind))?;
            }
            Ok(())
        }
        fn run_command(&mut self, _command: &str) {}
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _p: &str, _d: &str) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }
    }

    /// Viewer kinds [`MockGrid`] creates for the current test.
    static KINDS: StdMutex<Vec<ViewerKind>> = StdMutex::new(Vec::new());

    /// A window whose plugin creates exactly `kinds`.
    fn build_with(data: &[u8], name: &str, kinds: &[ViewerKind]) -> FileWindow {
        KINDS.lock().expect("kinds").clear();
        KINDS.lock().expect("kinds").extend_from_slice(kinds);
        let mut types = TypePluginRegistry::new();
        types.register_type::<MockGrid>("GRID").expect("grid");
        let mut inst = Instance::new(types, GenericPluginRegistry::new(), DEFAULT_CACHE_SIZE);
        let index = inst
            .add_buffer_window(data, name, OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect("open");
        let model = inst.take_window(index).expect("model");
        FileWindow::new(model, Vec::new(), Vec::new(), false)
    }

    fn build(data: &[u8], name: &str) -> FileWindow {
        let mut types = TypePluginRegistry::new();
        types.register_type::<MockPe>("PE").expect("pe");
        let mut inst = Instance::new(types, GenericPluginRegistry::new(), DEFAULT_CACHE_SIZE);
        let index = inst
            .add_buffer_window(data, name, OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect("open");
        let model = inst.take_window(index).expect("model");
        let commands = MockPe::metadata().commands;
        let generic = vec![GenericCommandSlot {
            key: Key::new(KeyCode::F5, KeyModifier::Ctrl),
            caption: String::from("Hashes"),
            plugin: 0,
            command: 0,
        }];
        FileWindow::new(model, commands, generic, false)
    }

    #[test]
    fn command_ids_roundtrip_through_the_enum() {
        for id in [
            cmd::CMD_NEXT_VIEW,
            cmd::CMD_GOTO,
            cmd::CMD_FIND,
            cmd::CMD_CHOSE_NEW_TYPE,
            cmd::CMD_SHOW_KEY_CONFIGURATOR,
            cmd::CMD_OPEN_ADD_NOTE,
            cmd::CMD_ANALYSIS_ENGINE,
            CMD_SHOW_VIEW_CONFIG_PANEL,
            CMD_SHOW_HORIZONTAL_PANEL,
            CMD_SHOW_HORIZONTAL_PANEL + 7,
            CMD_FOR_TYPE_PLUGIN_START,
            CMD_FOR_TYPE_PLUGIN_START + 15,
        ] {
            let command = command_for_id(id).expect("mapped");
            assert_eq!(id_for_command(command), Some(id), "{id}");
        }
        assert!(command_for_id(CMD_SHOW_HORIZONTAL_PANEL + 8).is_none());
        assert!(command_for_id(CMD_FOR_TYPE_PLUGIN_START + 16).is_none());
        assert!(command_for_id(0).is_none());
        assert_eq!(id_for_command(filewindow::Commands::Generic3), None);
        assert_eq!(generic_slot_for_command(filewindow::Commands::Generic3), Some(3));
        assert_eq!(generic_slot_for_command(filewindow::Commands::GoTo), None);
    }

    /// Reads `len` characters from `surface` at `(x, y)`.
    fn read(surface: &Surface, x: u32, y: u32, len: usize) -> String {
        (0..len)
            .filter_map(|i| {
                surface
                    .char(x.saturating_add(i as u32).cast_signed(), y.cast_signed())
                    .map(|c| c.code)
            })
            .collect()
    }

    /// The mounted `BufferView` on `handle` paints the object's first
    /// bytes (`4D 5A` / `MZ`).
    fn assert_buffer_paints_mz(win: &mut FileWindow, handle: Handle<BufferView>) {
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(120, 12);
        let view = win.control_mut(handle).expect("mounted buffer view");
        OnResize::on_resize(view, Size::new(0, 0), Size::new(120, 12));
        let x_numbers = view.layout().x_numbers;
        let x_text = view.layout().x_text;
        OnPaint::on_paint(view, &mut surface, &theme);
        // Data row 0 is screen row 1 (row 0 is the ruler).
        assert_eq!(read(&surface, x_numbers, 1, 6), "4D 5A ");
        assert_eq!(read(&surface, x_text, 1, 2), "MZ");
    }

    /// Every plugin `ViewerRequest` moved into its control: no slot
    /// still owns one (so no `ZonesList` was cloned).
    fn assert_requests_were_moved(win: &FileWindow, views: usize) {
        let model = win.model();
        let mut guard = model.lock().expect("model");
        for index in 0..views {
            assert!(
                slot_at(&mut guard, index).and_then(|slot| slot.request()).is_none(),
                "slot {index} still owns its request"
            );
        }
    }

    /// The command IDs the window forwards to the shell instead of
    /// servicing itself (`FileWindow::OnEvent`).
    fn assert_shell_requests(win: &mut FileWindow) {
        // Buffer object: choosing a new type is unsupported (C++ message).
        win.on_command_id(cmd::CMD_CHOSE_NEW_TYPE);
        win.on_command_id(cmd::CMD_SHOW_KEY_CONFIGURATOR);
        win.on_command_id(cmd::CMD_OPEN_ADD_NOTE);
        win.on_command_id(cmd::CMD_ANALYSIS_ENGINE);
        win.on_command_id(CMD_SHOW_VIEW_CONFIG_PANEL);
        assert_eq!(
            win.take_requests(),
            [
                ShellRequest::Error(ERR_CHOOSE_TYPE_UNSUPPORTED),
                ShellRequest::ShowKeyConfigurator,
                ShellRequest::AddNote,
                ShellRequest::ShowAnalysisEngine,
                ShellRequest::ShowProperties
            ]
        );

        // Type-plugin command slot runs the plugin command.
        win.on_command_id(CMD_FOR_TYPE_PLUGIN_START);
        assert_eq!(RUN_LOG.lock().expect("log").last().map(String::as_str), Some("DigitalSignature"));
        win.on_command_id(CMD_FOR_TYPE_PLUGIN_START + 5); // no such command: ignored
        assert_eq!(RUN_LOG.lock().expect("log").len(), 1);

        // Bottom panels: cursor info (0) and the plugin's "&Sections" (1).
        assert!(win.show_horizontal_panel(1));
        assert!(!win.show_horizontal_panel(5));
        assert_eq!(win.on_command_id(CMD_SHOW_HORIZONTAL_PANEL), CommandAction::ShowHorizontalPanel(0));

        // Generic slots are forwarded to the instance.
        CommandBarEvents::on_event(win, filewindow::Commands::Generic0);
        CommandBarEvents::on_event(win, filewindow::Commands::Generic9);
        assert_eq!(
            win.take_requests(),
            [ShellRequest::RunGenericPlugin { plugin: 0, command: 0 }]
        );
    }

    /// Single UI test (`App::debug` uses process-global state): open a
    /// file → the **mounted** Buffer viewer is the visible page, F4
    /// cycles views, the window owns exactly one object.
    #[test]
    fn open_file_shows_buffer_viewer_and_f4_cycles_views() {
        let script = "
            Paint.Enable(false)
            Paint('opened')
            Key.Pressed(F4)
            Paint('after f4')
            Key.Pressed(F4)
            Paint('wrapped')
        ";
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, script).command_bar().build().expect("debug app");
        let mut win = build(b"MZ\x90\x00", "sample.exe");
        assert_eq!(win.views_count(), 2);
        assert_eq!(win.current_view_name(), "Buffer View");
        assert_eq!(win.title(), "sample.exe");

        // Page 0 is a real `BufferView` over the window's object: it
        // paints the file's first bytes.
        let Some(MountedViewer::Buffer(buffer)) = win.mounted_view(0) else {
            panic!("page 0 must mount a BufferView");
        };
        assert!(matches!(win.mounted_view(1), Some(MountedViewer::Dissasm(_))));
        assert_buffer_paints_mz(&mut win, buffer);
        assert_requests_were_moved(&win, 2);

        // One Object per window: the window, its cursor-info control and
        // this test clone share the single model.
        let model = win.model();
        assert_eq!(Rc::strong_count(&model), 3);
        let object = model.lock().expect("model").object();
        assert_eq!(object.lock().expect("object").name(), "sample.exe");
        // Model + view container + this test clone + the two mounted
        // controls (spec §C.2: one `DataCache`, shared by every viewer).
        assert_eq!(std::sync::Arc::strong_count(&object), 5);
        drop(object);
        drop(model);

        win.start();
        assert!(win.is_started());
        assert_eq!(win.current_view_index(), 0);

        // Command routing without the event loop.
        assert_eq!(win.on_command_id(cmd::CMD_NEXT_VIEW), CommandAction::NextView);
        assert_eq!(win.current_view_name(), "Dissasm View");
        assert!(win.next_view());
        assert_eq!(win.current_view_name(), "Buffer View");
        assert!(win.set_view_by_index(1));
        assert!(!win.set_view_by_index(9));
        assert!(win.set_view_by_index(0));

        // The mounted Buffer view implements all three dialogs, so the
        // C++ "no implementation" texts are not produced; the control
        // raises its own event instead (asserted below).
        win.on_command_id(cmd::CMD_GOTO);
        win.on_command_id(cmd::CMD_FIND);
        win.show_view_dialog(ViewDialog::Copy);
        assert_eq!(win.take_requests(), []);

        assert_shell_requests(&mut win);

        // Custom events raised by the mounted controls.
        assert!(matches!(
            BufferViewEvents::on_event(&mut win, buffer, bufferview::Events::FocusView),
            EventProcessStatus::Processed
        ));
        BufferViewEvents::on_event(&mut win, buffer, bufferview::Events::ShowGoTo);
        BufferViewEvents::on_event(&mut win, buffer, bufferview::Events::ShowFind);
        BufferViewEvents::on_event(&mut win, buffer, bufferview::Events::ShowCopy);
        assert_eq!(
            win.take_requests(),
            [
                ShellRequest::ShowViewDialog(ViewDialog::GoTo),
                ShellRequest::ShowViewDialog(ViewDialog::Find),
                ShellRequest::ShowViewDialog(ViewDialog::Copy),
            ]
        );

        // The bottom bar reads the current page's published snapshot.
        let snapshot = win.cursor_slot(0).map(SharedCursorInfo::read).expect("slot 0");
        assert_eq!(snapshot.name_str(), "Buffer View");
        let mut bar = [b' '; CURSOR_BAR_CAPACITY];
        let len = write_cursor_bar(&mut bar, &snapshot);
        let text = String::from_utf8_lossy(bar.get(..len).unwrap_or(&[])).into_owned();
        assert!(text.starts_with("Buffer View  NO Selection  Pos:0"), "{text}");

        // Run the scripted session: F4 twice through the command bar.
        let model = win.model();
        app.add_window(win);
        app.run();
        let guard = model.lock().expect("model");
        // Buffer (0) → F4 → Dissasm (1) → F4 → Buffer (0).
        assert_eq!(guard.views().current_index(), 0);
        assert_eq!(guard.views().views_count(), 2);
    }

    /// A viewer kind with no control yet mounts the defined
    /// placeholder page (`00_APP §5.3.4`), and a view without any
    /// dialog produces the C++ error texts.
    #[test]
    fn unavailable_kinds_mount_a_placeholder_and_report_missing_dialogs() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, "Paint.Enable(false)\nPaint('grid')")
            .build()
            .expect("debug app");
        let mut win = build_with(b"GRIDcol1,col2\n1,2\n", "table.grid", &[ViewerKind::Grid]);
        assert_eq!(win.views_count(), 1);
        assert!(matches!(win.mounted_view(0), Some(MountedViewer::Unavailable(_))));
        assert_eq!(win.current_view_name(), "Grid View");

        win.on_command_id(cmd::CMD_GOTO);
        win.on_command_id(cmd::CMD_FIND);
        win.show_view_dialog(ViewDialog::Copy);
        assert_eq!(
            win.take_requests(),
            [
                ShellRequest::Error(ERR_NO_GOTO),
                ShellRequest::Error(ERR_NO_FIND),
                ShellRequest::Error(ERR_NO_COPY)
            ]
        );

        // The placeholder still publishes its name for the bottom bar.
        let snapshot = win.cursor_slot(0).map(SharedCursorInfo::read).expect("slot 0");
        assert_eq!(snapshot.name_str(), "Grid View");

        app.add_window(win);
        app.run();
    }

    #[test]
    fn cursor_bar_formats_the_published_snapshot() {
        let mut bar = [b' '; CURSOR_BAR_CAPACITY];

        // Empty object: C++ paints `----` instead of a percentage.
        let empty = CursorSnapshot::with_name("Buffer View");
        let len = write_cursor_bar(&mut bar, &empty);
        assert_eq!(
            String::from_utf8_lossy(bar.get(..len).unwrap_or(&[])),
            "Buffer View  NO Selection  Pos:0  ----"
        );

        // Selection + percentage, cursor offset in the cursor's base.
        let mut snapshot = CursorSnapshot::with_name("Dissasm View");
        snapshot.offset = 0x1F;
        snapshot.size = 0x20;
        snapshot.has_selection = true;
        snapshot.selection_start = 0x10;
        snapshot.selection_end = 0x1F;
        let len = write_cursor_bar(&mut bar, &snapshot);
        assert_eq!(
            String::from_utf8_lossy(bar.get(..len).unwrap_or(&[])),
            "Dissasm View  Sel:10,10  Pos:1F  100%"
        );

        // Decimal base (C++ `cursor.GetBase()` of 10).
        snapshot.base = 10;
        let len = write_cursor_bar(&mut bar, &snapshot);
        assert!(String::from_utf8_lossy(bar.get(..len).unwrap_or(&[])).contains("Pos:31"));

        // A name longer than the bar never writes out of bounds.
        let mut long = CursorSnapshot::with_name(&"n".repeat(64));
        long.size = 10;
        let len = write_cursor_bar(&mut bar, &long);
        assert!(len <= CURSOR_BAR_CAPACITY);
    }

    #[test]
    fn command_slot_constants_match_the_generated_enum() {
        assert_eq!(MAX_TYPE_PLUGIN_COMMANDS, PLUGIN_COMMANDS.len());
        assert_eq!(MAX_GENERIC_PLUGIN_COMMANDS, GENERIC_COMMANDS.len());
        assert_eq!(MAX_HORIZONTAL_PANELS, HPANEL_COMMANDS.len());
    }
}
