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
//! 3. one [`ViewerHost`] page per viewer in the hidden `view` tab and
//!    one page per plugin panel in the `verticalPanels` /
//!    `horizontalPanels` tabs, with [`CursorInformation`] as
//!    horizontal page 0;
//! 4. `Start()`: view page 0 current and focused.
//!
//! Key routing: `AppCUI` windows cannot override raw key handling
//! (`OnKeyPressed` is fixed for `#[Window]`), so the C++
//! `FileWindow::OnKeyEvent` shortcuts (Ctrl+G / Ctrl+F / Ctrl+C /
//! Ctrl+Insert / Alt+F / Escape) are evaluated by the focused
//! [`ViewerHost`] through [`events::route_key`] and forwarded to the
//! window as custom events — the same "children first, then the
//! window" precedence as the C++ chain. Command-bar commands go
//! through the generated `Commands` enum and [`events::dispatch_command`].
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
pub mod panels;
pub mod view_container;

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Mutex, PoisonError};

use appcui::prelude::*;
use gview_core::object::ObjectType;
use gview_plugin::type_plugin::CommandDef;

use crate::instance::window_lifecycle::FileWindowModel;
use command_bar::{build_command_bar, TypePluginCommand};
use events::{cmd, dispatch_command, route_key, ChainDelegation, CommandAction, KeyAction};
use layout::{
    build_layout, FileWindowLayout, CMD_FOR_TYPE_PLUGIN_START, CMD_SHOW_HORIZONTAL_PANEL,
    CMD_SHOW_VIEW_CONFIG_PANEL,
};

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

/// Which viewer dialog to open (C++ `ShowGoToDialog` /
/// `ShowFindDialog` / `ShowCopyDialog`; copy has no command ID and is
/// reached only through Ctrl+C / Ctrl+Insert).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewDialog {
    /// `GoTo`.
    GoTo,
    /// Find.
    Find,
    /// Copy.
    Copy,
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
}

/// Placeholder page for one smart viewer: paints the viewer name and
/// applies the C++ `OnKeyEvent` shortcut precedence for the window.
/// The concrete viewer surfaces replace the paint in their own tasks.
#[CustomControl(overwrite = OnPaint + OnKeyPressed, emit: ShowGoTo + ShowFind + ShowCopy + FocusView)]
pub struct ViewerHost {
    name: String,
    index: usize,
}

impl ViewerHost {
    /// A host for viewer `index` named `name`, filling its tab page.
    #[must_use]
    pub fn new(name: &str, index: usize) -> Self {
        Self {
            base: ControlBase::new(layout!("d:f"), true),
            name: name.to_owned(),
            index,
        }
    }

    /// Viewer name (tab caption / F4 caption).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Viewer index in the view tab.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }
}

impl OnPaint for ViewerHost {
    fn on_paint(&self, surface: &mut Surface, theme: &Theme) {
        surface.clear(Character::with_attributes(' ', theme.window.normal));
        surface.write_string(1, 0, &self.name, theme.window.normal, false);
    }
}

impl OnKeyPressed for ViewerHost {
    fn on_key_pressed(&mut self, key: Key, _character: char) -> EventProcessStatus {
        match route_key(key, self.has_focus(), ChainDelegation::default()) {
            KeyAction::FocusView => {
                self.raise_event(viewerhost::Events::FocusView);
                EventProcessStatus::Processed
            }
            KeyAction::ShowGoTo => {
                self.raise_event(viewerhost::Events::ShowGoTo);
                EventProcessStatus::Processed
            }
            KeyAction::ShowFind => {
                self.raise_event(viewerhost::Events::ShowFind);
                EventProcessStatus::Processed
            }
            KeyAction::ShowCopy => {
                self.raise_event(viewerhost::Events::ShowCopy);
                EventProcessStatus::Processed
            }
            KeyAction::HandledByChain | KeyAction::NotHandled => EventProcessStatus::Ignored,
        }
    }
}

/// C++ `CursorInformation`: bottom bar painted by the current viewer's
/// `PaintCursorInformation`.
#[CustomControl(overwrite = OnPaint)]
pub struct CursorInformation {
    model: SharedModel,
}

impl CursorInformation {
    /// Bound to the window model.
    #[must_use]
    pub fn new(model: SharedModel) -> Self {
        Self {
            base: ControlBase::new(layout!("d:f"), false),
            model,
        }
    }
}

impl OnPaint for CursorInformation {
    fn on_paint(&self, surface: &mut Surface, theme: &Theme) {
        surface.clear(Character::with_attributes(' ', theme.window.normal));
        let size = self.size();
        let mut model = self.model.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(view) = model.views_mut().current_view_mut() {
            view.paint_cursor_information(surface, size.width, size.height);
        }
    }
}

#[Window(
    events = CommandBarEvents,
    custom_events = ViewerHostEvents,
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
    view_hosts: Vec<Handle<ViewerHost>>,
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
        let (title, tag, view_names, vertical_captions, horizontal_captions) = {
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
                model.panels().vertical_captions().to_vec(),
                model.panels().horizontal_captions().to_vec(),
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
            plugin_commands,
            generic_commands,
            requests: Vec::new(),
            interactive,
            started: false,
        };

        // View pages (hidden tab bar): one host per viewer.
        let view_tab = win.layout.view;
        let mut hosts = Vec::with_capacity(view_names.len());
        if let Some(tab) = win.control_mut(view_tab) {
            for (index, name) in view_names.iter().enumerate() {
                let page = tab.add_tab(name);
                hosts.push(tab.add(page, ViewerHost::new(name, index)));
            }
        }
        win.view_hosts = hosts;

        // Plugin side panels (captions carry `&` hot keys).
        let vertical_tab = win.layout.vertical_panels;
        if let Some(tab) = win.control_mut(vertical_tab) {
            for caption in &vertical_captions {
                tab.add_tab(caption);
            }
        }

        // Bottom panels: cursor information first, then plugin panels.
        let horizontal_tab = win.layout.horizontal_panels;
        let cursor_info = CursorInformation::new(model);
        if let Some(tab) = win.control_mut(horizontal_tab) {
            let mut captions = horizontal_captions.iter();
            if let Some(first) = captions.next() {
                let page = tab.add_tab(first);
                tab.add(page, cursor_info);
            }
            for caption in captions {
                tab.add_tab(caption);
            }
            tab.set_current_tab(0);
        }
        win
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
        if let Some(host) = self.view_hosts.first().copied() {
            self.request_focus_for_control(host);
        }
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

    fn sync_view_tab(&mut self) {
        let index = self.current_view_index();
        let view_tab = self.layout.view;
        if let Some(tab) = self.control_mut(view_tab) {
            tab.set_current_tab(index);
        }
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

    /// Opens a viewer dialog; a viewer without one yields the C++
    /// `MessageBox::ShowError` text as a request (and a dialog when
    /// interactive).
    pub fn show_view_dialog(&mut self, dialog: ViewDialog) {
        let ok = {
            let mut model = self.model.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(view) = model.views_mut().current_view_mut() else {
                return;
            };
            let ok = match dialog {
                ViewDialog::GoTo => view.show_goto_dialog(),
                ViewDialog::Find => view.show_find_dialog(),
                ViewDialog::Copy => view.show_copy_dialog(),
            };
            drop(model);
            ok
        };
        if !ok {
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
        if let Some(host) = self.view_hosts.get(index).copied() {
            self.request_focus_for_control(host);
        }
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

impl ViewerHostEvents for FileWindow {
    fn on_event(&mut self, _handle: Handle<ViewerHost>, event: viewerhost::Events) -> EventProcessStatus {
        match event {
            viewerhost::Events::ShowGoTo => self.show_view_dialog(ViewDialog::GoTo),
            viewerhost::Events::ShowFind => self.show_view_dialog(ViewDialog::Find),
            viewerhost::Events::ShowCopy => self.show_view_dialog(ViewDialog::Copy),
            viewerhost::Events::FocusView => self.focus_view(),
        }
        EventProcessStatus::Processed
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

    /// Single UI test (`App::debug` uses process-global state): open a
    /// file → the Buffer viewer is the visible page, F4 cycles views,
    /// the window owns exactly one object.
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
        let mut app = App::debug(100, 40, script).command_bar().build().expect("debug app");
        let mut win = build(b"MZ\x90\x00", "sample.exe");
        assert_eq!(win.views_count(), 2);
        assert_eq!(win.current_view_name(), "Buffer View");
        assert_eq!(win.title(), "sample.exe");

        // One Object per window: the window, its cursor-info control and
        // this test clone share the single model.
        let model = win.model();
        assert_eq!(Rc::strong_count(&model), 3);
        let object = model.lock().expect("model").object();
        assert_eq!(object.lock().expect("object").name(), "sample.exe");
        assert_eq!(std::sync::Arc::strong_count(&object), 3);
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

        // Placeholder viewers implement no dialogs: C++ error texts.
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
        CommandBarEvents::on_event(&mut win, filewindow::Commands::Generic0);
        CommandBarEvents::on_event(&mut win, filewindow::Commands::Generic9);
        assert_eq!(
            win.take_requests(),
            [ShellRequest::RunGenericPlugin { plugin: 0, command: 0 }]
        );

        // Custom events from the viewer host.
        let host = win.view_hosts[0];
        assert!(matches!(
            ViewerHostEvents::on_event(&mut win, host, viewerhost::Events::FocusView),
            EventProcessStatus::Processed
        ));
        ViewerHostEvents::on_event(&mut win, host, viewerhost::Events::ShowGoTo);
        assert_eq!(win.take_requests(), [ShellRequest::Error(ERR_NO_GOTO)]);

        // Run the scripted session: F4 twice through the command bar.
        let model = win.model();
        app.add_window(win);
        app.run();
        let guard = model.lock().expect("model");
        // Buffer (0) → F4 → Dissasm (1) → F4 → Buffer (0).
        assert_eq!(guard.views().current_index(), 0);
        assert_eq!(guard.views().views_count(), 2);
    }

    #[test]
    fn viewer_host_and_constants() {
        let host = ViewerHost::new("Buffer View", 3);
        assert_eq!(host.name(), "Buffer View");
        assert_eq!(host.index(), 3);
        assert_eq!(MAX_TYPE_PLUGIN_COMMANDS, PLUGIN_COMMANDS.len());
        assert_eq!(MAX_GENERIC_PLUGIN_COMMANDS, GENERIC_COMMANDS.len());
        assert_eq!(MAX_HORIZONTAL_PANELS, HPANEL_COMMANDS.len());
    }
}
