//! Native type-plugin contract (spec `03_DUAL_PLUGIN` §6.1–6.2; C++
//! `TypeInterface` vtable §3.3, `Plugin` in `Type/Plugin.cpp`).
//!
//! A Rust type plugin replaces the four `.tpl` exports:
//!
//! | C++ export | Rust |
//! |------------|------|
//! | `UpdateSettings(IniSection)` | [`TypePlugin::metadata`] → [`PluginMetadata`] |
//! | `Validate(buf, extension)` | [`TypePlugin::validate`] |
//! | `CreateInstance()` | [`TypePlugin::create_instance`] |
//! | `PopulateWindow(win)` | [`TypePlugin::populate_window`] over [`WindowHandle`] |
//!
//! and the `TypeInterface` vtable methods (`GetTypeName`, `RunCommand`,
//! `UpdateKeys`, `GetSmartAssistantContext`, `GetSelectionZonesCount`
//! / `GetSelectionZone` with their defaults) map to the instance
//! methods. Because `validate` / `create_instance` / `metadata` are
//! associated functions, a plugin is handed to the host as a
//! [`TypePluginDescriptor`] (function pointers), and
//! [`TypePluginRegistry`] is the native counterpart of the C++
//! `Plugin` list: it compiles the metadata patterns once
//! (`Plugin::Init`), hashes the extensions, applies the §7.4 priority
//! clamp and ordering, and answers `MatchExtension` /
//! `MatchContent` / `IsOfType` without any dynamic loading.
//!
//! All traits are `Send + Sync` so instances can live behind the
//! window's shared object and be used from background workers.

use appcui::input::Key;
use gview_core::zones::ZonesList;
use gview_view::buffer_viewer::color::PositionToColorCallback;
use gview_view::buffer_viewer::dissasm_dialog::DissasmSettings;
use gview_view::container_viewer::open::OpenItemInterface;
use gview_view::container_viewer::tree::EnumerateInterface;
use gview_view::dissasm_viewer::zone::DisassemblyZone;
use gview_view::traits::SharedObject;
use serde_json::Value as JsonValue;

use crate::fnv::{extension_hash, EXTENSION_EMPTY_HASH};
use crate::matcher::{Matcher, TextParser};
use crate::panel::PanelContent;

/// C++ `Plugin::Init` priority clamp: `max(value, 0xFFFF)` — only
/// values above 65535 differentiate plugin order (spec §7.4).
pub const MIN_EFFECTIVE_PRIORITY: u32 = 0xFFFF;
/// Capacity of the C++ `FixSizeString<27>` plugin name.
pub const MAX_PLUGIN_NAME_LEN: usize = 27;
/// Capacity of the C++ `FixSizeString<124>` description.
pub const MAX_DESCRIPTION_LEN: usize = 124;
/// Capacity of the C++ `FixSizeString<25>` command name.
pub const MAX_COMMAND_NAME_LEN: usize = 25;

/// Plugin-side failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginError {
    /// A metadata pattern did not compile (C++ `CHECK(p, false,
    /// "Invalid pattern !")`).
    InvalidPattern(String),
    /// A plugin with the same name is already registered.
    DuplicateName(String),
    /// `PopulateWindow` could not build what it needs.
    Window(String),
    /// The plugin does not support the request.
    Unsupported(String),
    /// A command name is unknown to the plugin.
    UnknownCommand(String),
    /// The `SmartAssistant` context could not be produced.
    Assistant(String),
}

impl core::fmt::Display for PluginError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPattern(p) => write!(f, "Invalid pattern ! ({p})"),
            Self::DuplicateName(n) => write!(f, "plugin {n:?} already registered"),
            Self::Window(m) => write!(f, "window: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
            Self::UnknownCommand(c) => write!(f, "unknown command {c:?}"),
            Self::Assistant(m) => write!(f, "smart assistant: {m}"),
        }
    }
}

impl std::error::Error for PluginError {}

/// A metadata pattern (spec §6.2), serialisable to the INI syntax the
/// C++ `Matcher::CreateFromString` understands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// `magic:HH HH …` — bytes at offset 0.
    Magic(Vec<u8>),
    /// `startswith:…` — text prefix.
    StartsWith(Vec<u8>),
    /// `linestartswith:…` — a line among the first ten starts with it.
    LineStartsWith(String),
}

impl Pattern {
    /// The INI string form (`magic:4D 5A`, `startswith:PK`, …).
    #[must_use]
    pub fn to_ini_string(&self) -> String {
        match self {
            Self::Magic(bytes) => {
                let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
                format!("magic:{}", hex.join(" "))
            }
            Self::StartsWith(bytes) => format!("startswith:{}", String::from_utf8_lossy(bytes)),
            Self::LineStartsWith(text) => format!("linestartswith:{text}"),
        }
    }

    /// Compiles through the same parser the INI path uses, so a
    /// pattern that is invalid there is invalid here.
    #[must_use]
    pub fn compile(&self) -> Option<Matcher> {
        Matcher::from_string(&self.to_ini_string())
    }
}

/// One keyboard command (C++ `KeyboardControl` / INI
/// `Command.<name> = <key>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandDef {
    /// `Caption` — the `Command.<name>` INI suffix and `RunCommand`
    /// argument.
    pub name: String,
    /// Shortcut.
    pub key: Key,
    /// `Explanation` (command-bar help).
    pub description: String,
    /// `CommandId`.
    pub command_id: u32,
}

impl CommandDef {
    /// Builds a command definition.
    pub fn new(name: impl Into<String>, key: Key, description: impl Into<String>, command_id: u32) -> Self {
        Self {
            name: name.into(),
            key,
            description: description.into(),
            command_id,
        }
    }
}

/// C++ `UpdateSettings` output (spec §6.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PluginMetadata {
    /// `Pattern` (single value or array).
    pub pattern: Vec<Pattern>,
    /// `Priority` (raw; see [`Self::effective_priority`]).
    pub priority: u32,
    /// `Description`.
    pub description: String,
    /// `Extension` (single value or array; leading dots optional).
    pub extensions: Vec<String>,
    /// `Command.<name>` entries.
    pub commands: Vec<CommandDef>,
    /// `OpCodes.Mask` (dissasm viewer opcode highlighting).
    pub opcodes_mask: Option<u32>,
}

impl PluginMetadata {
    /// C++ `Plugin::Init` clamp: `std::max(value, 0xFFFF)`.
    #[must_use]
    pub const fn effective_priority(&self) -> u32 {
        if self.priority > MIN_EFFECTIVE_PRIORITY {
            self.priority
        } else {
            MIN_EFFECTIVE_PRIORITY
        }
    }

    /// FNV-1a hashes of the extensions (`Plugin::Init` extension set).
    #[must_use]
    pub fn extension_hashes(&self) -> Vec<u64> {
        self.extensions.iter().map(|e| extension_hash(e)).collect()
    }

    /// Compiles every pattern (`Plugin::Init` pattern loop).
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidPattern`] for the first pattern that does
    /// not parse.
    pub fn compile_patterns(&self) -> Result<Vec<Matcher>, PluginError> {
        self.pattern
            .iter()
            .map(|p| {
                p.compile()
                    .ok_or_else(|| PluginError::InvalidPattern(p.to_ini_string()))
            })
            .collect()
    }
}

/// C++ `TypeInterface::SelectionZone`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectionZone {
    /// First offset.
    pub start: u64,
    /// Last offset.
    pub end: u64,
}

/// C++ `KeyboardControlsInterface`: the host-side sink for
/// [`TypePlugin::register_keys`].
pub trait KeyRegistry {
    /// C++ `RegisterKey(KeyboardControl*)`; `false` on conflict.
    fn register_key(&mut self, command: &CommandDef) -> bool;
}

/// Which viewer a plugin asks the window to create.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ViewerKind {
    /// Hex / binary.
    Buffer,
    /// Plain text.
    Text,
    /// Syntax-highlighted source.
    Lexical,
    /// Terminal image.
    Image,
    /// Tabular.
    Grid,
    /// Disassembly.
    Dissasm,
    /// Archive / VFS tree.
    Container,
}

/// `BufferViewer::Settings` as a plugin fills it in `PopulateWindow`.
///
/// Covers `AddZone`, `AddBookmark`, `SetEntryPointOffset`,
/// `SetOffsetTranslationList`, `SetArchitecture` / `SetDesign` /
/// `SetEndianess` and `SetPositionToColorCallback`.
#[derive(Default)]
pub struct BufferViewerRequest {
    /// Colored regions (section headers, tables, …).
    pub zones: ZonesList,
    /// `(slot 0..=9, offset)` bookmarks.
    pub bookmarks: Vec<(u8, u64)>,
    /// F7 target.
    pub entry_point: Option<u64>,
    /// Address-column names after `FileOffset` (RVA, VA, …).
    pub translation_methods: Vec<String>,
    /// Dissasm dialog defaults (`SetArchitecture` & co.).
    pub dissasm_settings: DissasmSettings,
    /// `SetPositionToColorCallback`: the plugin colours executable
    /// bytes (opcode highlighting).
    pub position_to_color: bool,
}

/// A `DissasmViewer::Settings::AddMemoryMapping` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryMapping {
    /// Virtual address (RVA) of the mapped symbol.
    pub address: u64,
    /// Symbol name.
    pub name: String,
}

/// `DissasmViewer::Settings` as a plugin fills it (`AddDisassemblyZone`,
/// `AddMemoryMapping`, `SetOffsetTranslationList`, `AddType` /
/// `AddVariable`).
#[derive(Clone, Debug, Default)]
pub struct DissasmViewerRequest {
    /// Code zones to disassemble.
    pub zones: Vec<DisassemblyZone>,
    /// Import / export symbol mappings.
    pub memory_mappings: Vec<MemoryMapping>,
    /// Address-column names after `FileOffset`.
    pub translation_methods: Vec<String>,
    /// `(name, definition)` structure types (`AddType`).
    pub types: Vec<(String, String)>,
    /// `(offset, type name)` variables (`AddVariable`).
    pub variables: Vec<(u64, String)>,
}

impl core::fmt::Debug for BufferViewerRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BufferViewerRequest")
            .field("zones", &self.zones.count())
            .field("bookmarks", &self.bookmarks)
            .field("entry_point", &self.entry_point)
            .field("translation_methods", &self.translation_methods)
            .field("dissasm_settings", &self.dissasm_settings)
            .field("position_to_color", &self.position_to_color)
            .finish()
    }
}

/// `ContainerViewer::Settings` as a plugin fills it.
///
/// Covers `SetIcon`, `SetPathSeparator`, `SetColumns` and
/// `AddProperty` (spec `02_VIEWER_CONTAINER` §2.1); the
/// `EnumerateInterface` / `OpenItemInterface` callbacks are the plugin
/// instance itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerViewerRequest {
    /// `SetIcon`: the 16×16 image string (256 chars), when set.
    pub icon: Option<String>,
    /// `SetPathSeparator` (`/` by default).
    pub path_separator: char,
    /// `SetColumns`: `AppCUI` column layout strings (`n:…,a:…,w:…`).
    pub columns: Vec<String>,
    /// `AddProperty`: `(name, value)` rows for the property grid.
    pub properties: Vec<(String, String)>,
}

impl Default for ContainerViewerRequest {
    fn default() -> Self {
        Self {
            icon: None,
            path_separator: '/',
            columns: Vec::new(),
            properties: Vec::new(),
        }
    }
}

/// A viewer creation request (`WindowInterface::CreateViewer`).
#[derive(Debug)]
pub struct ViewerRequest {
    /// Viewer type.
    pub kind: ViewerKind,
    /// Optional tab name (`CreateViewer<T>(name)`).
    pub custom_name: Option<String>,
    /// Buffer-viewer specifics; ignored for other kinds.
    pub buffer: Option<BufferViewerRequest>,
    /// Dissasm-viewer specifics; ignored for other kinds.
    pub dissasm: Option<DissasmViewerRequest>,
    /// Container-viewer specifics; ignored for other kinds.
    pub container: Option<ContainerViewerRequest>,
}

impl ViewerRequest {
    /// A plain request for `kind`.
    #[must_use]
    pub const fn new(kind: ViewerKind) -> Self {
        Self {
            kind,
            custom_name: None,
            buffer: None,
            dissasm: None,
            container: None,
        }
    }

    /// A buffer-viewer request carrying its settings.
    #[must_use]
    pub const fn buffer(settings: BufferViewerRequest) -> Self {
        Self {
            kind: ViewerKind::Buffer,
            custom_name: None,
            buffer: Some(settings),
            dissasm: None,
            container: None,
        }
    }

    /// A dissasm-viewer request carrying its settings.
    #[must_use]
    pub const fn dissasm(settings: DissasmViewerRequest) -> Self {
        Self {
            kind: ViewerKind::Dissasm,
            custom_name: None,
            buffer: None,
            dissasm: Some(settings),
            container: None,
        }
    }

    /// A container-viewer request carrying its settings.
    #[must_use]
    pub const fn container(settings: ContainerViewerRequest) -> Self {
        Self {
            kind: ViewerKind::Container,
            custom_name: None,
            buffer: None,
            dissasm: None,
            container: Some(settings),
        }
    }

    /// Sets the tab name.
    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.custom_name = Some(name.into());
        self
    }
}

/// A side / bottom panel a plugin adds (`WindowInterface::AddPanel`).
/// The concrete `TabPage` is built by the shell from this
/// description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PanelRequest {
    /// Tab caption (`&` marks the hot key, e.g. `&Information`).
    pub caption: String,
    /// Plugin-defined panel identifier the shell maps to a builder.
    pub panel_id: String,
}

/// C++ `WindowInterface` as seen from `PopulateWindow` (spec §3.4).
pub trait WindowHandle {
    /// `GetObject()`.
    fn object(&self) -> SharedObject;
    /// `AddPanel(TabPage*, vertical)`; `false` when the panel could not
    /// be added.
    fn add_panel(&mut self, panel: PanelRequest, vertical: bool) -> bool;
    /// `CreateViewer(Settings&)`; returns the new view index.
    ///
    /// # Errors
    ///
    /// [`PluginError::Window`] when the viewer cannot be created.
    fn create_viewer(&mut self, request: ViewerRequest) -> Result<u32, PluginError>;
    /// `GetViewsCount()`.
    fn views_count(&self) -> u32;
    /// `SetViewByIndex(index)`.
    fn set_view_by_index(&mut self, index: u32) -> bool;
    /// `GetCurrentView()` index.
    fn current_view(&self) -> Option<u32>;
}

/// The native type plugin (spec §6.1).
pub trait TypePlugin: Send + Sync {
    /// `GetTypeName()`.
    fn name(&self) -> &'static str;

    /// `Validate(buf, extension)` export: `buf` is the identification
    /// probe (up to `0x8800` bytes), `extension` the file extension
    /// **with** its leading dot (or empty).
    fn validate(buf: &[u8], extension: &str) -> bool
    where
        Self: Sized;

    /// `CreateInstance()` export.
    fn create_instance() -> Box<Self>
    where
        Self: Sized;

    /// `UpdateSettings` export.
    fn metadata() -> PluginMetadata
    where
        Self: Sized;

    /// `PopulateWindow(win)` export.
    ///
    /// # Errors
    ///
    /// [`PluginError::Window`] when a required viewer or panel could
    /// not be created.
    fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError>;

    /// `RunCommand(commandName)`.
    fn run_command(&mut self, command: &str);

    /// `UpdateKeys(KeyboardControlsInterface*)`.
    fn register_keys(&self, keys: &mut dyn KeyRegistry);

    /// `GetSmartAssistantContext(prompt, displayPrompt)`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Assistant`] when no context can be built.
    fn smart_assistant_context(&self, prompt: &str, display: &str) -> Result<JsonValue, PluginError>;

    /// `GetSelectionZonesCount()` — vtable default `0`.
    fn selection_zones_count(&self) -> u32 {
        0
    }

    /// `GetSelectionZone(index)` — vtable default `{0, 0}`.
    fn selection_zone(&self, _index: u32) -> SelectionZone {
        SelectionZone::default()
    }

    /// C++ `BufferViewer::Settings::SetPositionToColorCallback`
    /// (spec `00_APP §5.3.3`).
    ///
    /// Returns an **owned snapshot** of the plugin's colouring state,
    /// which the mount function moves into the `BufferView` control.
    /// The C++ passes `this` (the `TypeInterface` itself implements
    /// `PositionToColorInterface`); the Rust control cannot borrow the
    /// plugin, so the plugin hands out a value instead.
    ///
    /// `None` when the format does not colour opcodes, when the file's
    /// machine is not supported, or before `populate_window` parsed
    /// anything.
    fn position_to_color(&self) -> Option<Box<dyn PositionToColorCallback + Send>> {
        None
    }

    /// C++ `ContainerViewer::Settings::SetEnumerateCallback`
    /// (spec `00_APP §5.3.3`).
    ///
    /// Same ownership rule as [`Self::position_to_color`]: an owned
    /// enumerator over the already-parsed listing. `None` for
    /// non-container formats and before `populate_window`.
    fn container_enumerator(&self) -> Option<Box<dyn EnumerateInterface + Send>> {
        None
    }

    /// C++ `ContainerViewer::Settings::SetOpenItemCallback`
    /// (spec `00_APP §5.3.3`).
    ///
    /// `None` for formats whose entries cannot be opened, and before
    /// `populate_window`.
    fn container_opener(&self) -> Option<Box<dyn OpenItemInterface + Send>> {
        None
    }

    /// Content for the plugin panel `panel_id` (spec `00_APP §5.4.1`).
    ///
    /// The C++ counterpart is the `TabPage` subclass built in
    /// `PopulateWindow` (`Types/*/src/Panels/*.cpp`); here the plugin
    /// only produces the *data* and the shell renders it (design
    /// decision `§0.3 D3`).
    ///
    /// Ids are `"<format>.<panel>"` in lowercase ASCII, e.g.
    /// `"pe.information"`. The vtable default is `None`, which makes
    /// the shell fall back to the generic `Information` panel; a plugin
    /// whose parse never ran must also answer `None` rather than
    /// panicking.
    fn panel_content(&self, _panel_id: &str) -> Option<PanelContent> {
        None
    }
}

/// Function-pointer view of a [`TypePlugin`] implementation: what a
/// registry stores (the Rust equivalent of the `.tpl` export table).
#[derive(Clone, Copy)]
pub struct TypePluginDescriptor {
    /// Plugin name (`Type.<Name>` section, `.tpl` file stem).
    pub name: &'static str,
    /// `Validate` export.
    pub validate: fn(&[u8], &str) -> bool,
    /// `CreateInstance` export.
    pub create_instance: fn() -> Box<dyn TypePlugin>,
    /// `UpdateSettings` export.
    pub metadata: fn() -> PluginMetadata,
}

impl core::fmt::Debug for TypePluginDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TypePluginDescriptor")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl TypePluginDescriptor {
    /// Describes plugin type `P` under `name`.
    #[must_use]
    pub fn of<P: TypePlugin + 'static>(name: &'static str) -> Self {
        Self {
            name,
            validate: P::validate,
            create_instance: || P::create_instance(),
            metadata: P::metadata,
        }
    }
}

/// One registered plugin with its compiled identification data
/// (the C++ `Plugin` object after `Init`).
#[derive(Debug)]
pub struct RegisteredTypePlugin {
    descriptor: TypePluginDescriptor,
    metadata: PluginMetadata,
    matchers: Vec<Matcher>,
    extension_hashes: Vec<u64>,
    priority: u32,
}

impl RegisteredTypePlugin {
    /// The descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &TypePluginDescriptor {
        &self.descriptor
    }

    /// Plugin name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.descriptor.name
    }

    /// The metadata as declared.
    #[must_use]
    pub const fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    /// Clamped priority (§7.4).
    #[must_use]
    pub const fn priority(&self) -> u32 {
        self.priority
    }

    /// C++ `Plugin::MatchExtension`: `false` without any declared
    /// extension, else membership of the hash.
    #[must_use]
    pub fn match_extension(&self, extension_hash: u64) -> bool {
        if self.extension_hashes.is_empty() || extension_hash == EXTENSION_EMPTY_HASH {
            return false;
        }
        self.extension_hashes.contains(&extension_hash)
    }

    /// C++ `Plugin::MatchContent`: any pattern matches.
    #[must_use]
    pub fn match_content(&self, buf: &[u8], text: &mut TextParser<'_>) -> bool {
        self.matchers.iter().any(|m| m.matches(buf, text))
    }

    /// C++ `Plugin::IsOfType` → the plugin's `Validate` export (no
    /// loading step for native plugins).
    #[must_use]
    pub fn is_of_type(&self, buf: &[u8], extension: &str) -> bool {
        (self.descriptor.validate)(buf, extension)
    }

    /// C++ `Plugin::CreateInstance`.
    #[must_use]
    pub fn create_instance(&self) -> Box<dyn TypePlugin> {
        (self.descriptor.create_instance)()
    }
}

/// The host's type-plugin table (C++ `Instance::typePlugins`), kept
/// sorted by descending priority (`Plugin::operator<`), stable for
/// equal priorities (registration order).
#[derive(Debug, Default)]
pub struct TypePluginRegistry {
    plugins: Vec<RegisteredTypePlugin>,
}

impl TypePluginRegistry {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { plugins: Vec::new() }
    }

    /// C++ `Plugin::Init` for a native plugin: compiles patterns,
    /// hashes extensions, clamps the priority and inserts in order.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidPattern`], [`PluginError::DuplicateName`].
    pub fn register(&mut self, descriptor: TypePluginDescriptor) -> Result<(), PluginError> {
        if self.plugins.iter().any(|p| p.name() == descriptor.name) {
            return Err(PluginError::DuplicateName(descriptor.name.to_owned()));
        }
        let metadata = (descriptor.metadata)();
        let matchers = metadata.compile_patterns()?;
        let extension_hashes = metadata.extension_hashes();
        let priority = metadata.effective_priority();
        let entry = RegisteredTypePlugin {
            descriptor,
            metadata,
            matchers,
            extension_hashes,
            priority,
        };
        // Insert after every plugin with priority >= ours: higher
        // priority first, stable among equals.
        let pos = self
            .plugins
            .iter()
            .position(|p| p.priority < priority)
            .unwrap_or(self.plugins.len());
        self.plugins.insert(pos, entry);
        Ok(())
    }

    /// Registers plugin type `P` under `name`.
    ///
    /// # Errors
    ///
    /// As [`Self::register`].
    pub fn register_type<P: TypePlugin + 'static>(&mut self, name: &'static str) -> Result<(), PluginError> {
        self.register(TypePluginDescriptor::of::<P>(name))
    }

    /// Plugins in evaluation order.
    #[must_use]
    pub fn plugins(&self) -> &[RegisteredTypePlugin] {
        &self.plugins
    }

    /// Number of registered plugins.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.plugins.len()
    }

    /// `true` when nothing is registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Lookup by name (`ForceType`).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&RegisteredTypePlugin> {
        self.plugins.iter().find(|p| p.name() == name)
    }

    /// The `IdentifyTypePlugin` metadata pass: plugins whose extension
    /// hash **or** content pattern matches and whose `Validate`
    /// accepts the probe, in priority order (extension matches first,
    /// as in `Instance.cpp`; a plugin is reported once).
    #[must_use]
    pub fn candidates(&self, buf: &[u8], text: &mut TextParser<'_>, extension: &str) -> Vec<&RegisteredTypePlugin> {
        let hash = extension_hash(extension);
        let mut out: Vec<&RegisteredTypePlugin> = Vec::new();
        if hash != 0 {
            for p in &self.plugins {
                if p.match_extension(hash) && p.is_of_type(buf, extension) {
                    out.push(p);
                }
            }
        }
        for p in &self.plugins {
            if out.iter().any(|seen| std::ptr::eq(*seen, p)) {
                continue;
            }
            if p.match_content(buf, text) && p.is_of_type(buf, extension) {
                out.push(p);
            }
        }
        out
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::matcher::utf16;
    use appcui::input::{KeyCode, KeyModifier};
    use gview_core::object::Object;
    use std::sync::{Arc, Mutex};

    /// The three viewer-service hooks of `00_APP §5.3.3` default to
    /// `None`, so a plugin that implements none of them (and any
    /// plugin before `populate_window` ran) never hands the shell a
    /// callback.
    #[test]
    fn viewer_service_hooks_default_to_none() {
        let plugin = MockPe::create_instance();
        assert!(plugin.position_to_color().is_none(), "hooks");
        assert!(plugin.container_enumerator().is_none(), "hooks");
        assert!(plugin.container_opener().is_none(), "hooks");
        assert!(plugin.panel_content("pe.information").is_none(), "hooks");
    }

    /// A PE-like mock plugin.
    pub struct MockPe {
        last_command: Mutex<Option<String>>,
    }

    impl TypePlugin for MockPe {
        fn name(&self) -> &'static str {
            "PE"
        }
        fn validate(buf: &[u8], _extension: &str) -> bool {
            buf.starts_with(b"MZ")
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self {
                last_command: Mutex::new(None),
            })
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata {
                pattern: vec![Pattern::Magic(vec![0x4D, 0x5A])],
                priority: 1,
                description: String::from("Portable executable format for Windows OS binaries"),
                extensions: vec![String::from("exe"), String::from(".dll")],
                commands: vec![
                    CommandDef::new(
                        "DigitalSignature",
                        Key::new(KeyCode::F8, KeyModifier::Alt),
                        "Validate digital signature",
                        0,
                    ),
                    CommandDef::new(
                        "AreaHighlighter",
                        Key::new(KeyCode::F9, KeyModifier::Alt),
                        "Highlight portions of code base on an input file",
                        1,
                    ),
                ],
                opcodes_mask: Some(0xFFFF_FFFF),
            }
        }
        fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            let mut settings = BufferViewerRequest::default();
            settings.zones.add(
                0,
                0x3F,
                appcui::graphics::CharAttribute::default(),
                "DOS header",
            );
            settings.entry_point = Some(0x1000);
            settings.translation_methods.push(String::from("RVA"));
            win.add_panel(
                PanelRequest {
                    caption: String::from("&Information"),
                    panel_id: String::from("pe.information"),
                },
                true,
            );
            win.create_viewer(ViewerRequest::buffer(settings))?;
            win.create_viewer(ViewerRequest::new(ViewerKind::Dissasm).named("Code"))?;
            Ok(())
        }
        fn run_command(&mut self, command: &str) {
            *self.last_command.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(command.to_owned());
        }
        fn register_keys(&self, keys: &mut dyn KeyRegistry) {
            for command in &Self::metadata().commands {
                keys.register_key(command);
            }
        }
        fn smart_assistant_context(&self, prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
            Ok(serde_json::json!({ "Name": "PE", "Prompt": prompt }))
        }
        fn selection_zones_count(&self) -> u32 {
            1
        }
        fn selection_zone(&self, index: u32) -> SelectionZone {
            if index == 0 {
                SelectionZone { start: 0, end: 0x3F }
            } else {
                SelectionZone::default()
            }
        }
    }

    /// A script-like plugin matched by text.
    pub struct MockShell;

    impl TypePlugin for MockShell {
        fn name(&self) -> &'static str {
            "SH"
        }
        fn validate(_buf: &[u8], _extension: &str) -> bool {
            true
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata {
                pattern: vec![
                    Pattern::LineStartsWith(String::from("#!")),
                    Pattern::StartsWith(b"PK".to_vec()),
                ],
                priority: 70_000,
                description: String::from("shell"),
                extensions: vec![String::from("sh")],
                ..PluginMetadata::default()
            }
        }
        fn populate_window(&self, _win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            Ok(())
        }
        fn run_command(&mut self, _command: &str) {}
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
            Err(PluginError::Assistant(String::from("none")))
        }
    }

    struct BadPattern;

    impl TypePlugin for BadPattern {
        fn name(&self) -> &'static str {
            "BAD"
        }
        fn validate(_buf: &[u8], _extension: &str) -> bool {
            true
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata {
                pattern: vec![Pattern::Magic(Vec::new())],
                ..PluginMetadata::default()
            }
        }
        fn populate_window(&self, _win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            Ok(())
        }
        fn run_command(&mut self, _command: &str) {}
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }
    }

    #[derive(Default)]
    pub struct MockWindow {
        pub panels: Vec<(PanelRequest, bool)>,
        pub viewers: Vec<ViewerRequest>,
        pub current: Option<u32>,
        pub fail_viewers: bool,
    }

    impl WindowHandle for MockWindow {
        fn object(&self) -> SharedObject {
            Arc::new(Mutex::new(Object::from_buffer(b"MZ", "mock", 0)))
        }
        fn add_panel(&mut self, panel: PanelRequest, vertical: bool) -> bool {
            self.panels.push((panel, vertical));
            true
        }
        fn create_viewer(&mut self, request: ViewerRequest) -> Result<u32, PluginError> {
            if self.fail_viewers {
                return Err(PluginError::Window(String::from("no viewers")));
            }
            self.viewers.push(request);
            let index = (self.viewers.len() as u32).saturating_sub(1);
            self.current = Some(index);
            Ok(index)
        }
        fn views_count(&self) -> u32 {
            self.viewers.len() as u32
        }
        fn set_view_by_index(&mut self, index: u32) -> bool {
            if index < self.views_count() {
                self.current = Some(index);
                true
            } else {
                false
            }
        }
        fn current_view(&self) -> Option<u32> {
            self.current
        }
    }

    #[derive(Default)]
    struct MockKeys(Vec<CommandDef>);

    impl KeyRegistry for MockKeys {
        fn register_key(&mut self, command: &CommandDef) -> bool {
            if self.0.iter().any(|c| c.key == command.key) {
                return false;
            }
            self.0.push(command.clone());
            true
        }
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn traits_are_send_and_sync() {
        assert_send_sync::<MockPe>();
        assert_send_sync::<Box<dyn TypePlugin>>();
    }

    #[test]
    fn mock_plugin_validates_and_populates_window() {
        assert!(MockPe::validate(b"MZ\x90", ".exe"));
        assert!(!MockPe::validate(b"ZM", ".exe"));

        let plugin = MockPe::create_instance();
        assert_eq!(plugin.name(), "PE");
        let mut win = MockWindow::default();
        plugin.populate_window(&mut win).expect("populate");
        assert_eq!(win.panels.len(), 1);
        assert_eq!(win.panels[0].0.caption, "&Information");
        assert!(win.panels[0].1);
        assert_eq!(win.views_count(), 2);
        assert_eq!(win.viewers[0].kind, ViewerKind::Buffer);
        let buffer = win.viewers[0].buffer.as_ref().expect("buffer settings");
        assert_eq!(buffer.zones.count(), 1);
        assert_eq!(buffer.entry_point, Some(0x1000));
        assert_eq!(buffer.translation_methods, ["RVA"]);
        assert_eq!(win.viewers[1].kind, ViewerKind::Dissasm);
        assert_eq!(win.viewers[1].custom_name.as_deref(), Some("Code"));
        assert_eq!(win.current_view(), Some(1));
        assert!(win.set_view_by_index(0));
        assert!(!win.set_view_by_index(5));

        let mut failing = MockWindow {
            fail_viewers: true,
            ..MockWindow::default()
        };
        assert!(matches!(
            plugin.populate_window(&mut failing),
            Err(PluginError::Window(_))
        ));
    }

    #[test]
    fn commands_keys_and_assistant_context() {
        let mut plugin = MockPe::create_instance();
        plugin.run_command("DigitalSignature");
        assert_eq!(
            plugin.last_command.lock().expect("lock").as_deref(),
            Some("DigitalSignature")
        );
        let mut keys = MockKeys::default();
        plugin.register_keys(&mut keys);
        assert_eq!(keys.0.len(), 2);
        assert_eq!(keys.0[0].key, Key::new(KeyCode::F8, KeyModifier::Alt));
        let ctx = plugin.smart_assistant_context("what is this", "…").expect("ctx");
        assert_eq!(ctx["Name"], "PE");
        assert_eq!(plugin.selection_zones_count(), 1);
        assert_eq!(plugin.selection_zone(0), SelectionZone { start: 0, end: 0x3F });
        assert_eq!(plugin.selection_zone(7), SelectionZone::default());
        // Vtable defaults.
        let shell = MockShell::create_instance();
        assert_eq!(shell.selection_zones_count(), 0);
        assert_eq!(shell.selection_zone(0), SelectionZone::default());
    }

    #[test]
    fn pattern_ini_strings_roundtrip_through_matcher() {
        assert_eq!(Pattern::Magic(vec![0x4D, 0x5A]).to_ini_string(), "magic:4D 5A");
        assert_eq!(Pattern::StartsWith(b"PK".to_vec()).to_ini_string(), "startswith:PK");
        assert_eq!(
            Pattern::LineStartsWith(String::from("#!")).to_ini_string(),
            "linestartswith:#!"
        );
        assert_eq!(
            Pattern::Magic(vec![0x4D, 0x5A]).compile(),
            Matcher::from_string("magic:4D 5A")
        );
        assert!(Pattern::Magic(Vec::new()).compile().is_none());
        assert!(Pattern::StartsWith(Vec::new()).compile().is_none());
    }

    #[test]
    fn priority_clamp_and_hashes() {
        let mut m = PluginMetadata::default();
        assert_eq!(m.effective_priority(), MIN_EFFECTIVE_PRIORITY);
        m.priority = 1;
        assert_eq!(m.effective_priority(), MIN_EFFECTIVE_PRIORITY);
        m.priority = 0xFFFF;
        assert_eq!(m.effective_priority(), MIN_EFFECTIVE_PRIORITY);
        m.priority = 0x1_0000;
        assert_eq!(m.effective_priority(), 0x1_0000);
        m.extensions = vec![String::from("exe"), String::from(".DLL")];
        assert_eq!(
            m.extension_hashes(),
            [extension_hash("exe"), extension_hash("dll")]
        );
    }

    #[test]
    fn registry_orders_by_priority_and_matches() {
        let mut registry = TypePluginRegistry::new();
        registry.register_type::<MockPe>("PE").expect("pe");
        registry.register_type::<MockShell>("SH").expect("sh");
        // SH (70000) is tried before PE (clamped 65535).
        let names: Vec<&str> = registry.plugins().iter().map(RegisteredTypePlugin::name).collect();
        assert_eq!(names, ["SH", "PE"]);
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());
        assert_eq!(registry.by_name("PE").map(RegisteredTypePlugin::priority), Some(0xFFFF));
        assert!(registry.by_name("ZIP").is_none());

        let pe = registry.by_name("PE").expect("pe");
        assert!(pe.match_extension(extension_hash(".EXE")));
        assert!(pe.match_extension(extension_hash("dll")));
        assert!(!pe.match_extension(extension_hash("sh")));
        assert!(!pe.match_extension(0));
        let mut empty = TextParser::new(&[]);
        assert!(pe.match_content(b"MZ\x90", &mut empty));
        assert!(!pe.match_content(b"PK", &mut empty));
        assert!(pe.is_of_type(b"MZ", ""));
        assert_eq!(pe.create_instance().name(), "PE");
        assert_eq!(pe.metadata().commands.len(), 2);

        // Extension match first, then content; each plugin once.
        let text = utf16("#!/bin/sh");
        let found = registry.candidates(b"#!/bin/sh", &mut TextParser::new(&text), ".sh");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name(), "SH");

        let found = registry.candidates(b"MZ\x00", &mut TextParser::new(&[]), ".bin");
        let names: Vec<&str> = found.iter().map(|p| p.name()).collect();
        assert_eq!(names, ["PE"]);

        // Content matches PE, extension matches SH: SH first (extension pass).
        let found = registry.candidates(b"MZ\x00", &mut TextParser::new(&[]), ".sh");
        let names: Vec<&str> = found.iter().map(|p| p.name()).collect();
        assert_eq!(names, ["SH", "PE"]);

        // Validate gates a metadata match (PE pattern hit, MZ absent).
        let text = utf16("PK");
        let found = registry.candidates(b"PK", &mut TextParser::new(&text), "");
        let names: Vec<&str> = found.iter().map(|p| p.name()).collect();
        assert_eq!(names, ["SH"]);
    }

    #[test]
    fn registry_rejects_bad_patterns_and_duplicates() {
        let mut registry = TypePluginRegistry::new();
        assert_eq!(
            registry.register_type::<BadPattern>("BAD"),
            Err(PluginError::InvalidPattern(String::from("magic:")))
        );
        registry.register_type::<MockPe>("PE").expect("pe");
        assert_eq!(
            registry.register_type::<MockPe>("PE"),
            Err(PluginError::DuplicateName(String::from("PE")))
        );
        assert_eq!(registry.len(), 1);
        assert!(format!("{:?}", registry.plugins()[0].descriptor()).contains("PE"));
    }

    #[test]
    fn stable_order_among_equal_priorities() {
        let mut registry = TypePluginRegistry::new();
        registry.register_type::<MockPe>("PE").expect("pe");
        registry.register_type::<BadPatternFree>("B").expect("b");
        let names: Vec<&str> = registry.plugins().iter().map(RegisteredTypePlugin::name).collect();
        assert_eq!(names, ["PE", "B"]);
    }

    struct BadPatternFree;

    impl TypePlugin for BadPatternFree {
        fn name(&self) -> &'static str {
            "B"
        }
        fn validate(_buf: &[u8], _extension: &str) -> bool {
            true
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata::default()
        }
        fn populate_window(&self, _win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            Ok(())
        }
        fn run_command(&mut self, _command: &str) {}
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }
    }
}
