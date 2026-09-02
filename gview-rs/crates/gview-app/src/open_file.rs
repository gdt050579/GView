//! Open-file flow: `FirstMatch` / `BestMatch` / `Select` / `ForceType`.
//!
//! Spec `03_DUAL_PLUGIN` §7.3; `APPCUI_RS_UI_AND_ASYNC_GUIDE` §5.7;
//! C++ `GViewApp.cpp` `OpenFile` / `OpenBuffer`, `Instance::OpenFile`,
//! `SelectTypeDialog.cpp`.
//!
//! The identification itself lives in
//! [`crate::instance::window_lifecycle`]; this module supplies the
//! pieces around it:
//!
//! - [`open_file`] / [`open_buffer`]: the `GView::App::OpenFile` entry
//!   points — a relative path is canonicalised first, then the
//!   instance adds the window;
//! - [`build_type_choices`]: the `SelectTypeDialog` list
//!   (`PluginsThatMatches` + `PopulateTypes`): plugins matched by
//!   extension, then by content, the `Unknown type (Buffer or Text)`
//!   default, then everything that did not match — each checked with
//!   `IsOfType` on the `0x8800`-byte probe, in registry (priority)
//!   order, labelled `<name padded to 8>: <description>`;
//! - [`SelectTypeDialog`]: the modal itself (type combo, editable
//!   name, read-only size / path, OK / Cancel); OK re-validates the
//!   chosen plugin against the buffer (`Selected plugin can not
//!   process/match current buffer/text !`). The canvas preview
//!   (buffer / hex / text modes) is presentation only and is not
//!   ported;
//! - [`ModalTypeSelector`]: the [`TypeSelector`] the lifecycle asks
//!   when a `BestMatch` is ambiguous or the method is `Select` —
//!   it shows the dialog (or, headless, records that one was needed).
//!
//! `Instance::OpenFile` (menu): the `AppCUI` open dialog starting at the
//! last used folder, then `AddFileWindow(BestMatch)`; the folder is
//! remembered on success ([`OpenFileFlow`]).

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use appcui::prelude::*;
use gview_core::constants::TYPE_IDENTIFICATION_PROBE_SIZE;
use gview_plugin::fnv::extension_hash;
use gview_plugin::matcher::TextParser;
use gview_plugin::type_plugin::RegisteredTypePlugin;

use crate::instance::window_lifecycle::{probe_text, Instance, InstanceError, OpenMethod, TypeSelector};

/// C++ `DEFAULT_PLUGIN_INDEX` combo user data.
pub const DEFAULT_PLUGIN_INDEX: u32 = 0xFF_FFFF;
/// C++ `INVALID_TYPE_INDEX`.
pub const INVALID_TYPE_INDEX: u32 = 0xFFFF_FFFF;
/// Width the plugin name is padded / truncated to in the list
/// (`BuildTypeName`: `AddChars(' ', 8)` + `Truncate(8)`).
pub const TYPE_NAME_WIDTH: usize = 8;
/// Default entry caption.
pub const DEFAULT_TYPE_CAPTION: &str = "Unknown type (Buffer or Text)";
/// Error shown when the chosen plugin rejects the data.
pub const ERR_PLUGIN_REJECTS: &str = "Selected plugin can not process/match current buffer/text !";
/// Dialog title (`Window("Select type", …)`).
pub const SELECT_TYPE_TITLE: &str = "Select type";

/// Which list section an entry belongs to (`PopulateTypes` separators).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchGroup {
    /// `Matched by extension`.
    ByExtension,
    /// `Matched by content`.
    ByContent,
    /// `Defaults` (the generic fallback).
    Default,
    /// `Not matched`.
    NotMatched,
}

impl MatchGroup {
    /// Separator caption.
    #[must_use]
    pub const fn caption(self) -> &'static str {
        match self {
            Self::ByExtension => "Matched by extension",
            Self::ByContent => "Matched by content",
            Self::Default => "Defaults",
            Self::NotMatched => "Not matched",
        }
    }
}

/// One entry of the type list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeChoice {
    /// Display label.
    pub label: String,
    /// Index into the plugin list handed to [`build_type_choices`];
    /// `None` is the default (generic) plugin.
    pub plugin: Option<usize>,
    /// Section.
    pub group: MatchGroup,
}

/// C++ `BuildTypeName`: name padded with spaces to 8 and truncated to
/// 8, then `": "` and the description.
#[must_use]
pub fn build_type_name(name: &str, description: &str) -> String {
    let mut padded: String = name.chars().take(TYPE_NAME_WIDTH).collect();
    while padded.chars().count() < TYPE_NAME_WIDTH {
        padded.push(' ');
    }
    format!("{padded}: {description}")
}

/// C++ `PluginsThatMatches` + `PopulateTypes`, over `plugins` in the
/// given (priority) order. `buf` is the identification probe — only
/// its first `0x8800` bytes are considered (`Instance.cpp`).
#[must_use]
pub fn build_type_choices(
    plugins: &[&RegisteredTypePlugin],
    buf: &[u8],
    text: &[u16],
    extension: &str,
) -> Vec<TypeChoice> {
    let probe = buf.get(..(TYPE_IDENTIFICATION_PROBE_SIZE as usize).min(buf.len())).unwrap_or(buf);
    let mut parser = TextParser::new(text);
    let hash = extension_hash(extension);

    let by_extension: Vec<bool> = plugins
        .iter()
        .map(|p| hash != 0 && p.match_extension(hash) && p.is_of_type(probe, extension))
        .collect();
    let by_content: Vec<bool> = plugins
        .iter()
        .map(|p| p.match_content(probe, &mut parser) && p.is_of_type(probe, extension))
        .collect();

    let label = |p: &RegisteredTypePlugin| build_type_name(p.name(), &p.metadata().description);
    let mut choices = Vec::new();
    if by_extension.iter().any(|m| *m) {
        for (idx, plugin) in plugins.iter().enumerate() {
            if by_extension.get(idx).copied().unwrap_or(false) {
                choices.push(TypeChoice {
                    label: label(plugin),
                    plugin: Some(idx),
                    group: MatchGroup::ByExtension,
                });
            }
        }
    }
    if by_content.iter().any(|m| *m) {
        for (idx, plugin) in plugins.iter().enumerate() {
            if by_content.get(idx).copied().unwrap_or(false) {
                choices.push(TypeChoice {
                    label: label(plugin),
                    plugin: Some(idx),
                    group: MatchGroup::ByContent,
                });
            }
        }
    }
    choices.push(TypeChoice {
        label: String::from(DEFAULT_TYPE_CAPTION),
        plugin: None,
        group: MatchGroup::Default,
    });
    // C++ `HasNoMatches`: `(ext + content) < count` — counts hits, so
    // a plugin matched both ways can hide the section; replicated.
    let hits = by_extension.iter().filter(|m| **m).count().saturating_add(by_content.iter().filter(|m| **m).count());
    if hits < plugins.len() {
        for (idx, plugin) in plugins.iter().enumerate() {
            let e = by_extension.get(idx).copied().unwrap_or(false);
            let c = by_content.get(idx).copied().unwrap_or(false);
            if !e && !c {
                choices.push(TypeChoice {
                    label: label(plugin),
                    plugin: Some(idx),
                    group: MatchGroup::NotMatched,
                });
            }
        }
    }
    choices
}

/// Result of the dialog: the chosen plugin (`None` = default) and the
/// possibly edited file name (`GetFilename`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectTypeChoice {
    /// Chosen plugin index (into the dialog's plugin list).
    pub plugin: Option<usize>,
    /// File name from the editable field.
    pub filename: String,
}

/// C++ `SelectTypeDialog` (`Window("Select type", "d:c,w:80,h:28")`).
#[ModalWindow(events = ButtonEvents + WindowEvents, response = SelectTypeChoice)]
pub struct SelectTypeDialog {
    types: Handle<ComboBox>,
    name: Handle<TextField>,
    ok: Handle<Button>,
    cancel: Handle<Button>,
    choices: Vec<TypeChoice>,
    accepts: Vec<bool>,
}

impl SelectTypeDialog {
    /// Builds the dialog over `choices`; `accepts[i]` tells whether
    /// the plugin of choice `i` accepts the data (the OK re-check).
    #[must_use]
    pub fn new(name: &str, path: &str, size: u64, choices: Vec<TypeChoice>, accepts: Vec<bool>) -> Self {
        let mut win = Self {
            base: ModalWindow::new(SELECT_TYPE_TITLE, layout!("a:c,w:80,h:14"), window::Flags::None),
            types: Handle::None,
            name: Handle::None,
            ok: Handle::None,
            cancel: Handle::None,
            choices,
            accepts,
        };
        win.add(Label::new("&Type", layout!("x:1,y:1,w:10")));
        win.add(Label::new("&Name", layout!("x:1,y:3,w:10")));
        win.add(Label::new("&Size", layout!("x:50,y:3,w:10")));
        win.add(Label::new("&Path", layout!("x:1,y:5,w:10")));
        let mut combo = ComboBox::new(layout!("l:12,t:1,r:1"), combobox::Flags::ShowDescription);
        for choice in &win.choices {
            combo.add_item(combobox::Item::new(&choice.label, choice.group.caption()));
        }
        if combo.count() > 0 {
            combo.set_index(0);
        }
        win.types = win.add(combo);
        win.name = win.add(TextField::new(name, layout!("x:12,y:3,w:33"), textfield::Flags::None));
        win.add(TextField::new(
            &format_size(size),
            layout!("l:56,t:3,r:1"),
            textfield::Flags::Readonly,
        ));
        win.add(TextField::new(path, layout!("l:12,t:5,r:1"), textfield::Flags::Readonly));
        win.ok = win.add(Button::new("&Ok", layout!("b:0,l:22,w:15")));
        win.cancel = win.add(Button::new("&Cancel", layout!("b:0,l:41,w:15")));
        win
    }

    /// Currently selected choice index.
    fn current_choice(&self) -> Option<usize> {
        let handle = self.types;
        self.control(handle).and_then(ComboBox::index).map(|i| i as usize)
    }

    /// C++ `Validate()`: default exits with `None`; a plugin must
    /// accept the data, otherwise an error is shown and the dialog
    /// stays open.
    fn validate(&mut self) {
        let Some(index) = self.current_choice() else {
            return;
        };
        let Some(choice) = self.choices.get(index).cloned() else {
            return;
        };
        let name_handle = self.name;
        let filename = self.control(name_handle).map(|t| t.text().to_owned()).unwrap_or_default();
        if let Some(plugin) = choice.plugin {
            if !self.accepts.get(index).copied().unwrap_or(false) {
                dialogs::error("Error", ERR_PLUGIN_REJECTS);
                return;
            }
            self.exit_with(SelectTypeChoice {
                plugin: Some(plugin),
                filename,
            });
        } else {
            self.exit_with(SelectTypeChoice { plugin: None, filename });
        }
    }
}

impl ButtonEvents for SelectTypeDialog {
    fn on_pressed(&mut self, handle: Handle<Button>) -> EventProcessStatus {
        if handle == self.ok {
            self.validate();
            EventProcessStatus::Processed
        } else if handle == self.cancel {
            self.exit();
            EventProcessStatus::Processed
        } else {
            EventProcessStatus::Ignored
        }
    }
}

impl WindowEvents for SelectTypeDialog {
    fn on_accept(&mut self) {
        self.validate();
    }
}

/// C++ `NumericFormat(None, 10, 3, ',')`: thousands separators.
#[must_use]
pub fn format_size(size: u64) -> String {
    let digits = size.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len().saturating_sub(i)) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// The [`TypeSelector`] backed by [`SelectTypeDialog`].
///
/// Holds the probe so the dialog can group candidates like C++. When
/// `interactive` is `false` (headless / tests) no window is shown:
/// the request is recorded ([`Self::dialog_requested`]) and the open
/// is cancelled.
#[derive(Clone, Debug)]
pub struct ModalTypeSelector {
    probe: Vec<u8>,
    text: Vec<u16>,
    extension: String,
    name: String,
    path: String,
    size: u64,
    interactive: bool,
    requested: usize,
    last_choices: Vec<TypeChoice>,
    filename: Option<String>,
}

impl ModalTypeSelector {
    /// A selector for the object being opened.
    #[must_use]
    pub fn new(probe: Vec<u8>, text: Vec<u16>, extension: &str, name: &str, path: &str, size: u64, interactive: bool) -> Self {
        Self {
            probe,
            text,
            extension: extension.to_owned(),
            name: name.to_owned(),
            path: path.to_owned(),
            size,
            interactive,
            requested: 0,
            last_choices: Vec::new(),
            filename: None,
        }
    }

    /// How many times a dialog was needed.
    #[must_use]
    pub const fn dialog_requested(&self) -> usize {
        self.requested
    }

    /// The choices of the last (would-be) dialog.
    #[must_use]
    pub fn last_choices(&self) -> &[TypeChoice] {
        &self.last_choices
    }

    /// The file name the user typed (C++ `newName`), if any.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }
}

impl TypeSelector for ModalTypeSelector {
    fn select(&mut self, candidates: &[&RegisteredTypePlugin]) -> Option<usize> {
        self.requested = self.requested.saturating_add(1);
        let choices = build_type_choices(candidates, &self.probe, &self.text, &self.extension);
        self.last_choices.clone_from(&choices);
        if !self.interactive {
            return None;
        }
        let all: &[u8] = self.probe.as_slice();
        let probe = <[u8]>::get(all, ..(TYPE_IDENTIFICATION_PROBE_SIZE as usize).min(all.len())).unwrap_or(all);
        let accepts: Vec<bool> = choices
            .iter()
            .map(|c| {
                c.plugin
                    .and_then(|i| candidates.get(i))
                    .is_none_or(|p| p.is_of_type(probe, &self.extension))
            })
            .collect();
        let response = SelectTypeDialog::new(&self.name, &self.path, self.size, choices, accepts).show()?;
        self.filename = Some(response.filename);
        // The default entry maps to "past the candidate list".
        Some(response.plugin.unwrap_or(candidates.len()))
    }
}

/// C++ `GView::App::OpenFile(path, method, typeName)`: canonicalises a
/// relative path, then `AddFileWindow`.
///
/// # Errors
///
/// [`InstanceError`] from the instance (open failure, cancel, populate
/// failure).
pub fn open_file(
    instance: &mut Instance,
    path: &Path,
    method: OpenMethod,
    type_name: &str,
    selector: &mut dyn TypeSelector,
) -> Result<u32, InstanceError> {
    let absolute: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(source) => {
                return Err(InstanceError::OpenFile {
                    path: path.to_path_buf(),
                    source,
                })
            }
        }
    };
    instance.add_file_window(&absolute, method, type_name, selector)
}

/// C++ `GView::App::OpenBuffer(buf, name, path, method, typeName)`.
///
/// # Errors
///
/// As [`Instance::add_buffer_window`].
pub fn open_buffer(
    instance: &mut Instance,
    buf: &[u8],
    name: &str,
    method: OpenMethod,
    type_name: &str,
    selector: &mut dyn TypeSelector,
) -> Result<u32, InstanceError> {
    instance.add_buffer_window(buf, name, method, type_name, selector)
}

/// Builds the `SelectTypeDialog` seam for `path` (`00_APP §4`).
///
/// The C++ creates the dialog inside `Instance::Add`, where the probe
/// is already in hand; the Rust desktop creates the selector *before*
/// calling the open pipeline, so it reads the same bounded
/// `TYPE_IDENTIFICATION_PROBE_SIZE` window itself. Nothing beyond that
/// window is read, and a path that cannot be read yields an empty
/// probe — the open then fails with the real I/O error.
#[must_use]
pub fn selector_for_path(path: &Path, interactive: bool) -> ModalTypeSelector {
    let mut probe = vec![0_u8; TYPE_IDENTIFICATION_PROBE_SIZE as usize];
    let read = File::open(path)
        .and_then(|mut file| read_probe(&mut file, &mut probe))
        .unwrap_or(0);
    probe.truncate(read);
    let size = std::fs::metadata(path).map_or(0, |m| m.len());
    let text = probe_text(&probe);
    let display = path.display().to_string();
    let extension = gview_plugin::fnv::extension_of(&display).unwrap_or("").to_owned();
    let name = path
        .file_name()
        .map_or_else(|| display.clone(), |n| n.to_string_lossy().into_owned());
    ModalTypeSelector::new(probe, text, &extension, &name, &display, size, interactive)
}

/// Fills `buf` from `file`, tolerating short reads.
fn read_probe(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0_usize;
    while filled < buf.len() {
        let Some(slot) = buf.get_mut(filled..) else {
            break;
        };
        match file.read(slot) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// C++ `Instance::OpenFile()` menu flow state
/// (`lastOpenedFolderLocation`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenFileFlow {
    last_opened_folder: Option<PathBuf>,
}

impl OpenFileFlow {
    /// Fresh flow (no remembered folder).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_opened_folder: None,
        }
    }

    /// The remembered folder.
    #[must_use]
    pub fn last_opened_folder(&self) -> Option<&Path> {
        self.last_opened_folder.as_deref()
    }

    /// Shows the `AppCUI` open dialog (`ShowOpenFileWindow`) starting at
    /// the last folder; `None` when cancelled.
    #[must_use]
    pub fn ask_path(&self) -> Option<PathBuf> {
        let location = self
            .last_opened_folder
            .as_deref()
            .map_or(dialogs::Location::Last, dialogs::Location::Path);
        dialogs::open("Open", "", location, None, dialogs::OpenFileDialogFlags::CheckIfFileExists)
    }

    /// Records `path`'s folder as the dialog's next starting point
    /// (C++ `lastOpenedFolderLocation`).
    pub fn remember_folder(&mut self, path: &Path) {
        self.last_opened_folder = path.parent().map(Path::to_path_buf);
    }

    /// Opens `path` with `BestMatch` (the menu path) and remembers its
    /// folder on success.
    ///
    /// # Errors
    ///
    /// As [`open_file`]; errors are also left in the instance's error
    /// list for `ShowErrors`.
    pub fn open_chosen(
        &mut self,
        instance: &mut Instance,
        path: &Path,
        selector: &mut dyn TypeSelector,
    ) -> Result<u32, InstanceError> {
        let index = open_file(instance, path, OpenMethod::BestMatch, "", selector)?;
        self.last_opened_folder = path.parent().map(Path::to_path_buf);
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::window_lifecycle::CancelSelector;
    use gview_core::constants::DEFAULT_CACHE_SIZE;
    use gview_plugin::generic_plugin::GenericPluginRegistry;
    use gview_plugin::matcher::utf16;
    use gview_plugin::type_plugin::{
        KeyRegistry, Pattern, PluginError, PluginMetadata, TypePlugin, TypePluginRegistry, ViewerKind,
        ViewerRequest, WindowHandle,
    };
    use serde_json::Value as JsonValue;

    macro_rules! mock_plugin {
        ($name:ident, $label:expr, $validate:expr, $meta:expr) => {
            struct $name;
            impl TypePlugin for $name {
                fn name(&self) -> &'static str {
                    $label
                }
                fn validate(buf: &[u8], _extension: &str) -> bool {
                    let f: fn(&[u8]) -> bool = $validate;
                    f(buf)
                }
                fn create_instance() -> Box<Self> {
                    Box::new(Self)
                }
                fn metadata() -> PluginMetadata {
                    $meta
                }
                fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
                    win.create_viewer(ViewerRequest::new(ViewerKind::Buffer))?;
                    Ok(())
                }
                fn run_command(&mut self, _command: &str) {}
                fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
                fn smart_assistant_context(&self, _p: &str, _d: &str) -> Result<JsonValue, PluginError> {
                    Ok(JsonValue::Null)
                }
            }
        };
    }

    mock_plugin!(
        Pe,
        "PE",
        |buf| buf.starts_with(b"MZ"),
        PluginMetadata {
            pattern: vec![Pattern::Magic(vec![0x4D, 0x5A])],
            priority: 1,
            description: String::from("Portable executable"),
            extensions: vec![String::from("exe")],
            ..PluginMetadata::default()
        }
    );
    mock_plugin!(
        Script,
        "SCRIPT",
        |_buf| true,
        PluginMetadata {
            pattern: vec![Pattern::LineStartsWith(String::from("#!"))],
            priority: 70_000,
            description: String::from("Shell script"),
            extensions: vec![String::from("sh")],
            ..PluginMetadata::default()
        }
    );
    mock_plugin!(
        Elf,
        "ELFPLUGIN",
        |buf| buf.starts_with(b"\x7fELF"),
        PluginMetadata {
            pattern: vec![Pattern::Magic(vec![0x7F, 0x45, 0x4C, 0x46])],
            priority: 2,
            description: String::from("ELF"),
            ..PluginMetadata::default()
        }
    );

    fn registry() -> TypePluginRegistry {
        let mut types = TypePluginRegistry::new();
        types.register_type::<Pe>("PE").expect("pe");
        types.register_type::<Script>("SCRIPT").expect("script");
        types.register_type::<Elf>("ELFPLUGIN").expect("elf");
        types
    }

    fn instance() -> Instance {
        Instance::new(registry(), GenericPluginRegistry::new(), DEFAULT_CACHE_SIZE)
    }

    #[test]
    fn type_name_is_padded_to_eight_columns() {
        assert_eq!(build_type_name("PE", "Portable executable"), "PE      : Portable executable");
        assert_eq!(build_type_name("ELFPLUGIN", "ELF"), "ELFPLUGI: ELF");
        assert_eq!(build_type_name("", "x"), "        : x");
    }

    #[test]
    fn choices_are_grouped_in_priority_order() {
        let types = registry();
        let plugins: Vec<&RegisteredTypePlugin> = types.plugins().iter().collect();
        // Registry order is by priority: SCRIPT (70000) first.
        assert_eq!(plugins[0].name(), "SCRIPT");
        let text = utf16("MZ#!");
        let choices = build_type_choices(&plugins, b"MZ#!", &text, ".sh");
        let summary: Vec<(MatchGroup, Option<&str>)> = choices
            .iter()
            .map(|c| (c.group, c.plugin.map(|i| plugins[i].name())))
            .collect();
        assert_eq!(
            summary,
            [
                (MatchGroup::ByExtension, Some("SCRIPT")),
                (MatchGroup::ByContent, Some("PE")),
                (MatchGroup::Default, None),
                (MatchGroup::NotMatched, Some("ELFPLUGIN")),
            ]
        );
        assert_eq!(choices[2].label, DEFAULT_TYPE_CAPTION);
        assert_eq!(choices[0].label, "SCRIPT  : Shell script");
        assert_eq!(MatchGroup::ByExtension.caption(), "Matched by extension");
        assert_eq!(MatchGroup::NotMatched.caption(), "Not matched");

        // No matches at all: only default + not matched.
        let choices = build_type_choices(&plugins, b"zzzz", &[], "");
        assert_eq!(choices.len(), 1 + plugins.len());
        assert_eq!(choices[0].group, MatchGroup::Default);
        assert!(choices[1..].iter().all(|c| c.group == MatchGroup::NotMatched));
    }

    #[test]
    fn probe_is_capped_at_0x8800_bytes() {
        let types = registry();
        let plugins: Vec<&RegisteredTypePlugin> = types.plugins().iter().collect();
        // ELF magic exactly at the probe boundary is invisible.
        let mut data = vec![0_u8; TYPE_IDENTIFICATION_PROBE_SIZE as usize + 8];
        data[TYPE_IDENTIFICATION_PROBE_SIZE as usize..TYPE_IDENTIFICATION_PROBE_SIZE as usize + 4]
            .copy_from_slice(b"\x7fELF");
        let choices = build_type_choices(&plugins, &data, &[], "");
        assert!(choices.iter().all(|c| c.group != MatchGroup::ByContent));
        // At offset 0 it matches.
        let choices = build_type_choices(&plugins, b"\x7fELF\x02", &[], "");
        assert!(choices.iter().any(|c| c.group == MatchGroup::ByContent && c.plugin == Some(2)));
    }

    #[test]
    fn ambiguous_best_match_requests_the_dialog() {
        let mut inst = instance();
        // ".sh" → SCRIPT by extension, "MZ" → PE by content: ambiguous.
        let probe = b"MZxx".to_vec();
        let mut selector = ModalTypeSelector::new(probe, Vec::new(), ".sh", "two.sh", "two.sh", 4, false);
        let err = open_buffer(&mut inst, b"MZxx", "two.sh", OpenMethod::BestMatch, "", &mut selector)
            .expect_err("headless dialog cancels");
        assert!(matches!(err, InstanceError::OpenCanceled));
        assert_eq!(selector.dialog_requested(), 1);
        let names: Vec<Option<&str>> = selector
            .last_choices()
            .iter()
            .map(|c| c.plugin.map(|i| ["SCRIPT", "PE"][i]))
            .collect();
        assert_eq!(names, [Some("SCRIPT"), Some("PE"), None]);
        assert_eq!(inst.objects_count(), 0);

        // An unambiguous open never asks.
        let mut selector = ModalTypeSelector::new(b"MZxx".to_vec(), Vec::new(), ".exe", "a.exe", "a.exe", 4, false);
        open_buffer(&mut inst, b"MZxx", "a.exe", OpenMethod::BestMatch, "", &mut selector).expect("open");
        assert_eq!(selector.dialog_requested(), 0);
        assert_eq!(inst.current_window().and_then(crate::instance::window_lifecycle::FileWindowModel::type_plugin_name), Some("PE"));

        // `Select` always asks.
        let mut selector = ModalTypeSelector::new(b"MZxx".to_vec(), Vec::new(), ".exe", "a.exe", "a.exe", 4, false);
        assert!(matches!(
            open_buffer(&mut inst, b"MZxx", "a.exe", OpenMethod::Select, "", &mut selector),
            Err(InstanceError::OpenCanceled)
        ));
        assert_eq!(selector.dialog_requested(), 1);
        // PE is listed twice (extension and content, like the C++ combo),
        // then the default, then SCRIPT and ELF under "Not matched".
        assert_eq!(selector.last_choices().len(), 5);
        let groups: Vec<MatchGroup> = selector.last_choices().iter().map(|c| c.group).collect();
        assert_eq!(
            groups,
            [
                MatchGroup::ByExtension,
                MatchGroup::ByContent,
                MatchGroup::Default,
                MatchGroup::NotMatched,
                MatchGroup::NotMatched
            ]
        );
    }

    /// The selector seam of `00_APP §4`: without a terminal the
    /// `SelectTypeDialog` is never built — the request is recorded and
    /// the open is cancelled with the C++ wording.
    #[test]
    fn identify_headless_selector_records_the_request_and_cancels() {
        let mut inst = instance();
        let mut selector = ModalTypeSelector::new(b"MZxx".to_vec(), Vec::new(), ".exe", "a.exe", "a.exe", 4, false);
        assert_eq!(selector.dialog_requested(), 0);
        assert!(selector.filename().is_none());

        // `Select` always needs the dialog; headless answers `None`.
        let error = open_buffer(&mut inst, b"MZxx", "a.exe", OpenMethod::Select, "", &mut selector)
            .expect_err("headless cancels");
        assert!(matches!(error, InstanceError::OpenCanceled));
        assert_eq!(error.to_string(), "Unable to identify a valid plugin open canceled !");
        assert_eq!(selector.dialog_requested(), 1, "the request is recorded");
        assert!(!selector.last_choices().is_empty(), "the choices are still built");
        assert!(selector.filename().is_none(), "no dialog, no new name");
        assert_eq!(inst.objects_count(), 0);

        // A second cancelled open increments the counter again.
        let _ = open_buffer(&mut inst, b"MZxx", "a.exe", OpenMethod::Select, "", &mut selector);
        assert_eq!(selector.dialog_requested(), 2);
    }

    #[test]
    fn open_file_canonicalises_relative_paths_and_remembers_the_folder() {
        let dir = std::env::temp_dir().join(format!("gview-open-flow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("bin.exe");
        std::fs::write(&path, b"MZ\x90\x00").expect("write");

        let mut inst = instance();
        let mut flow = OpenFileFlow::new();
        assert!(flow.last_opened_folder().is_none());
        let index = flow
            .open_chosen(&mut inst, &path, &mut CancelSelector)
            .expect("open");
        assert_eq!(index, 0);
        assert_eq!(flow.last_opened_folder(), Some(dir.as_path()));
        assert_eq!(inst.current_window().and_then(crate::instance::window_lifecycle::FileWindowModel::type_plugin_name), Some("PE"));

        // A relative path that does not exist fails at canonicalisation.
        let err = open_file(
            &mut inst,
            Path::new("does-not-exist-gview.bin"),
            OpenMethod::FirstMatch,
            "",
            &mut CancelSelector,
        )
        .expect_err("missing");
        assert!(matches!(err, InstanceError::OpenFile { .. }));
        assert_eq!(inst.objects_count(), 1);

        // Force type through the App entry point.
        open_file(&mut inst, &path, OpenMethod::ForceType, "pe", &mut CancelSelector).expect("forced");
        assert_eq!(inst.objects_count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn size_formatting_uses_thousands_separators() {
        assert_eq!(format_size(0), "0");
        assert_eq!(format_size(999), "999");
        assert_eq!(format_size(1000), "1,000");
        assert_eq!(format_size(1_234_567), "1,234,567");
    }

    #[test]
    fn constants_match_cpp() {
        assert_eq!(DEFAULT_PLUGIN_INDEX, 0xFF_FFFF);
        assert_eq!(INVALID_TYPE_INDEX, 0xFFFF_FFFF);
        assert_eq!(TYPE_NAME_WIDTH, 8);
        assert_eq!(SELECT_TYPE_TITLE, "Select type");
    }

    /// UI test: the modal lists the choices and Escape cancels.
    #[test]
    fn select_type_dialog_cancels_on_escape() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        #[Window(events = WindowEvents)]
        struct Host {
            choices: Vec<TypeChoice>,
            shown: Arc<AtomicBool>,
            cancelled: Arc<AtomicBool>,
            done: Arc<AtomicUsize>,
        }
        impl WindowEvents for Host {
            fn on_activate(&mut self) {
                if self.done.fetch_add(1, Ordering::SeqCst) > 0 {
                    return;
                }
                self.shown.store(true, Ordering::SeqCst);
                let accepts = vec![true; self.choices.len()];
                let response = SelectTypeDialog::new("sample.exe", "C:/sample.exe", 4, self.choices.clone(), accepts).show();
                self.cancelled.store(response.is_none(), Ordering::SeqCst);
            }
        }

        let script = "
            Paint.Enable(false)
            Paint('dialog')
            Key.Pressed(Escape)
            Paint('closed')
        ";
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, script).build().expect("debug app");
        let types = registry();
        let plugins: Vec<&RegisteredTypePlugin> = types.plugins().iter().collect();
        let choices = build_type_choices(&plugins, b"MZxx", &[], ".exe");
        let shown = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));
        let host = Host {
            base: Window::new("host", layout!("d:f"), window::Flags::None),
            choices,
            shown: Arc::clone(&shown),
            cancelled: Arc::clone(&cancelled),
            done: Arc::new(AtomicUsize::new(0)),
        };
        app.add_window(host);
        app.run();
        assert!(shown.load(Ordering::SeqCst));
        assert!(cancelled.load(Ordering::SeqCst));
    }
}
