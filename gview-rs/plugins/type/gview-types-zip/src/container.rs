//! The ZIP type plugin: the container-viewer VFS over the central
//! directory, extract-on-demand, `PopulateWindow` and the
//! `TypeInterface` methods.
//!
//! Spec `06_TYPE_PLUGINS` §ZIP `ContainerViewer` integration /
//! `SmartAssistant`; `02_VIEWER_CONTAINER` §3 (enumeration), §5
//! (open / extract), §10 (reference pattern), §12 (security); C++
//! `zip.cpp` `CreateContainerView` / `CreateBufferView` /
//! `PopulateWindow` / `UpdateSettings`, `ZIPFile.cpp` `Update` /
//! `BeginIteration` / `PopulateItem` / `OnOpenItem` /
//! `GetSmartAssistantContext`.
//!
//! `Update()` lists the archive with [`ZipInfo`]: from the path when
//! the object exists on disk (`isTopContainer`), otherwise from the
//! whole cached buffer (a ZIP opened out of another container). A
//! listing failure is ignored like the C++ `CHECK` whose result
//! `PopulateWindow` drops: the window still opens with an empty tree
//! and the error is kept in [`ZipPlugin::last_error`].
//!
//! `BeginIteration(path)` (`ZIPFile.cpp:31-79`) selects the direct
//! children of `path`: for the root, directories whose only `/` is the
//! trailing one and files without any `/`; when the root has none of
//! those — or for any other path — every entry whose name is
//! `path + '/' + <one component>` (directories with the trailing `/`
//! stripped first). `PopulateItem` fills the eight columns exactly as
//! the C++ does, including the quirk that column 5 shows the
//! **compressed size** next to the compression method name.
//!
//! `OnOpenItem` (`ZIPFile.cpp:190-261`) is [`ZipPlugin::open_item`] /
//! [`ZipPlugin::open_item_with_password`]: the entry is decompressed
//! on demand (never the whole archive), under the [`ZipLimits`] bomb
//! guards, and handed back with the name and the `<archive>.drop/<name>`
//! path the shell opens it under (`App::OpenBuffer(..., BestMatch)`);
//! the path goes through [`safe_extract_path`], so `..` / absolute
//! entry names are rejected (§12 zip-slip). Password prompting is the
//! shell's job: an encrypted entry without a usable password yields
//! [`OpenError::PasswordRequired`], a failed decrypt
//! [`OpenError::WrongPassword`]; a password accepted with
//! `save_as_default` becomes the plugin's default like the C++
//! "Save password as default" check box.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use gview_decoding::zip::{safe_extract_path, EntryType, ZipEntry, ZipError, ZipInfo, ZipLimits};
use gview_plugin::type_plugin::{
    BufferViewerRequest, ContainerViewerRequest, KeyRegistry, PanelRequest, Pattern, PluginError, PluginMetadata,
    TypePlugin, ViewerRequest, WindowHandle,
};
use gview_view::container_viewer::tree::{EnumerateInterface, TreeItemId, TreeNode};
use gview_view::traits::SharedObject;
use serde_json::Value as JsonValue;

use crate::validate::{validate, MAGIC_BYTES};

/// `UpdateSettings` `Description`.
pub const DESCRIPTION: &str = "Archive file format (*.zip)";
/// `UpdateSettings` `Extension`.
pub const EXTENSION: &str = "zip";
/// `UpdateSettings` `Priority`.
pub const PRIORITY: u32 = 1;
/// `SetPathSeparator('/')`.
pub const PATH_SEPARATOR: char = '/';
/// The `.drop` suffix appended to the archive path for extracted
/// entries (`path.append(u".drop")`).
pub const DROP_SUFFIX: &str = ".drop";
/// `ZIP_ICON` (16×16, `zip.cpp:15-30`).
pub const ZIP_ICON: &str = concat!(
    "................",
    "...WWW..........",
    "..WYYYW.........",
    ".WYYYYYWWWWWWW..",
    ".WbbbbybybbbbyW.",
    ".WyyybyyybyybyW.",
    ".WyybyybybbbbyW.",
    ".WybyyybybyyyyW.",
    ".WbbbbybybyyyyW.",
    ".WyyyyyyyyyyyyW.",
    "..WWWWWWWWWWWW..",
    "................",
    "................",
    "................",
    "................",
    "................",
);
/// `CreateContainerView` columns.
pub const CONTAINER_COLUMNS: [&str; 8] = [
    "n:&Filename,a:l,w:80",
    "n:&Type,a:l,w:20",
    "n:&Flags,a:r,w:40",
    "n:&Compressed Size,a:r,w:20",
    "n:&Uncompressed Size,a:r,w:20",
    "n:&Compression Method,a:r,w:20",
    "n:&Disk Number,a:r,w:20",
    "n:&Disk Offset,a:r,w:20",
];

/// The panels `PopulateWindow` adds, in order: `(caption, id, vertical)`.
pub const PANELS: [(&str, &str, bool); 2] = [
    ("Informa&tion", "zip.information", true),
    ("&Objects", "zip.objects", false),
];

/// Failures of [`ZipPlugin::open_item`].
#[derive(Debug)]
pub enum OpenError {
    /// `PopulateWindow` was not called.
    NotLoaded,
    /// The entry is encrypted and no default password is set (the
    /// C++ falls through to the password dialog).
    PasswordRequired,
    /// Decryption with the supplied / default password failed (C++
    /// "Wrong default password!" / "Wrong password!").
    WrongPassword,
    /// Decompression failed for a reason other than the password
    /// (C++ "Failed to decompress!"), including the bomb guards and an
    /// entry that is not a file.
    Decompress(ZipError),
    /// The entry name would escape the extraction directory
    /// (§12 zip-slip).
    UnsafePath(String),
    /// The cached buffer of a nested archive could not be read.
    Source(String),
}

impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotLoaded => f.write_str("archive not loaded"),
            Self::PasswordRequired => f.write_str("Unable to decompress without a password!"),
            Self::WrongPassword => f.write_str("Wrong password!"),
            Self::Decompress(e) => write!(f, "Failed to decompress! ({e})"),
            Self::UnsafePath(name) => write!(f, "unsafe archive path: {name:?}"),
            Self::Source(e) => write!(f, "cannot read the archive bytes: {e}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// A decompressed entry ready for `App::OpenBuffer`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedEntry {
    /// `entry.GetFilename()` — the name the new object gets.
    pub name: String,
    /// The path the object is opened under (`<archive>.drop/<name>`
    /// for the default-password path, `<name>` after the dialog).
    pub path: PathBuf,
    /// Decompressed bytes.
    pub bytes: Vec<u8>,
}

/// C++ `ZIPFile` members.
#[derive(Clone, Debug, Default)]
pub struct ZipState {
    /// `info`.
    pub info: ZipInfo,
    /// `isTopContainer` — the archive exists on disk.
    pub is_top_container: bool,
    /// `obj->GetPath()`.
    pub path: PathBuf,
    /// `currentItemIndex`.
    pub current_item_index: usize,
    /// `curentChildIndexes`.
    pub child_indexes: Vec<u32>,
}

/// Name of a directory entry without its trailing `/`.
fn directory_name(entry: &ZipEntry) -> &str {
    let name = entry.filename.as_str();
    if entry.entry_type == EntryType::Directory {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    }
}

/// C++ `BeginIteration` child selection over the listing.
#[must_use]
pub fn children_of(info: &ZipInfo, path: &str) -> Vec<u32> {
    let mut indexes = Vec::new();
    if path.is_empty() {
        for (i, entry) in info.entries().iter().enumerate() {
            let filename = entry.filename.as_str();
            let first_slash = filename.find('/');
            let is_dir = entry.entry_type == EntryType::Directory;
            let root_dir = is_dir && first_slash == filename.len().checked_sub(1);
            let root_file = !is_dir && first_slash.is_none();
            if root_dir || root_file {
                indexes.push(i as u32);
            }
        }
        if !indexes.is_empty() {
            return indexes;
        }
    }
    for (i, entry) in info.entries().iter().enumerate() {
        let name = directory_name(entry);
        if name.len() > path.len() && name.starts_with(path) && name.as_bytes().get(path.len()) == Some(&b'/') {
            let rest = name.get(path.len()..).unwrap_or("");
            if rest.find('/') == rest.rfind('/') {
                indexes.push(i as u32);
            }
        }
    }
    indexes
}

/// C++ `PopulateItem` column texts for one entry.
#[must_use]
pub fn entry_columns(entry: &ZipEntry) -> Vec<String> {
    let name = directory_name(entry);
    let leaf = name.rsplit('/').next().unwrap_or(name);
    vec![
        leaf.to_owned(),
        format!("{} ({:#x})", entry.type_name(), entry.entry_type as u32),
        format!("{} ({:#x})", entry.flag_names(), entry.flags),
        format!("{:#x}", entry.compressed_size),
        format!("{:#x}", entry.uncompressed_size),
        // C++ quirk: the compressed size is printed next to the method name.
        format!("{} ({:#x})", entry.compression_method_name(), entry.compressed_size),
        format!("{:#x}", entry.disk_number),
        format!("{:#x}", entry.disk_offset),
    ]
}

/// The `ContainerViewer::Settings` of `CreateContainerView` (`zip.cpp:73-93`).
#[must_use]
pub fn container_view_request() -> ContainerViewerRequest {
    ContainerViewerRequest {
        icon: Some(String::from(ZIP_ICON)),
        path_separator: PATH_SEPARATOR,
        columns: CONTAINER_COLUMNS.iter().map(|c| (*c).to_owned()).collect(),
        properties: Vec::new(),
    }
}

/// `<archive>.drop/<name>` with the zip-slip guard (`OnOpenItem`).
///
/// # Errors
///
/// [`OpenError::UnsafePath`] for names that escape the directory.
pub fn drop_path(archive: &Path, name: &str) -> Result<PathBuf, OpenError> {
    let mut base = archive.as_os_str().to_owned();
    base.push(DROP_SUFFIX);
    safe_extract_path(Path::new(&base), name).map_err(|_| OpenError::UnsafePath(name.to_owned()))
}

/// The ZIP `TypeInterface` (C++ `ZIP::ZIPFile` as a type instance).
pub struct ZipPlugin {
    state: Mutex<Option<ZipState>>,
    object: Mutex<Option<SharedObject>>,
    password: Mutex<String>,
    last_error: Mutex<Option<String>>,
    last_command: Mutex<Option<String>>,
    limits: ZipLimits,
}

impl Default for ZipPlugin {
    fn default() -> Self {
        Self::with_limits(ZipLimits::default())
    }
}

impl core::fmt::Debug for ZipPlugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let entries = self
            .state
            .lock()
            .ok()
            .and_then(|s| s.as_ref().map(|z| z.info.count()));
        f.debug_struct("ZipPlugin").field("entries", &entries).finish_non_exhaustive()
    }
}

impl ZipPlugin {
    /// A plugin with custom bomb / listing limits.
    #[must_use]
    pub const fn with_limits(limits: ZipLimits) -> Self {
        Self {
            state: Mutex::new(None),
            object: Mutex::new(None),
            password: Mutex::new(String::new()),
            last_error: Mutex::new(None),
            last_command: Mutex::new(None),
            limits,
        }
    }

    /// The listing state after `PopulateWindow`.
    #[must_use]
    pub fn state(&self) -> Option<ZipState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The `Update()` failure message, if the listing failed.
    #[must_use]
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The last `RunCommand` name (the C++ `RunCommand` is empty).
    #[must_use]
    pub fn last_command(&self) -> Option<String> {
        self.last_command.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The default password (`ZIPFile::password`).
    #[must_use]
    pub fn password(&self) -> String {
        self.password.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Sets the default password.
    pub fn set_password(&self, password: &str) {
        password.clone_into(&mut self.password.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// `ZipLimits` in effect.
    #[must_use]
    pub const fn limits(&self) -> ZipLimits {
        self.limits
    }

    /// C++ `Update()`: lists the archive from disk or from the cache.
    fn update(&self, object: &SharedObject) {
        let (path, size) = {
            let guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            (guard.path().to_path_buf(), guard.data().size())
        };
        let is_top_container = !path.as_os_str().is_empty() && path.exists();
        let bytes = if is_top_container {
            None
        } else {
            let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            Some(
                u32::try_from(size)
                    .ok()
                    .filter(|s| *s > 0)
                    .and_then(|s| guard.data_mut().copy_to_vec(0, s, true).ok())
                    .unwrap_or_default(),
            )
        };
        let listed = bytes.as_deref().map_or_else(
            || ZipInfo::from_path(&path, self.limits),
            |b| ZipInfo::from_bytes(b, self.limits),
        );
        let (info, error) = match listed {
            Ok(info) => (info, None),
            Err(e) => (ZipInfo::default(), Some(e.to_string())),
        };
        *self.last_error.lock().unwrap_or_else(PoisonError::into_inner) = error;
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = Some(ZipState {
            info,
            is_top_container,
            path,
            current_item_index: 0,
            child_indexes: Vec::new(),
        });
    }

    /// The whole archive bytes for a nested container
    /// (`obj->GetData().GetEntireFile()`).
    fn entire_file(&self) -> Result<Vec<u8>, OpenError> {
        let object = self
            .object
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(OpenError::NotLoaded)?;
        let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
        let size = u32::try_from(guard.data().size()).map_err(|e| OpenError::Source(e.to_string()))?;
        if size == 0 {
            return Err(OpenError::Source(String::from("empty archive")));
        }
        guard
            .data_mut()
            .copy_to_vec(0, size, true)
            .map_err(|e| OpenError::Source(e.to_string()))
    }

    /// Decompresses entry `index` with `password` from disk or cache.
    fn decompress(&self, state: &ZipState, index: u32, password: &str) -> Result<Vec<u8>, OpenError> {
        if state.is_top_container {
            state
                .info
                .decompress_from_path(&state.path, index, password, self.limits)
                .map_err(OpenError::Decompress)
        } else {
            let bytes = self.entire_file()?;
            state
                .info
                .decompress(&bytes, index, password, self.limits)
                .map_err(OpenError::Decompress)
        }
    }

    /// C++ `OnOpenItem` up to the password dialog: decompresses entry
    /// `index` with the default password (or none) and returns it with
    /// its `<archive>.drop/<name>` path.
    ///
    /// # Errors
    ///
    /// [`OpenError::PasswordRequired`] for an encrypted entry without a
    /// default password, [`OpenError::WrongPassword`] when the default
    /// password fails, [`OpenError::Decompress`] otherwise;
    /// [`OpenError::UnsafePath`] for a zip-slip name.
    pub fn open_item(&self, index: u32) -> Result<OpenedEntry, OpenError> {
        let state = self.state().ok_or(OpenError::NotLoaded)?;
        let entry = state
            .info
            .entry(index)
            .cloned()
            .ok_or(OpenError::Decompress(ZipError::InvalidIndex { index }))?;
        let password = self.password();
        if entry.is_encrypted() && password.is_empty() {
            return Err(OpenError::PasswordRequired);
        }
        let path = drop_path(&state.path, &entry.filename)?;
        match self.decompress(&state, index, &password) {
            Ok(bytes) => Ok(OpenedEntry {
                name: entry.filename,
                path,
                bytes,
            }),
            Err(e) if entry.is_encrypted() => match e {
                OpenError::Decompress(ZipError::Archive(_)) => Err(OpenError::WrongPassword),
                other => Err(other),
            },
            Err(e) => Err(e),
        }
    }

    /// C++ `OnOpenItem` password-dialog loop body: one attempt with
    /// `password`; on success the password becomes the default when
    /// `save_as_default` is set and the entry is opened under its bare
    /// name.
    ///
    /// # Errors
    ///
    /// [`OpenError::WrongPassword`] when the attempt fails (the C++
    /// message box), [`OpenError::Decompress`] for non-password
    /// failures, [`OpenError::UnsafePath`] for a zip-slip name.
    pub fn open_item_with_password(
        &self,
        index: u32,
        password: &str,
        save_as_default: bool,
    ) -> Result<OpenedEntry, OpenError> {
        let state = self.state().ok_or(OpenError::NotLoaded)?;
        let entry = state
            .info
            .entry(index)
            .cloned()
            .ok_or(OpenError::Decompress(ZipError::InvalidIndex { index }))?;
        let path = safe_extract_path(Path::new(""), &entry.filename)
            .map_err(|_| OpenError::UnsafePath(entry.filename.clone()))?;
        match self.decompress(&state, index, password) {
            Ok(bytes) => {
                if save_as_default {
                    self.set_password(password);
                }
                Ok(OpenedEntry {
                    name: entry.filename,
                    path,
                    bytes,
                })
            }
            Err(OpenError::Decompress(ZipError::Archive(_))) if entry.is_encrypted() => Err(OpenError::WrongPassword),
            Err(e) => Err(e),
        }
    }
}

// The state lock is held for the whole enumeration step on purpose:
// `begin_iteration` / `populate_item` read and advance the cursor
// atomically (the C++ members are plain fields of the same object).
#[allow(clippy::significant_drop_tightening)]
impl EnumerateInterface for ZipPlugin {
    /// C++ `BeginIteration`.
    fn begin_iteration(&mut self, path: &str, _parent: TreeItemId) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(state) = guard.as_mut() else {
            return false;
        };
        if state.info.count() == 0 {
            return false;
        }
        state.current_item_index = 0;
        state.child_indexes = children_of(&state.info, path);
        state.current_item_index != state.child_indexes.len()
    }

    /// C++ `PopulateItem`.
    fn populate_item(&mut self, child: &mut TreeNode) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(state) = guard.as_mut() else {
            return false;
        };
        let Some(&real_index) = state.child_indexes.get(state.current_item_index) else {
            return false;
        };
        let Some(entry) = state.info.entry(real_index) else {
            return false;
        };
        let is_dir = entry.entry_type == EntryType::Directory;
        child.priority = is_dir;
        child.expandable = is_dir;
        for (col, text) in entry_columns(entry).iter().enumerate() {
            child.set_text(col, text);
        }
        child.data = u64::from(real_index);
        state.current_item_index = state.current_item_index.saturating_add(1);
        state.current_item_index != state.child_indexes.len()
    }
}

impl TypePlugin for ZipPlugin {
    fn name(&self) -> &'static str {
        "ZIP"
    }

    fn validate(buf: &[u8], extension: &str) -> bool {
        validate(buf, extension)
    }

    fn create_instance() -> Box<Self> {
        Box::default()
    }

    /// C++ `UpdateSettings` (`zip.cpp:110-121`).
    fn metadata() -> PluginMetadata {
        PluginMetadata {
            pattern: MAGIC_BYTES.iter().map(|m| Pattern::Magic(m.to_vec())).collect(),
            priority: PRIORITY,
            description: String::from(DESCRIPTION),
            extensions: vec![String::from(EXTENSION)],
            commands: Vec::new(),
            opcodes_mask: None,
        }
    }

    /// C++ `PopulateWindow` (`zip.cpp:95-108`): container viewer,
    /// (empty) buffer viewer, `Information` and `Objects` panels.
    fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
        let object = win.object();
        self.update(&object);
        *self.object.lock().unwrap_or_else(PoisonError::into_inner) = Some(SharedObject::clone(&object));
        win.create_viewer(ViewerRequest::container(container_view_request()))?;
        win.create_viewer(ViewerRequest::buffer(BufferViewerRequest::default()))?;
        for (caption, id, vertical) in PANELS {
            win.add_panel(
                PanelRequest {
                    caption: String::from(caption),
                    panel_id: String::from(id),
                },
                vertical,
            );
        }
        Ok(())
    }

    fn run_command(&mut self, command: &str) {
        *self.last_command.lock().unwrap_or_else(PoisonError::into_inner) = Some(command.to_owned());
    }

    /// C++ `UpdateKeys`: nothing registered.
    fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}

    /// C++ `GetSmartAssistantContext`: `Name`, `ContentSize`,
    /// `EntriesCount`.
    fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
        let state = self
            .state()
            .ok_or_else(|| PluginError::Assistant(String::from("PopulateWindow was not called")))?;
        let bound = self
            .object
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(SharedObject::clone)
            .ok_or_else(|| PluginError::Assistant(String::from("no object bound")))?;
        let (name, size) = {
            let object = bound.lock().unwrap_or_else(PoisonError::into_inner);
            (object.name().to_owned(), object.data().size())
        };
        Ok(serde_json::json!({
            "Name": name,
            "ContentSize": size,
            "EntriesCount": state.info.count(),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use gview_core::object::Object;
    use gview_plugin::type_plugin::ViewerKind;
    use gview_view::container_viewer::tree::ContainerTree;
    use std::io::{Cursor, Write};
    use std::sync::{Arc, Mutex as StdMutex};
    use zip::write::{SimpleFileOptions, ZipWriter};
    use zip::{AesMode, CompressionMethod};

    #[derive(Default)]
    struct MockWindow {
        object: Option<SharedObject>,
        viewers: Vec<ViewerRequest>,
        panels: Vec<(String, bool)>,
    }

    impl WindowHandle for MockWindow {
        fn object(&self) -> SharedObject {
            self.object
                .clone()
                .unwrap_or_else(|| Arc::new(StdMutex::new(Object::from_buffer(b"", "x", 0))))
        }
        fn add_panel(&mut self, panel: PanelRequest, vertical: bool) -> bool {
            self.panels.push((panel.caption, vertical));
            true
        }
        fn create_viewer(&mut self, request: ViewerRequest) -> Result<u32, PluginError> {
            self.viewers.push(request);
            Ok(self.viewers.len() as u32 - 1)
        }
        fn views_count(&self) -> u32 {
            self.viewers.len() as u32
        }
        fn set_view_by_index(&mut self, _index: u32) -> bool {
            true
        }
        fn current_view(&self) -> Option<u32> {
            None
        }
    }

    fn window_for(image: &[u8], name: &str) -> MockWindow {
        MockWindow {
            object: Some(Arc::new(StdMutex::new(Object::from_buffer(image, name, 0)))),
            ..MockWindow::default()
        }
    }

    fn build(files: &[(&str, &[u8], SimpleFileOptions)], dirs: &[&str]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for dir in dirs {
            writer.add_directory(*dir, SimpleFileOptions::default()).expect("dir");
        }
        for (name, data, options) in files {
            writer.start_file(*name, *options).expect("start");
            writer.write_all(data).expect("write");
        }
        writer.finish().expect("finish").into_inner()
    }

    fn stored() -> SimpleFileOptions {
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored)
    }

    fn deflated() -> SimpleFileOptions {
        SimpleFileOptions::default().compression_method(CompressionMethod::Deflated)
    }

    fn encrypted(password: &'static str) -> SimpleFileOptions {
        deflated().with_aes_encryption(AesMode::Aes256, password)
    }

    /// `dir/`, `dir/sub/`, `dir/sub/deep.txt`, `dir/a.txt`, `top.bin`.
    fn sample() -> Vec<u8> {
        build(
            &[
                ("dir/sub/deep.txt", b"deep down", deflated()),
                ("dir/a.txt", b"aaaa", stored()),
                ("top.bin", b"\x00\x01\x02", stored()),
            ],
            &["dir/", "dir/sub/"],
        )
    }

    fn loaded(image: &[u8]) -> (Box<ZipPlugin>, MockWindow) {
        let plugin = ZipPlugin::create_instance();
        let mut win = window_for(image, "sample.zip");
        plugin.populate_window(&mut win).expect("populate");
        (plugin, win)
    }

    /// Listing index of `name` (the archive order is dirs-first when
    /// they are written first, parents synthesised otherwise).
    fn index_of(plugin: &ZipPlugin, name: &str) -> u32 {
        let state = plugin.state().expect("state");
        state
            .info
            .entries()
            .iter()
            .position(|e| e.filename == name)
            .map(|i| i as u32)
            .expect("entry present")
    }

    fn children_names(tree: &ContainerTree, id: TreeItemId) -> Vec<String> {
        tree.children(id)
            .iter()
            .filter_map(|c| tree.node(*c).map(|n| n.name().to_owned()))
            .collect()
    }

    #[test]
    fn populate_creates_container_and_buffer_views_and_panels() {
        let image = sample();
        let (plugin, win) = loaded(&image);
        assert_eq!(win.viewers.len(), 2);
        assert_eq!(win.viewers[0].kind, ViewerKind::Container);
        let container = win.viewers[0].container.as_ref().expect("container");
        assert_eq!(container.path_separator, '/');
        assert_eq!(container.icon.as_deref().map(str::len), Some(256));
        assert_eq!(container.columns.len(), 8);
        assert_eq!(container.columns[0], "n:&Filename,a:l,w:80");
        assert_eq!(win.viewers[1].kind, ViewerKind::Buffer);
        assert_eq!(win.viewers[1].buffer.as_ref().map(|b| b.zones.count()), Some(0));
        assert_eq!(win.panels, [(String::from("Informa&tion"), true), (String::from("&Objects"), false)]);
        let state = plugin.state().expect("state");
        assert!(!state.is_top_container, "buffers are nested containers");
        assert_eq!(state.info.count(), 5);
        assert!(plugin.last_error().is_none());
        assert!(format!("{plugin:?}").contains("entries: Some(5)"));
    }

    #[test]
    fn lazy_expand_lists_direct_children_only() {
        let image = sample();
        let (mut plugin, _) = loaded(&image);
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        assert!(tree.populate_item(root, &mut *plugin, &mut |_| false));
        // Root: only `dir/` and `top.bin` (folders first is the shell's sort;
        // the enumeration keeps archive order).
        assert_eq!(children_names(&tree, root), ["dir", "top.bin"]);
        let dir = tree.children(root)[0];
        let dir_node = tree.node(dir).expect("dir");
        assert!(dir_node.expandable && dir_node.priority);
        assert_eq!(dir_node.texts[1], "Directory (0x1)");
        assert_eq!(dir_node.texts[4], "0x0");
        let top = tree.node(tree.children(root)[1]).expect("top");
        assert!(!top.expandable && !top.priority);
        assert_eq!(top.texts[1], "File (0x3)");
        assert_eq!(top.texts[3], "0x3");
        assert_eq!(top.texts[4], "0x3");
        assert_eq!(top.texts[5], "stored (0x3)", "compressed size next to the method (C++ quirk)");
        assert_eq!(top.texts[6], "0x0");
        assert!(top.texts[7].starts_with("0x"));
        assert_eq!(top.data, u64::from(index_of(&plugin, "top.bin")));
        // Nothing below `dir` until it is expanded.
        assert!(tree.children(dir).is_empty());
        tree.unfold(dir);
        assert!(tree.on_item_toggle(dir, false, &mut *plugin, &mut |_| false));
        assert_eq!(children_names(&tree, dir), ["sub", "a.txt"]);
        let sub = tree.children(dir)[0];
        tree.unfold(sub);
        assert!(tree.on_item_toggle(sub, false, &mut *plugin, &mut |_| false));
        assert_eq!(children_names(&tree, sub), ["deep.txt"]);
        let deep = tree.node(tree.children(sub)[0]).expect("deep");
        assert_eq!(deep.data, u64::from(index_of(&plugin, "dir/sub/deep.txt")));
        assert!(deep.texts[5].starts_with("deflate ("));
        // Re-expanding does not duplicate.
        assert!(tree.populate_item(dir, &mut *plugin, &mut |_| false));
        assert_eq!(tree.children(dir).len(), 2);
    }

    #[test]
    fn children_of_matches_cpp_selection_rules() {
        let image = sample();
        let info = ZipInfo::from_bytes(&image, ZipLimits::default()).expect("info");
        let names = |info: &ZipInfo, ids: &[u32]| -> Vec<String> {
            ids.iter().map(|i| info.entry(*i).expect("e").filename.clone()).collect()
        };
        assert_eq!(names(&info, &children_of(&info, "")), ["dir/", "top.bin"]);
        assert_eq!(names(&info, &children_of(&info, "dir")), ["dir/sub/", "dir/a.txt"]);
        assert_eq!(names(&info, &children_of(&info, "dir/sub")), ["dir/sub/deep.txt"]);
        assert!(children_of(&info, "dir/sub/deep.txt").is_empty());
        assert!(children_of(&info, "nope").is_empty());
        assert!(children_of(&info, "di").is_empty(), "prefix must end at a separator");
        // An entry starting with '/': the listing synthesises the "/"
        // parent, which is the only root-level match.
        let odd = build(&[("/abs.txt", b"x", stored())], &[]);
        let info = ZipInfo::from_bytes(&odd, ZipLimits::default()).expect("info");
        assert_eq!(names(&info, &children_of(&info, "")), ["/"]);
        assert_eq!(names(&info, &children_of(&info, "/")), Vec::<String>::new(), "'//' never matches");
        // Without any root-level entry the generic scan runs with the
        // empty path and matches names whose first byte is '/'.
        let bare = ZipInfo::default();
        assert!(children_of(&bare, "").is_empty());
    }

    #[test]
    fn empty_archive_has_no_children_and_deep_nesting_is_fine() {
        let empty = build(&[], &[]);
        let (mut plugin, _) = loaded(&empty);
        assert_eq!(plugin.state().expect("state").info.count(), 0);
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        assert!(tree.populate_item(root, &mut *plugin, &mut |_| false));
        assert!(tree.children(root).is_empty());
        assert!(!plugin.begin_iteration("", root));

        let deep_name = format!("{}leaf.txt", "d/".repeat(100));
        let deep = build(&[(deep_name.as_str(), b"leaf", stored())], &[]);
        let (mut plugin, _) = loaded(&deep);
        let mut tree = ContainerTree::new('/');
        let mut current = tree.root();
        for level in 0..100 {
            assert!(tree.populate_item(current, &mut *plugin, &mut |_| false), "level {level}");
            let kids = tree.children(current).to_vec();
            assert_eq!(kids.len(), 1, "level {level}");
            current = kids[0];
            tree.unfold(current);
        }
        assert!(tree.populate_item(current, &mut *plugin, &mut |_| false));
        assert_eq!(children_names(&tree, current), ["leaf.txt"]);
    }

    #[test]
    fn open_leaf_decompresses_on_demand_into_the_drop_path() {
        let image = sample();
        let (plugin, _) = loaded(&image);
        let deep_index = index_of(&plugin, "dir/sub/deep.txt");
        let top_index = index_of(&plugin, "top.bin");
        let dir_index = index_of(&plugin, "dir/");
        let opened = plugin.open_item(deep_index).expect("deep");
        assert_eq!(opened.name, "dir/sub/deep.txt");
        assert_eq!(opened.bytes, b"deep down");
        let expected = Path::new(".drop").join("dir").join("sub").join("deep.txt");
        assert_eq!(opened.path, expected, "buffer objects have an empty path");
        let top = plugin.open_item(top_index).expect("top");
        assert_eq!(top.bytes, [0, 1, 2]);
        // CRC of the stored entry matches the listing.
        let entry = plugin.state().expect("state").info.entry(top_index).cloned().expect("entry");
        assert_eq!(entry.crc, crc32(&top.bytes));
        // Directories and bad indexes are not files.
        assert!(matches!(plugin.open_item(dir_index), Err(OpenError::Decompress(ZipError::NotAFile { index })) if index == dir_index));
        assert!(matches!(plugin.open_item(99), Err(OpenError::Decompress(ZipError::InvalidIndex { index: 99 }))));
        assert!(matches!(ZipPlugin::create_instance().open_item(0), Err(OpenError::NotLoaded)));
        assert_eq!(OpenError::NotLoaded.to_string(), "archive not loaded");
    }

    /// Reference CRC-32 (IEEE) for the test above.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFF_u32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }

    #[test]
    fn zip_slip_names_are_rejected() {
        let slip = build(&[("../../etc/passwd", b"root:x", stored()), ("ok.txt", b"ok", stored())], &[]);
        let (mut plugin, _) = loaded(&slip);
        // Listing still shows the entry (the C++ does); opening it is refused.
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        assert!(tree.populate_item(root, &mut *plugin, &mut |_| false));
        assert!(children_names(&tree, root).contains(&String::from("ok.txt")));
        let err = plugin.open_item(0).expect_err("zip slip");
        assert!(matches!(err, OpenError::UnsafePath(ref n) if n == "../../etc/passwd"));
        assert!(err.to_string().contains("unsafe archive path"));
        assert!(matches!(plugin.open_item_with_password(0, "", false), Err(OpenError::UnsafePath(_))));
        let ok_index = index_of(&plugin, "ok.txt");
        assert_eq!(plugin.open_item(ok_index).expect("ok").bytes, b"ok");
        assert!(drop_path(Path::new("C:/a/b.zip"), "/abs").is_err());
        assert!(drop_path(Path::new("C:/a/b.zip"), "x/../../y").is_err());
        let fine = drop_path(Path::new("b.zip"), "x/y.txt").expect("safe");
        assert_eq!(fine, Path::new("b.zip.drop").join("x").join("y.txt"));
    }

    #[test]
    fn decompression_ratio_cap_is_enforced() {
        let zeros = vec![0_u8; 200_000];
        let bomb = build(&[("zeros.bin", &zeros, deflated())], &[]);
        let limits = ZipLimits {
            max_compression_ratio: 10,
            ..ZipLimits::default()
        };
        let plugin = ZipPlugin::with_limits(limits);
        assert_eq!(plugin.limits().max_compression_ratio, 10);
        let mut win = window_for(&bomb, "bomb.zip");
        plugin.populate_window(&mut win).expect("populate");
        let err = plugin.open_item(0).expect_err("ratio");
        assert!(matches!(err, OpenError::Decompress(ZipError::SuspiciousRatio { .. })), "{err}");
        assert!(err.to_string().starts_with("Failed to decompress!"));
        // Absolute cap too.
        let plugin = ZipPlugin::with_limits(ZipLimits {
            max_output_size: 1000,
            ..ZipLimits::default()
        });
        let mut win = window_for(&bomb, "bomb.zip");
        plugin.populate_window(&mut win).expect("populate");
        assert!(matches!(
            plugin.open_item(0),
            Err(OpenError::Decompress(ZipError::OutputLimitExceeded { limit: 1000 }))
        ));
    }

    #[test]
    fn password_flow_mirrors_the_dialog_loop() {
        let image = build(&[("secret.txt", b"top secret", encrypted("hunter2")), ("plain.txt", b"plain", stored())], &[]);
        let (plugin, _) = loaded(&image);
        // No default password: the shell must prompt.
        assert!(matches!(plugin.open_item(0), Err(OpenError::PasswordRequired)));
        assert_eq!(plugin.open_item(1).expect("plain").bytes, b"plain");
        // Wrong password from the dialog.
        let err = plugin.open_item_with_password(0, "nope", true).expect_err("wrong");
        assert!(matches!(err, OpenError::WrongPassword));
        assert_eq!(err.to_string(), "Wrong password!");
        assert_eq!(plugin.password(), "", "a rejected password is not saved");
        // Right password without saving.
        let opened = plugin.open_item_with_password(0, "hunter2", false).expect("open");
        assert_eq!(opened.bytes, b"top secret");
        assert_eq!(opened.path, Path::new("secret.txt"), "dialog path is the bare name");
        assert_eq!(plugin.password(), "");
        // Right password, saved as default: the plain path now works.
        plugin.open_item_with_password(0, "hunter2", true).expect("open");
        assert_eq!(plugin.password(), "hunter2");
        let opened = plugin.open_item(0).expect("default password");
        assert_eq!(opened.bytes, b"top secret");
        assert_eq!(opened.path, Path::new(".drop").join("secret.txt"));
        // A wrong default password reports WrongPassword (C++ "Wrong default password!").
        plugin.set_password("stale");
        assert!(matches!(plugin.open_item(0), Err(OpenError::WrongPassword)));
        assert_eq!(OpenError::PasswordRequired.to_string(), "Unable to decompress without a password!");
    }

    #[test]
    fn corrupt_archives_open_with_an_empty_tree_and_an_error() {
        let (mut plugin, win) = loaded(b"PK\x03\x04garbage");
        assert_eq!(win.viewers.len(), 2);
        assert_eq!(win.panels.len(), 2);
        let state = plugin.state().expect("state");
        assert_eq!(state.info.count(), 0);
        assert!(plugin.last_error().is_some());
        assert!(!plugin.begin_iteration("", 0));
        let mut node = TreeNode::default();
        assert!(!plugin.populate_item(&mut node));
        assert!(matches!(plugin.open_item(0), Err(OpenError::Decompress(ZipError::InvalidIndex { index: 0 }))));
        // An empty buffer: same outcome.
        let (plugin, _) = loaded(b"");
        assert!(plugin.last_error().is_some());
        assert!(format!("{plugin:?}").contains("entries: Some(0)"));
    }

    #[test]
    fn metadata_commands_and_assistant_context() {
        struct Keys(Vec<String>);
        impl KeyRegistry for Keys {
            fn register_key(&mut self, command: &gview_plugin::type_plugin::CommandDef) -> bool {
                self.0.push(command.name.clone());
                true
            }
        }
        let meta = ZipPlugin::metadata();
        let inis: Vec<String> = meta.pattern.iter().map(Pattern::to_ini_string).collect();
        assert_eq!(inis, ["magic:50 4B 03 04", "magic:50 4B 05 06", "magic:50 4B 07 08"]);
        assert_eq!(meta.extensions, ["zip"]);
        assert_eq!(meta.priority, 1);
        assert_eq!(meta.description, DESCRIPTION);
        assert!(meta.commands.is_empty());
        assert_eq!(meta.opcodes_mask, None);
        assert!(ZipPlugin::validate(b"PK\x05\x06", ".zip"));

        let mut plugin = ZipPlugin::create_instance();
        assert_eq!(plugin.name(), "ZIP");
        assert!(plugin.smart_assistant_context("", "").is_err());
        plugin.run_command("Nothing");
        assert_eq!(plugin.last_command().as_deref(), Some("Nothing"));
        let mut keys = Keys(Vec::new());
        plugin.register_keys(&mut keys);
        assert!(keys.0.is_empty());

        let image = sample();
        let mut win = window_for(&image, "ctx.zip");
        plugin.populate_window(&mut win).expect("populate");
        let ctx = plugin.smart_assistant_context("what", "what").expect("ctx");
        assert_eq!(ctx["Name"], "ctx.zip");
        assert_eq!(ctx["ContentSize"], image.len() as u64);
        assert_eq!(ctx["EntriesCount"], 5);
        assert_eq!(container_view_request().properties.len(), 0);
        assert_eq!(PANELS[1].1, "zip.objects");
        assert_eq!(ZIP_ICON.len(), 256);
        let entry = ZipEntry {
            filename: String::from("a/b/"),
            entry_type: EntryType::Directory,
            ..ZipEntry::default()
        };
        assert_eq!(entry_columns(&entry)[0], "b");
        let file = ZipEntry {
            filename: String::from("name.txt"),
            entry_type: EntryType::File,
            compressed_size: 0x10,
            uncompressed_size: 0x20,
            compression_method: 8,
            ..ZipEntry::default()
        };
        let cols = entry_columns(&file);
        assert_eq!(cols[0], "name.txt");
        assert_eq!(cols[3], "0x10");
        assert_eq!(cols[4], "0x20");
        assert_eq!(cols[5], "deflate (0x10)");
    }
}
