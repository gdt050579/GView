//! The data-loading pipeline: a path in, a populated [`FileWindow`]
//! out (spec `00_APP §3`, design decision `§0.3 D5`).
//!
//! C++ anchors: `GView::App::OpenFile` (`GViewApp.cpp:127-148`, the
//! canonical-path fallback) and `Instance::Add` / `AddFileWindow`
//! (`Instance.cpp:369-474`).
//!
//! ```text
//! OpenRequest { path, method, type_name }
//!   1. canonicalise the path; keep the raw path when that fails
//!   2. Instance::add_file_window → identify → create → populate → start
//!   3. Instance::take_window(index)                       (D5)
//!   4. FileWindow::new(model, plugin_commands, generic_commands)
//!      — which mounts the viewers (§5.3) and the panels (§5.4)
//!   5. FileWindow::start()                                → page 0 focused
//! ```
//!
//! Nothing here reads the file beyond the `0x8800`-byte identification
//! probe; a viewer pulls the rest through the `DataCache` when it
//! paints.
//!
//! The headless [`Instance`] keeps the accumulated error list, so a
//! failure here leaves a message for `ShowErrors`
//! ([`crate::error_dialog`]) and never unwinds.

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Mutex, PoisonError};

use crate::error::AppError;
use crate::file_window::{FileWindow, GenericCommandSlot, MAX_GENERIC_PLUGIN_COMMANDS};
use crate::instance::window_lifecycle::{menu, Instance, OpenMethod, TypeSelector};

/// The shared, UI-thread-only [`Instance`] (`00_APP §0.3 D4`).
///
/// `Mutex` rather than `RefCell`: a poisoned lock degrades through
/// `PoisonError::into_inner` instead of panicking.
pub type SharedInstance = Rc<Mutex<Instance>>;

/// One queued open (`main` builds these, the desktop drains them —
/// `§0.3 D6`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    /// The path as the user gave it.
    pub path: PathBuf,
    /// C++ `OpenMethod`.
    pub method: OpenMethod,
    /// `--type:<name>` payload; empty unless `method` is
    /// [`OpenMethod::ForceType`].
    pub type_name: String,
    /// `false` builds the window without ever opening a message box,
    /// for `gview test` and for the tests of this layer. The C++ has
    /// no equivalent because it always runs interactively.
    pub interactive: bool,
}

impl OpenRequest {
    /// An interactive `BestMatch` open of `path` (the CLI default —
    /// C++ `OpenFile(path, OpenMethod::BestMatch)`).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            method: OpenMethod::BestMatch,
            type_name: String::new(),
            interactive: true,
        }
    }

    /// The same open forced to a named type (`--type:<name>`).
    #[must_use]
    pub fn with_type(path: impl Into<PathBuf>, type_name: impl Into<String>) -> Self {
        Self {
            method: OpenMethod::ForceType,
            type_name: type_name.into(),
            ..Self::new(path)
        }
    }

    /// The same open, always asking the type selector
    /// (`--selectType`, and the window's `CMD_CHOSE_NEW_TYPE`).
    #[must_use]
    pub fn select_type(path: impl Into<PathBuf>) -> Self {
        Self {
            method: OpenMethod::Select,
            ..Self::new(path)
        }
    }

    /// The same request without any message boxes.
    #[must_use]
    pub const fn headless(mut self) -> Self {
        self.interactive = false;
        self
    }
}

/// C++ `GView::App::OpenFile`: canonicalise when possible, otherwise
/// use the path as given (the C++ catches `std::filesystem_error` and
/// falls back to the raw path).
#[must_use]
pub fn canonical_or_raw(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Opens `request` and returns the window ready to be added to the
/// desktop (`00_APP §3`).
///
/// # Errors
///
/// [`AppError::Open`] for every failure of the C++ pipeline: the file
/// cannot be opened, the path is a directory (`§0.3 D7`), the type
/// selector cancelled, or `PopulateWindow` failed — in which case the
/// half-built model is dropped and no window exists, exactly as the
/// C++ `CHECKBK` does.
pub fn open(
    instance: &SharedInstance,
    request: &OpenRequest,
    selector: &mut dyn TypeSelector,
) -> Result<FileWindow, AppError> {
    let path = canonical_or_raw(&request.path);
    let mut guard = instance.lock().unwrap_or_else(PoisonError::into_inner);
    let index = guard.add_file_window(&path, request.method, &request.type_name, selector)?;
    let Some(model) = guard.take_window(index) else {
        // `add_file_window` just pushed it; unreachable in practice,
        // and a missing model is still not a panic.
        return Err(AppError::Open(
            crate::instance::window_lifecycle::InstanceError::OpenCanceled,
        ));
    };
    let plugin_commands = model
        .type_plugin_name()
        .and_then(|name| guard.type_plugins().by_name(name))
        .map(|plugin| plugin.metadata().commands.clone())
        .unwrap_or_default();
    let generic_commands = generic_command_slots(&guard);
    drop(guard);

    let mut window = FileWindow::new(model, plugin_commands, generic_commands, request.interactive);
    window.start();
    Ok(window)
}

/// The command-bar slots of every generic plugin.
///
/// C++ `Instance::UpdateCommandBar` (`Instance.cpp:515-522`) +
/// `Generic::Plugin::UpdateCommandBar` (`Plugin.cpp:76-82`): slot `i`
/// of plugin `p` takes the id
/// `GENERIC_PLUGINS_CMDID + p * GENERIC_PLUGINS_FRAME + i`.
///
/// The generated `Commands` enum has [`MAX_GENERIC_PLUGIN_COMMANDS`]
/// slots, so the list is capped there (`00_APP §5.2 (4)`); the C++ has
/// no cap because its command bar takes raw ids.
#[must_use]
pub fn generic_command_slots(instance: &Instance) -> Vec<GenericCommandSlot> {
    let mut slots = Vec::new();
    for (plugin, registered) in instance.generic_plugins().plugins().iter().enumerate() {
        for (command, def) in registered.metadata().commands.iter().enumerate() {
            if slots.len() >= MAX_GENERIC_PLUGIN_COMMANDS {
                return slots;
            }
            if command >= menu::GENERIC_PLUGINS_FRAME as usize {
                // Past the id frame this plugin owns: the next id would
                // collide with the following plugin's first command.
                break;
            }
            slots.push(GenericCommandSlot {
                key: def.key,
                caption: def.name.clone(),
                plugin,
                command,
            });
        }
    }
    slots
}

/// The C++ command id of generic command `command` of plugin `plugin`
/// (`GENERIC_PLUGINS_CMDID + plugin * GENERIC_PLUGINS_FRAME + command`).
#[must_use]
pub const fn generic_command_id(plugin: usize, command: usize) -> u32 {
    let base = menu::GENERIC_PLUGINS_CMDID;
    let frame = (plugin as u32).saturating_mul(menu::GENERIC_PLUGINS_FRAME);
    base.saturating_add(frame).saturating_add(command as u32)
}

#[cfg(test)]
// The fixture builders index and add on fixed-size buffers, exactly as
// `registry.rs`'s own `minimal_*` helpers do.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use crate::file_window::mount::MountedViewer;
    use crate::instance::window_lifecycle::{menu as gview_menu, CancelSelector, InstanceError};
    use crate::registry;
    use appcui::prelude::*;
    use gview_core::constants::DEFAULT_CACHE_SIZE;
    use gview_plugin::type_plugin::RegisteredTypePlugin;
    use std::path::Path;

    /// A selector that records the candidate names it was offered and
    /// then picks `choice` (or cancels).
    struct RecordingSelector {
        offered: Vec<Vec<String>>,
        choice: Option<usize>,
    }

    impl RecordingSelector {
        const fn cancelling() -> Self {
            Self {
                offered: Vec::new(),
                choice: None,
            }
        }
    }

    impl TypeSelector for RecordingSelector {
        fn select(&mut self, candidates: &[&RegisteredTypePlugin]) -> Option<usize> {
            self.offered
                .push(candidates.iter().map(|p| p.name().to_owned()).collect());
            self.choice
        }
    }

    fn instance() -> SharedInstance {
        let registries = registry::build().expect("registry");
        Rc::new(Mutex::new(Instance::new(
            registries.types,
            registries.generics,
            DEFAULT_CACHE_SIZE,
        )))
    }

    /// A directory under the system temp dir, unique per test.
    ///
    /// Created, never deleted: on Windows `remove_dir_all` can return
    /// before the directory is really gone, and the following
    /// `create_dir_all` + `write` then race with the pending deletion
    /// (observed as a fixture that exists but cannot be opened).
    /// Fixtures are overwritten instead.
    fn fixture_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("gview_open_pipeline").join(name);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        dir
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("fixture file");
        path
    }

    /// `registry.rs`'s `minimal_pe`, kept in step with it.
    fn minimal_pe() -> Vec<u8> {
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

    fn view_names(window: &FileWindow) -> Vec<String> {
        (0..window.views_count())
            .map(|i| {
                let model = window.model();
                let guard = model.lock().expect("model");
                let name = guard
                    .views()
                    .view_by_index(i)
                    .map(|v| v.name().to_owned())
                    .unwrap_or_default();
                drop(guard);
                name
            })
            .collect()
    }

    #[test]
    fn a_missing_file_reports_the_cpp_message_and_creates_no_window() {
        let instance = instance();
        let dir = fixture_dir("missing");
        let path = dir.join("nope.bin");
        let Err(error) = open(&instance, &OpenRequest::new(&path).headless(), &mut CancelSelector) else {
            panic!("a missing file cannot be opened");
        };
        assert!(matches!(error, AppError::Open(InstanceError::OpenFile { .. })), "{error:?}");
        assert!(error.to_string().starts_with("Fail to open file: "));

        let mut guard = instance.lock().expect("instance");
        assert_eq!(guard.objects_count(), 0);
        let errors = guard.take_errors();
        drop(guard);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("Fail to open file: "));
    }

    /// The `§3` "unreadable (permissions)" row: an existing file the
    /// process cannot open behaves exactly like a missing one.
    #[test]
    fn an_unreadable_file_behaves_like_a_missing_one() {
        let instance = instance();
        let dir = fixture_dir("unreadable");
        let path = write(&dir, "locked.bin", b"secret");

        // Hold the file so no other handle can be opened (Windows), or
        // strip every permission bit (unix).
        #[cfg(windows)]
        let _lock = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&path)
                .expect("exclusive handle")
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        }

        let result = open(&instance, &OpenRequest::new(&path).headless(), &mut CancelSelector);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        let Err(error) = result else {
            panic!("an unreadable file cannot be opened");
        };
        assert!(matches!(error, AppError::Open(InstanceError::OpenFile { .. })), "{error:?}");
        assert!(error.to_string().starts_with("Fail to open file: "));
        let mut guard = instance.lock().expect("instance");
        assert_eq!(guard.objects_count(), 0);
        assert_eq!(guard.take_errors().len(), 1);
        drop(guard);
    }

    #[test]
    fn a_directory_is_reported_as_unsupported() {
        let instance = instance();
        let dir = fixture_dir("directory");
        let Err(error) = open(&instance, &OpenRequest::new(&dir).headless(), &mut CancelSelector) else {
            panic!("D7: folder windows are out of scope");
        };
        assert!(
            matches!(error, AppError::Open(InstanceError::FolderUnsupported(_))),
            "{error:?}"
        );
        assert_eq!(instance.lock().expect("instance").objects_count(), 0);
    }

    /// A file the plugin accepts but cannot parse: C++ `CHECKBK` drops
    /// the half-built window instead of re-opening it with the default
    /// plugin.
    #[test]
    fn a_plugin_that_cannot_parse_leaves_no_window() {
        let instance = instance();
        let dir = fixture_dir("bad_pe");
        // Full NT headers (so `Validate` accepts it) with an optional
        // header magic that is neither PE32 nor PE32+, which
        // `PeFile::parse_cache` rejects.
        let mut image = minimal_pe();
        let opt = 0x80 + 4 + 20;
        image[opt..opt + 2].copy_from_slice(&0x0000_u16.to_le_bytes());
        let path = write(&dir, "sample.exe", &image);

        let Err(error) = open(&instance, &OpenRequest::new(&path).headless(), &mut CancelSelector) else {
            panic!("an unparsable PE cannot be populated");
        };
        assert!(
            matches!(error, AppError::Open(InstanceError::PopulateFailed(_))),
            "{error:?}"
        );
        assert!(error.to_string().starts_with("Failed to populate file window!"));
        assert_eq!(instance.lock().expect("instance").objects_count(), 0);
    }

    #[test]
    fn an_unknown_forced_type_falls_through_to_the_selector() {
        let instance = instance();
        let dir = fixture_dir("force_type");
        let path = write(&dir, "sample.bin", b"random bytes, no magic");

        // C++ `IdentifyTypePlugin_WithSelectedType`: an unknown name
        // shows the dialog with every plugin; cancelling aborts.
        let mut selector = RecordingSelector::cancelling();
        let request = OpenRequest::with_type(&path, "NOSUCHTYPE").headless();
        let Err(error) = open(&instance, &request, &mut selector) else {
            panic!("the selector cancelled");
        };
        assert!(matches!(error, AppError::Open(InstanceError::OpenCanceled)), "{error:?}");
        assert_eq!(selector.offered.len(), 1, "the selector is asked exactly once");
        assert_eq!(
            selector.offered[0],
            ["PE", "ELF", "Mach-O", "ZIP", "PCAP"],
            "every registered plugin is offered"
        );
        assert_eq!(instance.lock().expect("instance").objects_count(), 0);
    }

    #[test]
    fn a_relative_path_falls_back_to_the_raw_path_when_canonicalisation_fails() {
        // Nothing to canonicalise: the raw path is kept, so the error
        // names what the user typed.
        let raw = Path::new("this/does/not/exist.bin");
        assert_eq!(canonical_or_raw(raw), raw);

        // An existing file canonicalises to an absolute path.
        let dir = fixture_dir("canonical");
        let path = write(&dir, "sample.bin", b"abc");
        assert!(canonical_or_raw(&path).is_absolute());
    }

    #[test]
    fn generic_slots_follow_the_cpp_id_frame() {
        let instance = instance();
        let guard = instance.lock().expect("instance");
        let slots = generic_command_slots(&guard);
        assert!(!slots.is_empty(), "the registry ships two generic plugins");
        // Slot order is plugin-major, command-minor.
        for (index, slot) in slots.iter().enumerate() {
            if index > 0 {
                let previous = &slots[index - 1];
                assert!(
                    (slot.plugin, slot.command) > (previous.plugin, previous.command),
                    "slots are ordered"
                );
            }
        }
        drop(guard);

        assert_eq!(generic_command_id(0, 0), gview_menu::GENERIC_PLUGINS_CMDID);
        assert_eq!(
            generic_command_id(1, 2),
            gview_menu::GENERIC_PLUGINS_CMDID + gview_menu::GENERIC_PLUGINS_FRAME + 2
        );
        // Never overflows, however hostile the indices.
        assert_eq!(generic_command_id(usize::MAX, usize::MAX), u32::MAX);
    }

    /// Every "the file opens" row of the `§3` hardening table, in one
    /// UI test (`App::debug` is a process-wide singleton).
    #[test]
    fn the_hardening_table_opens_without_panicking() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, "Paint.Enable(false)\nPaint('open pipeline')")
            .build()
            .expect("debug app");
        let instance = instance();
        let dir = fixture_dir("opens");

        // Empty file: the probe is empty, no plugin matches, the
        // default plugin adds a Buffer view only (no text viewer).
        let empty = write(&dir, "empty.bin", b"");
        let Ok(window) = open(&instance, &OpenRequest::new(&empty).headless(), &mut CancelSelector) else {
            panic!("an empty file opens");
        };
        assert_eq!(view_names(&window), ["Buffer View"]);
        assert!(matches!(window.mounted_view(0), Some(MountedViewer::Buffer(_))));
        assert!(window.is_started());
        drop(window);

        // One byte: no plugin may index past the probe.
        let tiny = write(&dir, "tiny", b"\x00");
        let Ok(window) = open(&instance, &OpenRequest::new(&tiny).headless(), &mut CancelSelector) else {
            panic!("a 1-byte file opens");
        };
        assert_eq!(view_names(&window), ["Buffer View"]);
        drop(window);

        // No extension and no `.` at all: the extension is empty and
        // content matching still runs.
        let text = write(&dir, "readme", b"plain ascii text\nsecond line\n");
        let Ok(window) = open(&instance, &OpenRequest::new(&text).headless(), &mut CancelSelector) else {
            panic!("an extension-less file opens");
        };
        // The default plugin adds the text viewer for a non-binary
        // probe, before the buffer view.
        assert_eq!(view_names(&window), ["Text View", "Buffer View"]);
        assert!(matches!(window.mounted_view(0), Some(MountedViewer::Text(_))));
        drop(window);

        // Larger than the cache: only the probe is read at open time.
        let big = write(&dir, "big.bin", &vec![0x41_u8; DEFAULT_CACHE_SIZE as usize * 4]);
        let Ok(window) = open(&instance, &OpenRequest::new(&big).headless(), &mut CancelSelector) else {
            panic!("a file larger than the cache opens");
        };
        {
            let model = window.model();
            let guard = model.lock().expect("model");
            let object = guard.object();
            let size = object.lock().expect("object").data().size();
            assert_eq!(size, u64::from(DEFAULT_CACHE_SIZE) * 4);
            drop(guard);
        }
        drop(window);

        // Truncated PE (`MZ` + 3 bytes). **Documented discrepancy**
        // with `00_APP §3`, which predicts `PopulateFailed`: both the
        // C++ (`Plugin::IsOfType`, `Instance.cpp:266-286`) and the port
        // gate candidacy on the plugin's `Validate`, and PE's rejects a
        // file too short to hold `IMAGE_NT_HEADERS32`. So no plugin
        // matches and the default plugin opens a Buffer view — the
        // window is *not* dropped. (`a_plugin_that_cannot_parse_leaves_no_window`
        // covers the `PopulateFailed` path the table means.)
        let stub = write(&dir, "stub.exe", b"MZ\x90\x00");
        let Ok(window) = open(&instance, &OpenRequest::new(&stub).headless(), &mut CancelSelector) else {
            panic!("a truncated PE still opens with the default plugin");
        };
        // `DefaultTypePlugin::wants_text_viewer` finds this 4-byte probe
        // non-binary, so the text page precedes the buffer page.
        assert_eq!(view_names(&window), ["Text View", "Buffer View"]);
        {
            let model = window.model();
            let guard = model.lock().expect("model");
            assert_eq!(guard.type_plugin_name(), None, "the default plugin, not PE");
            drop(guard);
        }
        drop(window);

        // A real PE: the plugin is selected and its commands reach the
        // window's command bar.
        let pe = write(&dir, "sample.exe", &minimal_pe());
        let Ok(window) = open(&instance, &OpenRequest::new(&pe).headless(), &mut CancelSelector) else {
            panic!("a minimal PE opens");
        };
        assert_eq!(window.title(), "sample.exe");
        {
            let model = window.model();
            let guard = model.lock().expect("model");
            assert_eq!(guard.type_plugin_name(), Some("PE"));
            drop(guard);
        }
        assert!(matches!(window.mounted_view(0), Some(MountedViewer::Buffer(_))));
        // The window took ownership; the headless list is empty again.
        assert_eq!(instance.lock().expect("instance").objects_count(), 0);
        drop(window);

        // Forcing the right type by name is case-insensitive.
        let Ok(window) = open(
            &instance,
            &OpenRequest::with_type(&pe, "pe").headless(),
            &mut CancelSelector,
        ) else {
            panic!("--type:pe matches PE");
        };
        {
            let model = window.model();
            let guard = model.lock().expect("model");
            assert_eq!(guard.type_plugin_name(), Some("PE"));
            drop(guard);
        }

        app.add_window(window);
        app.run();
    }
}
