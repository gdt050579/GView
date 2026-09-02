//! Dynamic loading of legacy C++ type plugins (spec `03_DUAL_PLUGIN`
//! §3.1–3.2, §4, §10; C++ `Plugin::LoadPlugin` `Plugin.cpp:166-186`).
//!
//! A `.tpl` exports four `extern "C"` symbols compiled against
//! `GView.hpp`:
//!
//! ```cpp
//! bool Validate(const BufferView& buf, const std::string_view& ext);
//! TypeInterface* CreateInstance();
//! bool PopulateWindow(Reference<WindowInterface> win);
//! void UpdateSettings(IniSection sect);
//! ```
//!
//! The reference parameters are pointers to `{ptr, len}` pairs
//! ([`GViewBufferView`], [`GViewStringView`] — the `AppCUI::BufferView`
//! and MSVC / libstdc++ `string_view` layouts), and the by-value
//! `Reference<T>` / `IniSection` wrappers are single-pointer structs,
//! passed like a pointer on every x86-64 / `AArch64` ABI. The vtable
//! shims behind those pointers arrive with the `window-vtable-shim`
//! task; this module resolves the exports and guards every call.
//!
//! Loading rules (C++ parity + §10.2): the library is
//! `<plugins dir>/lib<Name>.tpl`, the name must be a bare identifier
//! (no path separators), and a plugin missing any export is
//! `Invalid` — it is never retried (C++ `Invalid = !LoadPlugin()`).
//!
//! Every export call is wrapped in `catch_unwind`; a panic marks the
//! plugin invalid and is reported as [`FfiError::Panicked`], so the
//! host keeps running (§5.1 row 1). C++ exceptions and hardware faults
//! are the `crash-isolation` task's concern.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use libloading::{Library, Symbol};

/// C++ `Plugin::LoadPlugin` file name pattern: `lib<Name>.tpl`.
pub const TYPE_PLUGIN_PREFIX: &str = "lib";
/// Type plugin extension.
pub const TYPE_PLUGIN_EXTENSION: &str = "tpl";
/// Generic plugin extension.
pub const GENERIC_PLUGIN_EXTENSION: &str = "gpl";
/// Directory of type plugins under the application path.
pub const TYPE_PLUGIN_DIR: &str = "Types";
/// Directory of generic plugins under the application path.
pub const GENERIC_PLUGIN_DIR: &str = "GenericPlugins";

/// Export names (`Plugin.cpp:175-177`).
pub const EXPORT_VALIDATE: &[u8] = b"Validate\0";
/// `CreateInstance`.
pub const EXPORT_CREATE_INSTANCE: &[u8] = b"CreateInstance\0";
/// `PopulateWindow`.
pub const EXPORT_POPULATE_WINDOW: &[u8] = b"PopulateWindow\0";
/// `UpdateSettings` (optional at load time: only used at config
/// regeneration).
pub const EXPORT_UPDATE_SETTINGS: &[u8] = b"UpdateSettings\0";

/// `AppCUI::Utils::BufferView` (`AppCUI.hpp:994-997`): `{const uint8*
/// data; size_t length;}`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GViewBufferView {
    /// Start of the bytes (may dangle when `len == 0`, never read then).
    pub data: *const u8,
    /// Byte count.
    pub len: usize,
}

impl GViewBufferView {
    /// A view over `bytes`, valid while `bytes` is.
    #[must_use]
    pub const fn from_slice(bytes: &[u8]) -> Self {
        Self {
            data: bytes.as_ptr(),
            len: bytes.len(),
        }
    }
}

/// `std::string_view` as laid out by MSVC and libstdc++: `{const char*
/// ptr; size_t len;}` (spec §3.2 `GViewStringView`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GViewStringView {
    /// UTF-8 bytes (not NUL-terminated).
    pub ptr: *const u8,
    /// Byte count.
    pub len: usize,
}

impl GViewStringView {
    /// A view over `text`, valid while `text` is.
    #[must_use]
    pub const fn from_str(text: &str) -> Self {
        Self {
            ptr: text.as_ptr(),
            len: text.len(),
        }
    }
}

/// Opaque `TypeInterface*` returned by `CreateInstance` (owned by the
/// plugin's allocator; the C++ host `delete`s it through the vtable,
/// which the type-interface shim task handles).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeInstancePtr(pub *mut c_void);

impl TypeInstancePtr {
    /// `true` for a null result (C++ `CHECK(contentType)`).
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0.is_null()
    }
}

type ValidateFn = unsafe extern "C" fn(*const GViewBufferView, *const GViewStringView) -> bool;
type CreateInstanceFn = unsafe extern "C" fn() -> *mut c_void;
type PopulateWindowFn = unsafe extern "C" fn(*mut c_void) -> bool;
type UpdateSettingsFn = unsafe extern "C" fn(*mut c_void);

/// Loading and call failures.
#[derive(Debug)]
pub enum FfiError {
    /// The plugin name is not a bare identifier (path traversal guard,
    /// §10.2).
    InvalidName(String),
    /// `dlopen` / `LoadLibrary` failed (`Unable to load: <path>`).
    Load {
        /// Library path.
        path: PathBuf,
        /// Loader error.
        source: libloading::Error,
    },
    /// An export is absent (`Missing 'Validate' export !` etc.).
    MissingExport {
        /// Export name.
        export: &'static str,
        /// Library path.
        path: PathBuf,
    },
    /// The plugin was marked invalid by an earlier failure and is not
    /// retried (§5.1 step 4).
    Invalid,
    /// A panic crossed the FFI boundary and was caught.
    Panicked {
        /// Export that was being called.
        export: &'static str,
    },
}

impl core::fmt::Display for FfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidName(name) => write!(f, "invalid plugin name {name:?}"),
            Self::Load { path, source } => write!(f, "Unable to load: {} ({source})", path.display()),
            Self::MissingExport { export, path } => {
                write!(f, "Missing '{export}' export ! ({})", path.display())
            }
            Self::Invalid => write!(f, "Invalid plugin (not loaded properly or no valid exports)"),
            Self::Panicked { export } => write!(f, "plugin call '{export}' panicked"),
        }
    }
}

impl std::error::Error for FfiError {}

/// A loaded `.tpl` with its resolved exports (C++ `Plugin` after
/// `LoadPlugin`: `fnValidate`, `fnCreateInstance`, `fnPopulateWindow`).
pub struct LoadedPlugin {
    name: String,
    path: PathBuf,
    validate: ValidateFn,
    create_instance: CreateInstanceFn,
    populate_window: PopulateWindowFn,
    update_settings: Option<UpdateSettingsFn>,
    invalid: AtomicBool,
    // Declared last: dropped after the function pointers above are no
    // longer reachable (they are plain copies, never used after drop).
    _library: Library,
}

impl core::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("invalid", &self.is_invalid())
            .field("has_update_settings", &self.update_settings.is_some())
            .finish_non_exhaustive()
    }
}

/// `true` when `name` is a bare plugin identifier (letters, digits,
/// `_`, `-`, `.` without `..`), the only form the loader accepts.
#[must_use]
pub fn is_valid_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// C++ `LoadPlugin` path: `<dir>/lib<Name>.tpl`.
///
/// # Errors
///
/// [`FfiError::InvalidName`] for names that are not bare identifiers.
pub fn type_plugin_path(plugins_dir: &Path, name: &str) -> Result<PathBuf, FfiError> {
    if !is_valid_plugin_name(name) {
        return Err(FfiError::InvalidName(name.to_owned()));
    }
    Ok(plugins_dir.join(format!("{TYPE_PLUGIN_PREFIX}{name}.{TYPE_PLUGIN_EXTENSION}")))
}

impl LoadedPlugin {
    /// C++ `Plugin::LoadPlugin`: loads `<plugins_dir>/lib<name>.tpl`
    /// and resolves the exports.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidName`], [`FfiError::Load`],
    /// [`FfiError::MissingExport`].
    pub fn load(plugins_dir: &Path, name: &str) -> Result<Self, FfiError> {
        let path = type_plugin_path(plugins_dir, name)?;
        Self::load_path(name, &path)
    }

    /// Loads the library at `path` under plugin name `name` (tests and
    /// explicit paths; production goes through [`Self::load`]).
    ///
    /// # Errors
    ///
    /// [`FfiError::Load`] when the library cannot be opened,
    /// [`FfiError::MissingExport`] when `Validate`, `CreateInstance` or
    /// `PopulateWindow` is absent.
    pub fn load_path(name: &str, path: &Path) -> Result<Self, FfiError> {
        // SAFETY: loading a shared library runs its initialisers; the
        // path comes from the host's plugin directory (or an explicit
        // caller path), which is the trust boundary the C++ host also
        // relies on. No Rust-side invariants are violated by the load
        // itself.
        let library = unsafe { Library::new(path) }.map_err(|source| FfiError::Load {
            path: path.to_path_buf(),
            source,
        })?;

        // SAFETY: each symbol is looked up by its exported name and
        // declared with the `extern "C"` signature the plugin was
        // compiled with (spec §3.1–3.2). Copying the raw fn pointer out
        // of the `Symbol` is sound because `library` is kept alive in
        // the returned struct for as long as the pointers are callable.
        let validate: ValidateFn = unsafe { Self::export(&library, EXPORT_VALIDATE, "Validate", path) }?;
        // SAFETY: as above.
        let create_instance: CreateInstanceFn =
            unsafe { Self::export(&library, EXPORT_CREATE_INSTANCE, "CreateInstance", path) }?;
        // SAFETY: as above.
        let populate_window: PopulateWindowFn =
            unsafe { Self::export(&library, EXPORT_POPULATE_WINDOW, "PopulateWindow", path) }?;
        // SAFETY: as above; `UpdateSettings` is optional.
        let update_settings: Option<UpdateSettingsFn> =
            unsafe { Self::export(&library, EXPORT_UPDATE_SETTINGS, "UpdateSettings", path) }.ok();

        Ok(Self {
            name: name.to_owned(),
            path: path.to_path_buf(),
            validate,
            create_instance,
            populate_window,
            update_settings,
            invalid: AtomicBool::new(false),
            _library: library,
        })
    }

    /// Resolves one export as a raw fn pointer.
    ///
    /// # Safety
    ///
    /// `T` must be the exact `extern "C"` signature of the symbol.
    unsafe fn export<T: Copy>(library: &Library, symbol: &[u8], export: &'static str, path: &Path) -> Result<T, FfiError> {
        // SAFETY: forwarded from the caller's contract on `T`.
        let found: Symbol<'_, T> = unsafe { library.get(symbol) }.map_err(|_| FfiError::MissingExport {
            export,
            path: path.to_path_buf(),
        })?;
        Ok(*found)
    }

    /// Plugin name (`Plugin::GetName`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Library path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `true` once a call panicked (C++ `Invalid`).
    #[must_use]
    pub fn is_invalid(&self) -> bool {
        self.invalid.load(Ordering::Acquire)
    }

    /// Whether the plugin exports `UpdateSettings`.
    #[must_use]
    pub const fn has_update_settings(&self) -> bool {
        self.update_settings.is_some()
    }

    /// Marks the plugin invalid (fault handlers call this).
    pub fn mark_invalid(&self) {
        self.invalid.store(true, Ordering::Release);
    }

    fn guarded<R>(&self, export: &'static str, call: impl FnOnce() -> R) -> Result<R, FfiError> {
        if self.is_invalid() {
            return Err(FfiError::Invalid);
        }
        catch_unwind(AssertUnwindSafe(call)).map_or_else(
            |_| {
                self.mark_invalid();
                Err(FfiError::Panicked { export })
            },
            Ok,
        )
    }

    /// `Validate(buf, extension)`: `buf` is the identification probe
    /// (at most `0x8800` bytes, §10.1), `extension` includes its dot.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`], [`FfiError::Panicked`].
    pub fn validate(&self, buf: &[u8], extension: &str) -> Result<bool, FfiError> {
        let view = GViewBufferView::from_slice(buf);
        let ext = GViewStringView::from_str(extension);
        self.guarded("Validate", || {
            // SAFETY: `view` and `ext` are live stack values pointing at
            // `buf` / `extension`, which outlive this call; the plugin
            // receives them as `const&` and must not retain them (C++
            // contract). The signature matches the export.
            unsafe { (self.validate)(&raw const view, &raw const ext) }
        })
    }

    /// `CreateInstance()`.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`], [`FfiError::Panicked`]. A null result is
    /// returned as [`TypeInstancePtr::is_null`] for the caller's
    /// `CHECK(contentType)`.
    pub fn create_instance(&self) -> Result<TypeInstancePtr, FfiError> {
        self.guarded("CreateInstance", || {
            // SAFETY: no arguments; the signature matches the export.
            TypeInstancePtr(unsafe { (self.create_instance)() })
        })
    }

    /// `PopulateWindow(Reference<WindowInterface>)`: `window` is the
    /// shim handle the vtable task hands out (`Reference<T>` is a
    /// single-pointer struct passed like a pointer).
    ///
    /// # Safety
    ///
    /// `window` must be null or a handle whose vtable stays valid for
    /// the whole call; the plugin dereferences it.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`], [`FfiError::Panicked`].
    pub unsafe fn populate_window(&self, window: *mut c_void) -> Result<bool, FfiError> {
        self.guarded("PopulateWindow", || {
            // SAFETY: the plugin only dereferences `window` through the
            // vtable the shim installs; a null handle is the C++
            // "invalid reference" and plugins CHECK it. Signature
            // matches the export.
            unsafe { (self.populate_window)(window) }
        })
    }

    /// `UpdateSettings(IniSection)`: `section` is the ini bridge handle
    /// (`IniSection` is a single-pointer struct).
    ///
    /// # Safety
    ///
    /// `section` must be null or a handle valid for the whole call.
    ///
    /// # Errors
    ///
    /// [`FfiError::MissingExport`] when the plugin has no
    /// `UpdateSettings`, [`FfiError::Invalid`], [`FfiError::Panicked`].
    pub unsafe fn update_settings(&self, section: *mut c_void) -> Result<(), FfiError> {
        let Some(update) = self.update_settings else {
            return Err(FfiError::MissingExport {
                export: "UpdateSettings",
                path: self.path.clone(),
            });
        };
        self.guarded("UpdateSettings", || {
            // SAFETY: as for `populate_window`; signature matches.
            unsafe { update(section) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example cdylib built alongside the tests
    /// (`examples/gview_ffi_test_plugin.rs`): `target/<profile>/examples/`.
    fn test_plugin_path() -> PathBuf {
        let exe = std::env::current_exe().expect("test exe");
        let profile_dir = exe
            .parent()
            .and_then(Path::parent)
            .expect("target/<profile>")
            .to_path_buf();
        let dir = profile_dir.join("examples");
        let stem = "gview_ffi_test_plugin";
        let candidates = [
            dir.join(format!("{stem}.dll")),
            dir.join(format!("lib{stem}.so")),
            dir.join(format!("lib{stem}.dylib")),
        ];
        candidates
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("example plugin not built under {}", dir.display()))
    }

    #[test]
    fn plugin_name_and_path_rules() {
        assert!(is_valid_plugin_name("PE"));
        assert!(is_valid_plugin_name("mach-o_2.0"));
        for bad in ["", "..", "../PE", "a/b", "a\\b", "P E", "PE\0"] {
            assert!(!is_valid_plugin_name(bad), "{bad:?}");
        }
        let path = type_plugin_path(Path::new("Types"), "PE").expect("path");
        assert_eq!(path, Path::new("Types").join("libPE.tpl"));
        assert!(matches!(
            type_plugin_path(Path::new("Types"), "../evil"),
            Err(FfiError::InvalidName(_))
        ));
        assert!(matches!(
            LoadedPlugin::load(Path::new("Types"), "x/y"),
            Err(FfiError::InvalidName(_))
        ));
    }

    #[test]
    fn missing_library_is_a_load_error() {
        let err = LoadedPlugin::load(&std::env::temp_dir(), "DoesNotExist").expect_err("missing");
        assert!(matches!(err, FfiError::Load { .. }));
        assert!(err.to_string().starts_with("Unable to load: "));
    }

    #[test]
    fn load_test_plugin_and_call_validate_on_mz_bytes() {
        let path = test_plugin_path();
        let plugin = LoadedPlugin::load_path("PE", &path).expect("load");
        assert_eq!(plugin.name(), "PE");
        assert_eq!(plugin.path(), path);
        assert!(!plugin.is_invalid());
        assert!(plugin.has_update_settings());

        assert!(plugin.validate(b"MZ\x90\x00", ".exe").expect("validate"));
        assert!(!plugin.validate(b"ZM", ".exe").expect("validate"));
        assert!(!plugin.validate(&[], "").expect("validate empty"));
        // The extension is passed by reference and readable.
        assert!(plugin.validate(b"MZ", ".dll").expect("validate"));
        assert!(!plugin.validate(b"MZ", ".txt-reject").expect("extension gate"));

        let instance = plugin.create_instance().expect("create");
        assert!(!instance.is_null());
        // The test plugin stores a marker byte at the returned pointer.
        // SAFETY: the example plugin leaks a `Box<u32>` with a known
        // value and never frees it; reading it back is in bounds.
        let marker = unsafe { *(instance.0.cast::<u32>()) };
        assert_eq!(marker, 0x5045_5045);

        // PopulateWindow is given an opaque handle; the test plugin
        // reports whether it was null.
        // SAFETY: the test plugin null-checks the handle first.
        let null_result = unsafe { plugin.populate_window(std::ptr::null_mut()) };
        assert!(!null_result.expect("populate"));

        // C++-style PopulateWindow through the vtable shim creates a
        // BufferViewer (and a Dissasm viewer, plus one panel).
        let mut window = crate::window_iface::tests::MockWindow::default();
        let (result, report) = crate::window_iface::with_window_shim(&mut window, |this| {
            // SAFETY: `this` is the live shim for this call.
            unsafe { plugin.populate_window(this) }
        });
        assert!(result.expect("populate"));
        assert_eq!(
            window.viewers,
            [
                gview_plugin::type_plugin::ViewerKind::Buffer,
                gview_plugin::type_plugin::ViewerKind::Dissasm
            ]
        );
        assert_eq!(window.panels.len(), 1);
        assert_eq!(report.foreign_panels, 1);
        assert_eq!(report.references, 1);
        // SAFETY: the test plugin ignores the section handle.
        unsafe { plugin.update_settings(std::ptr::null_mut()) }.expect("settings");
        assert!(format!("{plugin:?}").contains("PE"));
    }

    #[test]
    fn panics_are_caught_and_invalidate_the_plugin() {
        let plugin = LoadedPlugin::load_path("PE", &test_plugin_path()).expect("load");
        // The guard sits around the whole call closure: a panic raised
        // there is caught, the plugin becomes invalid and stays so.
        let err = plugin
            .guarded("Validate", || -> bool { panic!("boom") })
            .expect_err("caught");
        assert!(matches!(err, FfiError::Panicked { export: "Validate" }));
        assert!(plugin.is_invalid());
        assert!(matches!(plugin.validate(b"MZ", ""), Err(FfiError::Invalid)));
        assert!(matches!(plugin.create_instance(), Err(FfiError::Invalid)));
        // SAFETY: null handles; an invalid plugin is never called anyway.
        let populate = unsafe { plugin.populate_window(std::ptr::null_mut()) };
        assert!(matches!(populate, Err(FfiError::Invalid)));
        // SAFETY: as above.
        let settings = unsafe { plugin.update_settings(std::ptr::null_mut()) };
        assert!(matches!(settings, Err(FfiError::Invalid)));
        assert_eq!(
            FfiError::Invalid.to_string(),
            "Invalid plugin (not loaded properly or no valid exports)"
        );
    }

    #[test]
    fn views_wrap_slices_without_copying() {
        let bytes = [1_u8, 2, 3];
        let view = GViewBufferView::from_slice(&bytes);
        assert_eq!(view.len, 3);
        assert!(std::ptr::eq(view.data, bytes.as_ptr()));
        let text = GViewStringView::from_str(".exe");
        assert_eq!(text.len, 4);
        assert_eq!(std::mem::size_of::<GViewBufferView>(), 2 * std::mem::size_of::<usize>());
        assert_eq!(std::mem::size_of::<GViewStringView>(), 2 * std::mem::size_of::<usize>());
    }
}
