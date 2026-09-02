//! `WindowInterface` vtable shim (spec `03_DUAL_PLUGIN` §4.2–4.3;
//! C++ `GView::View::WindowInterface`, `GView.hpp:1820-1849`).
//!
//! A C++ `PopulateWindow(Reference<WindowInterface> win)` receives a
//! pointer to an object whose first word is a vtable pointer and calls
//! the pure virtuals through it. [`WindowShim`] is that object: a
//! `#[repr(C)]` header (`vtable`, magic) followed by the Rust window
//! ([`WindowHandle`]) it forwards to. [`with_window_shim`] builds one
//! for the duration of a plugin call — `Reference<T>` is non-owning,
//! so the plugin must not keep the pointer, exactly as with the C++
//! host.
//!
//! Vtable layout: slots follow the C++ declaration order
//! (`GetObject`, `AddPanel`, seven `CreateViewer` overloads,
//! `GetCurrentView`, `GetViewsCount`, `GetViewByIndex`,
//! `SetViewByIndex`, `GetQueryInterface`, `GetAnalysisEngine`,
//! `GetCurrentWindowSubject`, `GetSelectionZoneInterfaceFromViewerCreation`).
//! MSVC lays out **adjacent overloads in reverse declaration order**,
//! so under `target_env = "msvc"` the seven `CreateViewer` slots run
//! Lexical → Buffer ([`VIEWER_SLOT_ORDER`]); the Itanium ABI keeps
//! Buffer → Lexical. Only 64-bit targets are supported: `this` is the
//! first integer argument and single-pointer structs
//! (`Reference<T>`, `IniSection`) travel in registers, while the
//! non-trivial `Pointer<TabPage>` and every `Settings&` arrive as
//! pointers.
//!
//! Each shim method is a `catch_unwind` boundary (§4.3): a panic never
//! crosses into C++; the call reports failure (`false` / null).
//! References handed *to* the plugin (`Reference<Object>`,
//! `Reference<ViewControl>`, …) are entries of a bounds-checked
//! [`HandleTable`] owned by the shim; a pointer coming back is
//! validated against the table ([`WindowShim::resolve`]) instead of
//! being dereferenced. C++ inline access to `Object` / `ViewControl`
//! internals through those references is not supported in-process
//! (spec §5.2, §9) — the entries are opaque.
//!
//! Viewer `Settings` are opaque `SettingsData*` facades owned by the
//! plugin's C++ runtime; the shim creates the requested viewer kind
//! with default settings ([`ViewerRequest::new`]) and leaves the C++
//! data to the plugin.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

use gview_plugin::type_plugin::{PanelRequest, ViewerKind, ViewerRequest, WindowHandle};

/// Number of virtual slots in `WindowInterface`.
pub const VTABLE_SLOTS: usize = 17;
/// Slot of `GetObject`.
pub const SLOT_GET_OBJECT: usize = 0;
/// Slot of `AddPanel`.
pub const SLOT_ADD_PANEL: usize = 1;
/// First of the seven `CreateViewer` slots.
pub const SLOT_CREATE_VIEWER_FIRST: usize = 2;
/// Slot of `GetCurrentView`.
pub const SLOT_GET_CURRENT_VIEW: usize = 9;
/// Slot of `GetViewsCount`.
pub const SLOT_GET_VIEWS_COUNT: usize = 10;
/// Slot of `GetViewByIndex`.
pub const SLOT_GET_VIEW_BY_INDEX: usize = 11;
/// Slot of `SetViewByIndex`.
pub const SLOT_SET_VIEW_BY_INDEX: usize = 12;
/// Slot of `GetQueryInterface`.
pub const SLOT_GET_QUERY_INTERFACE: usize = 13;
/// Slot of `GetAnalysisEngine`.
pub const SLOT_GET_ANALYSIS_ENGINE: usize = 14;
/// Slot of `GetCurrentWindowSubject`.
pub const SLOT_GET_CURRENT_WINDOW_SUBJECT: usize = 15;
/// Slot of `GetSelectionZoneInterfaceFromViewerCreation`.
pub const SLOT_GET_SELECTION_ZONE_INTERFACE: usize = 16;

/// C++ declaration order of the `CreateViewer` overloads.
pub const VIEWER_DECLARATION_ORDER: [ViewerKind; 7] = [
    ViewerKind::Buffer,
    ViewerKind::Image,
    ViewerKind::Grid,
    ViewerKind::Dissasm,
    ViewerKind::Text,
    ViewerKind::Container,
    ViewerKind::Lexical,
];

/// Viewer kind created by `CreateViewer` slot
/// `SLOT_CREATE_VIEWER_FIRST + i` on this target's C++ ABI.
#[cfg(target_env = "msvc")]
pub const VIEWER_SLOT_ORDER: [ViewerKind; 7] = [
    ViewerKind::Lexical,
    ViewerKind::Container,
    ViewerKind::Text,
    ViewerKind::Dissasm,
    ViewerKind::Grid,
    ViewerKind::Image,
    ViewerKind::Buffer,
];
/// Viewer kind created by `CreateViewer` slot
/// `SLOT_CREATE_VIEWER_FIRST + i` on this target's C++ ABI.
#[cfg(not(target_env = "msvc"))]
pub const VIEWER_SLOT_ORDER: [ViewerKind; 7] = VIEWER_DECLARATION_ORDER;

/// Index within the `CreateViewer` group for `kind` on this ABI.
#[must_use]
pub fn viewer_slot(kind: ViewerKind) -> usize {
    VIEWER_SLOT_ORDER.iter().position(|k| *k == kind).unwrap_or(0)
}

/// Largest number of live references a shim hands out.
pub const MAX_HANDLES: usize = 1 << 16;

/// Marker stored after the vtable pointer so a stray `this` is
/// rejected before use.
const SHIM_MAGIC: u64 = 0x4756_4945_5753_4849; // "GVIEWSHI"

/// `Reference<T>` handle (spec §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefHandle(pub u32);

/// Non-owning reference table (spec §4.2 `HandleTable<T>`), bounds
/// checked on every access; slots are recycled through a free list.
#[derive(Debug)]
pub struct HandleTable<T> {
    slots: Vec<Option<T>>,
    free: Vec<u32>,
}

impl<T> Default for HandleTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> HandleTable<T> {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Stores `value`; `None` when [`MAX_HANDLES`] is reached.
    pub fn insert(&mut self, value: T) -> Option<RefHandle> {
        if let Some(index) = self.free.pop() {
            if let Some(slot) = self.slots.get_mut(index as usize) {
                *slot = Some(value);
                return Some(RefHandle(index));
            }
        }
        if self.slots.len() >= MAX_HANDLES {
            return None;
        }
        self.slots.push(Some(value));
        Some(RefHandle(self.slots.len().saturating_sub(1) as u32))
    }

    /// Bounds-checked lookup.
    #[must_use]
    pub fn get(&self, handle: RefHandle) -> Option<&T> {
        self.slots.get(handle.0 as usize).and_then(Option::as_ref)
    }

    /// Bounds-checked mutable lookup.
    pub fn get_mut(&mut self, handle: RefHandle) -> Option<&mut T> {
        self.slots.get_mut(handle.0 as usize).and_then(Option::as_mut)
    }

    /// Removes an entry, freeing its slot.
    pub fn remove(&mut self, handle: RefHandle) -> Option<T> {
        let value = self.slots.get_mut(handle.0 as usize).and_then(Option::take)?;
        self.free.push(handle.0);
        Some(value)
    }

    /// Live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// `true` without live entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterates live `(handle, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (RefHandle, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|v| (RefHandle(i as u32), v)))
    }
}

/// What a `Reference<T>` handed to the plugin stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefKind {
    /// `Reference<Object>` (`GetObject`).
    Object,
    /// `Reference<ViewControl>` for viewer `index`.
    ViewControl(u32),
    /// `Reference<QueryInterface>`.
    QueryInterface,
    /// `Reference<AnalysisEngineInterface>`.
    AnalysisEngine,
    /// `Reference<Subject>`.
    Subject,
    /// `Reference<SelectionZoneInterface>` of buffer viewer `index`.
    SelectionZone(u32),
}

/// A table-owned reference target; the plugin receives `&*Box<_>`.
#[derive(Debug)]
pub struct RefTarget {
    kind: RefKind,
}

/// `Settings` facade (`struct Settings { void* data; }`) — opaque here.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SettingsFacade {
    /// C++ `SettingsData*`, owned and interpreted by the plugin side.
    pub data: *mut c_void,
}

type GetObjectFn = unsafe extern "C" fn(*mut WindowShimRaw) -> *mut c_void;
type AddPanelFn = unsafe extern "C" fn(*mut WindowShimRaw, *mut *mut c_void, bool) -> bool;
type CreateViewerFn = unsafe extern "C" fn(*mut WindowShimRaw, *mut SettingsFacade) -> bool;
type GetViewFn = unsafe extern "C" fn(*mut WindowShimRaw) -> *mut c_void;
type GetViewsCountFn = unsafe extern "C" fn(*mut WindowShimRaw) -> u32;
type GetViewByIndexFn = unsafe extern "C" fn(*mut WindowShimRaw, u32) -> *mut c_void;
type SetViewByIndexFn = unsafe extern "C" fn(*mut WindowShimRaw, u32) -> bool;
type GetSelectionZoneFn = unsafe extern "C" fn(*mut WindowShimRaw, *mut SettingsFacade) -> *mut c_void;

/// The `WindowInterface` vtable as C++ reads it (17 slots, see module
/// docs for the `CreateViewer` group order).
#[repr(C)]
pub struct WindowVTable {
    /// `GetObject`.
    pub get_object: GetObjectFn,
    /// `AddPanel(Pointer<TabPage>, bool)`.
    pub add_panel: AddPanelFn,
    /// `CreateViewer` group, ABI slot order ([`VIEWER_SLOT_ORDER`]).
    pub create_viewer: [CreateViewerFn; 7],
    /// `GetCurrentView`.
    pub get_current_view: GetViewFn,
    /// `GetViewsCount`.
    pub get_views_count: GetViewsCountFn,
    /// `GetViewByIndex`.
    pub get_view_by_index: GetViewByIndexFn,
    /// `SetViewByIndex`.
    pub set_view_by_index: SetViewByIndexFn,
    /// `GetQueryInterface`.
    pub get_query_interface: GetViewFn,
    /// `GetAnalysisEngine`.
    pub get_analysis_engine: GetViewFn,
    /// `GetCurrentWindowSubject`.
    pub get_current_window_subject: GetViewFn,
    /// `GetSelectionZoneInterfaceFromViewerCreation`.
    pub get_selection_zone_interface: GetSelectionZoneFn,
}

/// The object a C++ plugin sees as `WindowInterface*`.
#[repr(C)]
pub struct WindowShim<'a> {
    vtable: *const WindowVTable,
    magic: u64,
    window: &'a mut dyn WindowHandle,
    refs: HandleTable<Box<RefTarget>>,
    /// Panels the plugin handed over as C++ `TabPage` pointers; they
    /// stay owned by the plugin's runtime (never freed here).
    foreign_panels: Vec<*mut c_void>,
}

/// Lifetime-erased `this` pointer type used in the vtable signatures
/// (the C++ side sees `WindowInterface*`).
#[repr(C)]
pub struct WindowShimRaw {
    _private: [u8; 0],
}

static VTABLE: WindowVTable = WindowVTable {
    get_object: shim_get_object,
    add_panel: shim_add_panel,
    create_viewer: [
        shim_create_viewer_slot0,
        shim_create_viewer_slot1,
        shim_create_viewer_slot2,
        shim_create_viewer_slot3,
        shim_create_viewer_slot4,
        shim_create_viewer_slot5,
        shim_create_viewer_slot6,
    ],
    get_current_view: shim_get_current_view,
    get_views_count: shim_get_views_count,
    get_view_by_index: shim_get_view_by_index,
    set_view_by_index: shim_set_view_by_index,
    get_query_interface: shim_get_query_interface,
    get_analysis_engine: shim_get_analysis_engine,
    get_current_window_subject: shim_get_current_window_subject,
    get_selection_zone_interface: shim_get_selection_zone_interface,
};

impl<'a> WindowShim<'a> {
    // Boxed on purpose: the plugin holds the object's address for the
    // whole call, so it must not move.
    #[allow(clippy::unnecessary_box_returns)]
    fn new(window: &'a mut dyn WindowHandle) -> Box<Self> {
        Box::new(Self {
            vtable: &raw const VTABLE,
            magic: SHIM_MAGIC,
            window,
            refs: HandleTable::new(),
            foreign_panels: Vec::new(),
        })
    }

    /// The `this` pointer to hand to the plugin.
    fn this_ptr(self: &mut Box<Self>) -> *mut c_void {
        std::ptr::from_mut::<Self>(&mut **self).cast::<c_void>()
    }

    /// Validates a `this` pointer coming back from C++.
    ///
    /// # Safety
    ///
    /// `this` must be null, garbage that does not alias a live shim, or
    /// a pointer obtained from [`with_window_shim`] during its call.
    unsafe fn from_this<'s>(this: *mut WindowShimRaw) -> Option<&'s mut Self> {
        let ptr = this.cast::<Self>();
        if ptr.is_null() || !ptr.is_aligned() {
            return None;
        }
        // SAFETY: non-null and aligned per the checks; per the caller's
        // contract the pointer designates a live `WindowShim` whose
        // header we may read to check the marker before trusting it.
        let header = unsafe { &*ptr };
        if header.magic != SHIM_MAGIC || !std::ptr::eq(header.vtable, &raw const VTABLE) {
            return None;
        }
        // SAFETY: validated above; the shim is exclusively used by the
        // single plugin call in progress (single-threaded UI contract).
        Some(unsafe { &mut *ptr })
    }

    fn hand_out(&mut self, kind: RefKind) -> *mut c_void {
        let target = Box::new(RefTarget { kind });
        let Some(handle) = self.refs.insert(target) else {
            return std::ptr::null_mut();
        };
        self.refs
            .get_mut(handle)
            .map_or(std::ptr::null_mut(), |boxed| std::ptr::from_mut::<RefTarget>(&mut **boxed).cast::<c_void>())
    }

    /// Resolves a reference pointer the plugin passes back to what it
    /// stands for, by table membership (never dereferenced).
    #[must_use]
    pub fn resolve(&self, reference: *const c_void) -> Option<RefKind> {
        if reference.is_null() {
            return None;
        }
        self.refs
            .iter()
            .find(|(_, boxed)| std::ptr::eq(std::ptr::from_ref::<RefTarget>(&***boxed).cast::<c_void>(), reference))
            .map(|(_, boxed)| boxed.kind)
    }

    /// Live references handed out so far.
    #[must_use]
    pub fn references(&self) -> usize {
        self.refs.len()
    }

    /// C++ `TabPage` pointers received through `AddPanel`.
    #[must_use]
    pub fn foreign_panels(&self) -> &[*mut c_void] {
        &self.foreign_panels
    }

    fn create_viewer(&mut self, kind: ViewerKind, settings: *mut SettingsFacade) -> bool {
        if settings.is_null() {
            return false;
        }
        self.window.create_viewer(ViewerRequest::new(kind)).is_ok()
    }
}

/// Runs `f` with a `WindowInterface*` for `window` valid only during
/// the call (the C++ `Reference<WindowInterface>` a plugin gets).
/// Returns `f`'s result together with the shim's bookkeeping.
pub fn with_window_shim<R>(window: &mut dyn WindowHandle, f: impl FnOnce(*mut c_void) -> R) -> (R, ShimReport) {
    let mut shim = WindowShim::new(window);
    let this = shim.this_ptr();
    let result = f(this);
    let report = ShimReport {
        references: shim.references(),
        foreign_panels: shim.foreign_panels.len(),
    };
    drop(shim);
    (result, report)
}

/// What a shim did during one plugin call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShimReport {
    /// References handed to the plugin.
    pub references: usize,
    /// `TabPage` pointers received through `AddPanel`.
    pub foreign_panels: usize,
}

fn guard<R>(fallback: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

unsafe extern "C" fn shim_get_object(this: *mut WindowShimRaw) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        // SAFETY: `this` comes from the plugin, which got it from
        // `with_window_shim`; `from_this` validates it before use.
        unsafe { WindowShim::from_this(this) }.map_or(std::ptr::null_mut(), |shim| shim.hand_out(RefKind::Object))
    })
}

unsafe extern "C" fn shim_add_panel(this: *mut WindowShimRaw, page: *mut *mut c_void, vertical: bool) -> bool {
    guard(false, || {
        // SAFETY: as in `shim_get_object`.
        let Some(shim) = (unsafe { WindowShim::from_this(this) }) else {
            return false;
        };
        if page.is_null() || !page.is_aligned() {
            return false;
        }
        // SAFETY: `page` is the hidden reference to the by-value
        // `Pointer<TabPage>` (a `unique_ptr`, i.e. one pointer); C++
        // passes a valid temporary for the call. We take the pointee
        // and null the unique_ptr so the caller's destructor frees
        // nothing (ownership transferred, C++ semantics).
        let tab_page = unsafe { std::ptr::replace(page, std::ptr::null_mut()) };
        if tab_page.is_null() {
            return false;
        }
        shim.foreign_panels.push(tab_page);
        let index = shim.foreign_panels.len();
        shim.window.add_panel(
            PanelRequest {
                caption: format!("Plugin panel {index}"),
                panel_id: format!("ffi.tabpage.{index}"),
            },
            vertical,
        )
    })
}

macro_rules! create_viewer_slot {
    ($name:ident, $index:expr) => {
        unsafe extern "C" fn $name(this: *mut WindowShimRaw, settings: *mut SettingsFacade) -> bool {
            guard(false, || {
                // SAFETY: as in `shim_get_object`.
                let Some(shim) = (unsafe { WindowShim::from_this(this) }) else {
                    return false;
                };
                let kind = VIEWER_SLOT_ORDER.get($index).copied().unwrap_or(ViewerKind::Buffer);
                shim.create_viewer(kind, settings)
            })
        }
    };
}

create_viewer_slot!(shim_create_viewer_slot0, 0);
create_viewer_slot!(shim_create_viewer_slot1, 1);
create_viewer_slot!(shim_create_viewer_slot2, 2);
create_viewer_slot!(shim_create_viewer_slot3, 3);
create_viewer_slot!(shim_create_viewer_slot4, 4);
create_viewer_slot!(shim_create_viewer_slot5, 5);
create_viewer_slot!(shim_create_viewer_slot6, 6);

unsafe extern "C" fn shim_get_current_view(this: *mut WindowShimRaw) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        // SAFETY: as in `shim_get_object`.
        let Some(shim) = (unsafe { WindowShim::from_this(this) }) else {
            return std::ptr::null_mut();
        };
        shim.window
            .current_view()
            .map_or(std::ptr::null_mut(), |index| shim.hand_out(RefKind::ViewControl(index)))
    })
}

unsafe extern "C" fn shim_get_views_count(this: *mut WindowShimRaw) -> u32 {
    guard(0, || {
        // SAFETY: as in `shim_get_object`.
        unsafe { WindowShim::from_this(this) }.map_or(0, |shim| shim.window.views_count())
    })
}

unsafe extern "C" fn shim_get_view_by_index(this: *mut WindowShimRaw, index: u32) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        // SAFETY: as in `shim_get_object`.
        let Some(shim) = (unsafe { WindowShim::from_this(this) }) else {
            return std::ptr::null_mut();
        };
        if index >= shim.window.views_count() {
            return std::ptr::null_mut();
        }
        shim.hand_out(RefKind::ViewControl(index))
    })
}

unsafe extern "C" fn shim_set_view_by_index(this: *mut WindowShimRaw, index: u32) -> bool {
    guard(false, || {
        // SAFETY: as in `shim_get_object`.
        unsafe { WindowShim::from_this(this) }.is_some_and(|shim| shim.window.set_view_by_index(index))
    })
}

unsafe extern "C" fn shim_get_query_interface(this: *mut WindowShimRaw) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        // SAFETY: as in `shim_get_object`.
        unsafe { WindowShim::from_this(this) }
            .map_or(std::ptr::null_mut(), |shim| shim.hand_out(RefKind::QueryInterface))
    })
}

unsafe extern "C" fn shim_get_analysis_engine(this: *mut WindowShimRaw) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        // SAFETY: as in `shim_get_object`.
        unsafe { WindowShim::from_this(this) }
            .map_or(std::ptr::null_mut(), |shim| shim.hand_out(RefKind::AnalysisEngine))
    })
}

unsafe extern "C" fn shim_get_current_window_subject(this: *mut WindowShimRaw) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        // SAFETY: as in `shim_get_object`.
        unsafe { WindowShim::from_this(this) }.map_or(std::ptr::null_mut(), |shim| shim.hand_out(RefKind::Subject))
    })
}

unsafe extern "C" fn shim_get_selection_zone_interface(this: *mut WindowShimRaw, settings: *mut SettingsFacade) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        // SAFETY: as in `shim_get_object`.
        let Some(shim) = (unsafe { WindowShim::from_this(this) }) else {
            return std::ptr::null_mut();
        };
        if settings.is_null() {
            return std::ptr::null_mut();
        }
        shim.window
            .create_viewer(ViewerRequest::new(ViewerKind::Buffer))
            .map_or(std::ptr::null_mut(), |index| shim.hand_out(RefKind::SelectionZone(index)))
    })
}

/// Reads the vtable pointer of a shim object the way C++ does
/// (first word), for callers that emulate a plugin.
///
/// # Safety
///
/// `this` must be a pointer produced by [`with_window_shim`] during
/// its call.
#[must_use]
pub unsafe fn vtable_of(this: *mut c_void) -> *const WindowVTable {
    // SAFETY: the shim's first field is the vtable pointer
    // (`#[repr(C)]`); the caller guarantees `this` is a live shim.
    unsafe { *this.cast::<*const WindowVTable>() }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use gview_core::object::Object;
    use gview_plugin::type_plugin::PluginError;
    use gview_view::traits::SharedObject;
    use std::sync::{Arc, Mutex};

    /// A window recording what the plugin asked for.
    #[derive(Default)]
    pub struct MockWindow {
        pub viewers: Vec<ViewerKind>,
        pub panels: Vec<(String, bool)>,
        pub current: Option<u32>,
        pub fail_viewers: bool,
    }

    impl WindowHandle for MockWindow {
        fn object(&self) -> SharedObject {
            Arc::new(Mutex::new(Object::from_buffer(b"MZ", "mock", 0)))
        }
        fn add_panel(&mut self, panel: PanelRequest, vertical: bool) -> bool {
            self.panels.push((panel.caption, vertical));
            true
        }
        fn create_viewer(&mut self, request: ViewerRequest) -> Result<u32, PluginError> {
            if self.fail_viewers {
                return Err(PluginError::Window(String::from("full")));
            }
            self.viewers.push(request.kind);
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

    #[test]
    fn handle_table_is_bounds_checked_and_recycles_slots() {
        let mut table: HandleTable<u32> = HandleTable::new();
        assert!(table.is_empty());
        let a = table.insert(10).expect("a");
        let b = table.insert(20).expect("b");
        assert_eq!(table.get(a), Some(&10));
        assert_eq!(table.get(b), Some(&20));
        assert_eq!(table.get(RefHandle(2)), None);
        assert_eq!(table.get(RefHandle(u32::MAX)), None);
        assert_eq!(table.remove(a), Some(10));
        assert_eq!(table.get(a), None);
        assert_eq!(table.remove(a), None);
        let c = table.insert(30).expect("c");
        assert_eq!(c, a, "freed slot is reused");
        *table.get_mut(c).expect("c") = 31;
        assert_eq!(table.len(), 2);
        assert_eq!(table.iter().count(), 2);
    }

    #[test]
    fn slot_layout_matches_cpp_declaration() {
        assert_eq!(std::mem::size_of::<WindowVTable>(), VTABLE_SLOTS * std::mem::size_of::<usize>());
        assert_eq!(SLOT_CREATE_VIEWER_FIRST + 7, SLOT_GET_CURRENT_VIEW);
        assert_eq!(SLOT_GET_SELECTION_ZONE_INTERFACE, VTABLE_SLOTS - 1);
        // The ABI order is a permutation of the declaration order.
        let mut declared = VIEWER_DECLARATION_ORDER.to_vec();
        let mut abi = VIEWER_SLOT_ORDER.to_vec();
        declared.sort_by_key(|k| *k as u8);
        abi.sort_by_key(|k| *k as u8);
        assert_eq!(declared, abi);
        if cfg!(target_env = "msvc") {
            assert_eq!(VIEWER_SLOT_ORDER[0], ViewerKind::Lexical);
            assert_eq!(VIEWER_SLOT_ORDER[6], ViewerKind::Buffer);
        } else {
            assert_eq!(VIEWER_SLOT_ORDER[0], ViewerKind::Buffer);
        }
        assert_eq!(VIEWER_SLOT_ORDER[viewer_slot(ViewerKind::Buffer)], ViewerKind::Buffer);
        assert_eq!(VIEWER_SLOT_ORDER[viewer_slot(ViewerKind::Text)], ViewerKind::Text);
    }

    /// Emulates a C++ `PopulateWindow` calling through the vtable.
    #[test]
    fn cpp_style_calls_through_the_vtable_create_a_buffer_viewer() {
        let mut window = MockWindow::default();
        let (result, report) = with_window_shim(&mut window, |this| {
            // SAFETY: `this` is the live shim for this closure.
            let vtable = unsafe { &*vtable_of(this) };
            let this = this.cast::<WindowShimRaw>();
            let mut settings = SettingsFacade {
                data: std::ptr::null_mut(),
            };
            // SAFETY: calling the shim's own vtable functions with the
            // live `this` and a valid settings pointer.
            unsafe {
                assert_eq!((vtable.get_views_count)(this), 0);
                assert!((vtable.get_current_view)(this).is_null());
                let buffer = vtable.create_viewer[viewer_slot(ViewerKind::Buffer)];
                assert!(buffer(this, &raw mut settings));
                assert!(!buffer(this, std::ptr::null_mut()));
                let dissasm = vtable.create_viewer[viewer_slot(ViewerKind::Dissasm)];
                assert!(dissasm(this, &raw mut settings));
                assert_eq!((vtable.get_views_count)(this), 2);
                assert!((vtable.set_view_by_index)(this, 0));
                assert!(!(vtable.set_view_by_index)(this, 5));
                let view0 = (vtable.get_view_by_index)(this, 0);
                assert!(!view0.is_null());
                assert!((vtable.get_view_by_index)(this, 9).is_null());
                let object = (vtable.get_object)(this);
                assert!(!object.is_null());
                let current = (vtable.get_current_view)(this);
                assert!(!current.is_null());
                let mut page: *mut c_void = 0x1000 as *mut c_void;
                assert!((vtable.add_panel)(this, &raw mut page, true));
                assert!(page.is_null(), "ownership moved out of the unique_ptr");
                assert!(!(vtable.add_panel)(this, std::ptr::null_mut(), true));
                let zone = (vtable.get_selection_zone_interface)(this, &raw mut settings);
                assert!(!zone.is_null());
                assert!(!(vtable.get_query_interface)(this).is_null());
                assert!(!(vtable.get_analysis_engine)(this).is_null());
                assert!(!(vtable.get_current_window_subject)(this).is_null());

                // References resolve by table membership, never by deref.
                let shim = WindowShim::from_this(this).expect("shim");
                assert_eq!(shim.resolve(object), Some(RefKind::Object));
                assert_eq!(shim.resolve(view0), Some(RefKind::ViewControl(0)));
                assert_eq!(shim.resolve(current), Some(RefKind::ViewControl(0)));
                assert_eq!(shim.resolve(zone), Some(RefKind::SelectionZone(2)));
                assert_eq!(shim.resolve(std::ptr::null()), None);
                assert_eq!(shim.resolve(0x1234 as *const c_void), None);
                assert_eq!(shim.foreign_panels(), &[0x1000 as *mut c_void][..]);
            }
            42
        });
        assert_eq!(result, 42);
        assert_eq!(report.references, 7);
        assert_eq!(report.foreign_panels, 1);
        assert_eq!(window.viewers, [ViewerKind::Buffer, ViewerKind::Dissasm, ViewerKind::Buffer]);
        assert_eq!(window.panels, [(String::from("Plugin panel 1"), true)]);
    }

    #[test]
    fn stray_this_pointers_are_rejected_without_deref() {
        let mut fake = [0_u64; 8];
        let this = fake.as_mut_ptr().cast::<WindowShimRaw>();
        // SAFETY: the vtable functions validate `this` before use; a
        // zeroed buffer has no magic and yields the failure values.
        unsafe {
            assert_eq!((VTABLE.get_views_count)(this), 0);
            assert!((VTABLE.get_object)(this).is_null());
            assert!(!(VTABLE.set_view_by_index)(this, 0));
            assert_eq!((VTABLE.get_views_count)(std::ptr::null_mut()), 0);
            assert!(WindowShim::from_this(std::ptr::null_mut()).is_none());
            let unaligned = fake.as_mut_ptr().cast::<u8>().wrapping_add(1).cast::<WindowShimRaw>();
            assert!(WindowShim::from_this(unaligned).is_none());
        }
    }

    #[test]
    fn viewer_failures_report_false() {
        let mut window = MockWindow {
            fail_viewers: true,
            ..MockWindow::default()
        };
        let ((), report) = with_window_shim(&mut window, |this| {
            // SAFETY: live shim for this closure.
            let vtable = unsafe { &*vtable_of(this) };
            let this = this.cast::<WindowShimRaw>();
            let mut settings = SettingsFacade {
                data: std::ptr::null_mut(),
            };
            // SAFETY: as above.
            unsafe {
                assert!(!vtable.create_viewer[viewer_slot(ViewerKind::Buffer)](this, &raw mut settings));
                assert!((vtable.get_selection_zone_interface)(this, &raw mut settings).is_null());
            }
        });
        assert_eq!(report.references, 0);
        assert!(window.viewers.is_empty());
    }
}
