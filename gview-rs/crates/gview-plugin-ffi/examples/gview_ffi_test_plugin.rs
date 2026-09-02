//! Test-only `.tpl` stand-in: a cdylib exporting the four C++ type
//! plugin symbols with the `GView.hpp` ABI (spec `03_DUAL_PLUGIN`
//! §3.1–3.2), used by `gview-plugin-ffi`'s loader tests in place of a
//! compiled C++ plugin.
//!
//! `Validate` accepts `MZ` data unless the extension is
//! `.txt-reject` (proves the `string_view` argument is read);
//! `CreateInstance` leaks a marker `u32` (`0x5045_5045`, "PEPE");
//! `PopulateWindow` reports whether its `Reference<WindowInterface>`
//! handle is non-null; `UpdateSettings` accepts any handle.

#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::undocumented_unsafe_blocks)]
#![allow(clippy::module_name_repetitions)]

use std::ffi::c_void;

use gview_plugin::type_plugin::ViewerKind;
use gview_plugin_ffi::window_iface::{viewer_slot, vtable_of, SettingsFacade, WindowShimRaw};

/// `AppCUI::Utils::BufferView` layout.
#[repr(C)]
pub struct GViewBufferView {
    data: *const u8,
    len: usize,
}

/// `std::string_view` layout.
#[repr(C)]
pub struct GViewStringView {
    ptr: *const u8,
    len: usize,
}

/// Reads a `{ptr, len}` view as a byte slice; empty when the pointer
/// is null.
///
/// # Safety
///
/// `ptr` must point at `len` readable bytes that stay alive for the
/// returned lifetime (the host guarantees this for the call duration).
const unsafe fn view<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: forwarded from the function contract.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// `bool Validate(const BufferView&, const std::string_view&)`.
///
/// # Safety
///
/// `buf` and `ext` must be null or point at valid views for the call.
#[no_mangle]
pub unsafe extern "C" fn Validate(buf: *const GViewBufferView, ext: *const GViewStringView) -> bool {
    if buf.is_null() {
        return false;
    }
    // SAFETY: non-null per the check above; the host passes a live view.
    let bytes = unsafe { view((*buf).data, (*buf).len) };
    let extension = if ext.is_null() {
        &[][..]
    } else {
        // SAFETY: non-null; the host passes a live view.
        unsafe { view((*ext).ptr, (*ext).len) }
    };
    bytes.starts_with(b"MZ") && extension != b".txt-reject"
}

/// `TypeInterface* CreateInstance()`: leaks a marker the test reads.
#[no_mangle]
pub extern "C" fn CreateInstance() -> *mut c_void {
    Box::into_raw(Box::new(0x5045_5045_u32)).cast::<c_void>()
}

/// `bool PopulateWindow(Reference<WindowInterface>)`: like the PE
/// plugin, adds a panel and creates a Buffer viewer through the
/// `WindowInterface` vtable, then a Dissasm viewer.
///
/// # Safety
///
/// `win` must be null or a live `WindowInterface` shim from the host.
#[no_mangle]
pub unsafe extern "C" fn PopulateWindow(win: *mut c_void) -> bool {
    if win.is_null() {
        return false;
    }
    // SAFETY: a non-null `Reference<WindowInterface>` from the host is
    // a live shim whose first word is the vtable pointer.
    let vtable = unsafe { &*vtable_of(win) };
    let this = win.cast::<WindowShimRaw>();
    let mut settings = SettingsFacade {
        data: std::ptr::null_mut(),
    };
    let mut page: *mut c_void = 0x4000 as *mut c_void;
    // SAFETY: calling the host's vtable with its own live `this`, a
    // valid settings facade and a valid `Pointer<TabPage>` slot.
    unsafe {
        if !(vtable.add_panel)(this, &raw mut page, true) {
            return false;
        }
        if !vtable.create_viewer[viewer_slot(ViewerKind::Buffer)](this, &raw mut settings) {
            return false;
        }
        if !vtable.create_viewer[viewer_slot(ViewerKind::Dissasm)](this, &raw mut settings) {
            return false;
        }
        (vtable.get_views_count)(this) == 2 && !(vtable.get_object)(this).is_null()
    }
}

/// `void UpdateSettings(IniSection)`.
#[no_mangle]
pub const extern "C" fn UpdateSettings(_section: *mut c_void) {}

