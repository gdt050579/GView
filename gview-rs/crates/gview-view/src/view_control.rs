//! Base contract implemented by every smart viewer
//! (C++ `GView::View::ViewControl`, `GView.hpp:1222-1267`, base
//! defaults in `ViewControl.cpp`; spec `02_SMART_VIEWERS_DEEP` §C.1).
//!
//! In C++ this is an abstract `UserControl`; in Rust the `AppCUI`
//! control wiring (paint, key events) attaches per-viewer via
//! `#[CustomControl]`, while this trait carries the GView-level
//! surface the `FileWindow` and plugins program against.

use appcui::graphics::Surface;
use gview_core::constants::INVALID_OFFSET;
use gview_core::zones::ZonesList;

/// Snapshot of a viewer's visible range and cursor
/// (C++ `ViewData`, `GView.hpp:1207-1212`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewData {
    /// First visible offset.
    pub view_start_offset: u64,
    /// Number of visible bytes.
    pub view_size: u64,
    /// Cursor offset.
    pub cursor_start_offset: u64,
    /// Byte under the cursor.
    pub byte: u8,
}

impl Default for ViewData {
    fn default() -> Self {
        Self {
            view_start_offset: INVALID_OFFSET,
            view_size: INVALID_OFFSET,
            cursor_start_offset: INVALID_OFFSET,
            byte: 0,
        }
    }
}

/// Clamps a requested `GoTo` offset into the valid cursor range
/// `[0, file_size - 1]`; an empty file clamps to 0.
///
/// The C++ viewers apply this bound inside their own `GoTo`
/// implementations; the helper centralizes it for the Rust port.
#[must_use]
pub const fn clamp_goto(offset: u64, file_size: u64) -> u64 {
    let last = file_size.saturating_sub(1);
    if offset > last {
        last
    } else {
        offset
    }
}

/// GView-level viewer contract (C++ `ViewControl`).
///
/// Required methods mirror the C++ pure virtuals; provided methods
/// mirror the C++ base implementations (`ViewControl.cpp` — all
/// return `false`, and the highlighting zones getter returns an
/// empty list).
pub trait ViewControl {
    /// Viewer display name shown on the view tab (C++ `GetName`).
    fn name(&self) -> &str;

    /// Moves the cursor to `offset`; implementations clamp with
    /// [`clamp_goto`] (C++ pure virtual `GoTo`).
    fn go_to(&mut self, offset: u64) -> bool;

    /// Selects `size` bytes starting at `offset`
    /// (C++ pure virtual `Select`).
    fn select(&mut self, offset: u64, size: u64) -> bool;

    /// Opens the viewer's `GoTo` dialog (C++ pure virtual).
    fn show_goto_dialog(&mut self) -> bool;

    /// Opens the viewer's Find dialog (C++ pure virtual; note the
    /// `TextViewer` stub — `02_VIEWER_TEXT`).
    fn show_find_dialog(&mut self) -> bool;

    /// Opens the viewer's Copy dialog (C++ pure virtual).
    fn show_copy_dialog(&mut self) -> bool;

    /// Paints the bottom cursor-information bar
    /// (C++ pure virtual `PaintCursorInformation`).
    fn paint_cursor_information(&mut self, surface: &mut Surface, width: u32, height: u32);

    /// Lets the viewer publish its key bindings; the C++ base returns
    /// `true` without registering anything (`GView.hpp:1233-1236`).
    fn update_keys(&mut self) -> bool {
        true
    }

    /// Fills `data` for the view at `offset`; base returns `false`
    /// (`ViewControl.cpp:54-57`).
    fn view_data(&self, data: &mut ViewData, offset: u64) -> bool {
        let _ = (data, offset);
        false
    }

    /// Scrolls the view start by `delta`; base returns `false`
    /// (`ViewControl.cpp:59-62`).
    fn advance_start_view(&mut self, delta: i64) -> bool {
        let _ = delta;
        false
    }

    /// Installs the object-highlighting zones; base returns `false`
    /// (`ViewControl.cpp:64-67`).
    fn set_objects_highlighting_zones(&mut self, zones: ZonesList) -> bool {
        let _ = zones;
        false
    }

    /// The viewer's object-highlighting zones; base has none
    /// (C++ returns a static empty list, `ViewControl.cpp:69-73`).
    fn objects_highlighting_zones(&self) -> Option<&ZonesList> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_goto_bounds() {
        assert_eq!(clamp_goto(0, 100), 0);
        assert_eq!(clamp_goto(99, 100), 99);
        assert_eq!(clamp_goto(100, 100), 99);
        assert_eq!(clamp_goto(u64::MAX, 100), 99);
        // Empty file: everything clamps to 0.
        assert_eq!(clamp_goto(0, 0), 0);
        assert_eq!(clamp_goto(50, 0), 0);
        // One-byte file.
        assert_eq!(clamp_goto(0, 1), 0);
        assert_eq!(clamp_goto(9, 1), 0);
    }

    #[test]
    fn view_data_defaults_match_cpp() {
        let vd = ViewData::default();
        assert_eq!(vd.view_start_offset, INVALID_OFFSET);
        assert_eq!(vd.view_size, INVALID_OFFSET);
        assert_eq!(vd.cursor_start_offset, INVALID_OFFSET);
        assert_eq!(vd.byte, 0);
    }

    /// Minimal viewer proving the trait's default impls compile and
    /// behave like the C++ base class.
    struct MockViewer {
        name: String,
        cursor: u64,
        file_size: u64,
    }

    impl ViewControl for MockViewer {
        fn name(&self) -> &str {
            &self.name
        }
        fn go_to(&mut self, offset: u64) -> bool {
            self.cursor = clamp_goto(offset, self.file_size);
            true
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
    }

    #[test]
    fn default_impls_match_cpp_base() {
        let mut v = MockViewer {
            name: "Buffer View".into(),
            cursor: 0,
            file_size: 10,
        };
        assert_eq!(v.name(), "Buffer View");
        assert!(v.update_keys());
        let mut vd = ViewData::default();
        assert!(!v.view_data(&mut vd, 0));
        assert!(!v.advance_start_view(5));
        assert!(!v.set_objects_highlighting_zones(ZonesList::new()));
        assert!(v.objects_highlighting_zones().is_none());
    }

    #[test]
    fn goto_clamps_via_helper() {
        let mut v = MockViewer {
            name: String::new(),
            cursor: 0,
            file_size: 100,
        };
        assert!(v.go_to(1000));
        assert_eq!(v.cursor, 99);
        assert!(v.go_to(42));
        assert_eq!(v.cursor, 42);
    }
}
