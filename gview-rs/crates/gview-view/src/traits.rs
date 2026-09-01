//! Smart-viewer construction contract
//! (spec `02_SMART_VIEWERS_DEEP` §C, §H; C++ `WindowInterface`
//! `CreateViewer(Settings&)`, `FileWindow.cpp:125-161`).
//!
//! Each of the seven viewers defines a `Settings` type; the
//! `FileWindow` builds it, then hands it to the viewer **by value**,
//! so a settings object is consumed exactly once (the C++ analogue
//! moves the internal `SettingsData` pointer into the instance).
//!
//! Ownership: `FileWindow` owns the window's single [`Object`]; every
//! viewer gets a [`SharedObject`] clone (spec §H). The C++ code
//! shares a mutable `DataCache&` across viewers on the UI thread; in
//! Rust that aliasing requires a lock, hence `Arc<Mutex<_>>`.

use std::sync::{Arc, Mutex};

use gview_core::object::Object;

use crate::view_control::ViewControl;

/// Shared handle to the per-window [`Object`]
/// (C++ `Reference<Object>` from `unique_ptr`, spec §C).
pub type SharedObject = Arc<Mutex<Object>>;

/// Per-viewer construction settings
/// (C++ `<Viewer>::Settings`, one per viewer type).
///
/// The optional custom name mirrors the C++ template helper
/// `CreateViewer<T>(optional name)` which calls `SetName` before
/// dispatching (spec §C).
pub trait ViewerSettings {
    /// Custom tab name for the created viewer, if any.
    fn custom_name(&self) -> Option<&str>;

    /// Overrides the viewer tab name.
    fn set_custom_name(&mut self, name: &str);
}

/// A viewer constructible by the `FileWindow`
/// (C++ `CreateViewer` targets: Buffer, Text, Lexical, Image, Grid,
/// Container, Dissasm).
///
/// `settings` is taken **by value**: it is consumed exactly once and
/// cannot be reused for a second viewer (move semantics — the
/// "settings consumed once" contract of the matrix task).
pub trait SmartViewer: ViewControl {
    /// The viewer's settings type.
    type Settings: ViewerSettings + Default;

    /// Builds the viewer over the window's shared object, consuming
    /// `settings`.
    fn from_settings(object: SharedObject, settings: Self::Settings) -> Self
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::graphics::Surface;

    /// Deliberately **not** `Clone`: once moved into the viewer it is
    /// gone, proving the consumed-once contract holds at compile
    /// time.
    #[derive(Default)]
    struct MockSettings {
        name: Option<String>,
        columns: u32,
    }

    impl ViewerSettings for MockSettings {
        fn custom_name(&self) -> Option<&str> {
            self.name.as_deref()
        }
        fn set_custom_name(&mut self, name: &str) {
            self.name = Some(name.to_owned());
        }
    }

    struct MockViewer {
        object: SharedObject,
        name: String,
        columns: u32,
        cursor: u64,
    }

    impl ViewControl for MockViewer {
        fn name(&self) -> &str {
            &self.name
        }
        fn go_to(&mut self, offset: u64) -> bool {
            let size = self.object.lock().map_or(0, |o| o.data().size());
            self.cursor = crate::view_control::clamp_goto(offset, size);
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
        fn paint_cursor_information(&mut self, _surface: &mut Surface, _w: u32, _h: u32) {}
    }

    impl SmartViewer for MockViewer {
        type Settings = MockSettings;

        fn from_settings(object: SharedObject, settings: Self::Settings) -> Self {
            let name = settings.name.unwrap_or_else(|| "Buffer View".to_owned());
            Self {
                object,
                name,
                columns: settings.columns,
                cursor: 0,
            }
        }
    }

    fn shared_object(bytes: &[u8]) -> SharedObject {
        Arc::new(Mutex::new(Object::from_buffer(bytes, "mock", 0)))
    }

    #[test]
    fn mock_viewer_constructs_from_settings() {
        let mut settings = MockSettings {
            columns: 16,
            ..Default::default()
        };
        settings.set_custom_name("Hex");
        assert_eq!(settings.custom_name(), Some("Hex"));

        let object = shared_object(&[1, 2, 3, 4]);
        let viewer = MockViewer::from_settings(Arc::clone(&object), settings);
        // `settings` is moved: using it here would not compile.
        assert_eq!(viewer.name(), "Hex");
        assert_eq!(viewer.columns, 16);
    }

    #[test]
    fn default_settings_yield_default_name() {
        let viewer = MockViewer::from_settings(shared_object(&[]), MockSettings::default());
        assert_eq!(viewer.name(), "Buffer View");
    }

    #[test]
    fn viewers_share_one_object() {
        let object = shared_object(&[0xAA; 100]);
        let mut a = MockViewer::from_settings(Arc::clone(&object), MockSettings::default());
        let mut b = MockViewer::from_settings(Arc::clone(&object), MockSettings::default());
        // Both viewers observe the same data (single DataCache per
        // window, spec §C.2) and clamp against the same size.
        assert!(a.go_to(1000));
        assert!(b.go_to(50));
        assert_eq!(a.cursor, 99);
        assert_eq!(b.cursor, 50);
        // 1 owner in the test + 2 viewers.
        assert_eq!(Arc::strong_count(&object), 3);
    }
}
