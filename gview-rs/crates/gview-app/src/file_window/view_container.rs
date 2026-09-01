//! View container for the `view` tab's smart viewers.
//!
//! C++ anchor: `FileWindow.cpp:125-182` — the seven `CreateViewer`
//! overloads, `GetCurrentView`, `GetViewsCount`, `GetViewByIndex`,
//! `SetViewByIndex` (spec `02_SMART_VIEWERS_DEEP` §B, §C). Each C++
//! overload calls
//! `view->CreateChildControl<Viewer::Instance>(Reference<Object>, &settings)`;
//! the Rust port expresses all seven with one generic
//! [`ViewContainer::create_viewer`] over [`SmartViewer`], handing
//! every viewer a clone of the window's single [`SharedObject`]
//! (§C.2: one `DataCache` per window). Attachment of the concrete
//! `AppCUI` controls to the tab pages is composed by the
//! `file-window-shell` task.

use gview_view::traits::{SharedObject, SmartViewer};
use gview_view::view_control::ViewControl;

use super::layout::MAX_TAB_PAGES;

/// Ordered collection of the window's viewers plus the active index
/// (C++ `view` tab children + current tab page).
pub struct ViewContainer {
    object: SharedObject,
    viewers: Vec<Box<dyn ViewControl>>,
    current: usize,
}

impl ViewContainer {
    /// Empty container over the window's shared object.
    #[must_use]
    pub const fn new(object: SharedObject) -> Self {
        Self {
            object,
            viewers: Vec::new(),
            current: 0,
        }
    }

    /// The shared per-window object every viewer receives.
    #[must_use]
    pub const fn object(&self) -> &SharedObject {
        &self.object
    }

    /// Creates a viewer of type `V`, consuming its settings
    /// (C++ `CreateViewer(Settings&)` — any of the seven overloads).
    ///
    /// Fails when the tab is full (C++ tab page limit of
    /// [`MAX_TAB_PAGES`], `FileWindow.cpp:49`).
    pub fn create_viewer<V>(&mut self, settings: V::Settings) -> bool
    where
        V: SmartViewer + 'static,
    {
        if self.viewers.len() >= MAX_TAB_PAGES as usize {
            return false;
        }
        let viewer = V::from_settings(SharedObject::clone(&self.object), settings);
        self.viewers.push(Box::new(viewer));
        true
    }

    /// Number of viewers created (C++ `GetViewsCount`).
    #[must_use]
    pub const fn views_count(&self) -> usize {
        self.viewers.len()
    }

    /// Index of the active viewer (C++ current tab page).
    #[must_use]
    pub const fn current_index(&self) -> usize {
        self.current
    }

    /// The active viewer (C++ `GetCurrentView`).
    #[must_use]
    pub fn current_view(&self) -> Option<&dyn ViewControl> {
        self.viewers.get(self.current).map(AsRef::as_ref)
    }

    /// Mutable access to the active viewer.
    pub fn current_view_mut(&mut self) -> Option<&mut (dyn ViewControl + 'static)> {
        self.viewers.get_mut(self.current).map(AsMut::as_mut)
    }

    /// Viewer by creation index (C++ `GetViewByIndex`).
    #[must_use]
    pub fn view_by_index(&self, index: usize) -> Option<&dyn ViewControl> {
        self.viewers.get(index).map(AsRef::as_ref)
    }

    /// Switches the active viewer (C++ `SetViewByIndex`,
    /// `FileWindow.cpp:178-182`: out-of-range is rejected).
    pub fn set_view_by_index(&mut self, index: usize) -> bool {
        if index >= self.viewers.len() {
            return false;
        }
        self.current = index;
        true
    }

    /// Switches to the next viewer, wrapping (used by F4 view
    /// cycling in the event-routing task).
    pub fn next_view(&mut self) -> bool {
        if self.viewers.is_empty() {
            return false;
        }
        self.current = self
            .current
            .saturating_add(1)
            .checked_rem(self.viewers.len())
            .unwrap_or(0);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::graphics::Surface;
    use gview_core::object::Object;
    use gview_view::traits::ViewerSettings;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockSettings {
        name: Option<String>,
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
        // Held (not read) to prove each viewer keeps an Arc clone.
        _object: SharedObject,
        name: String,
    }

    impl ViewControl for MockViewer {
        fn name(&self) -> &str {
            &self.name
        }
        fn go_to(&mut self, _offset: u64) -> bool {
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
            let name = settings.name.unwrap_or_else(|| "Mock".to_owned());
            Self {
                _object: object,
                name,
            }
        }
    }

    fn container() -> ViewContainer {
        let object = Arc::new(Mutex::new(Object::from_buffer(&[1, 2, 3], "obj", 0)));
        ViewContainer::new(object)
    }

    fn named(name: &str) -> MockSettings {
        MockSettings {
            name: Some(name.to_owned()),
        }
    }

    #[test]
    fn mock_plugin_adds_two_viewers_and_switches() {
        let mut vc = container();
        assert!(vc.create_viewer::<MockViewer>(named("Buffer View")));
        assert!(vc.create_viewer::<MockViewer>(named("Text View")));
        assert_eq!(vc.views_count(), 2);
        // Initial view is index 0.
        assert_eq!(
            vc.current_view().map(ViewControl::name),
            Some("Buffer View")
        );
        // SetViewByIndex(1) switches.
        assert!(vc.set_view_by_index(1));
        assert_eq!(vc.current_index(), 1);
        assert_eq!(vc.current_view().map(ViewControl::name), Some("Text View"));
        // Out of range rejected, current unchanged (C++ CHECK).
        assert!(!vc.set_view_by_index(2));
        assert_eq!(vc.current_index(), 1);
        // By-index access.
        assert_eq!(
            vc.view_by_index(0).map(ViewControl::name),
            Some("Buffer View")
        );
        assert!(vc.view_by_index(9).is_none());
    }

    #[test]
    fn all_viewers_share_one_object() {
        let mut vc = container();
        let baseline = Arc::strong_count(vc.object());
        vc.create_viewer::<MockViewer>(MockSettings::default());
        vc.create_viewer::<MockViewer>(MockSettings::default());
        vc.create_viewer::<MockViewer>(MockSettings::default());
        // Each viewer holds a clone of the same Arc.
        assert_eq!(Arc::strong_count(vc.object()), baseline + 3);
    }

    #[test]
    fn tab_page_limit_is_sixteen() {
        let mut vc = container();
        for _ in 0..MAX_TAB_PAGES {
            assert!(vc.create_viewer::<MockViewer>(MockSettings::default()));
        }
        assert!(!vc.create_viewer::<MockViewer>(MockSettings::default()));
        assert_eq!(vc.views_count(), MAX_TAB_PAGES as usize);
    }

    #[test]
    fn next_view_wraps() {
        let mut vc = container();
        assert!(!vc.next_view()); // empty container
        vc.create_viewer::<MockViewer>(named("a"));
        vc.create_viewer::<MockViewer>(named("b"));
        assert!(vc.next_view());
        assert_eq!(vc.current_index(), 1);
        assert!(vc.next_view());
        assert_eq!(vc.current_index(), 0);
    }
}
