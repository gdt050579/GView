//! Placeholder control for a viewer kind whose own task has not
//! landed yet (spec `00_APP §5.3.4`).
//!
//! This is a **defined, tested behaviour**, not a stub: when the
//! `FileWindow` mounts a `Grid` / `Lexical` / `Image` page before those
//! controls exist, the window still opens, `F4` still cycles the view
//! tabs, and the page states plainly what is missing. `mount_viewer`
//! drops the variant once all seven controls exist.

use appcui::prelude::*;

use gview_view::view_control::ViewControl;

use crate::cursor_info::{CursorSnapshot, SharedCursorInfo};

/// Text the control paints, `{name}` replaced by the viewer kind
/// (asserted verbatim by the E2E smoke test).
pub const UNAVAILABLE_SUFFIX: &str = " is not available in this build";

/// A view page for a viewer kind this build does not implement.
#[CustomControl(overwrite = OnPaint)]
pub struct UnavailableView {
    /// Viewer kind name, e.g. `"Grid"` — also the view tab name.
    name: String,
    /// The full painted line, built once at construction so
    /// `on_paint` allocates nothing (`00_APP §6.3`).
    message: String,
    /// The window's bottom-bar slot (`00_APP §5.3.5`).
    cursor_info: SharedCursorInfo,
}

impl UnavailableView {
    /// A page for viewer kind `name`, filling its parent.
    #[must_use]
    pub fn new(name: &str, cursor_info: SharedCursorInfo) -> Self {
        let view = Self {
            base: ControlBase::with_focus_overlay(layout!("d:f")),
            name: String::from(name),
            message: format!("{name}{UNAVAILABLE_SUFFIX}"),
            cursor_info,
        };
        // Nothing to navigate: publish an empty snapshot once so the
        // bottom bar shows this page's name rather than the previous
        // view's.
        view.cursor_info.write(CursorSnapshot::with_name(name));
        view
    }

    /// The exact line this control paints.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl OnPaint for UnavailableView {
    fn on_paint(&self, surface: &mut Surface, theme: &Theme) {
        surface.clear(Character::with_attributes(' ', theme.window.normal));
        surface.write_string(0, 0, &self.message, theme.window.normal, false);
    }
}

impl ViewControl for UnavailableView {
    fn name(&self) -> &str {
        &self.name
    }

    /// Nothing to go to: the C++ pure virtual has no meaningful
    /// behaviour without a viewer, so the request is refused.
    fn go_to(&mut self, _offset: u64) -> bool {
        false
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

    /// The bottom bar shows the same sentence, so the user sees why
    /// the page is empty from either half of the window.
    fn paint_cursor_information(&mut self, surface: &mut Surface, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        surface.write_string(0, 0, &self.message, CharAttribute::default(), false);
    }
}

#[cfg(test)]
mod tests {
    use super::{UnavailableView, UNAVAILABLE_SUFFIX};
    use crate::cursor_info::SharedCursorInfo;
    use appcui::graphics::Surface;
    use appcui::prelude::*;
    use gview_view::view_control::ViewControl;

    /// Reads `len` characters from `(x, y)` of a surface.
    fn read(surface: &Surface, x: u32, y: u32, len: usize) -> String {
        (0..len)
            .filter_map(|i| surface.char(x.saturating_add(i as u32).cast_signed(), y.cast_signed()).map(|c| c.code))
            .collect()
    }

    #[test]
    fn message_names_the_missing_viewer() {
        let view = UnavailableView::new("Grid", SharedCursorInfo::new());
        assert_eq!(view.message(), "Grid is not available in this build");
        assert_eq!(ViewControl::name(&view), "Grid");
        assert!(view.message().ends_with(UNAVAILABLE_SUFFIX));
    }

    #[test]
    fn construction_publishes_the_page_name_to_the_bottom_bar() {
        let info = SharedCursorInfo::new();
        let _view = UnavailableView::new("Lexical", info.clone());
        assert_eq!(info.read().name_str(), "Lexical");
        assert_eq!(info.read().offset, 0);
    }

    #[test]
    fn every_view_control_action_is_refused() {
        let mut view = UnavailableView::new("Image", SharedCursorInfo::new());
        assert!(!view.go_to(0x10));
        assert!(!view.select(0, 4));
        assert!(!view.show_goto_dialog());
        assert!(!view.show_find_dialog());
        assert!(!view.show_copy_dialog());
        // The base defaults still hold.
        assert!(view.update_keys());
        assert!(!view.advance_start_view(1));
        assert!(view.objects_highlighting_zones().is_none());
    }

    #[test]
    fn cursor_information_writes_the_same_sentence() {
        let mut view = UnavailableView::new("Grid", SharedCursorInfo::new());
        let mut surface = Surface::new(60, 1);
        view.paint_cursor_information(&mut surface, 60, 1);
        let expected = view.message().to_owned();
        assert_eq!(read(&surface, 0, 0, expected.len()), expected);
        // A zero-sized bar is a no-op, never a panic.
        let mut empty = Surface::new(1, 1);
        view.paint_cursor_information(&mut empty, 0, 0);
        assert_eq!(read(&empty, 0, 0, 1), " ", "a zero-sized bar paints nothing");
    }

    /// The control's own `on_paint` puts the exact sentence on the
    /// surface at (0, 0).
    #[test]
    fn on_paint_writes_the_exact_message() {
        let view = UnavailableView::new("Grid", SharedCursorInfo::new());
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(60, 5);
        OnPaint::on_paint(&view, &mut surface, &theme);
        let expected = view.message().to_owned();
        assert_eq!(read(&surface, 0, 0, expected.len()), expected);
        // The rest of the page is cleared, not left as garbage.
        assert_eq!(read(&surface, 0, 1, 10), "          ");
    }

    #[test]
    fn debug_app_paints_the_message_on_screen() {
        // The hash pins the rendered frame; the message assertion above
        // pins the text itself.
        let script = "
            Paint.Enable(false)
            Paint('Grid page states it is unavailable')
            CheckHash(0xEE121D19FCF47385)
        ";
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(60, 10, script).build().expect("debug app");
        let mut window = Window::new("Test", layout!("a:c,w:50,h:8"), window::Flags::None);
        window.add(UnavailableView::new("Grid", SharedCursorInfo::new()));
        app.add_window(window);
        app.run();
    }
}
