//! The viewer dialogs the `FileWindow` opens on behalf of the current
//! view (spec `00_APP §5.6`).
//!
//! C++ anchors: `FileWindow::ShowGoToDialog` / `ShowFindDialog` /
//! `ShowCopyDialog` (`FileWindow.cpp:85-105`) and
//! `GViewCore/src/View/BufferViewer/GoToDialog.cpp`.
//!
//! In the C++ each viewer owns its own dialogs; here a mounted control
//! raises `ShowGoTo` / `ShowFind` / `ShowCopy` and the window opens the
//! dialog, because `gview-viewers` must not depend on `gview-app`
//! (`§6.3`). The offset the dialog returns goes back to the control
//! through `ViewControl::go_to`.

use appcui::prelude::*;

/// C++ `Window("GoTo", "d:c,w:60,h:10", WindowFlags::ProcessReturn)`.
pub const GOTO_TITLE: &str = "GoTo";
/// C++ address-type caption when the plugin declared none
/// (`GoToDialog.cpp:15`).
pub const FILE_OFFSET: &str = "FileOffset";
/// C++ `"Invalid number (expecting ascii characters) for offset !"` /
/// `"Offset `%s` is not a valid UInt64 number !"`, merged: the Rust
/// parser cannot tell the two apart.
pub const ERR_INVALID_OFFSET: &str = "Offset is not a valid UInt64 number !";
/// C++ `"Offset `%llu` is bigger than the offset size: `%llu`"`.
pub const ERR_OFFSET_TOO_BIG: &str = "Offset is bigger than the object size";

/// C++ `Number::ToUInt64(text, NumberParseFlags::BaseAuto)`.
///
/// `0x`/`0X` is hexadecimal, `0b`/`0B` binary, `0o`/`0O` octal, and
/// everything else decimal; underscores and surrounding blanks are
/// ignored. An empty body, a bad digit or an overflow yields `None`
/// rather than panicking on hostile input.
#[must_use]
pub fn parse_offset(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    let (radix, body) = match trimmed.get(..2) {
        Some("0x" | "0X") => (16, trimmed.get(2..)?),
        Some("0b" | "0B") => (2, trimmed.get(2..)?),
        Some("0o" | "0O") => (8, trimmed.get(2..)?),
        _ => (10, trimmed),
    };
    let digits: String = body.chars().filter(|c| *c != '_').collect();
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(&digits, radix).ok()
}

/// C++ `GoToDialog` for the current view.
///
/// The address-type combo lists the plugin's translation methods
/// exactly as the C++ does. **Documented discrepancy:** the C++
/// converts the typed value with
/// `settings->offsetTranslateCallback->TranslateToFileOffset`; no Rust
/// viewer exposes that callback (`BufferViewerRequest` carries only the
/// method *names*), so the combo is informational and the value is
/// always read as a file offset.
#[ModalWindow(events = ButtonEvents + WindowEvents, response = u64)]
pub struct GoToDialog {
    offset: Handle<TextField>,
    kinds: Handle<ComboBox>,
    ok: Handle<Button>,
    cancel: Handle<Button>,
    /// Object size; the C++ rejects anything at or past it.
    max_size: u64,
    /// `false` keeps the error message boxes closed (headless).
    interactive: bool,
}

impl GoToDialog {
    /// The dialog over an object of `max_size` bytes, starting at
    /// `current` (shown as `0x…`, C++ `tmp.Format("0x%llX", …)`).
    ///
    /// `translation_methods` are the plugin's address-column names;
    /// an empty list shows [`FILE_OFFSET`].
    #[must_use]
    pub fn new(current: u64, max_size: u64, translation_methods: &[String], interactive: bool) -> Self {
        let mut win = Self {
            base: ModalWindow::new(GOTO_TITLE, layout!("a:c,w:60,h:10"), window::Flags::None),
            offset: Handle::None,
            kinds: Handle::None,
            ok: Handle::None,
            cancel: Handle::None,
            max_size,
            interactive,
        };
        win.add(Label::new("&Address", layout!("x:1,y:1,w:8")));
        win.add(Label::new("&Type", layout!("x:1,y:3,w:8")));
        win.offset = win.add(TextField::new(
            &format!("0x{current:X}"),
            layout!("x:10,y:1,w:46"),
            textfield::Flags::None,
        ));
        let mut kinds = ComboBox::new(layout!("x:10,y:3,w:46"), combobox::Flags::None);
        if translation_methods.is_empty() {
            kinds.add(FILE_OFFSET);
        } else {
            for method in translation_methods {
                kinds.add(method);
            }
        }
        if kinds.count() > 0 {
            kinds.set_index(0);
        }
        win.kinds = win.add(kinds);
        win.ok = win.add(Button::new("&OK", layout!("b:0,l:16,w:13")));
        win.cancel = win.add(Button::new("&Cancel", layout!("b:0,l:31,w:13")));
        win
    }

    /// The text currently in the address field.
    #[must_use]
    pub fn address_text(&self) -> String {
        let handle = self.offset;
        self.control(handle).map(|f| f.text().to_owned()).unwrap_or_default()
    }

    /// C++ `GoToDialog::Validate`: parse, bound-check, exit with the
    /// offset; a bad value shows the C++ error and keeps the dialog
    /// open.
    fn validate(&mut self) {
        let text = self.address_text();
        let Some(offset) = parse_offset(&text) else {
            self.report(ERR_INVALID_OFFSET);
            return;
        };
        if offset >= self.max_size {
            self.report(ERR_OFFSET_TOO_BIG);
            return;
        }
        self.exit_with(offset);
    }

    fn report(&self, message: &str) {
        if self.interactive {
            dialogs::error("Error", message);
        }
    }
}

impl ButtonEvents for GoToDialog {
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

impl WindowEvents for GoToDialog {
    /// C++ `Event::WindowAccept` (the `ProcessReturn` flag).
    fn on_accept(&mut self) {
        self.validate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_parse_in_every_base_the_cpp_accepts() {
        assert_eq!(parse_offset("0"), Some(0));
        assert_eq!(parse_offset("16"), Some(16));
        assert_eq!(parse_offset("0x10"), Some(0x10));
        assert_eq!(parse_offset("0X1f"), Some(0x1F));
        assert_eq!(parse_offset("0b1010"), Some(0b1010));
        assert_eq!(parse_offset("0o17"), Some(0o17));
        assert_eq!(parse_offset("  0x20  "), Some(0x20));
        assert_eq!(parse_offset("1_000"), Some(1000));
        assert_eq!(parse_offset(&format!("{}", u64::MAX)), Some(u64::MAX));

        // Hostile input never panics and never wraps.
        assert_eq!(parse_offset(""), None);
        assert_eq!(parse_offset("   "), None);
        assert_eq!(parse_offset("0x"), None);
        assert_eq!(parse_offset("zz"), None);
        assert_eq!(parse_offset("-1"), None);
        assert_eq!(parse_offset("18446744073709551616"), None, "u64 overflow");
        assert_eq!(parse_offset("0xFFFFFFFFFFFFFFFFF"), None, "u64 overflow");
        // Multi-byte characters must not slice mid-character.
        assert_eq!(parse_offset("é"), None);
        assert_eq!(parse_offset("0é"), None);
    }

    #[test]
    fn the_dialog_starts_at_the_cursor_and_bounds_check_the_result() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(80, 24, "Paint.Enable(false)\nPaint('goto')")
            .build()
            .expect("debug app");

        let mut dialog = GoToDialog::new(0x1F, 0x100, &[], false);
        assert_eq!(dialog.address_text(), "0x1F");
        // The address-type combo falls back to the C++ caption.
        let kinds = dialog.kinds;
        assert_eq!(dialog.control(kinds).map(ComboBox::count), Some(1));

        // Out of range: the dialog stays open (no response recorded).
        let offset = dialog.offset;
        if let Some(field) = dialog.control_mut(offset) {
            field.set_text("0x100");
        }
        dialog.validate();
        assert_eq!(dialog.address_text(), "0x100", "still editing");

        // A plugin's translation methods fill the combo instead.
        let named = GoToDialog::new(
            0,
            16,
            &[String::from("FileOffset"), String::from("RVA"), String::from("VA")],
            false,
        );
        let kinds = named.kinds;
        assert_eq!(named.control(kinds).map(ComboBox::count), Some(3));

        app.add_window(Window::new("host", layout!("d:f"), window::Flags::None));
        app.run();
    }
}
