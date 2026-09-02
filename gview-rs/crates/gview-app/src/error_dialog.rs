//! The accumulated-errors dialog (spec `00_APP §5.5`).
//!
//! C++ anchor: `GViewCore/src/App/ErrorDialog.cpp` (whole file) and
//! `Instance::ShowErrors` (`Instance.cpp:448-455`), which opens the
//! dialog only when the list is non-empty and clears the list
//! afterwards.
//!
//! The C++ window is
//! `Window("Errors", "d:c,w:80,h:16", WindowFlags::ErrorWindow)`
//! holding one single-column `ListView`
//! (`{ "a:l,w:255" }`, `HideSearchBar | HideColumns`) that is filled
//! with, in order:
//!
//! ```text
//! Errors   : <n>
//! Warnings : <n>
//! Errors            <- category, only when n > 0
//!   …each error…
//! Warnings          <- category, only when n > 0
//!   …each warning…
//! ```
//!
//! and a single `&Close` button (`d:b,w:10`) whose press exits with
//! `Dialogs::Result::Ok`.
//!
//! **Documented discrepancy** (`00_APP §5.5` vs. the C++): the spec
//! sketches a two-column `Severity` / `Message` list and an `OK`
//! button. The C++ is authoritative for behaviour (`CLAUDE.md §3`), so
//! the rendering below follows `ErrorDialog.cpp`: the severity is
//! expressed by the category rows, and the button is `&Close`. The
//! rows are still modelled as `(Severity, message)` pairs
//! ([`ErrorEntry`]), which is what the spec asks the caller to pass.

use appcui::prelude::*;

/// C++ `Window("Errors", …)`.
pub const ERROR_DIALOG_TITLE: &str = "Errors";
/// C++ `Factory::Button::Create(this, "&Close", "d:b,w:10")`.
pub const CLOSE_CAPTION: &str = "&Close";
/// C++ `lv->AddItem(tmp.Format("Errors   : %u", …))` — note the
/// three spaces that align it with the warnings row.
pub const ERRORS_COUNT_PREFIX: &str = "Errors   : ";
/// C++ `lv->AddItem(tmp.Format("Warnings : %u", …))`.
pub const WARNINGS_COUNT_PREFIX: &str = "Warnings : ";
/// C++ category row above the errors.
pub const ERRORS_CATEGORY: &str = "Errors";
/// C++ category row above the warnings.
pub const WARNINGS_CATEGORY: &str = "Warnings";

/// Which of the two C++ `ErrorList` buckets an entry belongs to
/// (`AddError` / `AddWarning`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Severity {
    /// `ErrorList::AddError`.
    #[default]
    Error,
    /// `ErrorList::AddWarning`.
    Warning,
}

/// One accumulated message (C++ `ErrorList` entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorEntry {
    /// Bucket the message belongs to.
    pub severity: Severity,
    /// The message as it is shown.
    pub message: String,
}

impl ErrorEntry {
    /// An `AddError` entry.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
        }
    }

    /// An `AddWarning` entry.
    #[must_use]
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }
}

/// One rendered row of the dialog's list.
///
/// The C++ list has a single hidden column and mixes plain rows with
/// `ListViewItem::Type::Category` headers; `AppCUI-rs` has no per-item
/// category type, so a category row is rendered as its own item and
/// flagged here.
pub struct ErrorRow {
    text: String,
    category: bool,
}

impl ErrorRow {
    /// A plain message row.
    #[must_use]
    pub const fn message(text: String) -> Self {
        Self { text, category: false }
    }

    /// A category header row (C++ `SetType(Category)`).
    #[must_use]
    pub const fn category(text: String) -> Self {
        Self { text, category: true }
    }

    /// The rendered text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// `true` for the `Errors` / `Warnings` header rows.
    #[must_use]
    pub const fn is_category(&self) -> bool {
        self.category
    }
}

impl ListItem for ErrorRow {
    fn columns_count() -> u16 {
        1
    }

    /// C++ `{ "a:l,w:255" }` with `HideColumns`, so the caption is
    /// never painted.
    fn column(_index: u16) -> Column {
        Column::new("", 255, TextAlignment::Left)
    }

    fn render_method(&self, column_index: u16) -> Option<RenderMethod<'_>> {
        (column_index == 0).then(|| RenderMethod::Text(&self.text))
    }

    fn matches(&self, text: &str) -> bool {
        self.text.contains(text)
    }
}

/// Builds the C++ row sequence for `errors` (counts, then a category
/// per non-empty bucket).
///
/// Exposed so the row order can be asserted without a terminal.
#[must_use]
pub fn rows(errors: &[ErrorEntry]) -> Vec<ErrorRow> {
    let error_count = errors.iter().filter(|e| e.severity == Severity::Error).count();
    let warning_count = errors.len().saturating_sub(error_count);
    let mut rows = Vec::with_capacity(errors.len().saturating_add(4));
    rows.push(ErrorRow::message(format!("{ERRORS_COUNT_PREFIX}{error_count}")));
    rows.push(ErrorRow::message(format!("{WARNINGS_COUNT_PREFIX}{warning_count}")));
    if error_count > 0 {
        rows.push(ErrorRow::category(String::from(ERRORS_CATEGORY)));
        rows.extend(
            errors
                .iter()
                .filter(|e| e.severity == Severity::Error)
                .map(|e| ErrorRow::message(e.message.clone())),
        );
    }
    if warning_count > 0 {
        rows.push(ErrorRow::category(String::from(WARNINGS_CATEGORY)));
        rows.extend(
            errors
                .iter()
                .filter(|e| e.severity == Severity::Warning)
                .map(|e| ErrorRow::message(e.message.clone())),
        );
    }
    rows
}

/// What the dialog returns: the C++ `Exit(Dialogs::Result::Ok)`
/// carries no payload, so this is the unit response the spec sketches
/// as `()` (the `#[ModalWindow]` macro needs a named type).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dismissed;

/// C++ `ErrorDialog`.
#[ModalWindow(events = ButtonEvents + WindowEvents, response = Dismissed)]
pub struct ErrorDialog {
    list: Handle<ListView<ErrorRow>>,
    close: Handle<Button>,
}

impl ErrorDialog {
    /// Builds the dialog over `errors` (C++ ctor).
    #[must_use]
    pub fn new(errors: &[ErrorEntry]) -> Self {
        let rows = rows(errors);
        let mut win = Self {
            base: ModalWindow::new(ERROR_DIALOG_TITLE, layout!("a:c,w:80,h:16"), window::Flags::None),
            list: Handle::None,
            close: Handle::None,
        };
        let mut list: ListView<ErrorRow> =
            ListView::with_capacity(rows.len().max(1), layout!("l:1,t:1,r:1,b:3"), listview::Flags::ScrollBars);
        for row in rows {
            list.add(row);
        }
        win.list = win.add(list);
        win.close = win.add(Button::new(CLOSE_CAPTION, layout!("a:b,w:10,h:1")));
        win
    }

    /// The row list, for tests.
    #[must_use]
    pub const fn list(&self) -> Handle<ListView<ErrorRow>> {
        self.list
    }
}

impl ButtonEvents for ErrorDialog {
    fn on_pressed(&mut self, handle: Handle<Button>) -> EventProcessStatus {
        if handle == self.close {
            // C++ `Exit(Dialogs::Result::Ok)`.
            self.exit_with(Dismissed);
            EventProcessStatus::Processed
        } else {
            EventProcessStatus::Ignored
        }
    }
}

impl WindowEvents for ErrorDialog {
    /// `Enter` on the window is the same as pressing `&Close`.
    fn on_accept(&mut self) {
        self.exit_with(Dismissed);
    }
}

/// C++ `Instance::ShowErrors`: opens the dialog only when there is
/// something to show.
///
/// Returns `true` when the dialog was opened (the caller clears its
/// list afterwards, as the C++ does).
#[must_use]
pub fn show(errors: &[ErrorEntry]) -> bool {
    if errors.is_empty() {
        return false;
    }
    ErrorDialog::new(errors).show();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn texts(entries: &[ErrorEntry]) -> Vec<String> {
        rows(entries).iter().map(|row| row.text().to_owned()).collect()
    }

    #[test]
    fn rows_follow_the_cpp_order_and_captions() {
        // Both buckets: counts, then each category with its messages.
        let entries = [
            ErrorEntry::error("Fail to open file: a.bin"),
            ErrorEntry::warning("Cache size clamped"),
            ErrorEntry::error("Failed to populate file window!"),
        ];
        assert_eq!(
            texts(&entries),
            [
                "Errors   : 2",
                "Warnings : 1",
                "Errors",
                "Fail to open file: a.bin",
                "Failed to populate file window!",
                "Warnings",
                "Cache size clamped",
            ]
        );
        // Only the two header rows are categories.
        let built = rows(&entries);
        let categories: Vec<usize> = built
            .iter()
            .enumerate()
            .filter_map(|(i, row)| row.is_category().then_some(i))
            .collect();
        assert_eq!(categories, [2, 5]);

        // An empty bucket contributes no category row.
        assert_eq!(
            texts(&[ErrorEntry::warning("only a warning")]),
            ["Errors   : 0", "Warnings : 1", "Warnings", "only a warning"]
        );
        assert_eq!(
            texts(&[ErrorEntry::error("only an error")]),
            ["Errors   : 1", "Warnings : 0", "Errors", "only an error"]
        );
        // The counts are shown even with nothing to list.
        assert_eq!(texts(&[]), ["Errors   : 0", "Warnings : 0"]);
    }

    #[test]
    fn a_row_renders_its_single_column_only() {
        assert_eq!(ErrorRow::columns_count(), 1);
        assert_eq!(ErrorRow::column(0).width(), 255);
        assert_eq!(ErrorRow::column(0).alignment(), TextAlignment::Left);

        let row = ErrorRow::message(String::from("Fail to open file: a.bin"));
        assert!(!row.is_category());
        assert!(matches!(row.render_method(0), Some(RenderMethod::Text(_))));
        assert!(row.render_method(1).is_none());
        assert!(row.matches("a.bin"));
        assert!(!row.matches("b.bin"));
        assert!(ErrorRow::category(String::from(ERRORS_CATEGORY)).is_category());
    }

    /// C++ `ShowErrors`: an empty list never opens a window.
    #[test]
    fn an_empty_list_opens_nothing() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(60, 20, "Paint.Enable(false)\nPaint('no dialog')")
            .build()
            .expect("debug app");
        // `show` must not touch the runtime when there is nothing to
        // report, so calling it outside any window is safe.
        assert!(!show(&[]));
        app.add_window(Window::new("host", layout!("d:f"), window::Flags::None));
        app.run();
    }

    /// The dialog opens with the two entries and `Enter` closes it.
    #[test]
    fn two_entries_are_listed_and_enter_closes_the_dialog() {
        #[Window(events = WindowEvents)]
        struct Host {
            shown: Arc<AtomicBool>,
            opened: Arc<AtomicBool>,
            rows: Arc<AtomicUsize>,
            done: Arc<AtomicUsize>,
        }
        impl WindowEvents for Host {
            fn on_activate(&mut self) {
                if self.done.fetch_add(1, Ordering::SeqCst) > 0 {
                    return;
                }
                self.shown.store(true, Ordering::SeqCst);
                let entries = [
                    ErrorEntry::error("Fail to open file: a.bin"),
                    ErrorEntry::warning("Cache size clamped"),
                ];
                let dialog = ErrorDialog::new(&entries);
                let list = dialog.list();
                self.rows.store(
                    dialog.control(list).map_or(0, ListView::items_count),
                    Ordering::SeqCst,
                );
                self.opened.store(show(&entries), Ordering::SeqCst);
            }
        }

        let script = "
            Paint.Enable(false)
            Paint('error dialog')
            Key.Pressed(Enter)
            Paint('closed')
        ";
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 30, script).build().expect("debug app");
        let shown = Arc::new(AtomicBool::new(false));
        let opened = Arc::new(AtomicBool::new(false));
        let rows_count = Arc::new(AtomicUsize::new(0));
        app.add_window(Host {
            base: Window::new("host", layout!("d:f"), window::Flags::None),
            shown: Arc::clone(&shown),
            opened: Arc::clone(&opened),
            rows: Arc::clone(&rows_count),
            done: Arc::new(AtomicUsize::new(0)),
        });
        app.run();
        assert!(shown.load(Ordering::SeqCst), "the host must have run");
        assert!(opened.load(Ordering::SeqCst), "a non-empty list opens the dialog");
        // Counts (2) + one category and message per bucket (4).
        assert_eq!(rows_count.load(Ordering::SeqCst), 6);
    }
}
