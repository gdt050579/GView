//! Cursor-information hand-off between a mounted viewer and the
//! window's bottom bar (spec `00_APP §5.3.5`).
//!
//! C++ `FileWindow`'s `CursorInformation` control paints by calling
//! `win->GetCurrentView()->PaintCursorInformation(...)` — it reaches
//! into the live viewer (`FileWindow.cpp:26-34`). `AppCUI-rs` controls
//! are siblings in a `Tab` and cannot borrow one another, so each
//! mounted control instead *publishes* a fixed-size snapshot after
//! every navigation and paint, and the bottom bar reads it.
//!
//! [`CursorSnapshot`] is `Copy` and stores the view name in an inline
//! `[u8; NAME_CAPACITY]` buffer: writing and reading it allocates
//! nothing, which keeps both sides inside the zero-allocation rule of
//! `00_APP §6.3`.

use std::rc::Rc;
use std::sync::{Mutex, PoisonError};

/// Inline capacity of [`CursorSnapshot::name`], sized for the longest
/// viewer tab name plus a plugin's custom name (C++
/// `CreateViewer<T>(name)`, e.g. `"StreamView"`).
pub const NAME_CAPACITY: usize = 32;

/// What one mounted viewer publishes for the bottom bar
/// (C++ `PaintCursorInformation` inputs: the cursor position, the
/// numeric base it is shown in, and the current selection).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorSnapshot {
    /// Cursor offset (C++ `cursor.GetCurrentPosition()`).
    pub offset: u64,
    /// First offset of selection 0, when one is active.
    pub selection_start: u64,
    /// Last offset of selection 0, when one is active.
    pub selection_end: u64,
    /// Whether `selection_start` / `selection_end` are meaningful
    /// (C++ `selection.GetSelection(0, start, end)` returning `false`
    /// paints `"NO Selection"`).
    pub has_selection: bool,
    /// Numeric base the position is shown in (C++
    /// `cursor.GetBase()`: 8, 10 or 16).
    pub base: u8,
    /// Size of the object, for the `%3u%%` progress field.
    pub size: u64,
    /// Inline UTF-8 view name; only the first [`Self::name_len`] bytes
    /// are meaningful.
    pub name: [u8; NAME_CAPACITY],
    /// Valid byte count of [`Self::name`].
    pub name_len: u8,
}

impl Default for CursorSnapshot {
    /// An empty snapshot: offset 0, no selection, hex base — what the
    /// bar shows before any viewer has published.
    fn default() -> Self {
        Self {
            offset: 0,
            selection_start: 0,
            selection_end: 0,
            has_selection: false,
            base: 16,
            size: 0,
            name: [0; NAME_CAPACITY],
            name_len: 0,
        }
    }
}

impl CursorSnapshot {
    /// A snapshot for `name`, truncated to [`NAME_CAPACITY`] bytes on
    /// a UTF-8 character boundary so [`Self::name_str`] never fails.
    #[must_use]
    pub fn with_name(name: &str) -> Self {
        let mut snapshot = Self::default();
        snapshot.set_name(name);
        snapshot
    }

    /// Replaces the inline name, truncating on a character boundary.
    /// Allocation-free: only the inline buffer is touched.
    pub fn set_name(&mut self, name: &str) {
        let mut end = name.len().min(NAME_CAPACITY);
        while end > 0 && !name.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        let bytes = name.as_bytes().get(..end).unwrap_or(&[]);
        self.name = [0; NAME_CAPACITY];
        for (slot, byte) in self.name.iter_mut().zip(bytes.iter()) {
            *slot = *byte;
        }
        self.name_len = end as u8;
    }

    /// The view name as a `&str` (empty when none was published).
    #[must_use]
    pub fn name_str(&self) -> &str {
        let len = usize::from(self.name_len).min(NAME_CAPACITY);
        self.name
            .get(..len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }

    /// Selection length in bytes (C++ `(end - start) + 1`), or 0 when
    /// nothing is selected.
    #[must_use]
    pub const fn selection_len(&self) -> u64 {
        if self.has_selection {
            self.selection_end.saturating_sub(self.selection_start).saturating_add(1)
        } else {
            0
        }
    }

    /// C++ `PrintCursorPosInfo` progress field: `(position + 1) * 100 /
    /// size`, or `None` for an empty object (which paints `"----"`).
    #[must_use]
    pub const fn percent(&self) -> Option<u64> {
        match self.offset.saturating_add(1).saturating_mul(100).checked_div(self.size) {
            Some(percent) => Some(percent),
            // `size == 0`: the C++ paints `"----"` instead.
            None => None,
        }
    }
}

/// The slot a mounted viewer writes and the bottom bar reads
/// (`00_APP §0.3 D4`: single UI thread, `Rc<Mutex<_>>` so a poisoned
/// lock degrades instead of panicking).
#[derive(Clone, Debug, Default)]
pub struct SharedCursorInfo {
    slot: Rc<Mutex<CursorSnapshot>>,
}

impl SharedCursorInfo {
    /// A slot holding the default snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes `snapshot` (called from `on_key_pressed` / `on_paint`
    /// of the mounted control). Never allocates, never panics.
    pub fn write(&self, snapshot: CursorSnapshot) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = snapshot;
    }

    /// Reads the current snapshot (called from the bottom bar's
    /// `on_paint`).
    #[must_use]
    pub fn read(&self) -> CursorSnapshot {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `true` when both handles refer to the same slot.
    #[must_use]
    pub fn is_same_slot(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.slot, &other.slot)
    }
}

#[cfg(test)]
mod tests {
    use super::{CursorSnapshot, SharedCursorInfo, NAME_CAPACITY};

    #[test]
    fn snapshot_is_copy_and_defaults_to_hex_without_selection() {
        let snapshot = CursorSnapshot::default();
        let copy = snapshot;
        // Both usable: `Copy`, not moved.
        assert_eq!(snapshot, copy);
        assert_eq!(snapshot.base, 16);
        assert!(!snapshot.has_selection);
        assert_eq!(snapshot.selection_len(), 0);
        assert_eq!(snapshot.name_str(), "");
        assert_eq!(snapshot.percent(), None, "an empty object shows ----");
    }

    #[test]
    fn name_round_trips_and_truncates_on_a_char_boundary() {
        let snapshot = CursorSnapshot::with_name("Buffer");
        assert_eq!(snapshot.name_str(), "Buffer");
        assert_eq!(snapshot.name_len, 6);

        // Exactly at capacity.
        let exact = "x".repeat(NAME_CAPACITY);
        assert_eq!(CursorSnapshot::with_name(&exact).name_str(), exact);

        // Past capacity: truncated, still valid UTF-8.
        let long = "y".repeat(NAME_CAPACITY + 10);
        let truncated = CursorSnapshot::with_name(&long);
        assert_eq!(truncated.name_str().len(), NAME_CAPACITY);

        // A multi-byte character straddling the cap is dropped whole.
        let wide = format!("{}é", "z".repeat(NAME_CAPACITY - 1));
        let cut = CursorSnapshot::with_name(&wide);
        assert_eq!(cut.name_str(), "z".repeat(NAME_CAPACITY - 1));

        // Re-setting a shorter name clears the old tail.
        let mut reused = CursorSnapshot::with_name("LongViewName");
        reused.set_name("Hex");
        assert_eq!(reused.name_str(), "Hex");
    }

    #[test]
    fn selection_and_percent_match_the_cpp_fields() {
        let mut snapshot = CursorSnapshot::with_name("Buffer");
        snapshot.offset = 0x0F;
        snapshot.size = 0x20;
        snapshot.has_selection = true;
        snapshot.selection_start = 0x10;
        snapshot.selection_end = 0x1F;
        // C++ `(end - start) + 1`.
        assert_eq!(snapshot.selection_len(), 0x10);
        // C++ `(position + 1) * 100 / size`.
        assert_eq!(snapshot.percent(), Some(50));

        // An inverted range never underflows.
        snapshot.selection_start = 0x20;
        snapshot.selection_end = 0x10;
        assert_eq!(snapshot.selection_len(), 1);
    }

    #[test]
    fn shared_slot_publishes_between_clones() {
        let writer = SharedCursorInfo::new();
        let reader = writer.clone();
        assert!(writer.is_same_slot(&reader));
        assert_eq!(reader.read(), CursorSnapshot::default());

        let mut snapshot = CursorSnapshot::with_name("Dissasm");
        snapshot.offset = 0x1234;
        writer.write(snapshot);
        assert_eq!(reader.read().offset, 0x1234);
        assert_eq!(reader.read().name_str(), "Dissasm");

        // Independent slots do not observe each other.
        let other = SharedCursorInfo::new();
        assert!(!writer.is_same_slot(&other));
        assert_eq!(other.read().offset, 0);
    }
}
