//! `BufferViewer` layout and viewport math
//! (C++ `BufferViewer.hpp` `Layout` struct, `Instance::UpdateViewSizes`
//! `Instance.cpp:617-653`, `MoveTo`/`MoveScrollTo`; spec
//! `02_VIEWER_BUFFER` §2.2, §3).
//!
//! All file offsets are `u64` (multi-gigabyte files); every
//! computation uses checked/saturating arithmetic.

use gview_core::selection::Selection;

/// Byte rendering format (C++ `CharacterFormatMode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CharacterFormatMode {
    /// 2 characters per byte.
    Hex,
    /// 3 characters per byte.
    Octal,
    /// 4 characters per byte (sign).
    SignedDecimal,
    /// 3 characters per byte.
    UnsignedDecimal,
}

impl CharacterFormatMode {
    /// Character cells one byte occupies
    /// (C++ `characterFormatModeSize[] = {2, 3, 4, 3}`).
    #[must_use]
    pub const fn size(self) -> u32 {
        match self {
            Self::Hex => 2,
            Self::Octal | Self::UnsignedDecimal => 3,
            Self::SignedDecimal => 4,
        }
    }
}

/// Column widths and screen x-positions (C++ `Layout`, spec §2.2).
#[derive(Clone, Copy, Debug)]
pub struct BufferLayout {
    /// Numeric format of the data columns.
    pub char_format_mode: CharacterFormatMode,
    /// Data columns per row: 0 = full-screen ASCII, else 8/16/32.
    pub nr_cols: u32,
    /// Hex digits of the address column (0 hides it).
    pub line_address_size: u32,
    /// Width of the zone-name column (0 hides it).
    pub line_name_size: u32,
    /// Bytes represented per row (derived).
    pub characters_per_line: u32,
    /// Rows available for data (height minus the header row).
    pub visible_rows: u32,
    /// X of the zone-name column.
    pub x_name: u32,
    /// X of the address column.
    pub x_address: u32,
    /// X of the numeric (hex/oct/dec) band.
    pub x_numbers: u32,
    /// X of the text band.
    pub x_text: u32,
}

impl Default for BufferLayout {
    /// Hex, 16 columns, 8-digit address, no zone-name column.
    fn default() -> Self {
        Self {
            char_format_mode: CharacterFormatMode::Hex,
            nr_cols: 16,
            line_address_size: 8,
            line_name_size: 0,
            characters_per_line: 16,
            visible_rows: 1,
            x_name: 0,
            x_address: 0,
            x_numbers: 0,
            x_text: 0,
        }
    }
}

impl BufferLayout {
    /// Recomputes derived fields for a `width × height` control
    /// (C++ `UpdateViewSizes`, `Instance.cpp:617-653`).
    pub fn update_view_sizes(&mut self, width: u32, height: u32) {
        let mut sz = self.line_name_size;
        self.x_name = 0;

        if self.line_address_size > 0 {
            self.x_address = sz;
            if sz > 0 {
                // one extra space between name and address
                sz = sz.saturating_add(self.line_address_size).saturating_add(1);
                self.x_address = self.x_address.saturating_add(1);
            } else {
                sz = sz.saturating_add(self.line_address_size);
            }
        }

        if sz > 0 {
            sz = sz.saturating_add(3); // gap before the data columns
        }
        self.x_numbers = sz;
        if self.nr_cols == 0 {
            // Full-screen ASCII.
            self.x_text = sz;
            if sz.saturating_add(1) < width {
                self.characters_per_line = width.saturating_sub(sz.saturating_add(1));
            } else {
                self.characters_per_line = 1;
            }
        } else {
            let byte_width = self.char_format_mode.size().saturating_add(1);
            self.x_text = sz
                .saturating_add(self.nr_cols.saturating_mul(byte_width))
                .saturating_add(3);
            self.characters_per_line = self.nr_cols;
        }

        self.visible_rows = height.saturating_sub(1).max(1);
    }

    /// Bytes visible in the viewport
    /// (`charactersPerLine * visibleRows`, spec §3).
    #[must_use]
    pub const fn visible_bytes(&self) -> u64 {
        // u32 × u32 always fits in u64.
        (self.characters_per_line as u64).saturating_mul(self.visible_rows as u64)
    }

    /// File offset of the first byte on `row`
    /// (`lineOffset(row) = charactersPerLine * row + startView`).
    #[must_use]
    pub const fn line_offset(&self, row: u32, start_view: u64) -> u64 {
        (self.characters_per_line as u64)
            .wrapping_mul(row as u64)
            .wrapping_add(start_view)
    }
}

/// Viewport origin and cursor position (C++ `Cursor`, spec §2.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferCursor {
    /// First visible byte offset.
    pub start_view: u64,
    /// Cursor byte offset, `0..file_size-1`.
    pub current_pos: u64,
}

/// Moves the cursor to `offset`, scrolling and updating the selection
/// as needed (C++ `MoveTo`, spec §3.1 — ported line by line).
pub fn move_to(
    cursor: &mut BufferCursor,
    selection: &mut Selection,
    offset: u64,
    select: bool,
    file_size: u64,
    visible_bytes: u64,
) {
    if file_size == 0 {
        return;
    }
    let offset = u64::min(offset, file_size.saturating_sub(1));

    if offset == cursor.current_pos {
        cursor.start_view = offset;
        return;
    }

    let selection_index = if select {
        selection.begin_selection(cursor.current_pos)
    } else {
        None
    };

    if offset >= cursor.start_view && offset < cursor.start_view.saturating_add(visible_bytes) {
        cursor.current_pos = offset;
        if select {
            if let Some(index) = selection_index {
                selection.update_selection(index, offset);
            }
            return; // early return ONLY when select == true
        }
        // fall through: startView may still need adjustment (no-op
        // in practice, kept for C++ parity)
    }

    let delta = cursor.current_pos.saturating_sub(cursor.start_view);
    if offset < cursor.start_view {
        cursor.start_view = offset;
    } else if offset >= delta {
        cursor.start_view = offset.saturating_sub(delta);
    } else {
        cursor.start_view = 0;
    }
    cursor.current_pos = offset;
    if select {
        if let Some(index) = selection_index {
            selection.update_selection(index, offset);
        }
    }
}

/// Scrolls the viewport origin to `offset`, dragging the cursor by
/// the same delta (C++ `MoveScrollTo`, spec §3.2).
pub fn move_scroll_to(
    cursor: &mut BufferCursor,
    selection: &mut Selection,
    offset: u64,
    file_size: u64,
    visible_bytes: u64,
) {
    if file_size == 0 {
        return;
    }
    let offset = u64::min(offset, file_size.saturating_sub(1));
    let previous = cursor.start_view;
    cursor.start_view = offset;
    if cursor.start_view > previous {
        let diff = cursor.start_view.saturating_sub(previous);
        let target = cursor.current_pos.saturating_add(diff);
        move_to(cursor, selection, target, false, file_size, visible_bytes);
    } else {
        let delta = previous.saturating_sub(cursor.start_view);
        if delta <= cursor.current_pos {
            let target = cursor.current_pos.saturating_sub(delta);
            move_to(cursor, selection, target, false, file_size, visible_bytes);
        } else {
            move_to(cursor, selection, 0, false, file_size, visible_bytes);
        }
    }
}

/// Offset of the row start under the cursor (Home target, spec §3.3).
#[must_use]
pub const fn home_offset(cursor: BufferCursor, characters_per_line: u32) -> u64 {
    let delta = cursor.current_pos.saturating_sub(cursor.start_view);
    let Some(col) = delta.checked_rem(characters_per_line as u64) else {
        return cursor.current_pos; // zero-width line: no row structure
    };
    cursor.current_pos.saturating_sub(col)
}

/// Offset of the row end under the cursor (End target, spec §3.3;
/// `move_to` clamps to `file_size - 1`).
#[must_use]
pub const fn end_offset(cursor: BufferCursor, characters_per_line: u32) -> u64 {
    if characters_per_line == 0 {
        return cursor.current_pos;
    }
    home_offset(cursor, characters_per_line)
        .saturating_add((characters_per_line as u64).saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(nr_cols: u32, addr: u32, name: u32, fmt: CharacterFormatMode) -> BufferLayout {
        BufferLayout {
            char_format_mode: fmt,
            nr_cols,
            line_address_size: addr,
            line_name_size: name,
            ..Default::default()
        }
    }

    #[test]
    fn format_mode_sizes_match_cpp_table() {
        assert_eq!(CharacterFormatMode::Hex.size(), 2);
        assert_eq!(CharacterFormatMode::Octal.size(), 3);
        assert_eq!(CharacterFormatMode::SignedDecimal.size(), 4);
        assert_eq!(CharacterFormatMode::UnsignedDecimal.size(), 3);
    }

    #[test]
    fn address_column_width_with_name_and_address() {
        // name=8, addr=8: xAddress = 8+1 = 9, sz = 8+8+1 = 17, +3 →
        // xNumbers = 20; hex 16 cols → xText = 20 + 16*3 + 3 = 71.
        let mut l = layout(16, 8, 8, CharacterFormatMode::Hex);
        l.update_view_sizes(120, 20);
        assert_eq!(l.x_name, 0);
        assert_eq!(l.x_address, 9);
        assert_eq!(l.x_numbers, 20);
        assert_eq!(l.x_text, 71);
        assert_eq!(l.characters_per_line, 16);
        assert_eq!(l.visible_rows, 19);
    }

    #[test]
    fn address_column_width_without_name() {
        // addr=8, no name: xAddress = 0, sz = 8, +3 → xNumbers = 11.
        let mut l = layout(8, 8, 0, CharacterFormatMode::Octal);
        l.update_view_sizes(80, 10);
        assert_eq!(l.x_address, 0);
        assert_eq!(l.x_numbers, 11);
        // 8 columns * (3+1) = 32; xText = 11 + 32 + 3 = 46.
        assert_eq!(l.x_text, 46);
        assert_eq!(l.characters_per_line, 8);
    }

    #[test]
    fn no_address_no_name_has_no_gap() {
        // sz stays 0: the 3-space gap is only added when sz > 0
        // (Instance.cpp:632-633).
        let mut l = layout(8, 0, 0, CharacterFormatMode::Hex);
        l.update_view_sizes(80, 10);
        assert_eq!(l.x_numbers, 0);
        assert_eq!(l.x_text, 8 * 3 + 3);
    }

    #[test]
    fn full_ascii_mode_uses_remaining_width() {
        let mut l = layout(0, 8, 0, CharacterFormatMode::Hex);
        l.update_view_sizes(80, 25);
        assert_eq!(l.x_text, 11);
        assert_eq!(l.characters_per_line, 80 - 12);
        // Degenerate width: clamps to 1 byte per line.
        l.update_view_sizes(10, 25);
        assert_eq!(l.characters_per_line, 1);
        l.update_view_sizes(0, 0);
        assert_eq!(l.characters_per_line, 1);
        assert_eq!(l.visible_rows, 1);
    }

    #[test]
    fn visible_bytes_and_line_offset() {
        let mut l = layout(16, 8, 0, CharacterFormatMode::Hex);
        l.update_view_sizes(100, 21);
        assert_eq!(l.visible_rows, 20);
        assert_eq!(l.visible_bytes(), 16 * 20);
        assert_eq!(l.line_offset(0, 0x1000), 0x1000);
        assert_eq!(l.line_offset(3, 0x1000), 0x1000 + 48);
        // u64 domain: no overflow panic near the top.
        let _ = l.line_offset(u32::MAX, u64::MAX);
    }

    #[test]
    fn move_to_within_view_keeps_origin() {
        let mut cursor = BufferCursor::default();
        let mut sel = Selection::new();
        move_to(&mut cursor, &mut sel, 10, false, 1000, 160);
        assert_eq!(
            cursor,
            BufferCursor {
                start_view: 0,
                current_pos: 10
            }
        );
    }

    #[test]
    fn move_to_scrolls_preserving_delta() {
        let mut cursor = BufferCursor {
            start_view: 0,
            current_pos: 10,
        };
        let mut sel = Selection::new();
        // Offset past the viewport: startView = offset - delta.
        move_to(&mut cursor, &mut sel, 500, false, 1000, 160);
        assert_eq!(cursor.current_pos, 500);
        assert_eq!(cursor.start_view, 490);
        // Offset before the viewport: startView = offset.
        move_to(&mut cursor, &mut sel, 100, false, 1000, 160);
        assert_eq!(cursor.current_pos, 100);
        assert_eq!(cursor.start_view, 100);
    }

    #[test]
    fn move_to_clamps_and_handles_same_offset() {
        let mut cursor = BufferCursor::default();
        let mut sel = Selection::new();
        // Clamp to fileSize - 1.
        move_to(&mut cursor, &mut sel, u64::MAX, false, 100, 160);
        assert_eq!(cursor.current_pos, 99);
        // offset == currentPos teleports the view origin (C++ §3.1).
        move_to(&mut cursor, &mut sel, 99, false, 100, 160);
        assert_eq!(cursor.start_view, 99);
        // Empty file: untouched.
        let mut cursor2 = BufferCursor {
            start_view: 7,
            current_pos: 7,
        };
        move_to(&mut cursor2, &mut sel, 50, false, 0, 160);
        assert_eq!(
            cursor2,
            BufferCursor {
                start_view: 7,
                current_pos: 7
            }
        );
    }

    #[test]
    fn move_to_with_select_drags_selection() {
        let mut cursor = BufferCursor {
            start_view: 0,
            current_pos: 10,
        };
        let mut sel = Selection::new();
        move_to(&mut cursor, &mut sel, 20, true, 1000, 160);
        assert_eq!(sel.get_selection(0), Some((10, 20)));
        // Extending further keeps the original anchor: BeginSelection
        // at 20 lands inside [10,20] and resizes in place, so the
        // subsequent update drags from anchor 10.
        move_to(&mut cursor, &mut sel, 30, true, 1000, 160);
        assert_eq!(sel.get_selection(0), Some((10, 30)));
    }

    #[test]
    fn move_scroll_to_shifts_cursor_with_view() {
        let mut cursor = BufferCursor {
            start_view: 100,
            current_pos: 110,
        };
        let mut sel = Selection::new();
        // Scroll down by 60: cursor follows.
        move_scroll_to(&mut cursor, &mut sel, 160, 10_000, 160);
        assert_eq!(cursor.current_pos, 170);
        // Scroll up by 100.
        move_scroll_to(&mut cursor, &mut sel, 60, 10_000, 160);
        assert_eq!(cursor.current_pos, 70);
        // Scroll up beyond the cursor delta: cursor to 0.
        let mut cursor = BufferCursor {
            start_view: 50,
            current_pos: 20,
        };
        move_scroll_to(&mut cursor, &mut sel, 0, 10_000, 160);
        assert_eq!(cursor.current_pos, 0);
    }

    #[test]
    fn home_end_within_row() {
        let cursor = BufferCursor {
            start_view: 0,
            current_pos: 37,
        };
        assert_eq!(home_offset(cursor, 16), 32);
        assert_eq!(end_offset(cursor, 16), 47);
        // Cursor already at row start.
        let cursor = BufferCursor {
            start_view: 0,
            current_pos: 32,
        };
        assert_eq!(home_offset(cursor, 16), 32);
        // Guard against a zero-width line.
        assert_eq!(home_offset(cursor, 0), 32);
        assert_eq!(end_offset(cursor, 0), 32);
    }
}
