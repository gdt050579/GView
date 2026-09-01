//! Pre-allocated character-cell grid for paint staging.
//!
//! Viewers stage their output into a [`CellBuffer`] (or draw directly
//! on an `appcui` `Surface`); the buffer is allocated once and reused,
//! so paint loops perform **zero heap allocations** (CLAUDE.md
//! invariant). All accesses are bounds-checked — out-of-range writes
//! are silently dropped, mirroring `Surface` clipping.

use appcui::graphics::{CharAttribute, Character};

/// A `width × height` grid of [`Character`] cells.
pub struct CellBuffer {
    width: u32,
    height: u32,
    cells: Vec<Character>,
}

impl CellBuffer {
    /// Allocates a `width × height` grid filled with the default
    /// character (space on white/black). A zero-sized dimension yields
    /// an empty, fully functional buffer.
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        let len = (width as usize).saturating_mul(height as usize);
        Self {
            width,
            height,
            cells: vec![Character::default(); len],
        }
    }

    /// Grid width in cells.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Grid height in cells.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Row-major cell index for `(x, y)`, or `None` outside the grid.
    fn index(&self, x: u32, y: u32) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        (y as usize)
            .checked_mul(self.width as usize)
            .and_then(|row| row.checked_add(x as usize))
    }

    /// Cell at `(x, y)`, or `None` outside the grid.
    #[must_use]
    pub fn get(&self, x: u32, y: u32) -> Option<&Character> {
        let idx = self.index(x, y)?;
        self.cells.get(idx)
    }

    /// Writes one cell; out-of-range coordinates are dropped
    /// (clipping semantics). Returns whether the write landed.
    pub fn write_char(&mut self, x: u32, y: u32, ch: Character) -> bool {
        let Some(idx) = self.index(x, y) else {
            return false;
        };
        if let Some(cell) = self.cells.get_mut(idx) {
            *cell = ch;
            return true;
        }
        false
    }

    /// Writes `text` horizontally starting at `(x, y)` with `attr`,
    /// clipping at the right edge. Returns the number of cells
    /// written.
    pub fn write_ascii(&mut self, x: u32, y: u32, text: &[u8], attr: CharAttribute) -> u32 {
        let mut written = 0_u32;
        for (i, &byte) in text.iter().enumerate() {
            let Some(cx) = (i as u32).checked_add(x) else {
                break;
            };
            if self.write_char(cx, y, Character::with_attributes(byte as char, attr)) {
                written = written.saturating_add(1);
            } else {
                break;
            }
        }
        written
    }

    /// Fills the whole grid with `ch` without reallocating.
    pub fn fill(&mut self, ch: Character) {
        self.cells.fill(ch);
    }

    /// Resizes the grid (reallocates; not for use inside paint
    /// loops), clearing it to the default character.
    pub fn resize(&mut self, width: u32, height: u32) {
        let len = (width as usize).saturating_mul(height as usize);
        self.width = width;
        self.height = height;
        self.cells.clear();
        self.cells.resize(len, Character::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::graphics::{CharFlags, Color};

    #[test]
    fn write_and_read_back() {
        let mut buf = CellBuffer::new(10, 4);
        let ch = Character::new('X', Color::Red, Color::Black, CharFlags::None);
        assert!(buf.write_char(3, 2, ch));
        let got = buf.get(3, 2).expect("cell");
        assert_eq!(got.code, 'X');
        assert_eq!(got.foreground, Color::Red);
        assert_eq!(got.background, Color::Black);
        // Neighbors untouched.
        assert_eq!(buf.get(4, 2).expect("cell").code, ' ');
    }

    #[test]
    fn color_pair_roundtrip() {
        // A CharAttribute survives write → read unchanged.
        let attr = CharAttribute::with_color(Color::Aqua, Color::DarkRed);
        let mut buf = CellBuffer::new(2, 2);
        assert!(buf.write_char(1, 1, Character::with_attributes('#', attr)));
        let got = buf.get(1, 1).expect("cell");
        assert_eq!(got.foreground, attr.foreground);
        assert_eq!(got.background, attr.background);
    }

    #[test]
    fn out_of_range_write_is_dropped() {
        let mut buf = CellBuffer::new(4, 4);
        assert!(!buf.write_char(4, 0, Character::default()));
        assert!(!buf.write_char(0, 4, Character::default()));
        assert!(!buf.write_char(u32::MAX, u32::MAX, Character::default()));
        assert!(buf.get(4, 0).is_none());
    }

    #[test]
    fn zero_width_paint_does_not_panic() {
        let mut buf = CellBuffer::new(0, 5);
        assert_eq!(buf.width(), 0);
        assert!(!buf.write_char(0, 0, Character::default()));
        assert!(buf.get(0, 0).is_none());
        assert_eq!(buf.write_ascii(0, 0, b"hello", CharAttribute::default()), 0);
        buf.fill(Character::default());

        let mut buf = CellBuffer::new(5, 0);
        assert!(!buf.write_char(2, 0, Character::default()));

        let mut buf = CellBuffer::new(0, 0);
        buf.fill(Character::default());
        assert!(buf.get(0, 0).is_none());
    }

    #[test]
    fn write_ascii_clips_at_edge() {
        let mut buf = CellBuffer::new(5, 1);
        let n = buf.write_ascii(3, 0, b"abcdef", CharAttribute::default());
        assert_eq!(n, 2); // only columns 3 and 4 fit
        assert_eq!(buf.get(3, 0).expect("cell").code, 'a');
        assert_eq!(buf.get(4, 0).expect("cell").code, 'b');
    }

    #[test]
    fn resize_reshapes_and_clears() {
        let mut buf = CellBuffer::new(2, 2);
        buf.write_char(0, 0, Character::with_char('Z'));
        buf.resize(3, 3);
        assert_eq!(buf.width(), 3);
        assert_eq!(buf.height(), 3);
        assert_eq!(buf.get(0, 0).expect("cell").code, ' ');
        assert!(buf.get(2, 2).is_some());
    }

    #[test]
    fn huge_dimensions_do_not_overflow_index() {
        // Index math is checked; constructing a huge buffer would
        // allocate, so only index arithmetic is exercised here.
        let buf = CellBuffer::new(8, 8);
        assert!(buf.get(u32::MAX, 1).is_none());
        assert!(buf.get(1, u32::MAX).is_none());
    }
}
