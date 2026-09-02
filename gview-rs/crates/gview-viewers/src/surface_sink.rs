//! Zero-allocation [`RowSink`] over an `AppCUI` [`Surface`].
//!
//! Spec `00_APP §6.1`, `§6.2` (paint row) and `§6.3` (hot-path rules);
//! C++ `Instance::Paint` / `PrepareDrawLineInfo`
//! (`BufferViewer/Instance.cpp:600-760`).
//!
//! `gview_view::buffer_viewer::paint::paint_rows` walks the visible
//! rows and hands each one's borrowed bytes to a sink; this is the
//! real renderer behind that seam. One row draws three bands, at the
//! x-positions [`BufferLayout::update_view_sizes`] computed:
//!
//! | Band | x | Cells per byte |
//! |------|---|----------------|
//! | address | `x_address` | `line_address_size` hex digits, zero padded |
//! | numbers | `x_numbers` | `char_format_mode.size() + 1` (C++ `nrCols * (sz + 1)`) |
//! | text | `x_text` | 1, `.` outside `[0x20, 0x7E]` |
//!
//! Every value is formatted into a stack array through [`HEX_DIGITS`]
//! (upper-case, matching the C++ `NumericFormatter`) and written with
//! `Surface::write_ascii`, so a painted frame performs **no heap
//! allocation** — the invariant `00_APP §6.3` demands and the tests
//! pin with a counting allocator.

use appcui::graphics::{CharAttribute, Surface};
use gview_core::selection::Selection;
use gview_core::zones::ZonesList;
use gview_view::buffer_viewer::color::{apply_selection_override, ColorConfig, PositionToColorCallback};
use gview_view::buffer_viewer::layout::{BufferLayout, CharacterFormatMode};
use gview_view::buffer_viewer::paint::{ascii_display_char, RowSink};

/// Upper-case hex digits, the static lookup table every band formats
/// through (C++ `NumericFormatter` `BaseLettersUpperCase`).
pub const HEX_DIGITS: [u8; 16] = *b"0123456789ABCDEF";

/// Widest numeric field a single byte can occupy
/// (`CharacterFormatMode::SignedDecimal` → `-128`, 4 cells).
const MAX_BYTE_CELLS: usize = 4;

/// Capacity of the address scratch buffer: a `u64` never needs more
/// than 16 hex digits.
const MAX_ADDRESS_DIGITS: usize = 16;

/// Colours one painted row uses. Kept as plain attributes so the sink
/// borrows nothing but the surface (`00_APP §6.2`: `on_paint` takes
/// `&self`).
#[derive(Clone, Copy, Debug)]
pub struct RowColors {
    /// Address column.
    pub address: CharAttribute,
    /// Numeric band.
    pub numbers: CharAttribute,
    /// Text band, used when no [`ByteColors`] is attached.
    pub text: CharAttribute,
}

/// The per-byte colour inputs a sink can consult **without** touching
/// the `DataCache`.
///
/// C++ `OffsetToColor` (`BufferViewer/Instance.cpp:530-614`) resolves a
/// byte's colour in seven steps. Four of them (selection similarity,
/// object highlighting, the `BufferColorInterface` callback and string
/// highlighting) need `&mut DataCache` and `&mut ColorState`, which the
/// sink cannot hold: `paint_rows` already borrows the cache to produce
/// the row bytes. The three that need only the row bytes, the zone list
/// and the selection are resolved here:
///
/// | C++ step | Here |
/// |----------|------|
/// | 4 — `PositionToColorInterface::GetColorForBuffer` | [`Self::colorizer`], fed the row's own bytes |
/// | 6 — plugin zones / `Cfg.Text.Inactive` | [`Self::zones`] |
/// | 7 — `Cfg.Selection.Editor` override | [`Self::selection`] |
///
/// The remaining steps are driven from the viewer's key/resize handlers
/// (where the cache is free) in the follow-up viewer tasks; until then a
/// byte they would have coloured falls through to its zone colour, which
/// is exactly what the C++ does when those toggles are off.
pub struct ByteColors<'a> {
    /// Plugin zones (`BufferViewerRequest::zones`).
    pub zones: &'a ZonesList,
    /// The viewer's selection.
    pub selection: &'a Selection,
    /// The plugin's opcode colouring hook, when it supplied one.
    pub colorizer: Option<&'a mut dyn PositionToColorCallback>,
    /// `Cfg.*` attributes the C++ steps fall back on.
    pub config: ColorConfig,
    /// C++ `showTypeObjects`: gates the [`Self::colorizer`] step.
    pub show_type_objects: bool,
}

/// Renders one visible row into a [`Surface`].
///
/// The lifetime ties the sink to the surface borrowed for the duration
/// of a single `on_paint`; the sink itself owns only `Copy` data.
pub struct SurfaceRowSink<'a> {
    surface: &'a mut Surface,
    layout: BufferLayout,
    colors: RowColors,
    /// Per-byte colour inputs; `None` paints the whole row in
    /// [`RowColors`] (what the scaffold tests and the E2E smoke test
    /// use).
    byte_colors: Option<ByteColors<'a>>,
    /// Scratch for one byte's numeric text.
    number_scratch: [u8; MAX_BYTE_CELLS],
    /// Scratch for the address column.
    address_scratch: [u8; MAX_ADDRESS_DIGITS],
}

impl<'a> SurfaceRowSink<'a> {
    /// Binds a sink to `surface` for one paint pass.
    pub const fn new(surface: &'a mut Surface, layout: BufferLayout, colors: RowColors) -> Self {
        Self {
            surface,
            layout,
            colors,
            byte_colors: None,
            number_scratch: [b' '; MAX_BYTE_CELLS],
            address_scratch: [b'0'; MAX_ADDRESS_DIGITS],
        }
    }

    /// Adds per-byte colouring (see [`ByteColors`]).
    #[must_use]
    pub const fn with_byte_colors(mut self, byte_colors: ByteColors<'a>) -> Self {
        self.byte_colors = Some(byte_colors);
        self
    }

    /// Colour of the byte at `offset`, whose row context starts at
    /// `context` (up to 16 bytes, as the C++ `BufferView` passes).
    fn color_for(&mut self, offset: u64, context: &[u8]) -> CharAttribute {
        let Some(byte_colors) = self.byte_colors.as_mut() else {
            return self.colors.numbers;
        };
        // Step 4 — the plugin's opcode colouring, gated exactly as the
        // C++ gates it on `showTypeObjects`.
        let from_callback = if byte_colors.show_type_objects {
            byte_colors
                .colorizer
                .as_mut()
                .and_then(|cb| cb.color_for_buffer(offset, context))
                .map(|buffer_color| buffer_color.color)
        } else {
            None
        };
        // Step 6 — the plugin zone, else `Cfg.Text.Inactive`.
        let color = from_callback.unwrap_or_else(|| {
            byte_colors
                .zones
                .offset_to_zone(offset)
                .map_or(byte_colors.config.inactive, |zone| zone.color)
        });
        // Step 7 — a selected byte always paints as the editor colour.
        apply_selection_override(color, byte_colors.selection, offset, &byte_colors.config)
    }

    /// Formats `byte` into `number_scratch` in the layout's mode and
    /// returns the written length (C++ `characterFormatModeSize`).
    fn format_byte(&mut self, byte: u8) -> usize {
        match self.layout.char_format_mode {
            CharacterFormatMode::Hex => {
                let digits = [
                    HEX_DIGITS[usize::from(byte >> 4)],
                    HEX_DIGITS[usize::from(byte & 0x0F)],
                ];
                self.number_scratch[..2].copy_from_slice(&digits);
                2
            }
            CharacterFormatMode::Octal => {
                self.number_scratch[0] = b'0'.saturating_add(byte >> 6);
                self.number_scratch[1] = b'0'.saturating_add((byte >> 3) & 0x07);
                self.number_scratch[2] = b'0'.saturating_add(byte & 0x07);
                3
            }
            CharacterFormatMode::UnsignedDecimal => {
                // C++ `Instance.cpp:895-929`: space padded, not zero
                // padded — `5` renders `"  5"`, `42` renders `" 42"`.
                let cells = if byte < 10 {
                    [b' ', b' ', digit(byte)]
                } else if byte < 100 {
                    [b' ', digit(byte / 10), digit(byte % 10)]
                } else {
                    [digit(byte / 100), digit((byte / 10) % 10), digit(byte % 10)]
                };
                self.number_scratch[..3].copy_from_slice(&cells);
                3
            }
            CharacterFormatMode::SignedDecimal => {
                // C++ `Instance.cpp:931-982`: the sign is `+` for a
                // positive value, `-` for a negative one and a space
                // for zero, it sits immediately left of the digits, and
                // the whole field is space-padded to four cells.
                let signed = byte.cast_signed();
                let magnitude = signed.unsigned_abs();
                let sign = match signed.cmp(&0) {
                    core::cmp::Ordering::Less => b'-',
                    core::cmp::Ordering::Greater => b'+',
                    core::cmp::Ordering::Equal => b' ',
                };
                let cells = if magnitude < 10 {
                    [b' ', b' ', sign, digit(magnitude)]
                } else if magnitude < 100 {
                    [b' ', sign, digit(magnitude / 10), digit(magnitude % 10)]
                } else {
                    [
                        sign,
                        digit(magnitude / 100),
                        digit((magnitude / 10) % 10),
                        digit(magnitude % 10),
                    ]
                };
                self.number_scratch.copy_from_slice(&cells);
                4
            }
        }
    }

    /// Writes the row's file offset in the address column, zero-padded
    /// to `line_address_size` upper-case hex digits.
    fn draw_address(&mut self, row: u32, offset: u64) {
        let digits = (self.layout.line_address_size as usize).min(MAX_ADDRESS_DIGITS);
        if digits == 0 {
            return;
        }
        let mut value = offset;
        for slot in self.address_scratch[..digits].iter_mut().rev() {
            *slot = HEX_DIGITS[(value & 0x0F) as usize];
            value >>= 4;
        }
        // Row 0 of the data area is screen row 1 (row 0 is the header).
        let y = row.saturating_add(1).cast_signed();
        self.surface.write_ascii(
            self.layout.x_address.cast_signed(),
            y,
            &self.address_scratch[..digits],
            self.colors.address,
            false,
        );
    }
}

/// One decimal digit as ASCII (C++ `'0' + n`); every call site passes
/// a value already reduced to `0..=9`.
const fn digit(n: u8) -> u8 {
    b'0'.saturating_add(n % 10)
}

impl RowSink for SurfaceRowSink<'_> {
    /// One visible row: address, numeric band, text band. Nothing here
    /// allocates — every buffer is an inline field.
    fn draw_row(&mut self, row: u32, offset: u64, bytes: &[u8]) {
        let y = row.saturating_add(1).cast_signed();
        self.draw_address(row, offset);

        let cell_width = self.layout.char_format_mode.size().saturating_add(1);
        for (index, byte) in bytes.iter().enumerate() {
            let column = index as u32;
            if self.layout.nr_cols > 0 && column >= self.layout.nr_cols {
                break;
            }
            let byte_offset = offset.saturating_add(index as u64);
            // The colourer sees the same up-to-16-byte window the C++
            // hands `GetColorForBuffer` — borrowed from this row, so
            // nothing is copied.
            let context = bytes.get(index..).map_or(&[][..], |rest| {
                rest.get(..16.min(rest.len())).unwrap_or(rest)
            });
            let color = self.color_for(byte_offset, context);
            if self.layout.nr_cols > 0 {
                let len = self.format_byte(*byte);
                let x = self
                    .layout
                    .x_numbers
                    .saturating_add(column.saturating_mul(cell_width))
                    .cast_signed();
                self.surface
                    .write_ascii(x, y, &self.number_scratch[..len], color, false);
            }
            // The text band renders one cell per byte, `.` for
            // anything outside the printable ASCII range (§4.1).
            let glyph = ascii_display_char(*byte) as u8;
            let x = self.layout.x_text.saturating_add(column).cast_signed();
            self.surface
                .write_ascii(x, y, core::slice::from_ref(&glyph), color, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RowColors, SurfaceRowSink, HEX_DIGITS};
    use appcui::graphics::{CharAttribute, Color, Size, Surface};
    use gview_view::buffer_viewer::layout::{BufferLayout, CharacterFormatMode};
    use gview_view::buffer_viewer::paint::RowSink;

    fn colors() -> RowColors {
        let attr = CharAttribute::with_color(Color::White, Color::Black);
        RowColors {
            address: attr,
            numbers: attr,
            text: attr,
        }
    }

    fn layout_for(mode: CharacterFormatMode, cols: u32) -> BufferLayout {
        let mut layout = BufferLayout {
            char_format_mode: mode,
            nr_cols: cols,
            ..BufferLayout::default()
        };
        layout.update_view_sizes(120, 11);
        layout
    }

    /// Reads the row of characters at `y` starting at `x`.
    fn read(surface: &Surface, x: u32, y: u32, len: usize) -> String {
        (0..len)
            .filter_map(|i| {
                surface
                    .char(x.saturating_add(i as u32).cast_signed(), y.cast_signed())
                    .map(|c| c.code)
            })
            .collect()
    }

    #[test]
    fn hex_row_writes_the_numeric_and_ascii_bands() {
        let layout = layout_for(CharacterFormatMode::Hex, 16);
        let mut surface = Surface::new(120, 12);
        let bytes: Vec<u8> = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00".to_vec();
        assert_eq!(bytes.len(), 16);
        {
            let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
            sink.draw_row(0, 0, &bytes);
        }
        // Row 0 of the data area is screen row 1 (row 0 is the header).
        assert_eq!(
            read(&surface, layout.x_numbers, 1, 12),
            "4D 5A 90 00 ",
            "hex band at x_numbers"
        );
        assert_eq!(
            read(&surface, layout.x_text, 1, 16),
            "MZ..............",
            "ascii band at x_text: only MZ is printable"
        );
        // Address column: 8 zero-padded hex digits.
        assert_eq!(read(&surface, layout.x_address, 1, 8), "00000000");
    }

    #[test]
    fn address_column_follows_the_row_offset() {
        let layout = layout_for(CharacterFormatMode::Hex, 16);
        let mut surface = Surface::new(120, 12);
        {
            let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
            sink.draw_row(2, 0x00AB_CDEF, &[0x00]);
        }
        assert_eq!(read(&surface, layout.x_address, 3, 8), "00ABCDEF");
    }

    #[test]
    fn every_format_mode_renders_its_cell_width() {
        for (mode, expected) in [
            (CharacterFormatMode::Hex, "FF 01 "),
            (CharacterFormatMode::Octal, "377 001 "),
            (CharacterFormatMode::UnsignedDecimal, "255   1 "),
            (CharacterFormatMode::SignedDecimal, "  -1   +1 "),
        ] {
            let layout = layout_for(mode, 16);
            let mut surface = Surface::new(160, 12);
            {
                let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
                sink.draw_row(0, 0, &[0xFF, 0x01]);
            }
            assert_eq!(
                read(&surface, layout.x_numbers, 1, expected.len()),
                expected,
                "{mode:?}"
            );
        }
    }

    /// C++ `Instance.cpp:895-982`: the decimal modes pad with spaces
    /// and the signed mode carries an explicit `+` / `-` / ` ` sign.
    #[test]
    fn decimal_modes_pad_with_spaces_and_sign_like_the_cpp() {
        let layout = layout_for(CharacterFormatMode::UnsignedDecimal, 16);
        let mut surface = Surface::new(160, 12);
        {
            let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
            sink.draw_row(0, 0, &[0x00, 0x09, 0x0A, 0x63, 0x64, 0xFF]);
        }
        assert_eq!(
            read(&surface, layout.x_numbers, 1, 24),
            "  0   9  10  99 100 255 "
        );

        let layout = layout_for(CharacterFormatMode::SignedDecimal, 16);
        let mut surface = Surface::new(160, 12);
        {
            let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
            // 0, +1, +9, +10, -1, -128
            sink.draw_row(0, 0, &[0x00, 0x01, 0x09, 0x0A, 0xFF, 0x80]);
        }
        assert_eq!(
            read(&surface, layout.x_numbers, 1, 30),
            "   0   +1   +9  +10   -1 -128 "
        );
    }

    #[test]
    fn a_short_row_at_eof_paints_only_its_bytes() {
        let layout = layout_for(CharacterFormatMode::Hex, 16);
        let mut surface = Surface::new(120, 12);
        {
            let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
            sink.draw_row(0, 0, &[0x41, 0x42]);
        }
        assert_eq!(read(&surface, layout.x_text, 1, 4), "AB  ", "nothing past EOF");
        // Extra bytes past `nr_cols` are ignored rather than wrapping.
        let mut surface = Surface::new(120, 12);
        {
            let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
            sink.draw_row(0, 0, &[0x41; 20]);
        }
        assert_eq!(read(&surface, layout.x_text, 1, 17), "AAAAAAAAAAAAAAAA ");
    }

    #[test]
    fn full_screen_ascii_mode_skips_the_numeric_band() {
        let layout = layout_for(CharacterFormatMode::Hex, 0);
        assert_eq!(layout.nr_cols, 0);
        let mut surface = Surface::new(120, 12);
        {
            let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
            sink.draw_row(0, 0, b"hello");
        }
        assert_eq!(read(&surface, layout.x_text, 1, 5), "hello");
    }

    #[test]
    fn hex_table_is_upper_case_like_the_cpp_formatter() {
        assert_eq!(&HEX_DIGITS, b"0123456789ABCDEF");
    }

    #[test]
    fn sink_size_is_bounded() {
        // The sink is a borrow plus inline scratch: nothing on the heap.
        assert!(core::mem::size_of::<SurfaceRowSink<'_>>() < 256);
        assert_eq!(Surface::new(1, 1).size(), Size::new(1, 1));
    }
}
