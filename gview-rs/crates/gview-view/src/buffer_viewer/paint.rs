//! `BufferViewer` per-frame paint loop
//! (C++ `Instance::Paint` / `PrepareDrawLineInfo`; spec
//! `02_VIEWER_BUFFER` §4.1–4.2; custom `OnPaint` per
//! `APPCUI_RS_UI_AND_ASYNC_GUIDE` §2.5, §3.5).
//!
//! Per frame: rebuild the zones viewport cache for the visible
//! interval, then for each visible row `Get` the row's bytes from the
//! `DataCache` (borrowed slices — zero allocations) and hand them to
//! the row sink (the real renderer, or a mock in tests). Rows at EOF
//! are truncated by the cache (`fail_if_cannot_read = false`).

use gview_core::cache::DataCache;
use gview_core::zones::ZonesList;

use super::layout::{BufferCursor, BufferLayout};

/// Paint target for one row (the concrete renderer draws into the
/// `appcui` `Surface`; tests use a recording mock).
pub trait RowSink {
    /// One visible row: `row` is the 0-based data row (row 0 is the
    /// first row under the header), `offset` its file offset, `bytes`
    /// the (possibly EOF-truncated) row content.
    fn draw_row(&mut self, row: u32, offset: u64, bytes: &[u8]);
}

/// What a paint pass covered (for assertions/telemetry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaintSummary {
    /// Rows handed to the sink.
    pub rows_painted: u32,
    /// Inclusive interval passed to `ZonesList::SetCache`.
    pub viewport: (u64, u64),
}

/// Character shown in the text column for `byte`
/// (§4.1: bytes outside `[0x20, 0x7E]` render as `.`).
#[must_use]
pub const fn ascii_display_char(byte: u8) -> char {
    if byte >= 0x20 && byte <= 0x7E {
        byte as char
    } else {
        '.'
    }
}

/// Runs one paint pass (C++ `Paint`, spec §4.1):
///
/// ```text
/// ZonesList.SetCache({ startView,
///                      startView + charactersPerLine * (visibleRows - 1) })
/// for each visible row:
///     offset = startView + row * charactersPerLine
///     bytes  = DataCache.Get(offset, charactersPerLine, false)
/// ```
///
/// Rows entirely past EOF are not painted; the returned summary says
/// how many rows reached the sink.
pub fn paint_rows(
    layout: &BufferLayout,
    cursor: BufferCursor,
    cache: &mut DataCache,
    zones: &mut ZonesList,
    sink: &mut impl RowSink,
) -> PaintSummary {
    let cpl = u64::from(layout.characters_per_line);
    let last_row_offset = cursor
        .start_view
        .saturating_add(cpl.saturating_mul(u64::from(layout.visible_rows.saturating_sub(1))));
    let viewport = (cursor.start_view, last_row_offset);
    zones.set_viewport_cache(viewport);

    let mut rows_painted = 0_u32;
    if layout.characters_per_line == 0 {
        return PaintSummary {
            rows_painted,
            viewport,
        };
    }
    for row in 0..layout.visible_rows {
        let offset = layout.line_offset(row, cursor.start_view);
        if offset >= cache.size() {
            break;
        }
        let Ok(bytes) = cache.get(offset, layout.characters_per_line, false) else {
            break;
        };
        if bytes.is_empty() {
            break;
        }
        sink.draw_row(row, offset, bytes);
        rows_painted = rows_painted.saturating_add(1);
    }
    PaintSummary {
        rows_painted,
        viewport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::graphics::{CharAttribute, Color};
    use gview_core::source::MemorySource;

    struct RecordingSink {
        rows: Vec<(u32, u64, Vec<u8>)>,
    }

    impl RowSink for RecordingSink {
        fn draw_row(&mut self, row: u32, offset: u64, bytes: &[u8]) {
            self.rows.push((row, offset, bytes.to_vec()));
        }
    }

    fn setup(file_len: usize, cols: u32, height: u32) -> (BufferLayout, DataCache, RecordingSink) {
        let data: Vec<u8> = (0..file_len).map(|i| (i & 0xFF) as u8).collect();
        let cache = DataCache::new(Box::new(MemorySource::new(data)), 0);
        let mut layout = BufferLayout {
            nr_cols: cols,
            ..Default::default()
        };
        layout.update_view_sizes(100, height);
        (layout, cache, RecordingSink { rows: Vec::new() })
    }

    #[test]
    fn mock_renderer_receives_correct_row_count() {
        // 16 cols × 10 data rows (height 11), file big enough.
        let (layout, mut cache, mut sink) = setup(4096, 16, 11);
        let mut zones = ZonesList::new();
        let cursor = BufferCursor::default();
        let summary = paint_rows(&layout, cursor, &mut cache, &mut zones, &mut sink);
        assert_eq!(layout.visible_rows, 10);
        assert_eq!(summary.rows_painted, 10);
        assert_eq!(sink.rows.len(), 10);
        // Per-row Get: offsets advance by charactersPerLine, full rows.
        for (i, (row, offset, bytes)) in sink.rows.iter().enumerate() {
            assert_eq!(*row, i as u32);
            assert_eq!(*offset, (i as u64) * 16);
            assert_eq!(bytes.len(), 16);
            assert_eq!(bytes[0], ((i * 16) & 0xFF) as u8);
        }
    }

    #[test]
    fn set_cache_interval_matches_cpp_formula() {
        // viewport = [startView, startView + cpl * (visibleRows - 1)]
        let (layout, mut cache, mut sink) = setup(4096, 16, 11);
        let mut zones = ZonesList::new();
        let attr = CharAttribute::with_color(Color::Red, Color::Black);
        zones.add(0x90, 0x9F, attr, "in-view");
        zones.add(0x2000, 0x2010, attr, "off-view");
        let cursor = BufferCursor {
            start_view: 0x40,
            current_pos: 0x40,
        };
        let summary = paint_rows(&layout, cursor, &mut cache, &mut zones, &mut sink);
        assert_eq!(summary.viewport, (0x40, 0x40 + 16 * 9));
        // The zones cache reflects exactly that interval.
        assert!(zones.offset_to_zone(0x95).is_some());
        assert!(zones.offset_to_zone(0x2005).is_none());
    }

    #[test]
    fn eof_truncates_last_row_and_stops() {
        // 100-byte file, 16 cols: rows 0..5 full, row 6 has 4 bytes,
        // remaining rows unpainted.
        let (layout, mut cache, mut sink) = setup(100, 16, 21);
        let mut zones = ZonesList::new();
        let summary = paint_rows(
            &layout,
            BufferCursor::default(),
            &mut cache,
            &mut zones,
            &mut sink,
        );
        assert_eq!(summary.rows_painted, 7);
        assert_eq!(sink.rows[5].2.len(), 16);
        assert_eq!(sink.rows[6].2.len(), 4);
    }

    #[test]
    fn empty_file_paints_nothing() {
        let (layout, mut cache, mut sink) = setup(0, 16, 11);
        let mut zones = ZonesList::new();
        let summary = paint_rows(
            &layout,
            BufferCursor::default(),
            &mut cache,
            &mut zones,
            &mut sink,
        );
        assert_eq!(summary.rows_painted, 0);
        assert!(sink.rows.is_empty());
    }

    #[test]
    fn ascii_display_replaces_non_printable() {
        assert_eq!(ascii_display_char(b'A'), 'A');
        assert_eq!(ascii_display_char(0x20), ' ');
        assert_eq!(ascii_display_char(0x7E), '~');
        assert_eq!(ascii_display_char(0x1F), '.');
        assert_eq!(ascii_display_char(0x7F), '.');
        assert_eq!(ascii_display_char(0x00), '.');
        assert_eq!(ascii_display_char(0xFF), '.');
    }
}
