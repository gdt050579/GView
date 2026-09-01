//! `TextViewer` viewport and cursor synchronization.
//!
//! C++ anchors: `CommputeViewPort_NoWrap` / `CommputeViewPort_Wrap`
//! (`Instance.cpp:622-751`), `UpdateCursor_NoWrap` / `UpdateCursor_Wrap`
//! (`Instance.cpp:1046-1111`), `UpdateViewPort`
//! (`Instance.cpp:1112-1147`); spec `02_VIEWER_TEXT` §2.5, §6.
//! A cursor outside the viewport re-centers it: before the start →
//! recompute top-to-bottom from the cursor; past the end → recompute
//! bottom-to-top ending at the cursor.

use gview_core::cache::DataCache;

use super::line_index::{Encoding, LineInfo};
use super::wrap::{
    character_index_to_sub_line_no, compute_sub_line_indexes, CharacterStream, SubLines, WrapMethod,
};

/// Maximum viewport rows (C++ `MAX_LINES_TO_VIEW`, spec §1).
pub const MAX_LINES_TO_VIEW: usize = 256;
/// Maximum characters drawn per line (C++ `MAX_CHARACTERS_PER_LINE`).
pub const MAX_CHARACTERS_PER_LINE: u32 = 1024;

/// Fill direction for a viewport computation (C++ `Direction`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The anchor becomes the first visible line.
    TopToBottom,
    /// The anchor becomes the last visible line.
    BottomToTop,
}

/// `(lineNo, subLineNo)` position (C++ `ViewPort.Start` / `End`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinePos {
    /// Logical line number.
    pub line_no: u32,
    /// Sub-line inside the logical line (0 without wrap).
    pub sub_line_no: u32,
}

/// One visible row (C++ `ViewPort.Lines[i]`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ViewPortLine {
    /// Absolute file offset of the fragment.
    pub offset: u64,
    /// Fragment byte size.
    pub size: u32,
    /// Logical line number.
    pub line_no: u32,
    /// Continuation indent column.
    pub x_start: u32,
    /// First character index of the fragment inside its line.
    pub line_char_index: u32,
}

/// Visible window over the line index (C++ `ViewPort`).
pub struct ViewPort {
    /// First visible position.
    pub start: LinePos,
    /// Last visible position.
    pub end: LinePos,
    /// Visible rows (pre-allocated; never exceeds
    /// [`MAX_LINES_TO_VIEW`]).
    pub lines: Vec<ViewPortLine>,
    /// Horizontal scroll for unwrapped long lines.
    pub scroll_x: u32,
}

impl Default for ViewPort {
    fn default() -> Self {
        Self {
            start: LinePos::default(),
            end: LinePos::default(),
            lines: Vec::with_capacity(MAX_LINES_TO_VIEW),
            scroll_x: 0,
        }
    }
}

impl ViewPort {
    /// C++ `ViewPort.Reset()` — keeps `scroll_x`.
    pub fn reset(&mut self) {
        self.start = LinePos::default();
        self.end = LinePos::default();
        self.lines.clear();
    }

    /// Visible row count (C++ `linesCount`).
    #[must_use]
    pub const fn lines_count(&self) -> usize {
        self.lines.len()
    }
}

/// Cursor state (C++ `Cursor`, spec §2.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TextCursor {
    /// Absolute file byte offset.
    pub pos: u64,
    /// Logical line number.
    pub line_no: u32,
    /// Sub-line inside the line.
    pub subline_no: u32,
    /// Character index within the logical line.
    pub char_index: u32,
}

/// Everything the viewport math reads (mirrors the C++ instance
/// state).
pub struct TextViewContext<'a> {
    /// Logical line index.
    pub lines: &'a [LineInfo],
    /// Backing data.
    pub cache: &'a mut DataCache,
    /// Detected encoding.
    pub encoding: Encoding,
    /// Active wrap method.
    pub wrap_method: WrapMethod,
    /// Tab width.
    pub tab_size: u32,
    /// Control width in cells.
    pub control_width: u32,
    /// Control height in cells.
    pub control_height: u32,
    /// Line-number gutter width.
    pub line_number_width: u32,
    /// Per-line sub-line cache.
    pub sub_lines: &'a mut SubLines,
}

impl TextViewContext<'_> {
    /// C++ `HasWordWrap()`.
    #[must_use]
    pub fn has_word_wrap(&self) -> bool {
        self.wrap_method != WrapMethod::None
    }

    /// C++ `GetLineInfo(lineNo)` — clamps to the last line; empty
    /// index yields a zero line.
    #[must_use]
    pub fn line_info(&self, line_no: u32) -> LineInfo {
        let idx = line_no as usize;
        self.lines.get(idx).copied().unwrap_or_else(|| {
            self.lines.last().copied().unwrap_or(LineInfo {
                offset: 0,
                char_count: 0,
                byte_size: 0,
            })
        })
    }

    /// Reads a line's bytes (terminator excluded).
    fn line_bytes(&mut self, line: LineInfo) -> Vec<u8> {
        if line.byte_size == 0 {
            return Vec::new();
        }
        self.cache
            .get(line.offset, line.byte_size, false)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }

    /// C++ `ComputeSubLineIndexes(lineNo)` — cached per line.
    pub fn compute_sub_lines(&mut self, line_no: u32) {
        if line_no == self.sub_lines.line_no {
            return;
        }
        let line = self.line_info(line_no);
        let bytes = self.line_bytes(line);
        compute_sub_line_indexes(
            self.sub_lines,
            line_no,
            line,
            &bytes,
            self.encoding,
            self.wrap_method,
            self.tab_size,
            self.control_width,
            self.line_number_width,
        );
    }
}

fn compute_view_port_no_wrap(
    vp: &mut ViewPort,
    ctx: &TextViewContext<'_>,
    line_no: u32,
    dir: Direction,
) {
    let h = u32::min(u32::max(ctx.control_height, 1), MAX_LINES_TO_VIEW as u32).saturating_sub(1);
    // C++ `lineNo > h ? lineNo - h : 0` is exactly a saturating sub.
    let start = if dir == Direction::BottomToTop {
        line_no.saturating_sub(h)
    } else {
        line_no
    };
    vp.reset();
    if ctx.lines.is_empty() {
        return;
    }
    let last_line_no = (ctx.lines.len() as u32).saturating_sub(1);
    vp.start = LinePos {
        line_no: start,
        sub_line_no: 0,
    };
    vp.end = LinePos {
        line_no: u32::min(start.saturating_add(h), last_line_no),
        sub_line_no: 0,
    };
    let count = vp
        .end
        .line_no
        .saturating_add(1)
        .saturating_sub(vp.start.line_no);
    let mut current = start;
    for _ in 0..count {
        let info = ctx.line_info(current);
        vp.lines.push(ViewPortLine {
            offset: info.offset,
            size: info.byte_size,
            line_no: current,
            x_start: 0,
            line_char_index: 0,
        });
        current = current.saturating_add(1);
    }
}

#[allow(clippy::too_many_lines)] // direct port of the two C++ fill loops
fn compute_view_port_wrap(
    vp: &mut ViewPort,
    ctx: &mut TextViewContext<'_>,
    line_no: u32,
    sub_line_no: u32,
    dir: Direction,
) {
    let h = u32::min(u32::max(ctx.control_height, 1), MAX_LINES_TO_VIEW as u32) as usize;
    vp.reset();
    if ctx.lines.is_empty() {
        return;
    }
    vp.start = LinePos {
        line_no,
        sub_line_no,
    };
    vp.end = vp.start;
    if dir == Direction::TopToBottom {
        let mut start = line_no;
        let mut start_sl = sub_line_no as usize;
        while vp.lines.len() < h && (start as usize) < ctx.lines.len() {
            let info = ctx.line_info(start);
            ctx.compute_sub_lines(start);
            vp.end.line_no = start;
            vp.end.sub_line_no = 0;
            while vp.lines.len() < h && start_sl < ctx.sub_lines.entries.len() {
                let Some(sl) = ctx.sub_lines.entries.get(start_sl) else {
                    break;
                };
                vp.lines.push(ViewPortLine {
                    offset: info.offset.saturating_add(u64::from(sl.buffer_offset)),
                    size: sl.size,
                    line_no: start,
                    x_start: if start_sl == 0 {
                        0
                    } else {
                        ctx.sub_lines.left_alignament
                    },
                    line_char_index: sl.relative_char_index,
                });
                vp.end.sub_line_no = start_sl as u32;
                start_sl = start_sl.saturating_add(1);
            }
            start_sl = 0;
            start = start.saturating_add(1);
        }
    } else {
        // Fill backward ending at (line_no, sub_line_no), then put the
        // rows in top-to-bottom order (C++ fills a fixed array from
        // the tail and memmoves; the reversal is equivalent).
        let mut collected: Vec<ViewPortLine> = Vec::with_capacity(h);
        // `None` plays the role of the C++ signed indices going below
        // zero (loop exit).
        let mut line: Option<u32> = Some(line_no);
        let mut sub_index: Option<usize> = Some(sub_line_no as usize);
        let mut reset_sl = false;
        while collected.len() < h {
            let Some(line_u32) = line else { break };
            let info = ctx.line_info(line_u32);
            ctx.compute_sub_lines(line_u32);
            vp.start.line_no = line_u32;
            if reset_sl {
                sub_index = Some(ctx.sub_lines.entries.len().saturating_sub(1));
            }
            if let Some(idx) = sub_index {
                vp.start.sub_line_no = idx as u32;
            }
            while collected.len() < h {
                let Some(idx) = sub_index else { break };
                let Some(sl) = ctx.sub_lines.entries.get(idx) else {
                    break;
                };
                collected.push(ViewPortLine {
                    offset: info.offset.saturating_add(u64::from(sl.buffer_offset)),
                    size: sl.size,
                    line_no: line_u32,
                    x_start: if idx == 0 {
                        0
                    } else {
                        ctx.sub_lines.left_alignament
                    },
                    line_char_index: sl.relative_char_index,
                });
                vp.start.sub_line_no = idx as u32;
                sub_index = idx.checked_sub(1);
            }
            reset_sl = true;
            line = line_u32.checked_sub(1);
        }
        collected.reverse();
        vp.lines = collected;
    }
}

/// C++ `ComputeViewPort` (`Instance.cpp:745-751`).
pub fn compute_view_port(
    vp: &mut ViewPort,
    ctx: &mut TextViewContext<'_>,
    line_no: u32,
    sub_line_no: u32,
    dir: Direction,
) {
    if ctx.has_word_wrap() {
        compute_view_port_wrap(vp, ctx, line_no, sub_line_no, dir);
    } else {
        compute_view_port_no_wrap(vp, ctx, line_no, dir);
    }
}

/// C++ `UpdateCursor_NoWrap` (`Instance.cpp:1046-1088`): computes
/// `Cursor.pos` and adjusts `scroll_x` so the cursor column is
/// visible.
pub fn update_cursor_no_wrap(
    vp: &mut ViewPort,
    ctx: &mut TextViewContext<'_>,
    cursor: &mut TextCursor,
) {
    let li = ctx.line_info(cursor.line_no);
    if cursor.char_index == 0 {
        vp.scroll_x = 0;
        cursor.pos = li.offset;
        return;
    }
    let w = ctx.control_width;
    let gutter = ctx.line_number_width.saturating_add(1);
    let w = if w <= gutter {
        1
    } else {
        w.saturating_sub(gutter)
    };

    let bytes = ctx.line_bytes(li);
    let mut cs = CharacterStream::new(&bytes, 0, ctx.encoding, ctx.tab_size);
    let mut idx = 0_u32;
    while idx < cursor.char_index && cs.next_char() {
        idx = idx.saturating_add(1);
    }
    let new_x_pos;
    if idx == cursor.char_index {
        new_x_pos = cs.next_x_offset();
        cursor.pos = u64::from(cs.current_buffer_pos()).saturating_add(li.offset);
    } else {
        // C++ leaves a literal 0 here ("de vazut daca e ok").
        new_x_pos = 0;
        cursor.pos = 0;
    }
    if new_x_pos >= vp.scroll_x && new_x_pos < vp.scroll_x.saturating_add(w) {
        return; // already visible
    }
    if new_x_pos <= vp.scroll_x {
        vp.scroll_x = new_x_pos;
    } else {
        vp.scroll_x = if new_x_pos >= w {
            new_x_pos.saturating_add(1).saturating_sub(w)
        } else {
            0
        };
    }
}

/// C++ `UpdateCursor_Wrap` (`Instance.cpp:1089-1111`): recomputes the
/// sub-line and `Cursor.pos`.
pub fn update_cursor_wrap(ctx: &mut TextViewContext<'_>, cursor: &mut TextCursor) {
    let li = ctx.line_info(cursor.line_no);
    ctx.compute_sub_lines(cursor.line_no);
    cursor.subline_no = character_index_to_sub_line_no(ctx.sub_lines, cursor.char_index);
    let Some(sl) = ctx
        .sub_lines
        .entries
        .get(cursor.subline_no as usize)
        .copied()
    else {
        cursor.pos = 0;
        return;
    };
    let fragment_offset = li.offset.saturating_add(u64::from(sl.buffer_offset));
    let bytes = if sl.size == 0 {
        Vec::new()
    } else {
        ctx.cache
            .get(fragment_offset, sl.size, false)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    };
    let mut cs = CharacterStream::new(&bytes, 0, ctx.encoding, ctx.tab_size);
    let mut idx = sl.relative_char_index;
    while idx < cursor.char_index && cs.next_char() {
        idx = idx.saturating_add(1);
    }
    if idx == cursor.char_index {
        cursor.pos = u64::from(cs.current_buffer_pos()).saturating_add(fragment_offset);
    } else {
        cursor.pos = 0; // C++ parity
    }
}

fn update_cursor(vp: &mut ViewPort, ctx: &mut TextViewContext<'_>, cursor: &mut TextCursor) {
    if ctx.has_word_wrap() {
        update_cursor_wrap(ctx, cursor);
    } else {
        update_cursor_no_wrap(vp, ctx, cursor);
    }
}

/// C++ `UpdateViewPort` (`Instance.cpp:1112-1147`): ensures the
/// cursor is inside the viewport, re-centering when it moved out.
pub fn update_view_port(vp: &mut ViewPort, ctx: &mut TextViewContext<'_>, cursor: &mut TextCursor) {
    if vp.lines_count() == 0 {
        compute_view_port(vp, ctx, 0, 0, Direction::TopToBottom);
        update_cursor(vp, ctx, cursor);
    }
    let before_start = cursor.line_no < vp.start.line_no
        || (cursor.line_no == vp.start.line_no && cursor.subline_no < vp.start.sub_line_no);
    if before_start {
        compute_view_port(
            vp,
            ctx,
            cursor.line_no,
            cursor.subline_no,
            Direction::TopToBottom,
        );
        update_cursor(vp, ctx, cursor);
        return;
    }
    let after_end = cursor.line_no > vp.end.line_no
        || (cursor.line_no == vp.end.line_no && cursor.subline_no > vp.end.sub_line_no);
    if after_end {
        compute_view_port(
            vp,
            ctx,
            cursor.line_no,
            cursor.subline_no,
            Direction::BottomToTop,
        );
        update_cursor(vp, ctx, cursor);
        return;
    }
    update_cursor(vp, ctx, cursor);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_viewer::line_index::{analyze_encoding, build_line_index};
    use gview_core::source::MemorySource;

    struct Fixture {
        lines: Vec<LineInfo>,
        cache: DataCache,
        encoding: Encoding,
        sub_lines: SubLines,
    }

    impl Fixture {
        fn new(data: &[u8]) -> Self {
            let mut cache = DataCache::new(Box::new(MemorySource::from_slice(data)), 0);
            let info = analyze_encoding(data);
            let lines = build_line_index(&mut cache, info.encoding, info.bom_size);
            Self {
                lines,
                cache,
                encoding: info.encoding,
                sub_lines: SubLines::default(),
            }
        }

        fn ctx(&mut self, wrap: WrapMethod, width: u32, height: u32) -> TextViewContext<'_> {
            TextViewContext {
                lines: &self.lines,
                cache: &mut self.cache,
                encoding: self.encoding,
                wrap_method: wrap,
                tab_size: 4,
                control_width: width,
                control_height: height,
                line_number_width: 2,
                sub_lines: &mut self.sub_lines,
            }
        }
    }

    fn ten_lines() -> Vec<u8> {
        let mut data = Vec::new();
        for i in 0..10 {
            data.extend_from_slice(format!("line-{i:02}\n").as_bytes());
        }
        data
    }

    #[test]
    fn no_wrap_top_to_bottom_window() {
        let mut f = Fixture::new(&ten_lines());
        let mut ctx = f.ctx(WrapMethod::None, 40, 6);
        let mut vp = ViewPort::default();
        // h = min(6, 256) - 1 = 5 → lines 2..=7.
        compute_view_port(&mut vp, &mut ctx, 2, 0, Direction::TopToBottom);
        assert_eq!(vp.start.line_no, 2);
        assert_eq!(vp.end.line_no, 7);
        assert_eq!(vp.lines_count(), 6);
        assert_eq!(vp.lines[0].line_no, 2);
        assert_eq!(vp.lines[5].line_no, 7);
        // Clamped at the file end.
        compute_view_port(&mut vp, &mut ctx, 8, 0, Direction::TopToBottom);
        assert_eq!(vp.end.line_no, 9);
        assert_eq!(vp.lines_count(), 2);
    }

    #[test]
    fn no_wrap_bottom_to_top_anchors_last_line() {
        let mut f = Fixture::new(&ten_lines());
        let mut ctx = f.ctx(WrapMethod::None, 40, 6);
        let mut vp = ViewPort::default();
        compute_view_port(&mut vp, &mut ctx, 9, 0, Direction::BottomToTop);
        assert_eq!(vp.start.line_no, 4);
        assert_eq!(vp.end.line_no, 9);
        assert_eq!(vp.lines_count(), 6);
        // Near the top: start clamps to 0.
        compute_view_port(&mut vp, &mut ctx, 3, 0, Direction::BottomToTop);
        assert_eq!(vp.start.line_no, 0);
    }

    #[test]
    fn update_view_port_recenters_when_cursor_outside() {
        let mut f = Fixture::new(&ten_lines());
        let mut ctx = f.ctx(WrapMethod::None, 40, 4);
        let mut vp = ViewPort::default();
        let mut cursor = TextCursor::default();
        // Initial: empty viewport → computed from line 0.
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        assert_eq!(vp.start.line_no, 0);
        assert_eq!(vp.end.line_no, 3);
        // Cursor moves past the end → scrolls so the cursor is last.
        cursor.line_no = 8;
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        assert_eq!(vp.end.line_no, 8);
        assert_eq!(vp.start.line_no, 5);
        // Cursor moves before the start → cursor becomes first line.
        cursor.line_no = 1;
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        assert_eq!(vp.start.line_no, 1);
        assert_eq!(vp.end.line_no, 4);
        // Cursor inside: viewport untouched.
        cursor.line_no = 3;
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        assert_eq!(vp.start.line_no, 1);
        assert_eq!(vp.end.line_no, 4);
    }

    #[test]
    fn cursor_pos_synchronized_from_line_and_char() {
        let mut f = Fixture::new(&ten_lines());
        let mut ctx = f.ctx(WrapMethod::None, 40, 6);
        let mut vp = ViewPort::default();
        let mut cursor = TextCursor {
            line_no: 2,
            char_index: 3,
            ..Default::default()
        };
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        // Line 2 starts at byte 16 ("line-NN\n" = 8 bytes each).
        assert_eq!(cursor.pos, 16 + 3);
        // char_index 0 → line start, scroll reset.
        cursor.char_index = 0;
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        assert_eq!(cursor.pos, 16);
        assert_eq!(vp.scroll_x, 0);
    }

    #[test]
    fn scroll_x_follows_cursor_on_long_line() {
        // One long unwrapped line; width 12, gutter 2+1 → w = 9.
        let data = vec![b'a'; 100];
        let mut f = Fixture::new(&data);
        let mut ctx = f.ctx(WrapMethod::None, 12, 6);
        let mut vp = ViewPort::default();
        let mut cursor = TextCursor {
            char_index: 50,
            ..Default::default()
        };
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        // The walk stops on char 49; newXPos = 50 → scrollX = 50+1-9.
        assert_eq!(vp.scroll_x, 42);
        // Moving left inside the visible window keeps scrollX.
        cursor.char_index = 45;
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        assert_eq!(vp.scroll_x, 42);
        // Moving further left pulls the window back to the column.
        cursor.char_index = 10;
        update_view_port(&mut vp, &mut ctx, &mut cursor);
        assert_eq!(vp.scroll_x, 10);
    }

    #[test]
    fn wrap_viewport_emits_sublines_with_alignament() {
        // A single 30-char line wrapped at ~8 columns (width 12,
        // gutter 2+2).
        let data = vec![b'x'; 30];
        let mut f = Fixture::new(&data);
        let mut ctx = f.ctx(WrapMethod::LeftMargin, 12, 6);
        let mut vp = ViewPort::default();
        compute_view_port(&mut vp, &mut ctx, 0, 0, Direction::TopToBottom);
        assert!(vp.lines_count() >= 3);
        assert_eq!(vp.lines[0].x_start, 0);
        // Continuation fragments advance through the same line.
        assert_eq!(vp.lines[1].line_no, 0);
        assert!(vp.lines[1].line_char_index > 0);
        assert_eq!(vp.lines[1].offset, u64::from(vp.lines[0].size));
    }

    #[test]
    fn wrap_bottom_to_top_ends_at_anchor() {
        // Several wrapped lines; anchor at (2, 0) from the bottom.
        let mut data = Vec::new();
        for _ in 0..3 {
            data.extend_from_slice(&[b'z'; 20]);
            data.push(b'\n');
        }
        let mut f = Fixture::new(&data);
        let mut ctx = f.ctx(WrapMethod::LeftMargin, 12, 4);
        let mut vp = ViewPort::default();
        compute_view_port(&mut vp, &mut ctx, 2, 0, Direction::BottomToTop);
        assert_eq!(vp.lines_count(), 4);
        // Last row is the anchor.
        let last = vp.lines.last().expect("rows");
        assert_eq!(last.line_no, 2);
        assert_eq!(last.line_char_index, 0);
        assert_eq!(
            vp.end,
            LinePos {
                line_no: 2,
                sub_line_no: 0
            }
        );
    }
}
