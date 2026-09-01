//! `TextViewer` keyboard navigation.
//!
//! C++ anchors: `Instance::OnKeyEvent` (`Instance.cpp:1292-1380`),
//! movement helpers (`Instance.cpp:752-1045`), `OpenCurrentSelection`
//! (`Instance.cpp:302-324`), `CharsGroups`/`GetCharGroup`
//! (`Instance.cpp:186-195`); spec `02_VIEWER_TEXT` §5.1, §8.
//! Note: `ShowFindDialog()` is `NOT_IMPLEMENTED` in the C++
//! `TextViewer` — there is deliberately no find action here.

use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::selection::Selection;

use super::line_index::{decode_char, Encoding, LineInfo};
use super::viewport::{
    compute_view_port, update_view_port, Direction, TextCursor, TextViewContext, ViewPort,
};
use super::wrap::character_index_to_sub_line_no;

/// One §8 matrix action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextNavAction {
    /// Left: previous char / previous line end.
    MoveLeft {
        /// Shift held.
        select: bool,
    },
    /// Right: next char / next line start.
    MoveRight {
        /// Shift held.
        select: bool,
    },
    /// Ctrl+Left: previous word boundary.
    WordLeft {
        /// Shift held.
        select: bool,
    },
    /// Ctrl+Right: next word boundary.
    WordRight {
        /// Shift held.
        select: bool,
    },
    /// Up: previous line / sub-line.
    MoveUp {
        /// Shift held.
        select: bool,
    },
    /// Down: next line / sub-line.
    MoveDown {
        /// Shift held.
        select: bool,
    },
    /// Ctrl+Up: scroll the viewport up, cursor follows if pushed out.
    ScrollUp,
    /// Ctrl+Down: scroll the viewport down.
    ScrollDown,
    /// `PageUp`: up by `max(1, height)` rows.
    PageUp {
        /// Shift held.
        select: bool,
    },
    /// `PageDown`: down by `max(1, height)` rows.
    PageDown {
        /// Shift held.
        select: bool,
    },
    /// Home: line start.
    LineStart {
        /// Shift held.
        select: bool,
    },
    /// End: line end.
    LineEnd {
        /// Shift held.
        select: bool,
    },
    /// Ctrl+Home: `MoveTo(0, 0)`.
    FileStart {
        /// Shift held.
        select: bool,
    },
    /// Ctrl+End: last line end.
    FileEnd {
        /// Shift held.
        select: bool,
    },
    /// Enter: open the selection under the cursor in a new buffer
    /// window.
    OpenSelection,
}

/// Maps a key to its §8 action (C++ `OnKeyEvent` switch).
#[must_use]
pub fn text_action_for_key(key: Key) -> Option<TextNavAction> {
    let none = key.modifier == KeyModifier::None;
    let shift = key.modifier == KeyModifier::Shift;
    let ctrl = key.modifier == KeyModifier::Ctrl;
    let ctrl_shift = key.modifier == KeyModifier::Ctrl | KeyModifier::Shift;
    let select = shift || ctrl_shift;
    match key.code {
        KeyCode::Left if none || shift => Some(TextNavAction::MoveLeft { select }),
        KeyCode::Left if ctrl || ctrl_shift => Some(TextNavAction::WordLeft { select }),
        KeyCode::Right if none || shift => Some(TextNavAction::MoveRight { select }),
        KeyCode::Right if ctrl || ctrl_shift => Some(TextNavAction::WordRight { select }),
        KeyCode::Up if none || shift => Some(TextNavAction::MoveUp { select }),
        KeyCode::Up if ctrl => Some(TextNavAction::ScrollUp),
        KeyCode::Down if none || shift => Some(TextNavAction::MoveDown { select }),
        KeyCode::Down if ctrl => Some(TextNavAction::ScrollDown),
        KeyCode::PageUp if none || shift => Some(TextNavAction::PageUp { select }),
        KeyCode::PageDown if none || shift => Some(TextNavAction::PageDown { select }),
        KeyCode::Home if none || shift => Some(TextNavAction::LineStart { select }),
        KeyCode::Home if ctrl || ctrl_shift => Some(TextNavAction::FileStart { select }),
        KeyCode::End if none || shift => Some(TextNavAction::LineEnd { select }),
        KeyCode::End if ctrl || ctrl_shift => Some(TextNavAction::FileEnd { select }),
        KeyCode::Enter if none => Some(TextNavAction::OpenSelection),
        _ => None,
    }
}

/// C++ `GetCharGroup` over `CharsGroups[128]`
/// (`Instance.cpp:186-195`); `ch >= 128` → letter group 1.
#[must_use]
pub fn char_group(ch: u32) -> u8 {
    const CHARS_GROUPS: [u8; 128] = [
        0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 0, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 1, 46, 47, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 58, 59, 60, 61, 62, 63, 64, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 91, 92, 93, 94, 1, 96, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 123, 124, 125, 126, 127,
    ];
    CHARS_GROUPS.get(ch as usize).copied().unwrap_or(1)
}

/// C++ `MoveTo(lineNo, charIndex, select)`
/// (`Instance.cpp:752-792`): clamps, recomputes the sub-line, syncs
/// the viewport and extends the selection.
pub fn move_to(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    line_no: u32,
    char_index: u32,
    select: bool,
) {
    let selection_index = if select {
        selection.begin_selection(cursor.pos)
    } else {
        None
    };
    let line_no = if ctx.lines.is_empty() {
        0
    } else {
        u32::min(line_no, (ctx.lines.len() as u32).saturating_sub(1))
    };
    let li = ctx.line_info(line_no);
    let char_index = if char_index >= li.char_count {
        li.char_count.saturating_sub(1)
    } else {
        char_index
    };
    cursor.line_no = line_no;
    cursor.char_index = char_index;
    if ctx.has_word_wrap() {
        ctx.compute_sub_lines(line_no);
        cursor.subline_no = character_index_to_sub_line_no(ctx.sub_lines, char_index);
    } else {
        cursor.subline_no = 0;
    }
    update_view_port(vp, ctx, cursor);
    if select {
        if let Some(index) = selection_index {
            selection.update_selection(index, cursor.pos);
        }
    }
}

/// C++ `MoveToStartOfLine` (`Instance.cpp:793-799`).
pub fn move_to_start_of_line(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    line_no: u32,
    select: bool,
) {
    if line_no as usize >= ctx.lines.len() {
        let last = (ctx.lines.len() as u32).saturating_sub(1);
        move_to_end_of_line(ctx, vp, cursor, selection, last, select);
    } else {
        move_to(ctx, vp, cursor, selection, line_no, 0, select);
    }
}

/// C++ `MoveToEndOfLine` (`Instance.cpp:800-807`).
pub fn move_to_end_of_line(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    line_no: u32,
    select: bool,
) {
    let li = ctx.line_info(line_no);
    let char_index = li.char_count.saturating_sub(1);
    move_to(ctx, vp, cursor, selection, line_no, char_index, select);
}

/// C++ `MoveToEndOfFile` (`Instance.cpp:808-813`).
pub fn move_to_end_of_file(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    select: bool,
) {
    if ctx.lines.is_empty() {
        return;
    }
    let last = (ctx.lines.len() as u32).saturating_sub(1);
    move_to(ctx, vp, cursor, selection, last, u32::MAX, select);
}

/// C++ `MoveLeft` (`Instance.cpp:814-827`).
pub fn move_left(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    select: bool,
) {
    if cursor.char_index > 0 {
        let target = cursor.char_index.saturating_sub(1);
        move_to(ctx, vp, cursor, selection, cursor.line_no, target, select);
    } else if cursor.line_no == 0 {
        move_to(ctx, vp, cursor, selection, 0, 0, select);
    } else {
        let prev = cursor.line_no.saturating_sub(1);
        move_to_end_of_line(ctx, vp, cursor, selection, prev, select);
    }
}

/// C++ `MoveRight` (`Instance.cpp:828-835`).
pub fn move_right(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    select: bool,
) {
    let li = ctx.line_info(cursor.line_no);
    if cursor.char_index.saturating_add(1) < li.char_count {
        let target = cursor.char_index.saturating_add(1);
        move_to(ctx, vp, cursor, selection, cursor.line_no, target, select);
    } else {
        let next = cursor.line_no.saturating_add(1);
        move_to_start_of_line(ctx, vp, cursor, selection, next, select);
    }
}

fn wrap_char_index_dif(ctx: &mut TextViewContext<'_>, cursor: TextCursor) -> (u32, u32) {
    ctx.compute_sub_lines(cursor.line_no);
    let sl_index = character_index_to_sub_line_no(ctx.sub_lines, cursor.char_index);
    let dif = ctx
        .sub_lines
        .entries
        .get(sl_index as usize)
        .map_or(0, |sl| {
            cursor.char_index.saturating_sub(sl.relative_char_index)
        });
    (sl_index, dif)
}

// Mirrors the C++ tail of MoveUp/MoveDown, which reads the same set
// of instance fields.
#[allow(clippy::too_many_arguments)]
fn move_to_sub_line(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    line_no: u32,
    sl_index: u32,
    char_index_dif: u32,
    select: bool,
) {
    let Some(sl) = ctx.sub_lines.entries.get(sl_index as usize).copied() else {
        return;
    };
    let char_index = if sl.chars_count == 0 {
        sl.relative_char_index
    } else {
        sl.relative_char_index
            .saturating_add(u32::min(sl.chars_count.saturating_sub(1), char_index_dif))
    };
    move_to(ctx, vp, cursor, selection, line_no, char_index, select);
}

/// C++ `MoveUp` (`Instance.cpp:984-1045`): in wrap mode moves by
/// sub-lines preserving the character offset within the sub-line.
pub fn move_up(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    mut no_of_times: u32,
    select: bool,
) {
    if ctx.has_word_wrap() {
        let mut line_no = cursor.line_no;
        let (mut sl_index, char_index_dif) = wrap_char_index_dif(ctx, *cursor);
        loop {
            ctx.compute_sub_lines(line_no);
            let dif = u32::min(no_of_times, sl_index);
            no_of_times = no_of_times.saturating_sub(dif);
            sl_index = sl_index.saturating_sub(dif);
            if no_of_times > 0 {
                if line_no > 0 {
                    line_no = line_no.saturating_sub(1);
                    ctx.compute_sub_lines(line_no);
                    sl_index = (ctx.sub_lines.entries.len() as u32).saturating_sub(1);
                    no_of_times = no_of_times.saturating_sub(1);
                    if no_of_times == 0 {
                        break;
                    }
                } else {
                    move_to_start_of_line(ctx, vp, cursor, selection, 0, select);
                    return;
                }
            } else {
                break;
            }
        }
        move_to_sub_line(
            ctx,
            vp,
            cursor,
            selection,
            line_no,
            sl_index,
            char_index_dif,
            select,
        );
    } else if cursor.line_no == 0 {
        move_to_start_of_line(ctx, vp, cursor, selection, 0, select);
    } else {
        let target = cursor.line_no.saturating_sub(no_of_times);
        let char_index = cursor.char_index;
        move_to(ctx, vp, cursor, selection, target, char_index, select);
    }
}

/// C++ `MoveDown` (`Instance.cpp:848-920`).
pub fn move_down(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    mut no_of_times: u32,
    select: bool,
) {
    if ctx.lines.is_empty() {
        return;
    }
    let last_line = (ctx.lines.len() as u32).saturating_sub(1);
    if ctx.has_word_wrap() {
        let mut line_no = cursor.line_no;
        let (mut sl_index, char_index_dif) = wrap_char_index_dif(ctx, *cursor);
        let initial_sub_line = sl_index;
        loop {
            ctx.compute_sub_lines(line_no);
            let sl_count = ctx.sub_lines.entries.len() as u32;
            let dif = u32::min(no_of_times, sl_count.saturating_sub(sl_index));
            no_of_times = no_of_times.saturating_sub(dif);
            sl_index = sl_index.saturating_add(dif);
            if no_of_times > 0 {
                line_no = line_no.saturating_add(1);
                sl_index = 0;
                if line_no > last_line {
                    line_no = last_line;
                    no_of_times = 0;
                    sl_index = sl_count.saturating_sub(1);
                }
            } else {
                if sl_index >= sl_count {
                    if line_no < last_line {
                        line_no = line_no.saturating_add(1);
                        sl_index = 0;
                        ctx.compute_sub_lines(line_no);
                    } else if initial_sub_line.saturating_add(1) == sl_count {
                        move_to_end_of_line(ctx, vp, cursor, selection, last_line, select);
                        return;
                    } else {
                        sl_index = sl_count.saturating_sub(1);
                    }
                }
                break;
            }
        }
        ctx.compute_sub_lines(line_no);
        move_to_sub_line(
            ctx,
            vp,
            cursor,
            selection,
            line_no,
            sl_index,
            char_index_dif,
            select,
        );
    } else if cursor.line_no == last_line {
        move_to_end_of_line(ctx, vp, cursor, selection, last_line, select);
    } else {
        let target = u32::min(last_line, cursor.line_no.saturating_add(no_of_times));
        let char_index = cursor.char_index;
        move_to(ctx, vp, cursor, selection, target, char_index, select);
    }
}

/// C++ `MoveScrollDown` (`Instance.cpp:921-942`).
pub fn move_scroll_down(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
) {
    if ctx.has_word_wrap() {
        ctx.compute_sub_lines(vp.start.line_no);
        if cursor.line_no == vp.start.line_no && cursor.subline_no == vp.start.sub_line_no {
            move_down(ctx, vp, cursor, selection, 1, false);
        }
        ctx.compute_sub_lines(vp.start.line_no);
        if (vp.start.sub_line_no as usize).saturating_add(1) < ctx.sub_lines.entries.len() {
            let (line, sl) = (vp.start.line_no, vp.start.sub_line_no.saturating_add(1));
            compute_view_port(vp, ctx, line, sl, Direction::TopToBottom);
        } else {
            let line = vp.start.line_no.saturating_add(1);
            compute_view_port(vp, ctx, line, 0, Direction::TopToBottom);
        }
    } else {
        if cursor.line_no == vp.start.line_no {
            move_down(ctx, vp, cursor, selection, 1, false);
        }
        let line = vp.start.line_no.saturating_add(1);
        compute_view_port(vp, ctx, line, 0, Direction::TopToBottom);
    }
    update_view_port(vp, ctx, cursor);
}

/// C++ `MoveScrollUp` (`Instance.cpp:943-971`).
pub fn move_scroll_up(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
) {
    if ctx.has_word_wrap() {
        if vp.start.line_no == 0 && vp.start.sub_line_no == 0 {
            return;
        }
        ctx.compute_sub_lines(vp.end.line_no);
        if cursor.line_no == vp.end.line_no && cursor.subline_no == vp.end.sub_line_no {
            move_up(ctx, vp, cursor, selection, 1, false);
        }
        if vp.start.sub_line_no > 0 {
            let (line, sl) = (vp.start.line_no, vp.start.sub_line_no.saturating_sub(1));
            compute_view_port(vp, ctx, line, sl, Direction::TopToBottom);
        } else {
            let line = vp.start.line_no.saturating_sub(1);
            ctx.compute_sub_lines(line);
            let sl = (ctx.sub_lines.entries.len() as u32).saturating_sub(1);
            compute_view_port(vp, ctx, line, sl, Direction::TopToBottom);
        }
    } else if vp.start.line_no > 0 {
        if cursor.line_no == vp.end.line_no {
            move_up(ctx, vp, cursor, selection, 1, false);
        }
        let line = vp.start.line_no.saturating_sub(1);
        compute_view_port(vp, ctx, line, 0, Direction::TopToBottom);
    }
    update_view_port(vp, ctx, cursor);
}

/// Reads one logical line's decoded characters.
fn decode_line(ctx: &mut TextViewContext<'_>, line: LineInfo) -> Vec<u32> {
    let bytes = if line.byte_size == 0 {
        Vec::new()
    } else {
        ctx.cache
            .get(line.offset, line.byte_size, false)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    };
    decode_all(&bytes, ctx.encoding)
}

fn decode_all(bytes: &[u8], encoding: Encoding) -> Vec<u32> {
    let mut chars = Vec::new();
    let mut at = 0_usize;
    while at < bytes.len() {
        if let Some((ch, len)) = decode_char(encoding, bytes, at) {
            chars.push(ch);
            at = at.saturating_add(len);
        } else {
            chars.push(bytes.get(at).copied().map_or(0, u32::from));
            at = at.saturating_add(1);
        }
    }
    chars
}

/// Cross-line character walk (C++ `DataCharacterStream`,
/// `Instance.cpp:197+`), used by word navigation.
struct DataCharacterWalk {
    line_no: u32,
    char_index: u32,
    chars: Vec<u32>,
}

impl DataCharacterWalk {
    fn init(ctx: &mut TextViewContext<'_>, line_no: u32, char_index: u32) -> Option<Self> {
        if line_no as usize >= ctx.lines.len() {
            return None;
        }
        let chars = decode_line(ctx, ctx.line_info(line_no));
        let char_index = u32::min(char_index, (chars.len() as u32).saturating_sub(1));
        Some(Self {
            line_no,
            char_index,
            chars,
        })
    }

    fn get_char(&self) -> u32 {
        self.chars
            .get(self.char_index as usize)
            .copied()
            .unwrap_or(0)
    }

    fn next(&mut self, ctx: &mut TextViewContext<'_>) -> bool {
        if (self.char_index as usize).saturating_add(1) < self.chars.len() {
            self.char_index = self.char_index.saturating_add(1);
            return true;
        }
        let next_line = self.line_no.saturating_add(1);
        if (next_line as usize) >= ctx.lines.len() {
            return false;
        }
        self.line_no = next_line;
        self.chars = decode_line(ctx, ctx.line_info(next_line));
        self.char_index = 0;
        true
    }

    fn previous(&mut self, ctx: &mut TextViewContext<'_>) -> bool {
        if self.char_index > 0 {
            self.char_index = self.char_index.saturating_sub(1);
            return true;
        }
        if self.line_no == 0 {
            return false;
        }
        self.line_no = self.line_no.saturating_sub(1);
        self.chars = decode_line(ctx, ctx.line_info(self.line_no));
        self.char_index = (self.chars.len() as u32).saturating_sub(1);
        true
    }
}

/// C++ `MoveToNextWord` (`Instance.cpp:836-847`).
pub fn move_to_next_word(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    select: bool,
) {
    let Some(mut walk) = DataCharacterWalk::init(ctx, cursor.line_no, cursor.char_index) else {
        return;
    };
    let group = char_group(walk.get_char());
    while walk.next(ctx) && char_group(walk.get_char()) == group {}
    let (line, idx) = (walk.line_no, walk.char_index);
    move_to(ctx, vp, cursor, selection, line, idx, select);
}

/// C++ `MoveToPreviousWord` (`Instance.cpp:972-983`).
pub fn move_to_previous_word(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
    select: bool,
) {
    let Some(mut walk) = DataCharacterWalk::init(ctx, cursor.line_no, cursor.char_index) else {
        return;
    };
    let group = char_group(walk.get_char());
    while walk.previous(ctx) && char_group(walk.get_char()) == group {}
    let (line, idx) = (walk.line_no, walk.char_index);
    move_to(ctx, vp, cursor, selection, line, idx, select);
}

/// Request produced by Enter (C++ `OpenCurrentSelection`,
/// `Instance.cpp:302-324`): the shell copies `[start, start+size)`
/// and opens it as a new buffer window with `Select` type choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSelectionRequest {
    /// First selected byte.
    pub start: u64,
    /// Selection size in bytes (inclusive range + 1).
    pub size: u64,
    /// Suggested buffer name (`Buffer_{start:x}_{end:x}`).
    pub name: String,
}

/// Enter: resolves the selection zone containing the cursor and
/// returns the open request, or `None` when the cursor is outside
/// every selection.
#[must_use]
pub fn open_current_selection(
    selection: &Selection,
    cursor: TextCursor,
) -> Option<OpenSelectionRequest> {
    let (_, start, end) = selection.offset_to_selection(cursor.pos)?;
    Some(OpenSelectionRequest {
        start,
        size: end.saturating_sub(start).saturating_add(1),
        name: format!("Buffer_{start:x}_{end:x}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_viewer::line_index::{analyze_encoding, build_line_index};
    use crate::text_viewer::wrap::{SubLines, WrapMethod};
    use gview_core::cache::DataCache;
    use gview_core::source::MemorySource;

    struct Fixture {
        lines: Vec<LineInfo>,
        cache: DataCache,
        encoding: Encoding,
        sub_lines: SubLines,
        wrap: WrapMethod,
        width: u32,
        height: u32,
    }

    impl Fixture {
        fn new(data: &[u8], wrap: WrapMethod, width: u32, height: u32) -> Self {
            let mut cache = DataCache::new(Box::new(MemorySource::from_slice(data)), 0);
            let info = analyze_encoding(data);
            let lines = build_line_index(&mut cache, info.encoding, info.bom_size);
            Self {
                lines,
                cache,
                encoding: info.encoding,
                sub_lines: SubLines::default(),
                wrap,
                width,
                height,
            }
        }

        fn run(
            &mut self,
            vp: &mut ViewPort,
            cursor: &mut TextCursor,
            selection: &mut Selection,
            f: impl FnOnce(&mut TextViewContext<'_>, &mut ViewPort, &mut TextCursor, &mut Selection),
        ) {
            let mut ctx = TextViewContext {
                lines: &self.lines,
                cache: &mut self.cache,
                encoding: self.encoding,
                wrap_method: self.wrap,
                tab_size: 4,
                control_width: self.width,
                control_height: self.height,
                line_number_width: 2,
                sub_lines: &mut self.sub_lines,
            };
            f(&mut ctx, vp, cursor, selection);
        }
    }

    #[test]
    fn move_up_preserves_char_index_across_sub_lines() {
        // One 30-char wrapped line (≈8 cols): cursor on the second
        // sub-line at intra-fragment offset 3; MoveUp keeps offset 3
        // within the first sub-line.
        let data = vec![b'q'; 30];
        let mut f = Fixture::new(&data, WrapMethod::LeftMargin, 12, 8);
        let mut vp = ViewPort::default();
        let mut cursor = TextCursor::default();
        let mut sel = Selection::new();
        f.run(&mut vp, &mut cursor, &mut sel, |ctx, vp, cursor, sel| {
            // Sub-line 1 starts at char 9 (first fragment holds 9).
            move_to(ctx, vp, cursor, sel, 0, 12, false);
            assert_eq!(cursor.subline_no, 1);
            move_up(ctx, vp, cursor, sel, 1, false);
            // charIndexDif = 12 - 9 = 3 → first sub-line char 3.
            assert_eq!(cursor.line_no, 0);
            assert_eq!(cursor.subline_no, 0);
            assert_eq!(cursor.char_index, 3);
        });
    }

    #[test]
    fn move_down_preserves_char_index_across_sub_lines() {
        let data = vec![b'q'; 30];
        let mut f = Fixture::new(&data, WrapMethod::LeftMargin, 12, 8);
        let mut vp = ViewPort::default();
        let mut cursor = TextCursor::default();
        let mut sel = Selection::new();
        f.run(&mut vp, &mut cursor, &mut sel, |ctx, vp, cursor, sel| {
            move_to(ctx, vp, cursor, sel, 0, 3, false);
            assert_eq!(cursor.subline_no, 0);
            move_down(ctx, vp, cursor, sel, 1, false);
            // Next sub-line starts at char 9 → 9 + 3.
            assert_eq!(cursor.subline_no, 1);
            assert_eq!(cursor.char_index, 12);
        });
    }

    #[test]
    fn enter_opens_buffer_at_selection_offset() {
        let data = b"hello selected world";
        let f = Fixture::new(data, WrapMethod::None, 40, 6);
        drop(f);
        let mut selection = Selection::new();
        assert!(selection.set_selection(0, 6, 13)); // "selected"
        let cursor = TextCursor {
            pos: 8,
            ..Default::default()
        };
        let request = open_current_selection(&selection, cursor).expect("selection under cursor");
        assert_eq!(request.start, 6);
        assert_eq!(request.size, 8);
        assert_eq!(request.name, "Buffer_6_d");
        // Cursor outside the selection: nothing to open.
        let outside = TextCursor {
            pos: 1,
            ..Default::default()
        };
        assert!(open_current_selection(&selection, outside).is_none());
    }

    #[test]
    fn plain_line_navigation() {
        let mut data = Vec::new();
        for i in 0..5 {
            data.extend_from_slice(format!("row{i}x\n").as_bytes());
        }
        let mut f = Fixture::new(&data, WrapMethod::None, 40, 6);
        let mut vp = ViewPort::default();
        let mut cursor = TextCursor::default();
        let mut sel = Selection::new();
        f.run(&mut vp, &mut cursor, &mut sel, |ctx, vp, cursor, sel| {
            move_down(ctx, vp, cursor, sel, 2, false);
            assert_eq!(cursor.line_no, 2);
            move_right(ctx, vp, cursor, sel, false);
            assert_eq!(cursor.char_index, 1);
            // Right at line end hops to the next line start.
            move_to_end_of_line(ctx, vp, cursor, sel, 2, false);
            move_right(ctx, vp, cursor, sel, false);
            assert_eq!((cursor.line_no, cursor.char_index), (3, 0));
            // Left at line start hops to the previous line end.
            move_left(ctx, vp, cursor, sel, false);
            assert_eq!(cursor.line_no, 2);
            assert_eq!(cursor.char_index, 4);
            // Ctrl+Home / Ctrl+End.
            move_to(ctx, vp, cursor, sel, 0, 0, false);
            assert_eq!(cursor.pos, 0);
            move_to_end_of_file(ctx, vp, cursor, sel, false);
            assert_eq!(cursor.line_no, 4);
        });
    }

    #[test]
    fn word_navigation_crosses_boundaries() {
        let data = b"foo bar\nbaz";
        let mut f = Fixture::new(data, WrapMethod::None, 40, 6);
        let mut vp = ViewPort::default();
        let mut cursor = TextCursor::default();
        let mut sel = Selection::new();
        f.run(&mut vp, &mut cursor, &mut sel, |ctx, vp, cursor, sel| {
            // From 'f' (letter group): skip letters → space at 3.
            move_to_next_word(ctx, vp, cursor, sel, false);
            assert_eq!((cursor.line_no, cursor.char_index), (0, 3));
            // From the space: skip spaces → 'b' at 4.
            move_to_next_word(ctx, vp, cursor, sel, false);
            assert_eq!((cursor.line_no, cursor.char_index), (0, 4));
            // Next word crosses into line 1 ("bar" then "baz").
            move_to_next_word(ctx, vp, cursor, sel, false);
            assert_eq!(cursor.line_no, 1);
        });
    }

    #[test]
    fn shift_variants_extend_selection() {
        let mut data = Vec::new();
        for _ in 0..3 {
            data.extend_from_slice(b"abcdef\n");
        }
        let mut f = Fixture::new(&data, WrapMethod::None, 40, 6);
        let mut vp = ViewPort::default();
        let mut cursor = TextCursor::default();
        let mut sel = Selection::new();
        f.run(&mut vp, &mut cursor, &mut sel, |ctx, vp, cursor, sel| {
            update_view_port(vp, ctx, cursor);
            move_down(ctx, vp, cursor, sel, 1, true);
            // Selected from offset 0 to line 1 char 0 (offset 7).
            assert_eq!(sel.get_selection(0), Some((0, 7)));
        });
    }

    #[test]
    fn key_mapping_matrix() {
        use KeyCode as K;
        let none = KeyModifier::None;
        let key = Key::new;
        assert_eq!(
            text_action_for_key(key(K::Up, none)),
            Some(TextNavAction::MoveUp { select: false })
        );
        assert_eq!(
            text_action_for_key(key(K::Down, KeyModifier::Shift)),
            Some(TextNavAction::MoveDown { select: true })
        );
        assert_eq!(
            text_action_for_key(key(K::Up, KeyModifier::Ctrl)),
            Some(TextNavAction::ScrollUp)
        );
        assert_eq!(
            text_action_for_key(key(K::Left, KeyModifier::Ctrl)),
            Some(TextNavAction::WordLeft { select: false })
        );
        assert_eq!(
            text_action_for_key(key(K::Right, KeyModifier::Ctrl | KeyModifier::Shift)),
            Some(TextNavAction::WordRight { select: true })
        );
        assert_eq!(
            text_action_for_key(key(K::Home, KeyModifier::Ctrl)),
            Some(TextNavAction::FileStart { select: false })
        );
        assert_eq!(
            text_action_for_key(key(K::End, KeyModifier::Ctrl | KeyModifier::Shift)),
            Some(TextNavAction::FileEnd { select: true })
        );
        assert_eq!(
            text_action_for_key(key(K::Enter, none)),
            Some(TextNavAction::OpenSelection)
        );
        // No find shortcut: C++ TextViewer's ShowFindDialog is a stub.
        assert_eq!(text_action_for_key(key(K::F7, KeyModifier::Alt)), None);
    }

    #[test]
    fn char_groups_match_cpp_table() {
        assert_eq!(char_group(u32::from(b'a')), 1);
        assert_eq!(char_group(u32::from(b'Z')), 1);
        assert_eq!(char_group(u32::from(b'0')), 1);
        assert_eq!(char_group(u32::from(b' ')), 0);
        assert_eq!(char_group(u32::from(b'\t')), 0);
        assert_eq!(char_group(u32::from(b'+')), 43);
        assert_eq!(char_group(u32::from(b'(')), 40);
        assert_eq!(char_group(200), 1); // >= 128 → letter group
    }
}
