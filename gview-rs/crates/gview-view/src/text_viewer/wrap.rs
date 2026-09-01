//! `TextViewer` word-wrap sub-lines.
//!
//! C++ anchors: `Instance::ComputeSubLineIndexes`
//! (`Instance.cpp:461-582`), `CharacterStream` (`Instance.cpp:19-133`),
//! `CharacterIndexToSubLineNo` (`Instance.cpp:583-621`); spec
//! `02_VIEWER_TEXT` §4.1.
//! Wrapping is **not** word-boundary based: a sub-line is emitted
//! when a character's next x-offset exceeds the available width, and
//! the overflowing character stays in the emitted sub-line (the C++
//! break runs after the stream has consumed it). Continuation lines
//! start at `left_alignament` per the wrap method.

use super::line_index::{decode_char, Encoding, LineInfo};

/// Sentinel for "sub-lines need recomputation"
/// (C++ `INVALID_LINE_NUMBER`).
pub const INVALID_LINE_NUMBER: u32 = u32::MAX;

/// Wrap behavior (C++ `WrapMethod`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapMethod {
    /// One sub-line covering the whole logical line.
    None,
    /// Continuations start at column 0.
    LeftMargin,
    /// Continuations align under the first non-space character.
    Padding,
    /// `- * . )` bullet prefixes set the continuation column.
    Bullets,
}

/// One wrapped fragment (C++ `SubLineInfo`); offsets/indices are
/// relative to the logical line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubLineInfo {
    /// Byte offset inside the line.
    pub buffer_offset: u32,
    /// Fragment byte size.
    pub size: u32,
    /// First character index.
    pub relative_char_index: u32,
    /// Character count (the trailing fragment's count comes from the
    /// C++ `GetCharIndex()` and excludes the final character — a
    /// preserved off-by-one).
    pub chars_count: u32,
}

/// Sub-line cache for one logical line (C++ `SubLines`).
pub struct SubLines {
    /// Which line the entries describe; [`INVALID_LINE_NUMBER`] when
    /// stale.
    pub line_no: u32,
    /// Wrapped fragments, at least one after a compute.
    pub entries: Vec<SubLineInfo>,
    /// Continuation start column.
    pub left_alignament: u32,
}

impl Default for SubLines {
    fn default() -> Self {
        Self {
            line_no: INVALID_LINE_NUMBER,
            entries: Vec::new(),
            left_alignament: 0,
        }
    }
}

/// Streaming decoder with x-column tracking
/// (C++ `CharacterStream`, `Instance.cpp:19-133`).
pub struct CharacterStream<'a> {
    bytes: &'a [u8],
    encoding: Encoding,
    tab_size: u32,
    pos: usize,
    ch: u32,
    x_pos: u32,
    next_pos: u32,
    char_index: u32,
    next_char_index: u32,
    char_is_tab: bool,
}

impl<'a> CharacterStream<'a> {
    /// Stream over `bytes` starting at `character_index`.
    #[must_use]
    pub const fn new(
        bytes: &'a [u8],
        character_index: u32,
        encoding: Encoding,
        tab_size: u32,
    ) -> Self {
        Self {
            bytes,
            encoding,
            tab_size: if tab_size == 0 { 1 } else { tab_size },
            pos: 0,
            ch: 0,
            x_pos: 0,
            next_pos: 0,
            char_index: character_index,
            next_char_index: character_index,
            char_is_tab: false,
        }
    }

    /// Advances to the next character (C++ `Next`).
    pub fn next_char(&mut self) -> bool {
        if self.pos >= self.bytes.len() {
            return false;
        }
        if let Some((ch, len)) = decode_char(self.encoding, self.bytes, self.pos) {
            self.ch = ch;
            self.char_is_tab = ch == u32::from(b'\t');
            self.pos = self.pos.saturating_add(len);
            self.x_pos = self.next_pos;
            self.char_index = self.next_char_index;
            self.next_char_index = self.next_char_index.saturating_add(1);
            if self.char_is_tab {
                let advance = self
                    .tab_size
                    .saturating_sub(self.x_pos.checked_rem(self.tab_size).unwrap_or(0));
                self.next_pos = self.next_pos.saturating_add(advance);
            } else {
                self.next_pos = self.next_pos.saturating_add(1);
            }
        } else {
            // Decoding error: one raw byte.
            self.ch = self.bytes.get(self.pos).copied().map_or(0, u32::from);
            self.char_is_tab = false;
            self.pos = self.pos.saturating_add(1);
            self.x_pos = self.next_pos;
            self.next_pos = self.next_pos.saturating_add(1);
            self.char_index = self.next_char_index;
            self.next_char_index = self.next_char_index.saturating_add(1);
        }
        true
    }

    /// X column after the current character (C++ `GetNextXOffset`).
    #[must_use]
    pub const fn next_x_offset(&self) -> u32 {
        self.next_pos
    }

    /// Index of the current character (C++ `GetCharIndex`).
    #[must_use]
    pub const fn char_index(&self) -> u32 {
        self.char_index
    }

    /// Index the next character will get (C++ `GetNextCharIndex`).
    #[must_use]
    pub const fn next_char_index(&self) -> u32 {
        self.next_char_index
    }

    /// Byte position after the current character
    /// (C++ `GetCurrentBufferPos`).
    #[must_use]
    pub const fn current_buffer_pos(&self) -> u32 {
        self.pos as u32
    }

    /// Restarts the column counter at `value` (C++ `ResetXOffset`).
    pub const fn reset_x_offset(&mut self, value: u32) {
        self.x_pos = value;
        self.next_pos = value;
    }

    /// The current character (C++ `GetCharacter`; tabs already read
    /// as tabs — display substitution is a paint concern).
    #[must_use]
    pub const fn character(&self) -> u32 {
        self.ch
    }

    /// Whether the current character is a TAB (C++ `IsTabCharacter`).
    #[must_use]
    pub const fn is_tab(&self) -> bool {
        self.char_is_tab
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BulletParserState {
    FirstPadding,
    Bullet,
    NextPadding,
}

/// Computes the sub-lines of one logical line
/// (C++ `ComputeSubLineIndexes(lineNo, buf, startOffset)`,
/// `Instance.cpp:461-574`).
///
/// `control_width` is the full control width; the available text
/// width subtracts `line_number_width + 2` (min 1).
// Direct port of the C++ parser: the parameters mirror the C++
// instance state the function reads.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub fn compute_sub_line_indexes(
    sub: &mut SubLines,
    line_no: u32,
    line: LineInfo,
    line_bytes: &[u8],
    encoding: Encoding,
    wrap_method: WrapMethod,
    tab_size: u32,
    control_width: u32,
    line_number_width: u32,
) {
    if line_no == sub.line_no {
        return; // cached
    }
    let mut width = control_width;
    let gutter = line_number_width.saturating_add(2);
    if gutter >= width {
        width = 1;
    } else {
        width = width.saturating_sub(gutter);
    }

    sub.entries.clear();
    sub.line_no = line_no;
    sub.left_alignament = 0;

    if wrap_method == WrapMethod::None {
        sub.entries.push(SubLineInfo {
            buffer_offset: 0,
            size: line.byte_size,
            relative_char_index: 0,
            chars_count: line.char_count,
        });
        if line.byte_size == 0 || line.char_count == 0 {
            sub.line_no = INVALID_LINE_NUMBER; // recompute next time
        }
        return;
    }

    let mut cs = CharacterStream::new(line_bytes, 0, encoding, tab_size);
    let mut buf_pos = 0_u32;
    let mut char_index = 0_u32;
    let mut compute_alignament = true;
    let mut bp = BulletParserState::FirstPadding;
    let mut bp_bullet_width = 0_u32;

    while cs.next_char() {
        if cs.next_x_offset() > width {
            sub.entries.push(SubLineInfo {
                buffer_offset: buf_pos,
                size: cs.current_buffer_pos().saturating_sub(buf_pos),
                relative_char_index: char_index,
                chars_count: cs.next_char_index().saturating_sub(char_index),
            });
            buf_pos = cs.current_buffer_pos();
            char_index = cs.next_char_index();
            compute_alignament = false;
            cs.reset_x_offset(sub.left_alignament);
        }
        if compute_alignament {
            match wrap_method {
                WrapMethod::LeftMargin => {
                    compute_alignament = false;
                    sub.left_alignament = 0;
                }
                WrapMethod::Padding => {
                    if cs.character() == u32::from(b' ') || cs.is_tab() {
                        sub.left_alignament = cs.next_x_offset();
                    } else {
                        compute_alignament = false;
                    }
                }
                WrapMethod::Bullets => {
                    // State checks in this exact order (C++ comment).
                    if bp == BulletParserState::NextPadding {
                        if cs.character() == u32::from(b' ') || cs.is_tab() {
                            sub.left_alignament = cs.next_x_offset();
                        } else {
                            compute_alignament = false;
                        }
                    }
                    if bp == BulletParserState::FirstPadding {
                        if cs.character() == u32::from(b' ') || cs.is_tab() {
                            sub.left_alignament = cs.next_x_offset();
                        } else {
                            bp = BulletParserState::Bullet;
                            bp_bullet_width = 0;
                        }
                    }
                    if bp == BulletParserState::Bullet {
                        sub.left_alignament = cs.next_x_offset();
                        bp_bullet_width = bp_bullet_width.saturating_add(1);
                        let ch = cs.character();
                        if ch == u32::from(b'-')
                            || ch == u32::from(b'*')
                            || ch == u32::from(b'.')
                            || ch == u32::from(b')')
                        {
                            bp = BulletParserState::NextPadding;
                        } else if bp_bullet_width > 4 {
                            compute_alignament = false;
                            sub.left_alignament = 0;
                        }
                    }
                }
                WrapMethod::None => {
                    compute_alignament = false;
                }
            }
        }
    }
    if cs.current_buffer_pos() > buf_pos {
        // Trailing fragment: chars_count uses GetCharIndex() — the
        // final character is not counted (C++ off-by-one, preserved).
        sub.entries.push(SubLineInfo {
            buffer_offset: buf_pos,
            size: cs.current_buffer_pos().saturating_sub(buf_pos),
            relative_char_index: char_index,
            chars_count: cs.char_index().saturating_sub(char_index),
        });
    }
    if sub.entries.is_empty() {
        sub.entries.push(SubLineInfo {
            buffer_offset: 0,
            size: 0,
            relative_char_index: 0,
            chars_count: 0,
        });
        sub.line_no = INVALID_LINE_NUMBER;
    }
}

/// Sub-line index containing `char_index`
/// (C++ `CharacterIndexToSubLineNo`, `Instance.cpp:583-621` — ported
/// binary search, including its boundary rules).
#[must_use]
pub fn character_index_to_sub_line_no(sub: &SubLines, char_index: u32) -> u32 {
    let count = sub.entries.len();
    if count <= 1 {
        return 0;
    }
    let mut start = 0_u32;
    let mut end = (count as u32).saturating_sub(1);
    let mut middle = (start.saturating_add(end)) >> 1;
    let last_valid_start_index = end.saturating_sub(1);

    let Some(first) = sub.entries.first() else {
        return 0;
    };
    if char_index < first.relative_char_index {
        return 0;
    }
    let Some(last) = sub.entries.last() else {
        return 0;
    };
    if char_index > last.relative_char_index.saturating_add(last.chars_count) {
        return end;
    }
    loop {
        let Some(sl) = sub.entries.get(middle as usize) else {
            return 0;
        };
        let Some(next) = sub.entries.get((middle as usize).saturating_add(1)) else {
            return (count as u32).saturating_sub(1);
        };
        if char_index >= sl.relative_char_index && char_index < next.relative_char_index {
            return middle;
        }
        if char_index < sl.relative_char_index {
            if middle == 0 {
                return 0; // C++ sanity check
            }
            end = middle.saturating_sub(1);
        } else {
            start = middle.saturating_add(1);
            if start > last_valid_start_index {
                return (count as u32).saturating_sub(1);
            }
        }
        middle = (start.saturating_add(end)) >> 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(
        bytes: &[u8],
        method: WrapMethod,
        control_width: u32,
        line_number_width: u32,
    ) -> SubLines {
        let mut sub = SubLines::default();
        let line = LineInfo {
            offset: 0,
            char_count: bytes.len() as u32,
            byte_size: bytes.len() as u32,
        };
        compute_sub_line_indexes(
            &mut sub,
            0,
            line,
            bytes,
            Encoding::Ascii,
            method,
            4,
            control_width,
            line_number_width,
        );
        sub
    }

    #[test]
    fn no_wrap_single_subline() {
        let sub = wrap(b"hello world", WrapMethod::None, 20, 2);
        assert_eq!(
            sub.entries,
            vec![SubLineInfo {
                buffer_offset: 0,
                size: 11,
                relative_char_index: 0,
                chars_count: 11
            }]
        );
        assert_eq!(sub.line_no, 0);
    }

    #[test]
    fn left_margin_wraps_on_column_overflow() {
        // control 12, gutter 2+2 → available width 8. 20 chars of
        // text: fragments break when next_x_offset exceeds 8.
        let sub = wrap(b"abcdefghijklmnopqrst", WrapMethod::LeftMargin, 12, 2);
        assert_eq!(sub.left_alignament, 0);
        assert!(sub.entries.len() >= 2);
        // First fragment: overflow happens on the 9th char (x=9 > 8),
        // and the overflowing char is included (C++ break-after).
        assert_eq!(sub.entries[0].buffer_offset, 0);
        assert_eq!(sub.entries[0].size, 9);
        assert_eq!(sub.entries[0].chars_count, 9);
        // Second fragment starts where the first ended.
        assert_eq!(sub.entries[1].buffer_offset, 9);
        assert_eq!(sub.entries[1].relative_char_index, 9);
    }

    #[test]
    fn padding_aligns_under_first_text_column() {
        // Three leading spaces: continuation column = 3.
        let sub = wrap(b"   abcdefghijkl", WrapMethod::Padding, 12, 2);
        assert_eq!(sub.left_alignament, 3);
    }

    #[test]
    fn bullets_detect_dash_prefix() {
        // "- item...": bullet '-' at x=0..1, then padding space → the
        // continuation aligns after the bullet and its space.
        let sub = wrap(b"- abcdefghijklmno", WrapMethod::Bullets, 12, 2);
        assert_eq!(sub.left_alignament, 2);
        // A line with no bullet in the first 5 columns falls back to 0.
        let sub = wrap(b"abcdefghijklmnop", WrapMethod::Bullets, 12, 2);
        assert_eq!(sub.left_alignament, 0);
    }

    #[test]
    fn trailing_fragment_charcount_offby_one_preserved() {
        // Single fragment (no overflow): trailing push counts
        // GetCharIndex() - start = last index, excluding the final
        // char (C++ parity).
        let sub = wrap(b"abc", WrapMethod::LeftMargin, 40, 2);
        assert_eq!(sub.entries.len(), 1);
        assert_eq!(sub.entries[0].size, 3);
        assert_eq!(sub.entries[0].chars_count, 2);
    }

    #[test]
    fn tab_expansion_advances_columns() {
        let mut cs = CharacterStream::new(b"\ta\tb", 0, Encoding::Ascii, 4);
        assert!(cs.next_char());
        assert!(cs.is_tab());
        assert_eq!(cs.next_x_offset(), 4); // tab from column 0 → 4
        assert!(cs.next_char());
        assert_eq!(cs.character(), u32::from(b'a'));
        assert_eq!(cs.next_x_offset(), 5);
        assert!(cs.next_char());
        assert!(cs.is_tab());
        assert_eq!(cs.next_x_offset(), 8); // tab from column 5 → 8
        assert!(cs.next_char());
        assert!(!cs.next_char()); // end of stream
    }

    #[test]
    fn sub_line_binary_search_matches() {
        // Wrapped fragments every 9 chars: verify lookups per the C++
        // search semantics.
        let sub = wrap(
            b"abcdefghijklmnopqrstuvwxyz0123456789",
            WrapMethod::LeftMargin,
            12,
            2,
        );
        assert!(sub.entries.len() >= 3);
        for (expected, entry) in sub.entries.iter().enumerate() {
            let found = character_index_to_sub_line_no(&sub, entry.relative_char_index);
            assert_eq!(found as usize, expected, "start of fragment {expected}");
        }
        // Mid-fragment lookups.
        assert_eq!(character_index_to_sub_line_no(&sub, 4), 0);
        assert_eq!(character_index_to_sub_line_no(&sub, 10), 1);
        // Past the end: last fragment.
        assert_eq!(
            character_index_to_sub_line_no(&sub, 10_000) as usize,
            sub.entries.len() - 1
        );
        // Single-fragment lines always resolve to 0.
        let single = wrap(b"ab", WrapMethod::LeftMargin, 40, 2);
        assert_eq!(character_index_to_sub_line_no(&single, 1), 0);
    }

    #[test]
    fn cache_hit_skips_recompute() {
        let mut sub = SubLines::default();
        let line = LineInfo {
            offset: 0,
            char_count: 3,
            byte_size: 3,
        };
        compute_sub_line_indexes(
            &mut sub,
            7,
            line,
            b"abc",
            Encoding::Ascii,
            WrapMethod::None,
            4,
            40,
            2,
        );
        let first = sub.entries.clone();
        // Same line number: untouched even with different input.
        compute_sub_line_indexes(
            &mut sub,
            7,
            line,
            b"zzzzzzzz",
            Encoding::Ascii,
            WrapMethod::None,
            4,
            40,
            2,
        );
        assert_eq!(sub.entries, first);
    }
}
