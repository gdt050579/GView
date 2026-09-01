//! `LexicalViewer` token model and parse pipeline.
//!
//! C++ anchors: `Instance::Parse` (`Instance.cpp:715-775`),
//! `UpdateTokensInformation` (`Instance.cpp:116-128`),
//! `UpdateVisibilityStatus` (`Instance.cpp:574-604`),
//! `UpdateTokensWidthAndHeight` (`Instance.cpp:605-625`),
//! `ComputeOriginalPositions` (`Instance.cpp:168-231`),
//! `TokenObject::UpdateSizes` (`SyntaxManager.cpp:195-227`),
//! `TextParser_ComputeHash64` (`TextParser.cpp:45-73`); spec
//! `02_VIEWER_LEXICAL` §3.1, §4, §6.
//!
//! Text is stored as UTF-16 code units (`Vec<u16>`) so token
//! `start`/`end` offsets match the C++ `char16*` arithmetic.

/// Marker for "no block" (C++ `BlockObject::INVALID_ID`).
pub const INVALID_BLOCK_ID: u32 = u32::MAX;

/// FNV-1a 64 over the raw UTF-16LE bytes, skipping zero bytes; with
/// `ignore_case` ASCII (< 128) units are lowercased
/// (C++ `TextParser_ComputeHash64`, `TextParser.cpp:45-73`).
#[must_use]
pub fn compute_hash64(text: &[u16], ignore_case: bool) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
    let mut hash = FNV_OFFSET;
    for &unit in text {
        let unit = if ignore_case && unit < 128 {
            u16::from((unit as u8).to_ascii_lowercase())
        } else {
            unit
        };
        for byte in unit.to_le_bytes() {
            if byte == 0 {
                continue;
            }
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}

/// Computed layout position of a token.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenPos {
    /// Column.
    pub x: i32,
    /// Row.
    pub y: i32,
    /// Rendered width (min 1 after layout).
    pub width: u32,
    /// Rendered height (min 1 after layout).
    pub height: u32,
}

/// One lexical token (subset of C++ `TokenObject` needed by the
/// pipeline; colors/types attach in later tasks).
// The bools mirror independent C++ TokenStatus flags; keeping them
// 1:1 preserves the parity mapping.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct Token {
    /// Start offset in UTF-16 units.
    pub start: u32,
    /// End offset (exclusive) in UTF-16 units.
    pub end: u32,
    /// Layout position.
    pub pos: TokenPos,
    /// 1-based visual line number (assigned by the parse step 3).
    pub line_no: u32,
    /// Owning block for block starters, else [`INVALID_BLOCK_ID`].
    pub block_id: u32,
    /// Similarity hash (0 when disabled).
    pub hash: u64,
    /// Intrinsic width (longest content line).
    pub content_width: u32,
    /// Intrinsic height (content line count).
    pub content_height: u32,
    /// `TokenStatus::Visible`.
    pub visible: bool,
    /// `TokenStatus::Folded` (block starters only).
    pub folded: bool,
    /// `TokenStatus::BlockStart`.
    pub block_starter: bool,
    /// `TokenDataType::MetaInformation`.
    pub meta_information: bool,
    /// `TokenStatus::ShouldDelete`.
    pub marked_for_deletion: bool,
    /// `TokenStatus::SizeableSize`.
    pub sizeable: bool,
    /// `TokenStatus::DisableSimilarityHighlight`.
    pub disable_similarity_highlight: bool,
}

impl Token {
    /// Plain token over `[start, end)`.
    #[must_use]
    pub const fn new(start: u32, end: u32) -> Self {
        Self {
            start,
            end,
            pos: TokenPos {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            line_no: 0,
            block_id: INVALID_BLOCK_ID,
            hash: 0,
            content_width: 0,
            content_height: 0,
            visible: true,
            folded: false,
            block_starter: false,
            meta_information: false,
            marked_for_deletion: false,
            sizeable: false,
            disable_similarity_highlight: false,
        }
    }

    fn slice<'a>(&self, text: &'a [u16]) -> &'a [u16] {
        text.get(self.start as usize..self.end as usize)
            .unwrap_or(&[])
    }

    /// C++ `TokenObject::UpdateSizes` (`SyntaxManager.cpp:195-227`).
    pub fn update_sizes(&mut self, text: &[u16]) {
        let content = self.slice(text);
        let mut nr_lines = 1_u32;
        let mut w = 0_u32;
        let mut max_w = 0_u32;
        let mut i = 0_usize;
        while let Some(&unit) = content.get(i) {
            if unit == u16::from(b'\n') || unit == u16::from(b'\r') {
                nr_lines = nr_lines.saturating_add(1);
                max_w = u32::max(max_w, w);
                w = 0;
                let paired = content.get(i.saturating_add(1)).is_some_and(|&n| {
                    (n == u16::from(b'\n') || n == u16::from(b'\r')) && n != unit
                });
                i = i.saturating_add(if paired { 2 } else { 1 });
            } else {
                i = i.saturating_add(1);
                w = w.saturating_add(1);
            }
        }
        self.content_height = nr_lines;
        self.content_width = u32::max(max_w, w);
    }

    /// C++ `TokenObject::UpdateHash` (`LexicalViewer.hpp:207+`).
    pub fn update_hash(&mut self, text: &[u16], ignore_case: bool) {
        if self.disable_similarity_highlight {
            self.hash = 0;
        } else {
            self.hash = compute_hash64(self.slice(text), ignore_case);
        }
    }
}

/// Foldable region (C++ `BlockObject`).
#[derive(Clone, Debug)]
pub struct Block {
    /// Index of the starter token.
    pub token_start: u32,
    /// Index of the last token (or the closer, see
    /// `has_end_marker`).
    pub token_end: u32,
    /// `BlockFlags::EndMarker`: `token_end` is a visible closer that
    /// stays visible while folded.
    pub has_end_marker: bool,
    /// C++ `CanOnlyBeFoldedManually()`: skipped by Fold-All and
    /// recursive folds.
    pub manual_fold_only: bool,
    /// Folded replacement text.
    pub fold_message: String,
}

impl Block {
    /// Exclusive end token index (C++ `GetEndIndex`): the end marker
    /// itself when present, else one past `token_end`.
    #[must_use]
    pub const fn end_index(&self) -> u32 {
        if self.has_end_marker {
            self.token_end
        } else {
            self.token_end.saturating_add(1)
        }
    }
}

/// Parser plugin surface (C++ `ParseInterface`, spec §2.1).
pub trait ParseInterface {
    /// Step 1: normalize the text before lexing.
    fn preprocess_text(&mut self, text: &mut Vec<u16>);
    /// Step 2: emit tokens and blocks.
    fn analyze_text(&mut self, text: &[u16], tokens: &mut Vec<Token>, blocks: &mut Vec<Block>);
}

/// Parsed viewer state (C++ `Instance` token/block fields).
#[derive(Default)]
pub struct LexicalState {
    /// The (possibly preprocessed) text as UTF-16 units.
    pub text: Vec<u16>,
    /// Token stream in source order.
    pub tokens: Vec<Token>,
    /// Foldable blocks.
    pub blocks: Vec<Block>,
    /// Highest assigned line number.
    pub last_line_number: u32,
    /// Gutter width from the line count.
    pub line_nr_width: u32,
    /// `true` when nothing is visible.
    pub no_items_visible: bool,
    /// Show meta-information tokens.
    pub show_meta_data: bool,
    /// Case-insensitive similarity hashes.
    pub ignore_case: bool,
    /// `SetMaxTokenSize` cap used when re-laying out.
    pub max_token_size: (u32, u32),
    /// Index of the current token (C++ `currentTokenIndex`).
    pub current_token_index: u32,
}

/// C++ `UpdateVisibilityStatus(start, end, visible)`
/// (`Instance.cpp:574-604`) — recursive over block starters: a folded
/// block hides its interior (the end marker stays when present).
pub fn update_visibility_status(state: &mut LexicalState, start: u32, end: u32, visible: bool) {
    let mut pos = start;
    while pos < end {
        let Some(tok) = state.tokens.get_mut(pos as usize) else {
            return;
        };
        let hidden = (tok.meta_information && !state.show_meta_data) || tok.marked_for_deletion;
        let mut show_status = visible && !hidden;
        tok.visible = show_status;
        state.no_items_visible &= !show_status;

        if tok.block_starter {
            let folded = tok.folded;
            let block_id = tok.block_id;
            if folded {
                show_status = false;
            }
            let Some(block) = state.blocks.get(block_id as usize) else {
                pos = pos.saturating_add(1);
                continue;
            };
            let end_token = if block.has_end_marker {
                block.token_end
            } else {
                block.token_end.saturating_add(1)
            };
            let inner_start = block.token_start.saturating_add(1);
            update_visibility_status(state, inner_start, end_token, show_status);
            pos = end_token;
        } else {
            pos = pos.saturating_add(1);
        }
    }
}

/// C++ `UpdateTokensWidthAndHeight` (`Instance.cpp:605-625`); the
/// sizeable cap uses `max_token_size`.
pub fn update_tokens_width_and_height(state: &mut LexicalState, max_token_size: (u32, u32)) {
    for tok in &mut state.tokens {
        if !tok.visible {
            continue;
        }
        if tok.sizeable {
            tok.pos.width = u32::min(tok.content_width, max_token_size.0);
            tok.pos.height = u32::min(tok.content_height, max_token_size.1);
        } else {
            tok.pos.width = tok.content_width;
            tok.pos.height = tok.content_height;
        }
        tok.pos.width = u32::max(1, tok.pos.width);
        tok.pos.height = u32::max(1, tok.pos.height);
    }
}

/// C++ `ComputeOriginalPositions` (`Instance.cpp:168-231`): walk the
/// text tracking `(x, y)`; hardcoded 4-column tabs; newline pairs
/// (`\r\n` / `\n\r`) advance one row.
#[allow(clippy::arithmetic_side_effects)] // indices bounded by text length
pub fn compute_original_positions(state: &mut LexicalState) {
    let mut x = 0_i32;
    let mut y = 0_i32;
    let text = &state.text;
    let len = text.len();
    let mut p = 0_usize;
    let mut pos = 0_u32;
    let mut idx = 0_usize;
    let count = state.tokens.len();

    // Skip to the first visible token.
    while idx < count && !state.tokens.get(idx).is_some_and(|t| t.visible) {
        idx += 1;
    }
    let mut tkn_offs = state.tokens.get(idx).map_or(u32::MAX, |t| t.start);

    while p < len {
        let unit = text.get(p).copied().unwrap_or(0);
        if unit == u16::from(b'\t') {
            x = (x / 4 + 1) * 4;
        }
        if pos == tkn_offs {
            let Some(tok) = state.tokens.get_mut(idx) else {
                break;
            };
            if tok.visible {
                tok.pos.x = x;
                tok.pos.y = y;
            } else {
                tok.pos.x = 0;
                tok.pos.y = 0;
                let skip = tok.end.saturating_sub(tok.start) as usize;
                p += skip;
                pos += skip as u32;
                if p >= len {
                    break;
                }
            }
            idx += 1;
            if idx >= count {
                break;
            }
            tkn_offs = state.tokens.get(idx).map_or(u32::MAX, |t| t.start);
        }
        let unit = text.get(p).copied().unwrap_or(0);
        if unit == u16::from(b'\n') || unit == u16::from(b'\r') {
            x = 0;
            y += 1;
            let paired = text
                .get(p + 1)
                .is_some_and(|&n| (n == u16::from(b'\n') || n == u16::from(b'\r')) && n != unit);
            let step = if paired { 2 } else { 1 };
            p += step;
            pos += step as u32;
        } else {
            x += 1;
            p += 1;
            pos += 1;
        }
    }
}

/// C++ `RecomputeTokenPositions` (`Instance.cpp:105-115`), original
/// (non-pretty) layout path.
pub fn recompute_token_positions(state: &mut LexicalState, max_token_size: (u32, u32)) {
    state.no_items_visible = true;
    let count = state.tokens.len() as u32;
    update_visibility_status(state, 0, count, true);
    update_tokens_width_and_height(state, max_token_size);
    compute_original_positions(state);
}

/// [`recompute_token_positions`] using the stored
/// `state.max_token_size`.
pub fn relayout(state: &mut LexicalState) {
    let cap = state.max_token_size;
    recompute_token_positions(state, cap);
}

/// The full parse pipeline (C++ `Instance::Parse`,
/// `Instance.cpp:715-775`; spec §4). Returns the populated state.
pub fn parse(
    parser: &mut dyn ParseInterface,
    text: Vec<u16>,
    ignore_case: bool,
    max_token_size: (u32, u32),
) -> LexicalState {
    let mut state = LexicalState {
        text,
        show_meta_data: true, // must be true to compute line numbers
        no_items_visible: true,
        ignore_case,
        max_token_size,
        ..Default::default()
    };

    // Step 1: preprocessor.
    parser.preprocess_text(&mut state.text);

    // Step 2: analyzer.
    let mut tokens = Vec::new();
    let mut blocks = Vec::new();
    parser.analyze_text(&state.text, &mut tokens, &mut blocks);
    state.tokens = tokens;
    state.blocks = blocks;

    // Hashes and intrinsic sizes.
    let text_snapshot = state.text.clone();
    for tok in &mut state.tokens {
        tok.update_sizes(&text_snapshot);
        tok.update_hash(&text_snapshot, ignore_case);
    }
    recompute_token_positions(&mut state, max_token_size);

    // Step 3: line numbers — increments whenever pos.y changes
    // (everything is expanded right after a parse).
    let mut last_y = -1_i32;
    let mut line_no = 0_u32;
    for tok in &mut state.tokens {
        if tok.pos.y != last_y {
            line_no = line_no.saturating_add(1);
            last_y = tok.pos.y;
        }
        tok.line_no = line_no;
    }
    state.last_line_number = line_no;
    state.line_nr_width = if line_no < 100 {
        4
    } else if line_no < 1_000 {
        5
    } else if line_no < 10_000 {
        6
    } else if line_no < 100_000 {
        7
    } else {
        8
    };
    state
}

/// Convenience: UTF-16 units from ASCII/Unicode text.
#[must_use]
pub fn text_to_utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whitespace tokenizer: each non-space run becomes a token.
    struct MockParser;

    impl ParseInterface for MockParser {
        fn preprocess_text(&mut self, _text: &mut Vec<u16>) {}
        fn analyze_text(
            &mut self,
            text: &[u16],
            tokens: &mut Vec<Token>,
            _blocks: &mut Vec<Block>,
        ) {
            let mut start: Option<usize> = None;
            for (i, &u) in text.iter().enumerate() {
                let is_space = u == u16::from(b' ')
                    || u == u16::from(b'\n')
                    || u == u16::from(b'\r')
                    || u == u16::from(b'\t');
                match (is_space, start) {
                    (false, None) => start = Some(i),
                    (true, Some(s)) => {
                        tokens.push(Token::new(s as u32, i as u32));
                        start = None;
                    }
                    _ => {}
                }
            }
            if let Some(s) = start {
                tokens.push(Token::new(s as u32, text.len() as u32));
            }
        }
    }

    fn parse_str(text: &str) -> LexicalState {
        parse(&mut MockParser, text_to_utf16(text), false, (100, 100))
    }

    #[test]
    fn token_count_matches_sample_file() {
        let state = parse_str("let x = 40 + two;\nfn main() { call(x); }\n");
        // Whitespace tokenizer: "let x = 40 + two;" → 6 tokens,
        // "fn main() { call(x); }" → 5 tokens.
        assert_eq!(state.tokens.len(), 11);
    }

    #[test]
    fn line_no_increments_on_pos_y_change() {
        let state = parse_str("alpha beta\ngamma\n\ndelta epsilon");
        // Rows: y=0 (alpha, beta), y=1 (gamma), y=3 (delta, epsilon)
        // → lineNo increments only when y changes: 1, 1, 2, 3, 3.
        let line_nos: Vec<u32> = state.tokens.iter().map(|t| t.line_no).collect();
        assert_eq!(line_nos, vec![1, 1, 2, 3, 3]);
        assert_eq!(state.last_line_number, 3);
        assert_eq!(state.line_nr_width, 4);
    }

    #[test]
    fn original_positions_track_columns_and_rows() {
        let state = parse_str("ab cd\nef");
        let positions: Vec<(i32, i32)> = state.tokens.iter().map(|t| (t.pos.x, t.pos.y)).collect();
        assert_eq!(positions, vec![(0, 0), (3, 0), (0, 1)]);
        // Sizes: every token 1 row high, width = length.
        assert_eq!(state.tokens[0].pos.width, 2);
        assert_eq!(state.tokens[0].pos.height, 1);
    }

    #[test]
    fn tab_advances_to_next_4_column_stop() {
        let state = parse_str("\tx\ta");
        // C++ quirk (Instance.cpp:184-185, 224-228): the tab snaps x
        // to the next 4-column stop AND the generic `x++` advance
        // still runs, so "x" lands at column 5 (not 4) and "a" at 9.
        assert_eq!(state.tokens[0].pos.x, 5);
        assert_eq!(state.tokens[1].pos.x, 9);
    }

    #[test]
    fn crlf_pairs_advance_one_row() {
        let state = parse_str("one\r\ntwo\n\rthree");
        let ys: Vec<i32> = state.tokens.iter().map(|t| t.pos.y).collect();
        assert_eq!(ys, vec![0, 1, 2]);
    }

    #[test]
    fn hash_ignore_case_folds_ascii() {
        let a = compute_hash64(&text_to_utf16("Function"), true);
        let b = compute_hash64(&text_to_utf16("function"), true);
        let c = compute_hash64(&text_to_utf16("function"), false);
        assert_eq!(a, b);
        assert_eq!(b, c); // lowercase input hashes identically
        let d = compute_hash64(&text_to_utf16("Function"), false);
        assert_ne!(c, d);
    }

    #[test]
    fn folded_block_hides_interior_tokens() {
        // Tokens: "{" t0 (block starter), "a" t1, "b" t2, "}" t3.
        let mut state = parse_str("{ a b }");
        assert_eq!(state.tokens.len(), 4);
        state.blocks.push(Block {
            token_start: 0,
            token_end: 3,
            has_end_marker: true,
            manual_fold_only: false,
            fold_message: "...".to_owned(),
        });
        state.tokens[0].block_starter = true;
        state.tokens[0].block_id = 0;
        state.tokens[0].folded = true;
        recompute_token_positions(&mut state, (100, 100));
        assert!(state.tokens[0].visible); // starter stays
        assert!(!state.tokens[1].visible); // interior hidden
        assert!(!state.tokens[2].visible);
        assert!(state.tokens[3].visible); // end marker stays
                                          // Unfold: everything returns.
        state.tokens[0].folded = false;
        recompute_token_positions(&mut state, (100, 100));
        assert!(state.tokens.iter().all(|t| t.visible));
    }

    #[test]
    fn meta_information_hidden_when_disabled() {
        let mut state = parse_str("a b");
        state.tokens[1].meta_information = true;
        state.show_meta_data = false;
        recompute_token_positions(&mut state, (100, 100));
        assert!(state.tokens[0].visible);
        assert!(!state.tokens[1].visible);
    }
}
