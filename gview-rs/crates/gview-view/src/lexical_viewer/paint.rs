//! `LexicalViewer` paint loop and cull predicate
//! (C++ `Instance::Paint`, `Instance.cpp:1025-1060`; spec
//! `02_VIEWER_LEXICAL` §7.1).
//!
//! The cull predicate is exact (§7.1): `scroll_right` / `scroll_bottom`
//! use the **full** control width/height — no `lineNrWidth`
//! subtraction (that subtraction exists only in
//! `EnsureCurrentItemIsVisible`, §7.1.1). Painting clips to
//! `x >= lineNrWidth`; screen coords are `pos - Scroll`.

use super::parse::{LexicalState, Token};

/// Scroll origin in token-layout coordinates (C++ `Scroll`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scroll {
    /// Horizontal scroll.
    pub x: i32,
    /// Vertical scroll.
    pub y: i32,
}

/// Exact §7.1 cull predicate (`Instance.cpp:1038-1046`): `true` when
/// the token lies entirely outside the visible screen.
#[must_use]
pub const fn is_token_culled(token: &Token, scroll: Scroll, width: u32, height: u32) -> bool {
    let scroll_right = scroll
        .x
        .saturating_add(width.cast_signed())
        .saturating_sub(1);
    let scroll_bottom = scroll
        .y
        .saturating_add(height.cast_signed())
        .saturating_sub(1);
    let tk_right = token
        .pos
        .x
        .saturating_add(token.pos.width.cast_signed())
        .saturating_sub(1);
    let tk_bottom = token
        .pos
        .y
        .saturating_add(token.pos.height.cast_signed())
        .saturating_sub(1);
    token.pos.x > scroll_right
        || token.pos.y > scroll_bottom
        || tk_right < scroll.x
        || tk_bottom < scroll.y
}

/// Paint target (the concrete renderer draws on the `appcui`
/// `Surface`; tests record).
pub trait TokenSink {
    /// Paints one visible token (clipped to `x >= lineNrWidth` by the
    /// caller's renderer).
    fn paint_token(&mut self, index: u32, token: &Token, is_current: bool);
    /// Writes the gutter line number at screen row `y`.
    fn write_line_number(&mut self, y: i32, line_no: u32);
}

/// Paint statistics for assertions/telemetry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PaintStats {
    /// Tokens handed to the sink.
    pub painted: u32,
    /// Visible tokens skipped by the cull predicate.
    pub culled: u32,
}

/// One paint pass (C++ `Paint` token loop, `Instance.cpp:1000-1059`):
/// the current token paints first, then every visible non-culled
/// token, emitting a gutter line number whenever `pos.y` changes.
pub fn paint_tokens(
    state: &LexicalState,
    scroll: Scroll,
    width: u32,
    height: u32,
    sink: &mut impl TokenSink,
) -> PaintStats {
    let mut result = PaintStats::default();

    // Current token first (C++ paints it before the loop).
    if !state.no_items_visible {
        if let Some(current) = state.tokens.get(state.current_token_index as usize) {
            if current.visible {
                sink.paint_token(state.current_token_index, current, true);
                sink.write_line_number(
                    i32::max(0, current.pos.y.saturating_sub(scroll.y)),
                    current.line_no,
                );
                result.painted = result.painted.saturating_add(1);
            }
        }
    }

    let mut last_y = -1_i32;
    for (idx, token) in state.tokens.iter().enumerate() {
        let idx = idx as u32;
        // Skip hidden tokens and the (already painted) current one.
        if !token.visible || idx == state.current_token_index {
            continue;
        }
        if is_token_culled(token, scroll, width, height) {
            result.culled = result.culled.saturating_add(1);
            continue;
        }
        sink.paint_token(idx, token, false);
        if token.pos.y != last_y {
            sink.write_line_number(
                i32::max(0, token.pos.y.saturating_sub(scroll.y)),
                token.line_no,
            );
            last_y = token.pos.y;
        }
        result.painted = result.painted.saturating_add(1);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexical_viewer::parse::{parse, text_to_utf16, Block, ParseInterface, Token};

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
                let sep = u == u16::from(b' ') || u == u16::from(b'\n');
                match (sep, start) {
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

    struct RecordingSink {
        painted: Vec<(u32, bool)>,
        line_numbers: Vec<(i32, u32)>,
    }

    impl TokenSink for RecordingSink {
        fn paint_token(&mut self, index: u32, _token: &Token, is_current: bool) {
            self.painted.push((index, is_current));
        }
        fn write_line_number(&mut self, y: i32, line_no: u32) {
            self.line_numbers.push((y, line_no));
        }
    }

    fn sink() -> RecordingSink {
        RecordingSink {
            painted: Vec::new(),
            line_numbers: Vec::new(),
        }
    }

    /// 20 one-char tokens, one per row (y = 0..19).
    fn tall_state() -> LexicalState {
        let text = (0..20).map(|_| "t\n").collect::<String>();
        parse(&mut MockParser, text_to_utf16(&text), false, (100, 100))
    }

    #[test]
    fn cull_predicate_boundaries() {
        // Screen: scroll (10, 5), 20×10 → visible x 10..=29, y 5..=14.
        let scroll = Scroll { x: 10, y: 5 };
        let mut t = Token::new(0, 1);
        t.pos.width = 1;
        t.pos.height = 1;
        // Inside corners.
        t.pos.x = 10;
        t.pos.y = 5;
        assert!(!is_token_culled(&t, scroll, 20, 10));
        t.pos.x = 29;
        t.pos.y = 14;
        assert!(!is_token_culled(&t, scroll, 20, 10));
        // One step outside each edge.
        t.pos.x = 30;
        t.pos.y = 5;
        assert!(is_token_culled(&t, scroll, 20, 10));
        t.pos.x = 9;
        assert!(is_token_culled(&t, scroll, 20, 10)); // tk_right 9 < 10
        t.pos.x = 10;
        t.pos.y = 15;
        assert!(is_token_culled(&t, scroll, 20, 10));
        t.pos.y = 4;
        assert!(is_token_culled(&t, scroll, 20, 10)); // tk_bottom 4 < 5
                                                      // Wide token straddling the left edge stays visible.
        t.pos.x = 5;
        t.pos.y = 5;
        t.pos.width = 10; // right edge at 14 >= 10
        assert!(!is_token_culled(&t, scroll, 20, 10));
    }

    #[test]
    fn off_screen_tokens_skipped() {
        let state = tall_state();
        assert_eq!(state.tokens.len(), 20);
        // 10-row screen at scroll y=0: rows 0..=9 visible.
        let outcome = paint_tokens(&state, Scroll::default(), 40, 10, &mut sink());
        assert_eq!(outcome.painted, 10);
        assert_eq!(outcome.culled, 10);
        // Scrolled down by 15: only rows 15..=19 visible.
        let outcome = paint_tokens(&state, Scroll { x: 0, y: 15 }, 40, 10, &mut sink());
        // Current token (index 0, row 0) is painted unconditionally
        // by the current-token pass; the loop culls it.
        assert_eq!(outcome.painted, 5 + 1);
        assert_eq!(outcome.culled, 14);
    }

    #[test]
    fn current_token_painted_first_and_not_repeated() {
        let mut state = tall_state();
        state.current_token_index = 3;
        let mut rec = sink();
        paint_tokens(&state, Scroll::default(), 40, 10, &mut rec);
        assert_eq!(rec.painted.first(), Some(&(3, true)));
        // Painted exactly once.
        let count = rec.painted.iter().filter(|(i, _)| *i == 3).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn line_numbers_written_once_per_row() {
        // Two tokens per row: "a b\nc d".
        let state = parse(
            &mut MockParser,
            text_to_utf16("a b\nc d"),
            false,
            (100, 100),
        );
        let mut rec = sink();
        paint_tokens(&state, Scroll::default(), 40, 10, &mut rec);
        // Current token (0) emits its own line number; the loop then
        // emits one per distinct row (row 0 again for token 1, row 1
        // for token 2).
        let rows: Vec<i32> = rec.line_numbers.iter().map(|&(y, _)| y).collect();
        assert_eq!(rows, vec![0, 0, 1]);
        let line_nos: Vec<u32> = rec.line_numbers.iter().map(|&(_, n)| n).collect();
        assert_eq!(line_nos, vec![1, 1, 2]);
    }

    #[test]
    fn hidden_tokens_never_reach_the_sink() {
        let mut state = parse(&mut MockParser, text_to_utf16("a b c"), false, (100, 100));
        state.tokens[1].visible = false;
        let mut rec = sink();
        let outcome = paint_tokens(&state, Scroll::default(), 40, 10, &mut rec);
        assert_eq!(outcome.painted, 2);
        assert!(rec.painted.iter().all(|&(i, _)| i != 1));
    }
}
