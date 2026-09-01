//! `LexicalViewer` folding.
//!
//! C++ anchors: `TokenIndexStack.cpp` (parse-time block stack),
//! `Instance::SetFoldStatus` (`Instance.cpp:1307-1354`), `FoldAll` /
//! `ExpandAll` (`Instance.cpp:1355-1372`), `TokenToBlock`
//! (`Instance.cpp:626-652`), `MoveToClosestVisibleToken`
//! (`Instance.cpp:129-167`); spec `02_VIEWER_LEXICAL` §5.
//! Runtime folding toggles `Folded` on block starters and re-runs the
//! visibility/layout pipeline; hidden tokens are never painted.

use super::parse::{relayout, LexicalState, INVALID_BLOCK_ID};

/// Fold request (C++ `FoldStatus`): not a plain boolean — `Reverse`
/// toggles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldStatus {
    /// Force folded.
    Folded,
    /// Force expanded.
    Expanded,
    /// Toggle the current state.
    Reverse,
}

/// Parse-time LIFO of opener token indices
/// (C++ `TokenIndexStack`, `TokenIndexStack.cpp`): 8 inline slots,
/// then doubling heap storage capped once the capacity exceeds
/// `MAX_ITEMS`.
pub struct TokenIndexStack {
    items: Vec<u32>,
    capacity: u32,
}

impl TokenIndexStack {
    /// C++ `LOCAL_SIZE`.
    pub const LOCAL_SIZE: u32 = 8;
    /// C++ `MAX_ITEMS`: pushing fails once a full stack's capacity
    /// exceeds this.
    pub const MAX_ITEMS: u32 = 0x10000;

    /// Empty stack with the inline capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Vec::with_capacity(Self::LOCAL_SIZE as usize),
            capacity: Self::LOCAL_SIZE,
        }
    }

    /// Pushes an opener index; `false` when the growth cap is hit
    /// (C++ `Push`, `TokenIndexStack.cpp:21-73`).
    pub fn push(&mut self, index: u32) -> bool {
        if self.items.len() as u32 >= self.capacity {
            if self.capacity > Self::MAX_ITEMS {
                return false;
            }
            self.capacity = self.capacity.saturating_mul(2);
        }
        self.items.push(index);
        true
    }

    /// Pops the most recent opener, or `error_value` when empty
    /// (C++ `Pop`).
    pub fn pop(&mut self, error_value: u32) -> u32 {
        self.items.pop().unwrap_or(error_value)
    }

    /// Current depth.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// `true` when no opener is pending.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl Default for TokenIndexStack {
    fn default() -> Self {
        Self::new()
    }
}

/// Finds the innermost block containing `token_index` by scanning
/// backwards for a starter whose block spans it
/// (C++ `TokenToBlock`, `Instance.cpp:626-652`).
#[must_use]
pub fn token_to_block(state: &LexicalState, token_index: u32) -> u32 {
    if token_index as usize >= state.tokens.len() {
        return INVALID_BLOCK_ID;
    }
    let blocks_count = state.blocks.len() as u32;
    let mut pos = token_index;
    loop {
        if let Some(tok) = state.tokens.get(pos as usize) {
            if tok.block_starter && tok.block_id < blocks_count {
                if let Some(block) = state.blocks.get(tok.block_id as usize) {
                    if token_index < block.end_index() {
                        return tok.block_id;
                    }
                }
            }
        }
        if pos == 0 {
            return INVALID_BLOCK_ID;
        }
        pos = pos.saturating_sub(1);
    }
}

/// Moves the current token to `index` when possible (C++
/// `MoveToToken` without the scroll sync, which belongs to the
/// paint/viewport tasks).
pub fn move_to_token(state: &mut LexicalState, index: u32) {
    if state.no_items_visible || index == state.current_token_index {
        return;
    }
    let last = (state.tokens.len() as u32).saturating_sub(1);
    state.current_token_index = u32::min(index, last);
}

/// C++ `MoveToClosestVisibleToken` (`Instance.cpp:129-167`): if the
/// token at `start_index` is hidden, jump to the nearest visible
/// neighbor (ties prefer the earlier one).
pub fn move_to_closest_visible_token(state: &mut LexicalState, start_index: u32) {
    let count = state.tokens.len() as u32;
    if start_index >= count {
        return;
    }
    let visible_at = |s: &LexicalState, i: u32| s.tokens.get(i as usize).is_some_and(|t| t.visible);
    if visible_at(state, start_index) {
        move_to_token(state, start_index);
        return;
    }
    let mut before: Option<u32> = None;
    if start_index > 0 {
        let mut idx = start_index.saturating_sub(1);
        while idx > 0 && !visible_at(state, idx) {
            idx = idx.saturating_sub(1);
        }
        if visible_at(state, idx) {
            before = Some(idx);
        }
    }
    let mut after: Option<u32> = None;
    if start_index.saturating_add(1) < count {
        let mut idx = start_index.saturating_add(1);
        while idx < count && !visible_at(state, idx) {
            idx = idx.saturating_add(1);
        }
        if idx < count {
            after = Some(idx);
        }
    }
    let dif_before = before.map_or(u32::MAX, |i| start_index.saturating_sub(i));
    let dif_after = after.map_or(u32::MAX, |i| i.saturating_sub(start_index));
    if dif_after < dif_before {
        if let Some(i) = after {
            move_to_token(state, i);
        }
    } else if dif_before != u32::MAX {
        if let Some(i) = before {
            move_to_token(state, i);
        }
    }
}

/// C++ `SetFoldStatus(index, foldStatus, recursive)`
/// (`Instance.cpp:1307-1354`).
///
/// On a block starter: apply the requested state (`Reverse` toggles),
/// optionally propagate to nested starters (skipping manual-only
/// blocks when folding), then re-run visibility + layout. On any
/// other token: fold the block it belongs to.
pub fn set_fold_status(
    state: &mut LexicalState,
    index: u32,
    fold_status: FoldStatus,
    recursive: bool,
) {
    if state.no_items_visible {
        return;
    }
    let Some(tok) = state.tokens.get(index as usize) else {
        return;
    };
    if tok.block_starter {
        let fold_value = match fold_status {
            FoldStatus::Folded => true,
            FoldStatus::Expanded => false,
            FoldStatus::Reverse => !tok.folded,
        };
        let block_id = tok.block_id;
        if let Some(tok) = state.tokens.get_mut(index as usize) {
            tok.folded = fold_value;
        }
        if recursive {
            if let Some(block) = state.blocks.get(block_id as usize) {
                let (start, end) = (block.token_start, block.token_end);
                for idx in start..end {
                    let Some(current) = state.tokens.get(idx as usize) else {
                        continue;
                    };
                    if !current.block_starter {
                        continue;
                    }
                    let nested_id = current.block_id;
                    let manual_only = state
                        .blocks
                        .get(nested_id as usize)
                        .is_some_and(|b| b.manual_fold_only);
                    if fold_value && manual_only {
                        continue; // skip manual-fold-only blocks
                    }
                    if let Some(current) = state.tokens.get_mut(idx as usize) {
                        current.folded = fold_value;
                    }
                }
            }
        }
        relayout(state);
    } else if tok.block_id != INVALID_BLOCK_ID {
        // Token references a block: fold that block's starter.
        let starter = state
            .blocks
            .get(tok.block_id as usize)
            .map(|b| b.token_start);
        if let Some(starter) = starter {
            set_fold_status(state, starter, fold_status, recursive);
        }
    } else {
        // Otherwise: collapse the enclosing block.
        let block_idx = token_to_block(state, index);
        if block_idx != INVALID_BLOCK_ID {
            let starter = state.blocks.get(block_idx as usize).map(|b| b.token_start);
            if let Some(starter) = starter {
                move_to_token(state, starter);
                move_to_closest_visible_token(state, starter);
                set_fold_status(state, starter, FoldStatus::Folded, recursive);
            }
        }
    }
}

/// F9 — folds every block except manual-only ones, then moves the
/// cursor to the closest visible token
/// (C++ `FoldAll`, `Instance.cpp:1363-1372`).
pub fn fold_all(state: &mut LexicalState) {
    for i in 0..state.blocks.len() {
        let Some(block) = state.blocks.get(i) else {
            continue;
        };
        if block.manual_fold_only {
            continue;
        }
        let starter = block.token_start;
        if let Some(tok) = state.tokens.get_mut(starter as usize) {
            tok.folded = true;
        }
    }
    relayout(state);
    let current = state.current_token_index;
    move_to_closest_visible_token(state, current);
}

/// Ctrl+F9 — expands every block
/// (C++ `ExpandAll`, `Instance.cpp:1355-1362`).
pub fn expand_all(state: &mut LexicalState) {
    for i in 0..state.blocks.len() {
        let starter = state.blocks.get(i).map(|b| b.token_start);
        if let Some(starter) = starter {
            if let Some(tok) = state.tokens.get_mut(starter as usize) {
                tok.folded = false;
            }
        }
    }
    relayout(state);
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

    /// "{ a b }" with a block over tokens 0..=3 (end marker "}").
    fn braced_state() -> LexicalState {
        let mut state = parse(&mut MockParser, text_to_utf16("{ a b }"), false, (100, 100));
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
        state
    }

    #[test]
    fn toggle_fold_via_reverse() {
        let mut state = braced_state();
        // Fold: interior hidden, starter + end marker stay.
        set_fold_status(&mut state, 0, FoldStatus::Reverse, false);
        assert!(state.tokens[0].folded);
        assert!(state.tokens[0].visible);
        assert!(!state.tokens[1].visible);
        assert!(!state.tokens[2].visible);
        assert!(state.tokens[3].visible);
        // Toggle again: everything expands.
        set_fold_status(&mut state, 0, FoldStatus::Reverse, false);
        assert!(!state.tokens[0].folded);
        assert!(state.tokens.iter().all(|t| t.visible));
        // Explicit states are idempotent.
        set_fold_status(&mut state, 0, FoldStatus::Expanded, false);
        assert!(!state.tokens[0].folded);
        set_fold_status(&mut state, 0, FoldStatus::Folded, false);
        assert!(state.tokens[0].folded);
    }

    #[test]
    fn fold_on_interior_token_folds_enclosing_block() {
        let mut state = braced_state();
        // Token 2 ("b") has no block reference: the enclosing block
        // is found via TokenToBlock and folded.
        set_fold_status(&mut state, 2, FoldStatus::Reverse, false);
        assert!(state.tokens[0].folded);
        assert!(!state.tokens[2].visible);
        // The cursor moved off the hidden token.
        assert_eq!(state.current_token_index, 0);
    }

    #[test]
    fn fold_all_and_expand_all() {
        let mut state = braced_state();
        // Second block: manual-fold-only.
        state.blocks.push(Block {
            token_start: 3,
            token_end: 3,
            has_end_marker: false,
            manual_fold_only: true,
            fold_message: String::new(),
        });
        state.tokens[3].block_starter = true;
        state.tokens[3].block_id = 1;

        fold_all(&mut state);
        assert!(state.tokens[0].folded);
        // Manual-only block untouched by FoldAll.
        assert!(!state.tokens[3].folded);
        // Hidden tokens are not painted.
        assert!(!state.tokens[1].visible);
        assert!(!state.tokens[2].visible);

        expand_all(&mut state);
        assert!(!state.tokens[0].folded);
        assert!(state.tokens.iter().all(|t| t.visible));
    }

    #[test]
    fn recursive_fold_skips_manual_only_nested_blocks() {
        // "{ ( x ) }" — outer block 0..=4, nested manual-only block
        // over tokens 1..=3.
        let mut state = parse(
            &mut MockParser,
            text_to_utf16("{ ( x ) }"),
            false,
            (100, 100),
        );
        assert_eq!(state.tokens.len(), 5);
        state.blocks.push(Block {
            token_start: 0,
            token_end: 4,
            has_end_marker: true,
            manual_fold_only: false,
            fold_message: String::new(),
        });
        state.blocks.push(Block {
            token_start: 1,
            token_end: 3,
            has_end_marker: true,
            manual_fold_only: true,
            fold_message: String::new(),
        });
        state.tokens[0].block_starter = true;
        state.tokens[0].block_id = 0;
        state.tokens[1].block_starter = true;
        state.tokens[1].block_id = 1;

        set_fold_status(&mut state, 0, FoldStatus::Folded, true);
        assert!(state.tokens[0].folded);
        assert!(!state.tokens[1].folded); // manual-only skipped
                                          // Recursive expand clears nested blocks regardless.
        set_fold_status(&mut state, 0, FoldStatus::Expanded, true);
        state.tokens[1].folded = true;
        set_fold_status(&mut state, 0, FoldStatus::Expanded, true);
        assert!(!state.tokens[1].folded);
    }

    #[test]
    fn token_index_stack_push_pop_and_growth() {
        let mut stack = TokenIndexStack::new();
        assert!(stack.is_empty());
        assert_eq!(stack.pop(0xDEAD), 0xDEAD);
        // Fill past the 8 inline slots: heap growth is transparent.
        for i in 0..100 {
            assert!(stack.push(i));
        }
        assert_eq!(stack.len(), 100);
        for i in (0..100).rev() {
            assert_eq!(stack.pop(u32::MAX), i);
        }
        assert!(stack.is_empty());
    }

    #[test]
    fn token_to_block_scans_backwards() {
        let state = braced_state();
        assert_eq!(token_to_block(&state, 1), 0);
        assert_eq!(token_to_block(&state, 2), 0);
        // The end marker (index 3) equals end_index → outside.
        assert_eq!(token_to_block(&state, 3), INVALID_BLOCK_ID);
        assert_eq!(token_to_block(&state, 99), INVALID_BLOCK_ID);
    }

    #[test]
    fn closest_visible_prefers_nearer_then_earlier() {
        let mut state = braced_state();
        set_fold_status(&mut state, 0, FoldStatus::Folded, false);
        // Token 1 hidden: before-neighbor 0 (dist 1) beats
        // after-neighbor 3 (dist 2).
        state.current_token_index = 3;
        move_to_closest_visible_token(&mut state, 1);
        assert_eq!(state.current_token_index, 0);
        // Token 2 hidden: dist to 0 is 2, to 3 is 1 → picks 3.
        move_to_closest_visible_token(&mut state, 2);
        assert_eq!(state.current_token_index, 3);
    }
}
