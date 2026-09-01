//! `LexicalViewer` keyboard navigation (spec `02_VIEWER_LEXICAL`
//! §7.2–§7.4, §9).
//!
//! C++ anchors: `Instance::OnKeyEvent` (`Instance.cpp:1539-1672`),
//! `MoveToToken` (`Instance.cpp:1083-1102`), `MoveLeft` / `MoveRight`
//! (`Instance.cpp:1103-1154`), `MoveUp` / `MoveDown`
//! (`Instance.cpp:1155-1270`), `MoveToNextSimilarToken`
//! (`Instance.cpp:1271-1305`), `MoveToClosestVisibleToken`
//! (`Instance.cpp:129-167`), `MakeTokenVisible`
//! (`Instance.cpp:666-690`), `EnsureCurrentItemIsVisible`
//! (`Instance.cpp:692-714`), `ShowFindAllDialog`
//! (`Instance.cpp:1969-1986`), `ComputeXDist` (`Instance.cpp:50`).
//!
//! Vertical movement is **visual-row** navigation: walk to the
//! previous/next distinct `pos.y`, then pick the token on that row
//! whose X is closest to the current one (§7.2). `PageUp`/`PageDown`
//! move by `GetHeight()` visual rows, not token count (§7.3).
//!
//! Spec §9 lists **Ctrl+F → `FindSimilar`** (highlight tokens with the
//! same hash). The C++ `OnKeyEvent` has no `Ctrl+F` case — similarity
//! highlighting is permanently driven by the paint loop through
//! `currentHash` plus the `HighlightSimilarTokens` property, and the
//! explicit hash search lives in `ShowFindAllDialog` (key `A`). The
//! Rust port binds `Ctrl+F` per the spec matrix and reuses the same
//! hash-matching search; the discrepancy is noted here per the
//! anchor-first rule.

use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::selection::Selection;

use super::fold::{expand_all, fold_all, set_fold_status, token_to_block, FoldStatus};
use super::paint::Scroll;
use super::parse::{relayout, LexicalState, INVALID_BLOCK_ID};

/// C++ `ComputeXDist` (`Instance.cpp:50`): absolute distance.
#[must_use]
pub const fn compute_x_dist(x1: i32, x2: i32) -> i32 {
    if x1 > x2 {
        x1.saturating_sub(x2)
    } else {
        x2.saturating_sub(x1)
    }
}

/// Outcome of an `N`/`P` similar-token jump
/// (C++ `MoveToNextSimilarToken`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimilarMove {
    /// The current token's hash is 0: C++ shows the "similarity
    /// search disabled" error box **but still runs the search loop**
    /// (`Instance.cpp:1277-1296` has no early return — intentional
    /// parity).
    pub similarity_disabled: bool,
    /// New token index, or `None` when no other token shares the hash
    /// (C++ shows the "There aren't any similar tokens" notification).
    pub moved_to: Option<u32>,
}

/// What the shell must do after a key event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyResponse {
    /// Not a lexical-viewer key — forward to `ViewControl`.
    NotHandled,
    /// Consumed; all state changes already applied.
    Handled,
    /// Enter — open the token edit dialog (C++ `EditCurrentToken`).
    EditToken,
    /// `A` — open the Find-All dialog over these token indices; an
    /// empty list means the hash is 0 and C++ shows the "similarity
    /// search disabled" error instead.
    FindAll(Vec<u32>),
    /// Ctrl+F (spec §9) — indices of tokens sharing the current
    /// token's hash, for similarity highlight.
    FindSimilar(Vec<u32>),
    /// `N`/`P`/Ctrl+PageDown/Ctrl+PageUp — jump result; the shell
    /// surfaces the C++ message boxes.
    SimilarMove(SimilarMove),
}

/// Tokens sharing the hash of `tokens[index]` (the search behind
/// `ShowFindAllDialog` and the §9 Ctrl+F highlight). A zero hash means
/// similarity is disabled for that token → empty.
#[must_use]
pub fn find_similar_tokens(state: &LexicalState, index: u32) -> Vec<u32> {
    let Some(tok) = state.tokens.get(index as usize) else {
        return Vec::new();
    };
    if tok.hash == 0 {
        return Vec::new();
    }
    let hash = tok.hash;
    let mut result = Vec::new();
    for (i, t) in state.tokens.iter().enumerate() {
        if t.hash == hash {
            result.push(i as u32);
        }
    }
    result
}

/// C++ `MakeTokenVisible` (`Instance.cpp:666-690`): force the token
/// visible and unfold every enclosing block, walking outward to the
/// root (C++ recursion, bounded here by the block count).
pub fn make_token_visible(state: &mut LexicalState, index: u32) {
    if index as usize >= state.tokens.len() {
        return;
    }
    let mut idx = index;
    // The C++ recursion depth is the block-nesting depth; one hop per
    // block is a safe upper bound against malformed block tables.
    let mut guard = state.blocks.len().saturating_add(1);
    while guard > 0 {
        guard = guard.saturating_sub(1);
        let Some(tok) = state.tokens.get_mut(idx as usize) else {
            return;
        };
        let starter = tok.block_starter;
        tok.visible = true;
        if starter {
            tok.folded = false;
            if idx == 0 {
                return;
            }
        }
        // Find the block that contains this token (for starters:
        // start the scan at the preceding token).
        let scan_from = if starter { idx.saturating_sub(1) } else { idx };
        let block_id = token_to_block(state, scan_from);
        if block_id == INVALID_BLOCK_ID {
            return;
        }
        let Some(block) = state.blocks.get(block_id as usize) else {
            return;
        };
        idx = block.token_start;
    }
}

fn visible_at(state: &LexicalState, idx: usize) -> bool {
    state.tokens.get(idx).is_some_and(|t| t.visible)
}

fn y_at(state: &LexicalState, idx: usize) -> i32 {
    state.tokens.get(idx).map_or(0, |t| t.pos.y)
}

fn x_at(state: &LexicalState, idx: usize) -> i32 {
    state.tokens.get(idx).map_or(0, |t| t.pos.x)
}

/// Per-viewer input state the C++ `Instance` holds next to the token
/// model: selection, scroll origin and the viewport size used for
/// page jumps and scroll syncing.
pub struct LexicalInput {
    /// Token-index based selection (C++ `this->selection`).
    pub selection: Selection,
    /// Viewport scroll origin (C++ `this->Scroll`).
    pub scroll: Scroll,
    /// Control width (C++ `GetWidth()`).
    pub width: u32,
    /// Control height (C++ `GetHeight()`).
    pub height: u32,
}

impl LexicalInput {
    /// Fresh input state for a viewport of `width`×`height`.
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            selection: Selection::new(),
            scroll: Scroll::default(),
            width,
            height,
        }
    }

    /// C++ `EnsureCurrentItemIsVisible` (`Instance.cpp:692-714`);
    /// §7.1.1: unlike the paint cull, `scroll_right` subtracts
    /// `lineNrWidth`.
    pub fn ensure_current_item_is_visible(&mut self, state: &LexicalState) {
        if state.no_items_visible {
            return;
        }
        let Some(tok) = state.tokens.get(state.current_token_index as usize) else {
            return;
        };
        let tk_right = tok
            .pos
            .x
            .saturating_add(tok.pos.width.cast_signed())
            .saturating_sub(1);
        let tk_bottom = tok
            .pos
            .y
            .saturating_add(tok.pos.height.cast_signed())
            .saturating_sub(1);
        let scroll_right = self
            .scroll
            .x
            .saturating_add(self.width.cast_signed())
            .saturating_sub(1)
            .saturating_sub(state.line_nr_width.cast_signed());
        let scroll_bottom = self
            .scroll
            .y
            .saturating_add(self.height.cast_signed())
            .saturating_sub(1);
        if tok.pos.x >= self.scroll.x
            && tok.pos.y >= self.scroll.y
            && tk_right <= scroll_right
            && tk_bottom <= scroll_bottom
        {
            return;
        }
        if tk_right > scroll_right {
            self.scroll.x = self.scroll.x.saturating_add(tk_right.saturating_sub(scroll_right));
        }
        if tk_bottom > scroll_bottom {
            self.scroll.y = self
                .scroll
                .y
                .saturating_add(tk_bottom.saturating_sub(scroll_bottom));
        }
        if tok.pos.x < self.scroll.x {
            self.scroll.x = tok.pos.x;
        }
        if tok.pos.y < self.scroll.y {
            self.scroll.y = tok.pos.y;
        }
    }

    /// C++ `MoveToToken(index, selected, makeVisibleIfHidden)`
    /// (`Instance.cpp:1083-1102`): optional unfold-to-reveal, clamp,
    /// selection drag protocol, scroll sync.
    pub fn move_to_token(
        &mut self,
        state: &mut LexicalState,
        index: u32,
        selected: bool,
        make_visible_if_hidden: bool,
    ) {
        if make_visible_if_hidden {
            make_token_visible(state, index);
            relayout(state);
        }
        if state.no_items_visible || index == state.current_token_index {
            return;
        }
        let sidx = if selected {
            self.selection
                .begin_selection(u64::from(state.current_token_index))
        } else {
            None
        };
        let last = (state.tokens.len() as u32).saturating_sub(1);
        state.current_token_index = u32::min(index, last);
        self.ensure_current_item_is_visible(state);
        if selected {
            if let Some(sidx) = sidx {
                self.selection
                    .update_selection(sidx, u64::from(state.current_token_index));
            }
        }
    }

    /// C++ `MoveToClosestVisibleToken(startPoint, selected)`
    /// (`Instance.cpp:129-167`): if hidden, jump to the nearest
    /// visible neighbor (ties prefer the earlier one).
    pub fn move_to_closest_visible_token(
        &mut self,
        state: &mut LexicalState,
        start_index: u32,
        selected: bool,
    ) {
        let count = state.tokens.len() as u32;
        if start_index >= count {
            return;
        }
        if visible_at(state, start_index as usize) {
            self.move_to_token(state, start_index, selected, false);
            return;
        }
        let mut before: Option<u32> = None;
        if start_index > 0 {
            let mut idx = start_index.saturating_sub(1);
            while idx > 0 && !visible_at(state, idx as usize) {
                idx = idx.saturating_sub(1);
            }
            if visible_at(state, idx as usize) {
                before = Some(idx);
            }
        }
        let mut after: Option<u32> = None;
        let next = start_index.saturating_add(1);
        if next < count {
            let mut idx = next;
            while idx < count && !visible_at(state, idx as usize) {
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
                self.move_to_token(state, i, selected, false);
            }
        } else if dif_before != u32::MAX {
            if let Some(i) = before {
                self.move_to_token(state, i, selected, false);
            }
        }
    }

    /// C++ `MoveLeft(selected, stopAfterFirst)`
    /// (`Instance.cpp:1103-1129`): previous visible token on the same
    /// row (Left) or the row's first token (Home).
    pub fn move_left(&mut self, state: &mut LexicalState, selected: bool, stop_after_first: bool) {
        if state.current_token_index == 0 || state.no_items_visible {
            return;
        }
        let current = state.current_token_index as usize;
        let y_pos = y_at(state, current);
        let mut idx = current.saturating_sub(1);
        let mut last_valid = current;
        while idx > 0 {
            if !visible_at(state, idx) {
                idx = idx.saturating_sub(1);
                continue;
            }
            if y_at(state, idx) != y_pos {
                break;
            }
            last_valid = idx;
            if stop_after_first {
                break;
            }
            idx = idx.saturating_sub(1);
        }
        if idx == 0 && visible_at(state, 0) && y_at(state, 0) == y_pos {
            last_valid = 0;
        }
        self.move_to_token(state, last_valid as u32, selected, false);
    }

    /// C++ `MoveRight(selected, stopAfterFirst)`
    /// (`Instance.cpp:1130-1154`): next visible token on the same row
    /// (Right) or the row's last token (End).
    pub fn move_right(&mut self, state: &mut LexicalState, selected: bool, stop_after_first: bool) {
        if state.no_items_visible {
            return;
        }
        let current = state.current_token_index as usize;
        let y_pos = y_at(state, current);
        let count = state.tokens.len();
        let mut idx = current.saturating_add(1);
        let mut last_valid = current;
        while idx < count {
            if !visible_at(state, idx) {
                idx = idx.saturating_add(1);
                continue;
            }
            if y_at(state, idx) != y_pos {
                break;
            }
            last_valid = idx;
            if stop_after_first {
                break;
            }
            idx = idx.saturating_add(1);
        }
        self.move_to_token(state, last_valid as u32, selected, false);
    }

    /// C++ `MoveUp(times, selected)` (`Instance.cpp:1155-1225`), §7.2:
    /// walk back `times` distinct `pos.y` rows, then pick the visible
    /// token on that row with the smallest `ComputeXDist` to the
    /// current X.
    pub fn move_up(&mut self, state: &mut LexicalState, times: u32, selected: bool) {
        if state.no_items_visible || times == 0 || state.current_token_index == 0 {
            return;
        }
        let current = state.current_token_index as usize;
        let mut last_y = y_at(state, current);
        let pos_x = x_at(state, current);
        let mut idx = current.saturating_sub(1);
        let mut times = times;
        while times > 0 {
            while idx > 0 && y_at(state, idx) == last_y {
                idx = idx.saturating_sub(1);
            }
            while idx > 0 && (!visible_at(state, idx) || y_at(state, idx) == last_y) {
                idx = idx.saturating_sub(1);
            }
            if idx == 0 {
                if visible_at(state, 0) {
                    if y_at(state, 0) == last_y {
                        // Already on the first line → first token.
                        self.move_to_token(state, 0, selected, false);
                        return;
                    }
                    // Otherwise: just consume one `times` step.
                } else {
                    self.move_to_closest_visible_token(state, 0, selected);
                    return;
                }
            }
            last_y = y_at(state, idx);
            times = times.saturating_sub(1);
        }
        // Row found — pick the closest X on it.
        let mut found = idx;
        let mut best_dist = compute_x_dist(x_at(state, found), pos_x);
        let mut i = idx;
        while i > 0 && best_dist > 0 {
            if !visible_at(state, i) {
                i = i.saturating_sub(1);
                continue;
            }
            if y_at(state, i) != last_y {
                break;
            }
            let dist = compute_x_dist(x_at(state, i), pos_x);
            if dist < best_dist {
                found = i;
                best_dist = dist;
            }
            i = i.saturating_sub(1);
        }
        if i == 0 && visible_at(state, 0) {
            // The first token itself might be the closest.
            let dist = compute_x_dist(x_at(state, 0), pos_x);
            if dist < best_dist {
                found = 0;
            }
        }
        self.move_to_token(state, found as u32, selected, false);
    }

    /// C++ `MoveDown(times, selected)` (`Instance.cpp:1226-1270`),
    /// §7.2 mirror of [`Self::move_up`].
    pub fn move_down(&mut self, state: &mut LexicalState, times: u32, selected: bool) {
        if state.no_items_visible || times == 0 {
            return;
        }
        let cnt = state.tokens.len();
        let current = state.current_token_index as usize;
        let mut last_y = y_at(state, current);
        let pos_x = x_at(state, current);
        let mut idx = current.saturating_add(1);
        if idx >= cnt {
            return;
        }
        let mut times = times;
        while times > 0 {
            while idx < cnt && (!visible_at(state, idx) || y_at(state, idx) == last_y) {
                idx = idx.saturating_add(1);
            }
            if idx >= cnt {
                // Already on the last line → last token.
                let last = (cnt as u32).saturating_sub(1);
                self.move_to_closest_visible_token(state, last, selected);
                return;
            }
            last_y = y_at(state, idx);
            times = times.saturating_sub(1);
        }
        let mut found = idx;
        let mut best_dist = compute_x_dist(x_at(state, found), pos_x);
        let mut i = idx;
        while i < cnt && best_dist > 0 {
            if !visible_at(state, i) {
                i = i.saturating_add(1);
                continue;
            }
            if y_at(state, i) != last_y {
                break;
            }
            let dist = compute_x_dist(x_at(state, i), pos_x);
            if dist < best_dist {
                found = i;
                best_dist = dist;
            }
            i = i.saturating_add(1);
        }
        self.move_to_token(state, found as u32, selected, false);
    }

    /// C++ `MoveToNextSimilarToken(direction)`
    /// (`Instance.cpp:1271-1305`): circular scan for the next token
    /// with the same hash. When the hash is 0 the error box is shown
    /// **and the scan still runs** (parity — no early return in C++),
    /// so a move can happen even with similarity disabled.
    pub fn move_to_next_similar_token(
        &mut self,
        state: &mut LexicalState,
        direction: i32,
    ) -> Option<SimilarMove> {
        if state.no_items_visible {
            return None;
        }
        let count = state.tokens.len() as u32;
        let current = state.current_token_index;
        let hash = state.tokens.get(current as usize).map(|t| t.hash)?;
        let similarity_disabled = hash == 0;
        let mut index = current;
        loop {
            if direction == 1 {
                index = index.saturating_add(1);
                if index >= count {
                    index = 0;
                }
            } else if index == 0 {
                index = count.saturating_sub(1);
            } else {
                index = index.saturating_sub(1);
            }
            if index == current
                || state.tokens.get(index as usize).is_some_and(|t| t.hash == hash)
            {
                break;
            }
        }
        if index == current {
            Some(SimilarMove {
                similarity_disabled,
                moved_to: None,
            })
        } else {
            self.move_to_token(state, index, false, true);
            Some(SimilarMove {
                similarity_disabled,
                moved_to: Some(index),
            })
        }
    }

    /// Ctrl+A (`Instance.cpp:1639-1645`): one zone over every token.
    pub fn select_all(&mut self, state: &LexicalState) {
        if !state.tokens.is_empty() && !state.no_items_visible {
            self.selection.clear();
            let last = (state.tokens.len() as u64).saturating_sub(1);
            self.selection.set_selection(0, 0, last);
        }
    }

    /// F8 `ChangeSelectionType` command (note: the C++
    /// `KeyboardControl` captions for F8/F9 are swapped in
    /// `LexicalViewer.hpp:29-30`; the command IDs map correctly).
    pub fn change_selection_type(&mut self) {
        self.selection.invert_multi_selection_mode();
    }

    /// Movement and viewport-scroll keys from the `OnKeyEvent` switch
    /// (`Instance.cpp:1543-1606`); `None` when the key is not a
    /// navigation key.
    fn handle_navigation_key(&mut self, state: &mut LexicalState, key: Key) -> Option<KeyResponse> {
        let none = key.modifier == KeyModifier::None;
        let shift = key.modifier == KeyModifier::Shift;
        let ctrl = key.modifier == KeyModifier::Ctrl;
        let page = u32::max(1, self.height);
        match key.code {
            KeyCode::Up if none || shift => self.move_up(state, 1, shift),
            KeyCode::PageUp if none || shift => self.move_up(state, page, shift),
            KeyCode::Down if none || shift => self.move_down(state, 1, shift),
            KeyCode::PageDown if none || shift => self.move_down(state, page, shift),
            KeyCode::Left if none || shift => self.move_left(state, shift, true),
            KeyCode::Right if none || shift => self.move_right(state, shift, true),
            KeyCode::Home if none || shift => self.move_left(state, shift, false),
            KeyCode::End if none || shift => self.move_right(state, shift, false),
            // Viewport scroll (Ctrl+arrows).
            KeyCode::Left if ctrl => {
                if self.scroll.x > 0 {
                    self.scroll.x = self.scroll.x.saturating_sub(1);
                }
            }
            KeyCode::Right if ctrl => self.scroll.x = self.scroll.x.saturating_add(1),
            KeyCode::Up if ctrl => {
                if self.scroll.y > 0 {
                    self.scroll.y = self.scroll.y.saturating_sub(1);
                }
            }
            KeyCode::Down if ctrl => self.scroll.y = self.scroll.y.saturating_add(1),
            _ => return None,
        }
        Some(KeyResponse::Handled)
    }

    /// The `OnKeyEvent` switch (`Instance.cpp:1539-1672`) + spec §9.
    /// `character` carries the raw typed char for the `[ ] { }`
    /// token-size keys (C++ `characterCode`).
    pub fn handle_key(
        &mut self,
        state: &mut LexicalState,
        key: Key,
        character: Option<char>,
    ) -> KeyResponse {
        if let Some(response) = self.handle_navigation_key(state, key) {
            return response;
        }
        let none = key.modifier == KeyModifier::None;
        let ctrl = key.modifier == KeyModifier::Ctrl;
        match key.code {
            // Fold / unfold.
            KeyCode::Space if none => {
                let current = state.current_token_index;
                set_fold_status(state, current, FoldStatus::Reverse, false);
                return KeyResponse::Handled;
            }
            KeyCode::Space if ctrl => {
                let current = state.current_token_index;
                set_fold_status(state, current, FoldStatus::Reverse, true);
                return KeyResponse::Handled;
            }
            KeyCode::Enter if none => return KeyResponse::EditToken,
            KeyCode::E if none => {
                expand_all(state);
                return KeyResponse::Handled;
            }
            KeyCode::F if none => {
                fold_all(state);
                return KeyResponse::Handled;
            }
            KeyCode::A if none => {
                if state.no_items_visible {
                    return KeyResponse::Handled;
                }
                return KeyResponse::FindAll(find_similar_tokens(
                    state,
                    state.current_token_index,
                ));
            }
            // Spec §9 Ctrl+F FindSimilar (no C++ OnKeyEvent case; see
            // module docs).
            KeyCode::F if ctrl => {
                if state.no_items_visible {
                    return KeyResponse::Handled;
                }
                return KeyResponse::FindSimilar(find_similar_tokens(
                    state,
                    state.current_token_index,
                ));
            }
            KeyCode::N if none => {
                return self
                    .move_to_next_similar_token(state, 1)
                    .map_or(KeyResponse::Handled, KeyResponse::SimilarMove);
            }
            KeyCode::PageDown if ctrl => {
                return self
                    .move_to_next_similar_token(state, 1)
                    .map_or(KeyResponse::Handled, KeyResponse::SimilarMove);
            }
            KeyCode::P if none => {
                return self
                    .move_to_next_similar_token(state, -1)
                    .map_or(KeyResponse::Handled, KeyResponse::SimilarMove);
            }
            KeyCode::PageUp if ctrl => {
                return self
                    .move_to_next_similar_token(state, -1)
                    .map_or(KeyResponse::Handled, KeyResponse::SimilarMove);
            }
            KeyCode::A if ctrl => {
                self.select_all(state);
                return KeyResponse::Handled;
            }
            _ => {}
        }
        // Character keys: token size caps (C++ clamps 6..=500 width,
        // 1..=500 height, then RecomputeTokenPositions).
        if let Some(ch) = character {
            match ch {
                '[' => {
                    state.max_token_size.0 = u32::max(6, state.max_token_size.0.saturating_sub(1));
                    relayout(state);
                    return KeyResponse::Handled;
                }
                ']' => {
                    state.max_token_size.0 =
                        u32::min(500, state.max_token_size.0.saturating_add(1));
                    relayout(state);
                    return KeyResponse::Handled;
                }
                '{' => {
                    state.max_token_size.1 = u32::max(1, state.max_token_size.1.saturating_sub(1));
                    relayout(state);
                    return KeyResponse::Handled;
                }
                '}' => {
                    state.max_token_size.1 =
                        u32::min(500, state.max_token_size.1.saturating_add(1));
                    relayout(state);
                    return KeyResponse::Handled;
                }
                _ => {}
            }
        }
        KeyResponse::NotHandled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexical_viewer::fold::{set_fold_status, FoldStatus};
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

    fn parse_str(text: &str) -> LexicalState {
        parse(&mut MockParser, text_to_utf16(text), false, (100, 100))
    }

    fn key(code: KeyCode, modifier: KeyModifier) -> Key {
        Key::new(code, modifier)
    }

    /// Three rows:
    /// row 0: `aa`(x=0) `bb`(x=3) `cc`(x=6)
    /// row 1: `dddddd`(x=0) `e`(x=7)
    /// row 2: `ff`(x=0) `gg`(x=3) `hh`(x=6)
    fn grid_state() -> LexicalState {
        parse_str("aa bb cc\ndddddd e\nff gg hh")
    }

    #[test]
    fn move_up_walks_by_pos_y_and_picks_closest_x() {
        let mut state = grid_state();
        let mut input = LexicalInput::new(80, 25);
        // Start on "hh" (index 7, x=6, y=2).
        state.current_token_index = 7;
        // Up → row 1: "dddddd" x=0 (dist 6), "e" x=7 (dist 1) → "e".
        input.move_up(&mut state, 1, false);
        assert_eq!(state.current_token_index, 4);
        // Up again → row 0: "cc" x=6 vs x=7 → dist 1 wins over
        // "bb" (dist 4) and "aa" (dist 7).
        input.move_up(&mut state, 1, false);
        assert_eq!(state.current_token_index, 2);
        // Up on the first row → first token.
        input.move_up(&mut state, 1, false);
        assert_eq!(state.current_token_index, 0);
    }

    #[test]
    fn move_down_walks_by_pos_y_and_picks_closest_x() {
        let mut state = grid_state();
        let mut input = LexicalInput::new(80, 25);
        // "bb" (index 1, x=3) → row 1: "dddddd" x=0 (3) vs "e" x=7
        // (4) → "dddddd".
        state.current_token_index = 1;
        input.move_down(&mut state, 1, false);
        assert_eq!(state.current_token_index, 3);
        // Down from "e"-adjacent "dddddd" (x=0) → row 2 → "ff" x=0.
        input.move_down(&mut state, 1, false);
        assert_eq!(state.current_token_index, 5);
        // Down on the last row → last token.
        input.move_down(&mut state, 1, false);
        assert_eq!(state.current_token_index, 7);
    }

    #[test]
    fn page_moves_use_visual_rows() {
        let mut state = grid_state();
        // Height 2 → PageDown jumps two rows at once.
        let mut input = LexicalInput::new(80, 2);
        state.current_token_index = 0;
        input.handle_key(&mut state, key(KeyCode::PageDown, KeyModifier::None), None);
        // Two rows down from row 0 → row 2, closest to x=0 → "ff".
        assert_eq!(state.current_token_index, 5);
        input.handle_key(&mut state, key(KeyCode::PageUp, KeyModifier::None), None);
        assert_eq!(state.current_token_index, 0);
    }

    #[test]
    fn move_left_right_stop_after_first_vs_row_ends() {
        let mut state = grid_state();
        let mut input = LexicalInput::new(80, 25);
        state.current_token_index = 1; // "bb"
        input.move_right(&mut state, false, true);
        assert_eq!(state.current_token_index, 2); // one step
        input.move_left(&mut state, false, true);
        assert_eq!(state.current_token_index, 1);
        // End → last token of the row; Home → first.
        input.move_right(&mut state, false, false);
        assert_eq!(state.current_token_index, 2);
        input.move_left(&mut state, false, false);
        assert_eq!(state.current_token_index, 0);
        // Right at the row end stays (next row not entered).
        state.current_token_index = 2;
        input.move_right(&mut state, false, true);
        assert_eq!(state.current_token_index, 2);
    }

    #[test]
    fn vertical_move_skips_hidden_tokens() {
        // "{ a b }" then a second row "x".
        let mut state = parse_str("{ a b }\nx");
        state.blocks.push(Block {
            token_start: 0,
            token_end: 3,
            has_end_marker: true,
            manual_fold_only: false,
            fold_message: String::new(),
        });
        state.tokens[0].block_starter = true;
        state.tokens[0].block_id = 0;
        set_fold_status(&mut state, 0, FoldStatus::Folded, false);
        assert!(!state.tokens[1].visible);
        let mut input = LexicalInput::new(80, 25);
        // From "x" (index 4, row 1), Up lands on the visible row-0
        // tokens only ("{" or "}"), never on hidden "a"/"b".
        state.current_token_index = 4;
        input.move_up(&mut state, 1, false);
        assert!(state.current_token_index == 0 || state.current_token_index == 3);
        assert!(state.tokens[state.current_token_index as usize].visible);
    }

    #[test]
    fn shift_movement_builds_a_selection() {
        let mut state = grid_state();
        let mut input = LexicalInput::new(80, 25);
        state.current_token_index = 1;
        input.handle_key(&mut state, key(KeyCode::Down, KeyModifier::Shift), None);
        // Selection spans token indices 1..=3 (inclusive bounds).
        assert_eq!(input.selection.get_selection(0), Some((1, 3)));
        // Extending the drag updates the same zone.
        input.handle_key(&mut state, key(KeyCode::Down, KeyModifier::Shift), None);
        assert_eq!(input.selection.get_selection(0), Some((1, 5)));
    }

    #[test]
    fn ctrl_a_selects_all_tokens() {
        let mut state = grid_state();
        let mut input = LexicalInput::new(80, 25);
        let response = input.handle_key(&mut state, key(KeyCode::A, KeyModifier::Ctrl), None);
        assert_eq!(response, KeyResponse::Handled);
        assert_eq!(input.selection.get_selection(0), Some((0, 7)));
    }

    #[test]
    fn ctrl_f_returns_similar_token_hashes() {
        // "x" appears at indices 0, 2, 4.
        let mut state = parse_str("x y x z\nx");
        let mut input = LexicalInput::new(80, 25);
        state.current_token_index = 0;
        let response = input.handle_key(&mut state, key(KeyCode::F, KeyModifier::Ctrl), None);
        assert_eq!(response, KeyResponse::FindSimilar(vec![0, 2, 4]));
        // A (FindAll) uses the same hash search.
        let response = input.handle_key(&mut state, key(KeyCode::A, KeyModifier::None), None);
        assert_eq!(response, KeyResponse::FindAll(vec![0, 2, 4]));
        // Zero hash → similarity disabled → empty list.
        state.tokens[0].hash = 0;
        let response = input.handle_key(&mut state, key(KeyCode::F, KeyModifier::Ctrl), None);
        assert_eq!(response, KeyResponse::FindSimilar(Vec::new()));
    }

    #[test]
    fn similar_token_navigation_wraps_circularly() {
        let mut state = parse_str("x y x z x");
        let mut input = LexicalInput::new(80, 25);
        // x at 0, 2, 4.
        state.current_token_index = 4;
        let response = input.handle_key(&mut state, key(KeyCode::N, KeyModifier::None), None);
        assert_eq!(
            response,
            KeyResponse::SimilarMove(SimilarMove {
                similarity_disabled: false,
                moved_to: Some(0), // wrapped past the end
            })
        );
        assert_eq!(state.current_token_index, 0);
        // P wraps backwards.
        let response = input.handle_key(&mut state, key(KeyCode::P, KeyModifier::None), None);
        assert_eq!(
            response,
            KeyResponse::SimilarMove(SimilarMove {
                similarity_disabled: false,
                moved_to: Some(4),
            })
        );
        // Ctrl+PageDown is an N alias.
        let response =
            input.handle_key(&mut state, key(KeyCode::PageDown, KeyModifier::Ctrl), None);
        assert_eq!(
            response,
            KeyResponse::SimilarMove(SimilarMove {
                similarity_disabled: false,
                moved_to: Some(0),
            })
        );
    }

    #[test]
    fn similar_navigation_with_unique_hash_reports_none() {
        let mut state = parse_str("aa bb cc");
        let mut input = LexicalInput::new(80, 25);
        state.current_token_index = 1;
        let outcome = input.move_to_next_similar_token(&mut state, 1);
        assert_eq!(
            outcome,
            Some(SimilarMove {
                similarity_disabled: false,
                moved_to: None,
            })
        );
        assert_eq!(state.current_token_index, 1);
    }

    #[test]
    fn disabled_hash_reports_error_but_still_scans() {
        // C++ parity: hash==0 shows the error box yet the do-while
        // still runs and can land on another zero-hash token.
        let mut state = parse_str("aa bb cc");
        state.tokens[0].hash = 0;
        state.tokens[2].hash = 0;
        let mut input = LexicalInput::new(80, 25);
        state.current_token_index = 0;
        let outcome = input.move_to_next_similar_token(&mut state, 1);
        assert_eq!(
            outcome,
            Some(SimilarMove {
                similarity_disabled: true,
                moved_to: Some(2),
            })
        );
        assert_eq!(state.current_token_index, 2);
    }

    #[test]
    fn similar_jump_unfolds_hidden_target() {
        // "x { x } y": block hides the inner x; N must unfold it.
        let mut state = parse_str("x { x } y");
        state.blocks.push(Block {
            token_start: 1,
            token_end: 3,
            has_end_marker: true,
            manual_fold_only: false,
            fold_message: String::new(),
        });
        state.tokens[1].block_starter = true;
        state.tokens[1].block_id = 0;
        set_fold_status(&mut state, 1, FoldStatus::Folded, false);
        assert!(!state.tokens[2].visible);
        let mut input = LexicalInput::new(80, 25);
        state.current_token_index = 0;
        let outcome = input.move_to_next_similar_token(&mut state, 1);
        assert_eq!(
            outcome,
            Some(SimilarMove {
                similarity_disabled: false,
                moved_to: Some(2),
            })
        );
        // MakeTokenVisible unfolded the enclosing block.
        assert!(state.tokens[2].visible);
        assert!(!state.tokens[1].folded);
        assert_eq!(state.current_token_index, 2);
    }

    #[test]
    fn fold_keys_route_to_fold_engine() {
        let mut state = parse_str("{ a b }");
        state.blocks.push(Block {
            token_start: 0,
            token_end: 3,
            has_end_marker: true,
            manual_fold_only: false,
            fold_message: String::new(),
        });
        state.tokens[0].block_starter = true;
        state.tokens[0].block_id = 0;
        let mut input = LexicalInput::new(80, 25);
        // Space toggles the current block.
        input.handle_key(&mut state, key(KeyCode::Space, KeyModifier::None), None);
        assert!(state.tokens[0].folded);
        // E expands all, F folds all.
        input.handle_key(&mut state, key(KeyCode::E, KeyModifier::None), None);
        assert!(!state.tokens[0].folded);
        input.handle_key(&mut state, key(KeyCode::F, KeyModifier::None), None);
        assert!(state.tokens[0].folded);
    }

    #[test]
    fn ctrl_arrows_scroll_the_viewport() {
        let mut state = grid_state();
        let mut input = LexicalInput::new(80, 25);
        input.handle_key(&mut state, key(KeyCode::Down, KeyModifier::Ctrl), None);
        input.handle_key(&mut state, key(KeyCode::Right, KeyModifier::Ctrl), None);
        assert_eq!((input.scroll.x, input.scroll.y), (1, 1));
        input.handle_key(&mut state, key(KeyCode::Up, KeyModifier::Ctrl), None);
        input.handle_key(&mut state, key(KeyCode::Left, KeyModifier::Ctrl), None);
        assert_eq!((input.scroll.x, input.scroll.y), (0, 0));
        // Clamped at zero.
        input.handle_key(&mut state, key(KeyCode::Up, KeyModifier::Ctrl), None);
        assert_eq!(input.scroll.y, 0);
    }

    #[test]
    fn token_size_chars_clamp_and_relayout() {
        let mut state = parse_str("aa bb");
        state.max_token_size = (6, 1);
        let mut input = LexicalInput::new(80, 25);
        let none_key = key(KeyCode::None, KeyModifier::None);
        // At the minimums, shrinking is a no-op.
        input.handle_key(&mut state, none_key, Some('['));
        input.handle_key(&mut state, none_key, Some('{'));
        assert_eq!(state.max_token_size, (6, 1));
        input.handle_key(&mut state, none_key, Some(']'));
        input.handle_key(&mut state, none_key, Some('}'));
        assert_eq!(state.max_token_size, (7, 2));
        // Cap at 500.
        state.max_token_size = (500, 500);
        input.handle_key(&mut state, none_key, Some(']'));
        input.handle_key(&mut state, none_key, Some('}'));
        assert_eq!(state.max_token_size, (500, 500));
    }

    #[test]
    fn ensure_visible_subtracts_line_nr_width() {
        let mut state = grid_state();
        assert_eq!(state.line_nr_width, 4);
        // 10-wide viewport, gutter 4 → usable right edge is
        // scroll.x + 10 - 1 - 4 = scroll.x + 5.
        let mut input = LexicalInput::new(10, 25);
        // "cc" at x=6..7: tk_right 7 > 5 → scroll.x += 2.
        state.current_token_index = 2;
        input.ensure_current_item_is_visible(&state);
        assert_eq!(input.scroll.x, 2);
        // Moving back to x=0 pulls the scroll left again.
        state.current_token_index = 0;
        input.ensure_current_item_is_visible(&state);
        assert_eq!(input.scroll.x, 0);
        // Vertical: token on row 2 with height 1 viewport.
        input.height = 1;
        state.current_token_index = 5;
        input.ensure_current_item_is_visible(&state);
        assert_eq!(input.scroll.y, 2);
    }

    #[test]
    fn unmapped_keys_fall_through() {
        let mut state = grid_state();
        let mut input = LexicalInput::new(80, 25);
        let response = input.handle_key(&mut state, key(KeyCode::F5, KeyModifier::None), None);
        assert_eq!(response, KeyResponse::NotHandled);
        let response = input.handle_key(&mut state, key(KeyCode::None, KeyModifier::None), Some('q'));
        assert_eq!(response, KeyResponse::NotHandled);
    }

    #[test]
    fn enter_requests_token_editor() {
        let mut state = grid_state();
        let mut input = LexicalInput::new(80, 25);
        let response = input.handle_key(&mut state, key(KeyCode::Enter, KeyModifier::None), None);
        assert_eq!(response, KeyResponse::EditToken);
    }

    #[test]
    fn change_selection_type_toggles_multi_mode() {
        let mut input = LexicalInput::new(80, 25);
        assert!(!input.selection.is_multi_selection_enabled());
        input.change_selection_type();
        assert!(input.selection.is_multi_selection_enabled());
        input.change_selection_type();
        assert!(!input.selection.is_multi_selection_enabled());
    }

    #[test]
    fn movement_on_empty_state_is_safe() {
        let mut state = LexicalState {
            no_items_visible: true,
            ..Default::default()
        };
        let mut input = LexicalInput::new(80, 25);
        input.move_up(&mut state, 5, false);
        input.move_down(&mut state, 5, true);
        input.move_left(&mut state, false, false);
        input.move_right(&mut state, true, true);
        assert_eq!(input.move_to_next_similar_token(&mut state, 1), None);
        input.select_all(&state);
        assert!(!input.selection.has_any_selection());
        assert_eq!(state.current_token_index, 0);
    }
}
