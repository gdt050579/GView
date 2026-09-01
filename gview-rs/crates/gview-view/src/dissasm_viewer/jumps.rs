//! `DissasmViewer` jump history (spec `02_VIEWER_DISSASM` §7).
//!
//! C++ anchors: `CursorState` (`DissasmViewer.hpp:455-462`),
//! `JumpsHolder` (`DissasmViewer.hpp:464-502`),
//! `DISSASM_MAX_STORED_JUMPS` (`Instance.cpp:16`).
//!
//! A bounded back/forward jump stack. `insert` dedupes against the
//! whole deque — an existing state just re-points `current_index` to
//! it (no reordering, no re-push). A new state, when at capacity,
//! evicts the **most recent** entry (C++ `pop_back`, a quirk — the
//! oldest entries never leave) and lands at the back. `jump_back`
//! returns the state
//! at `current_index` then steps back; `jump_front` steps forward
//! first, then returns. The C++ quirk this preserves: `jump_back`
//! hands out the state the cursor is **on** and only then
//! decrements, so an immediate `jump_front` afterwards moves to the
//! same state rather than a new one.

use std::collections::VecDeque;

/// C++ `DISSASM_MAX_STORED_JUMPS` (`Instance.cpp:16`).
pub const DISSASM_MAX_STORED_JUMPS: usize = 5;

/// A stored viewport position (C++ `CursorState`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CursorState {
    /// First document line shown (C++ `startViewLine`).
    pub start_view_line: u32,
    /// Cursor row within the view (C++ `lineInView`).
    pub line_in_view: u32,
}

impl CursorState {
    /// A `(start_view_line, line_in_view)` position.
    #[must_use]
    pub const fn new(start_view_line: u32, line_in_view: u32) -> Self {
        Self {
            start_view_line,
            line_in_view,
        }
    }
}

/// Bounded back/forward jump history (C++ `JumpsHolder`).
pub struct JumpsHolder {
    max_capacity: usize,
    current_index: i32,
    jumps: VecDeque<CursorState>,
}

impl JumpsHolder {
    /// A holder bounded to `max_capacity` entries (C++ ctor asserts
    /// `> 0`; a zero cap is clamped to 1 here to stay panic-free).
    #[must_use]
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity: max_capacity.max(1),
            current_index: -1,
            jumps: VecDeque::new(),
        }
    }

    /// C++ `insert` (`DissasmViewer.hpp:476-487`): dedupe → repoint
    /// the cursor; otherwise evict the oldest at capacity and push to
    /// the back as the new current.
    pub fn insert(&mut self, new_state: CursorState) {
        for (i, state) in self.jumps.iter().enumerate() {
            if *state == new_state {
                self.current_index = i32::try_from(i).unwrap_or(i32::MAX);
                return;
            }
        }
        if self.jumps.len() == self.max_capacity {
            // C++ pops the BACK, not the front: once full, only the
            // last slot churns — the oldest entries never evict
            // (intentional parity, DissasmViewer.hpp:483-484).
            self.jumps.pop_back();
        }
        self.jumps.push_back(new_state);
        self.current_index = self.len_i32().saturating_sub(1);
    }

    /// C++ `JumpBack` (`DissasmViewer.hpp:489-494`): returns the
    /// state at `current_index` then decrements; `None` when the
    /// cursor is exhausted.
    pub fn jump_back(&mut self) -> Option<CursorState> {
        let idx = usize::try_from(self.current_index).ok()?;
        let state = self.jumps.get(idx).copied();
        self.current_index = self.current_index.saturating_sub(1);
        state
    }

    /// C++ `JumpFront` (`DissasmViewer.hpp:496-501`): increments then
    /// returns the new current; `None` when already at the front.
    pub fn jump_front(&mut self) -> Option<CursorState> {
        if self.current_index.saturating_add(1) < self.len_i32() {
            self.current_index = self.current_index.saturating_add(1);
            let idx = usize::try_from(self.current_index).ok()?;
            return self.jumps.get(idx).copied();
        }
        None
    }

    fn len_i32(&self) -> i32 {
        i32::try_from(self.jumps.len()).unwrap_or(i32::MAX)
    }

    /// Current cursor index (C++ `current_index`; `-1` = before the
    /// first entry).
    #[must_use]
    pub const fn current_index(&self) -> i32 {
        self.current_index
    }

    /// Number of stored jumps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.jumps.len()
    }

    /// `true` when no jumps are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.jumps.is_empty()
    }
}

impl Default for JumpsHolder {
    fn default() -> Self {
        Self::new(DISSASM_MAX_STORED_JUMPS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_back_front_transitions() {
        let mut holder = JumpsHolder::new(DISSASM_MAX_STORED_JUMPS);
        assert!(holder.is_empty());
        assert_eq!(holder.current_index(), -1);
        // Empty: JumpBack yields nothing.
        assert_eq!(holder.jump_back(), None);

        holder.insert(CursorState::new(0, 0));
        holder.insert(CursorState::new(10, 1));
        holder.insert(CursorState::new(20, 2));
        assert_eq!(holder.len(), 3);
        assert_eq!(holder.current_index(), 2);

        // JumpBack returns the current state, then steps back.
        assert_eq!(holder.jump_back(), Some(CursorState::new(20, 2)));
        assert_eq!(holder.current_index(), 1);
        assert_eq!(holder.jump_back(), Some(CursorState::new(10, 1)));
        assert_eq!(holder.jump_back(), Some(CursorState::new(0, 0)));
        assert_eq!(holder.current_index(), -1);
        assert_eq!(holder.jump_back(), None); // exhausted

        // JumpFront steps forward first: from ci = -1 it lands on
        // index 0, then walks up to the newest.
        assert_eq!(holder.jump_front(), Some(CursorState::new(0, 0)));
        assert_eq!(holder.current_index(), 0);
        assert_eq!(holder.jump_front(), Some(CursorState::new(10, 1)));
        assert_eq!(holder.jump_front(), Some(CursorState::new(20, 2)));
        assert_eq!(holder.current_index(), 2);
        assert_eq!(holder.jump_front(), None); // at the front
    }

    #[test]
    fn insert_dedupes_and_repoints_without_reordering() {
        let mut holder = JumpsHolder::new(DISSASM_MAX_STORED_JUMPS);
        holder.insert(CursorState::new(0, 0));
        holder.insert(CursorState::new(10, 1));
        holder.insert(CursorState::new(20, 2));
        // Re-inserting an existing state just moves current_index to
        // it — no new entry, no reordering.
        holder.insert(CursorState::new(10, 1));
        assert_eq!(holder.len(), 3);
        assert_eq!(holder.current_index(), 1);
        // The order in the deque is unchanged: back is still (20, 2).
        assert_eq!(holder.jump_front(), Some(CursorState::new(20, 2)));
    }

    #[test]
    fn capacity_five_churns_only_the_last_slot() {
        let mut holder = JumpsHolder::new(DISSASM_MAX_STORED_JUMPS);
        for i in 0..7 {
            holder.insert(CursorState::new(i * 10, i));
        }
        // Cap 5. C++ pop_back quirk: once full ([0,1,2,3,4]), each
        // new insert pops the last and pushes → the front four
        // (0..3) stay, only the tail slot updates → [0,1,2,3,6].
        assert_eq!(holder.len(), DISSASM_MAX_STORED_JUMPS);
        assert_eq!(holder.current_index(), 4);
        let mut states = Vec::new();
        while let Some(state) = holder.jump_back() {
            states.push(state);
        }
        assert_eq!(states.first(), Some(&CursorState::new(60, 6))); // last slot
        assert_eq!(states.last(), Some(&CursorState::new(0, 0))); // oldest kept
        assert_eq!(states.len(), 5);
        // The evicted values are 4 and 5 (the churned tail), not 0/1.
        assert!(!states.contains(&CursorState::new(40, 4)));
        assert!(!states.contains(&CursorState::new(50, 5)));
    }

    #[test]
    fn back_then_front_returns_same_state() {
        // C++ quirk: JumpBack returns the on-cursor state before
        // decrementing, so a following JumpFront lands on it again.
        let mut holder = JumpsHolder::new(DISSASM_MAX_STORED_JUMPS);
        holder.insert(CursorState::new(0, 0));
        holder.insert(CursorState::new(10, 1));
        assert_eq!(holder.jump_back(), Some(CursorState::new(10, 1)));
        assert_eq!(holder.current_index(), 0);
        assert_eq!(holder.jump_front(), Some(CursorState::new(10, 1)));
        assert_eq!(holder.current_index(), 1);
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let mut holder = JumpsHolder::new(0);
        holder.insert(CursorState::new(1, 1));
        holder.insert(CursorState::new(2, 2));
        assert_eq!(holder.len(), 1);
        assert_eq!(holder.jump_back(), Some(CursorState::new(2, 2)));
    }
}
