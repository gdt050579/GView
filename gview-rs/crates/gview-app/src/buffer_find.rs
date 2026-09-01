//! Find ↔ `BufferViewer` integration (matrix task
//! `buffer-find-integration`).
//!
//! C++ anchors: `BUFFERVIEW_CMD_FINDNEXT` / `BUFFERVIEW_CMD_FINDPREVIOUS`
//! (`BufferViewer/Instance.cpp:1361-1410`), `ShowFindDialog`
//! (`Instance.cpp:366-388`), `FindDialog::GetNextMatch` /
//! `GetPreviousMatch` (`FindDialog.cpp:297-319`); spec
//! `02_VIEWER_BUFFER` §7.4.
//!
//! Ctrl+F7 searches forward from `currentPos + 1`; Ctrl+Shift+F7
//! backward from `currentPos - 1` (nothing when the cursor is at 0).
//! A hit moves the cursor (`MoveScrollTo` when the
//! align-to-upper-corner option is set, else `MoveTo`) and, with the
//! select option, replaces the selection with the match range.

use gview_core::cache::DataCache;
use gview_core::selection::Selection;
use gview_view::buffer_viewer::layout::{move_scroll_to, move_to, BufferCursor};

use crate::find_dialog::{FindEngine, Match};

/// Dialog options that shape navigation
/// (C++ `bufferSelect` / `alingTextToUpperLeftCorner` radios).
#[derive(Clone, Copy, Debug, Default)]
pub struct BufferFindOptions {
    /// Select the match range instead of only moving the cursor.
    pub select_match: bool,
    /// Scroll the match to the view origin (`MoveScrollTo`) instead
    /// of a plain `MoveTo`.
    pub align_to_corner: bool,
}

/// Result of a find-next/previous step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindOutcome {
    /// A match was found and the cursor moved to it. `same_position`
    /// mirrors the C++ quirk of still reporting "no next match" when
    /// the hit equals the previous cursor position.
    Found {
        /// The match reached.
        matched: Match,
        /// The cursor was already there.
        same_position: bool,
    },
    /// No match (also: find-previous with the cursor at offset 0).
    NotFound,
}

/// One active search bound to a compiled [`FindEngine`].
#[derive(Debug)]
pub struct BufferFindSession {
    engine: FindEngine,
    /// Navigation options.
    pub options: BufferFindOptions,
}

impl BufferFindSession {
    /// Binds a compiled engine and options.
    #[must_use]
    pub const fn new(engine: FindEngine, options: BufferFindOptions) -> Self {
        Self { engine, options }
    }

    fn apply_match(
        &self,
        matched: Match,
        cursor: &mut BufferCursor,
        selection: &mut Selection,
        cache: &DataCache,
        visible_bytes: u64,
    ) {
        let file_size = cache.size();
        if self.options.align_to_corner {
            move_scroll_to(cursor, selection, matched.offset, file_size, visible_bytes);
        } else {
            move_to(
                cursor,
                selection,
                matched.offset,
                false,
                file_size,
                visible_bytes,
            );
        }
        if self.options.select_match {
            // C++: Clear → BeginSelection(start) →
            // UpdateSelection(0, start + length - 1).
            selection.clear();
            selection.begin_selection(matched.offset);
            let last = matched
                .offset
                .saturating_add(matched.length.saturating_sub(1));
            selection.update_selection(0, last);
        }
    }

    /// Ctrl+F7 (C++ `BUFFERVIEW_CMD_FINDNEXT`,
    /// `Instance.cpp:1361-1389`): search forward from
    /// `currentPos + 1`; the selection is cleared up front.
    pub fn find_next(
        &self,
        cursor: &mut BufferCursor,
        selection: &mut Selection,
        cache: &mut DataCache,
        visible_bytes: u64,
    ) -> FindOutcome {
        selection.clear();
        let previous_pos = cursor.current_pos;
        let from = previous_pos.saturating_add(1);
        let size = cache.size();
        let Some(matched) = self.engine.find_forward(cache, from, size) else {
            return FindOutcome::NotFound;
        };
        self.apply_match(matched, cursor, selection, cache, visible_bytes);
        FindOutcome::Found {
            matched,
            same_position: previous_pos == matched.offset,
        }
    }

    /// Ctrl+Shift+F7 (C++ `BUFFERVIEW_CMD_FINDPREVIOUS`,
    /// `Instance.cpp:1390-1410`): search backward before the cursor;
    /// a cursor at 0 has no previous match.
    pub fn find_previous(
        &self,
        cursor: &mut BufferCursor,
        selection: &mut Selection,
        cache: &mut DataCache,
        visible_bytes: u64,
    ) -> FindOutcome {
        let previous_pos = cursor.current_pos;
        if previous_pos == 0 {
            return FindOutcome::NotFound;
        }
        selection.clear();
        // C++ GetPreviousMatch(pos - 1) accepts matches starting at
        // most pos - 2 → exclusive end = pos - 1.
        let end = previous_pos.saturating_sub(1);
        let Some(matched) = self.engine.find_backward(cache, 0, end) else {
            return FindOutcome::NotFound;
        };
        self.apply_match(matched, cursor, selection, cache, visible_bytes);
        FindOutcome::Found {
            matched,
            same_position: previous_pos == matched.offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_core::source::MemorySource;

    const VISIBLE: u64 = 160;

    fn setup(data: &[u8]) -> (DataCache, BufferCursor, Selection) {
        (
            DataCache::new(Box::new(MemorySource::from_slice(data)), 0),
            BufferCursor::default(),
            Selection::new(),
        )
    }

    fn mz_session(select: bool) -> BufferFindSession {
        let engine = FindEngine::new_binary("4D 5A", true, false).expect("engine");
        BufferFindSession::new(
            engine,
            BufferFindOptions {
                select_match: select,
                align_to_corner: false,
            },
        )
    }

    #[test]
    fn find_hex_pattern_moves_cursor_to_match() {
        // "MZ" at offsets 4 and 20.
        let mut data = vec![0_u8; 32];
        data[4] = 0x4D;
        data[5] = 0x5A;
        data[20] = 0x4D;
        data[21] = 0x5A;
        let (mut cache, mut cursor, mut selection) = setup(&data);
        let session = mz_session(false);

        let outcome = session.find_next(&mut cursor, &mut selection, &mut cache, VISIBLE);
        assert_eq!(
            outcome,
            FindOutcome::Found {
                matched: Match {
                    offset: 4,
                    length: 2
                },
                same_position: false
            }
        );
        assert_eq!(cursor.current_pos, 4);

        // Next hit continues past the cursor.
        let outcome = session.find_next(&mut cursor, &mut selection, &mut cache, VISIBLE);
        assert!(matches!(
            outcome,
            FindOutcome::Found {
                matched: Match { offset: 20, .. },
                ..
            }
        ));
        assert_eq!(cursor.current_pos, 20);

        // No further match.
        assert_eq!(
            session.find_next(&mut cursor, &mut selection, &mut cache, VISIBLE),
            FindOutcome::NotFound
        );
    }

    #[test]
    fn select_option_selects_the_match_range() {
        let mut data = vec![0_u8; 16];
        data[8] = 0x4D;
        data[9] = 0x5A;
        let (mut cache, mut cursor, mut selection) = setup(&data);
        let session = mz_session(true);
        session.find_next(&mut cursor, &mut selection, &mut cache, VISIBLE);
        assert_eq!(cursor.current_pos, 8);
        assert_eq!(selection.get_selection(0), Some((8, 9)));
    }

    #[test]
    fn find_previous_walks_backward() {
        let mut data = vec![0_u8; 40];
        for &at in &[4_usize, 20, 30] {
            data[at] = 0x4D;
            data[at + 1] = 0x5A;
        }
        let (mut cache, mut cursor, mut selection) = setup(&data);
        let session = mz_session(false);
        cursor.current_pos = 35;
        let outcome = session.find_previous(&mut cursor, &mut selection, &mut cache, VISIBLE);
        assert!(matches!(
            outcome,
            FindOutcome::Found {
                matched: Match { offset: 30, .. },
                ..
            }
        ));
        assert_eq!(cursor.current_pos, 30);
        // Continue backwards: matches strictly before the cursor.
        let outcome = session.find_previous(&mut cursor, &mut selection, &mut cache, VISIBLE);
        assert!(matches!(
            outcome,
            FindOutcome::Found {
                matched: Match { offset: 20, .. },
                ..
            }
        ));
        // Cursor at 0: nothing before it.
        cursor.current_pos = 0;
        assert_eq!(
            session.find_previous(&mut cursor, &mut selection, &mut cache, VISIBLE),
            FindOutcome::NotFound
        );
    }

    #[test]
    fn align_to_corner_scrolls_view_origin() {
        let mut data = vec![0_u8; 4096];
        data[2000] = 0x4D;
        data[2001] = 0x5A;
        let (mut cache, mut cursor, mut selection) = setup(&data);
        let engine = FindEngine::new_binary("4D 5A", true, false).expect("engine");
        let session = BufferFindSession::new(
            engine,
            BufferFindOptions {
                select_match: false,
                align_to_corner: true,
            },
        );
        session.find_next(&mut cursor, &mut selection, &mut cache, VISIBLE);
        // MoveScrollTo puts the match at the view origin.
        assert_eq!(cursor.start_view, 2000);
    }
}
