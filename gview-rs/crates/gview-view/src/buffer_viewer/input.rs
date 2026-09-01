//! `BufferViewer` keyboard navigation
//! (C++ `Instance::OnKeyEvent` + movement helpers
//! `Instance.cpp:242-356`; spec `02_VIEWER_BUFFER` §6 matrix).
//!
//! [`navigation_for_key`] maps a key press to a [`NavAction`];
//! [`apply_navigation`] executes it against the cursor, selection,
//! zones and bookmarks. Display-mode keys (F2/F3/F6/F9, Alt+F3, …)
//! surface as actions for the shell to apply, since they mutate
//! settings rather than the cursor.

use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::cache::DataCache;
use gview_core::constants::INVALID_OFFSET;
use gview_core::selection::Selection;
use gview_core::zones::ZonesList;

use super::layout::{end_offset, home_offset, move_scroll_to, move_to, BufferCursor, BufferLayout};

/// One §6 matrix action. `select` on movement actions is the
/// Shift-extend flag (§6: `Shift+*` → `select=true`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NavAction {
    /// Down: `currentPos += charactersPerLine`.
    MoveDown {
        /// Shift held.
        select: bool,
    },
    /// Up: `currentPos -= charactersPerLine`.
    MoveUp {
        /// Shift held.
        select: bool,
    },
    /// Left: `currentPos -= 1`.
    MoveLeft {
        /// Shift held.
        select: bool,
    },
    /// Right: `currentPos += 1`.
    MoveRight {
        /// Shift held.
        select: bool,
    },
    /// `PageDown`: `currentPos += charactersPerLine * visibleRows`.
    PageDown {
        /// Shift held.
        select: bool,
    },
    /// `PageUp`: `currentPos -= charactersPerLine * visibleRows`.
    PageUp {
        /// Shift held.
        select: bool,
    },
    /// Home: align to row start.
    LineStart {
        /// Shift held.
        select: bool,
    },
    /// End: align to row end.
    LineEnd {
        /// Shift held.
        select: bool,
    },
    /// Ctrl+Home: `MoveTo(0)`.
    FileStart {
        /// Shift held.
        select: bool,
    },
    /// Ctrl+End: `MoveTo(fileSize)` (clamped).
    FileEnd {
        /// Shift held.
        select: bool,
    },
    /// Ctrl+Up/Down/Left/Right: scroll the view origin by `delta`
    /// bytes (negative = towards 0).
    Scroll {
        /// Signed byte delta of the view origin.
        delta: i64,
    },
    /// Ctrl+PageUp / Ctrl+PageDown: jump to the current zone's low
    /// (`true`) or high (`false`) bound.
    ZoneJump {
        /// Jump to the zone start (else its end).
        start_of_zone: bool,
        /// Shift held.
        select: bool,
    },
    /// Alt+1..4: jump to selection zone `index`.
    GotoSelection {
        /// Selection zone 0..3.
        index: usize,
    },
    /// Digit 0–9: jump to `bookmarks[digit]` when set.
    GotoBookmark {
        /// Bookmark slot.
        digit: usize,
    },
    /// F7: `MoveTo(entryPointOffset)`.
    GoToEntryPoint,
    /// F6: cycle `nrCols` 0 → 8 → 16 → 32 → 0 (shell applies).
    ChangeColumnsCount,
    /// F2: cycle value format / codepage (shell applies).
    ChangeValueFormatOrCp,
    /// F3: next address-translation mode (shell applies).
    ChangeAddressMode,
    /// F9: toggle single/multi selection (shell applies).
    ChangeSelectionType,
    /// Alt+F3: toggle string highlighting (shell applies).
    ShowHideStrings,
    /// Ctrl+F7 / Ctrl+Shift+F7 (shell runs the find engine).
    FindNext,
    /// Ctrl+Shift+F7.
    FindPrevious,
    /// Ctrl+D: dissasm dialog (shell).
    DissasmDialog,
    /// Enter: open current selection in a new window (shell).
    OpenSelection,
}

/// Maps a pressed key to its §6 action, or `None` when the viewer
/// does not handle it.
#[must_use]
pub fn navigation_for_key(key: Key) -> Option<NavAction> {
    let shift_only = key.modifier == KeyModifier::Shift;
    let none = key.modifier == KeyModifier::None;
    let select = shift_only;
    if none || shift_only {
        let action = match key.code {
            KeyCode::Down => Some(NavAction::MoveDown { select }),
            KeyCode::Up => Some(NavAction::MoveUp { select }),
            KeyCode::Left => Some(NavAction::MoveLeft { select }),
            KeyCode::Right => Some(NavAction::MoveRight { select }),
            KeyCode::PageDown => Some(NavAction::PageDown { select }),
            KeyCode::PageUp => Some(NavAction::PageUp { select }),
            KeyCode::Home => Some(NavAction::LineStart { select }),
            KeyCode::End => Some(NavAction::LineEnd { select }),
            _ => None,
        };
        if action.is_some() {
            return action;
        }
    }
    if none {
        let action = match key.code {
            KeyCode::F2 => Some(NavAction::ChangeValueFormatOrCp),
            KeyCode::F3 => Some(NavAction::ChangeAddressMode),
            KeyCode::F6 => Some(NavAction::ChangeColumnsCount),
            KeyCode::F7 => Some(NavAction::GoToEntryPoint),
            KeyCode::F9 => Some(NavAction::ChangeSelectionType),
            KeyCode::Enter => Some(NavAction::OpenSelection),
            KeyCode::N0 => Some(NavAction::GotoBookmark { digit: 0 }),
            KeyCode::N1 => Some(NavAction::GotoBookmark { digit: 1 }),
            KeyCode::N2 => Some(NavAction::GotoBookmark { digit: 2 }),
            KeyCode::N3 => Some(NavAction::GotoBookmark { digit: 3 }),
            KeyCode::N4 => Some(NavAction::GotoBookmark { digit: 4 }),
            KeyCode::N5 => Some(NavAction::GotoBookmark { digit: 5 }),
            KeyCode::N6 => Some(NavAction::GotoBookmark { digit: 6 }),
            KeyCode::N7 => Some(NavAction::GotoBookmark { digit: 7 }),
            KeyCode::N8 => Some(NavAction::GotoBookmark { digit: 8 }),
            KeyCode::N9 => Some(NavAction::GotoBookmark { digit: 9 }),
            _ => None,
        };
        if action.is_some() {
            return action;
        }
    }
    let ctrl = key.modifier == KeyModifier::Ctrl;
    let ctrl_shift = key.modifier == KeyModifier::Ctrl | KeyModifier::Shift;
    if ctrl || ctrl_shift {
        let select = ctrl_shift;
        let action = match key.code {
            KeyCode::Home => Some(NavAction::FileStart { select }),
            KeyCode::End => Some(NavAction::FileEnd { select }),
            KeyCode::PageUp => Some(NavAction::ZoneJump {
                start_of_zone: true,
                select,
            }),
            KeyCode::PageDown => Some(NavAction::ZoneJump {
                start_of_zone: false,
                select,
            }),
            _ => None,
        };
        if action.is_some() {
            return action;
        }
    }
    if ctrl {
        return match key.code {
            KeyCode::Up => Some(NavAction::Scroll { delta: i64::MIN }),
            KeyCode::Down => Some(NavAction::Scroll { delta: i64::MAX }),
            KeyCode::Left => Some(NavAction::Scroll { delta: -1 }),
            KeyCode::Right => Some(NavAction::Scroll { delta: 1 }),
            KeyCode::F7 => Some(NavAction::FindNext),
            KeyCode::D => Some(NavAction::DissasmDialog),
            _ => None,
        };
    }
    if ctrl_shift && key.code == KeyCode::F7 {
        return Some(NavAction::FindPrevious);
    }
    if key.modifier == KeyModifier::Alt {
        return match key.code {
            KeyCode::F3 => Some(NavAction::ShowHideStrings),
            KeyCode::N1 => Some(NavAction::GotoSelection { index: 0 }),
            KeyCode::N2 => Some(NavAction::GotoSelection { index: 1 }),
            KeyCode::N3 => Some(NavAction::GotoSelection { index: 2 }),
            KeyCode::N4 => Some(NavAction::GotoSelection { index: 3 }),
            _ => None,
        };
    }
    None
}

/// Everything a navigation action mutates.
pub struct NavContext<'a> {
    /// Viewport/cursor state.
    pub cursor: &'a mut BufferCursor,
    /// Selection zones.
    pub selection: &'a mut Selection,
    /// Current layout (row geometry).
    pub layout: &'a BufferLayout,
    /// Data source (for size and skip scans).
    pub cache: &'a mut DataCache,
    /// Plugin zones for Ctrl+PageUp/PageDown.
    pub zones: &'a ZonesList,
    /// Bookmark table (digit keys); `INVALID_OFFSET` = unset.
    pub bookmarks: &'a [u64; 10],
    /// F7 target; `INVALID_OFFSET` = unset.
    pub entry_point: u64,
}

/// Executes a movement action; returns `false` for actions the shell
/// must handle (display toggles, find, dialogs).
// One match arm per §6 matrix row — splitting would only scatter the
// parity mapping.
#[allow(clippy::too_many_lines)]
pub fn apply_navigation(action: NavAction, ctx: &mut NavContext<'_>) -> bool {
    let file_size = ctx.cache.size();
    let visible = ctx.layout.visible_bytes();
    let cpl = u64::from(ctx.layout.characters_per_line);
    let pos = ctx.cursor.current_pos;
    match action {
        NavAction::MoveDown { select } => {
            let target = pos.saturating_add(cpl);
            move_to(
                ctx.cursor,
                ctx.selection,
                target,
                select,
                file_size,
                visible,
            );
        }
        NavAction::MoveUp { select } => {
            let target = pos.saturating_sub(cpl);
            move_to(
                ctx.cursor,
                ctx.selection,
                target,
                select,
                file_size,
                visible,
            );
        }
        NavAction::MoveLeft { select } => {
            let target = pos.saturating_sub(1);
            move_to(
                ctx.cursor,
                ctx.selection,
                target,
                select,
                file_size,
                visible,
            );
        }
        NavAction::MoveRight { select } => {
            let target = pos.saturating_add(1);
            move_to(
                ctx.cursor,
                ctx.selection,
                target,
                select,
                file_size,
                visible,
            );
        }
        NavAction::PageDown { select } => {
            let target = pos.saturating_add(visible);
            move_to(
                ctx.cursor,
                ctx.selection,
                target,
                select,
                file_size,
                visible,
            );
        }
        NavAction::PageUp { select } => {
            let target = pos.saturating_sub(visible);
            move_to(
                ctx.cursor,
                ctx.selection,
                target,
                select,
                file_size,
                visible,
            );
        }
        NavAction::LineStart { select } => {
            let target = home_offset(*ctx.cursor, ctx.layout.characters_per_line);
            move_to(
                ctx.cursor,
                ctx.selection,
                target,
                select,
                file_size,
                visible,
            );
        }
        NavAction::LineEnd { select } => {
            let target = end_offset(*ctx.cursor, ctx.layout.characters_per_line);
            move_to(
                ctx.cursor,
                ctx.selection,
                target,
                select,
                file_size,
                visible,
            );
        }
        NavAction::FileStart { select } => {
            move_to(ctx.cursor, ctx.selection, 0, select, file_size, visible);
        }
        NavAction::FileEnd { select } => {
            // C++ passes fileSize; MoveTo clamps to fileSize - 1.
            move_to(
                ctx.cursor,
                ctx.selection,
                file_size,
                select,
                file_size,
                visible,
            );
        }
        NavAction::Scroll { delta } => {
            // Ctrl+Up/Down scroll by one row, Ctrl+Left/Right by one
            // byte (§6); sentinel deltas encode the row variants.
            let target = match delta {
                i64::MIN => ctx.cursor.start_view.saturating_sub(cpl),
                i64::MAX => ctx.cursor.start_view.saturating_add(cpl),
                d if d < 0 => ctx.cursor.start_view.saturating_sub(d.unsigned_abs()),
                d => ctx.cursor.start_view.saturating_add(d.unsigned_abs()),
            };
            move_scroll_to(ctx.cursor, ctx.selection, target, file_size, visible);
        }
        NavAction::ZoneJump {
            start_of_zone,
            select,
        } => {
            // C++ MoveToZone (Instance.cpp:351-356): zone containing
            // the cursor decides the target; no zone → no move.
            if let Some(zone) = ctx.zones.offset_to_zone(pos) {
                let target = if start_of_zone { zone.low } else { zone.high };
                move_to(
                    ctx.cursor,
                    ctx.selection,
                    target,
                    select,
                    file_size,
                    visible,
                );
            }
        }
        NavAction::GotoSelection { index } => {
            // C++ MoveToSelection (Instance.cpp:242-252): jump to the
            // zone start, or its end when already there.
            if let Some((start, end)) = ctx.selection.get_selection(index) {
                let target = if pos == start { end } else { start };
                // Split borrows: get_selection above is immutable.
                move_to(ctx.cursor, ctx.selection, target, false, file_size, visible);
            }
        }
        NavAction::GotoBookmark { digit } => {
            if let Some(&offset) = ctx.bookmarks.get(digit) {
                if offset != INVALID_OFFSET {
                    move_to(ctx.cursor, ctx.selection, offset, false, file_size, visible);
                }
            }
        }
        NavAction::GoToEntryPoint => {
            if ctx.entry_point != INVALID_OFFSET {
                move_to(
                    ctx.cursor,
                    ctx.selection,
                    ctx.entry_point,
                    false,
                    file_size,
                    visible,
                );
            }
        }
        NavAction::ChangeColumnsCount
        | NavAction::ChangeValueFormatOrCp
        | NavAction::ChangeAddressMode
        | NavAction::ChangeSelectionType
        | NavAction::ShowHideStrings
        | NavAction::FindNext
        | NavAction::FindPrevious
        | NavAction::DissasmDialog
        | NavAction::OpenSelection => return false,
    }
    true
}

/// F6 column cycle: 0 → 8 → 16 → 32 → 0 (§6).
#[must_use]
pub const fn next_columns_count(nr_cols: u32) -> u32 {
    match nr_cols {
        0 => 8,
        8 => 16,
        16 => 32,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::graphics::{CharAttribute, Color};
    use gview_core::source::MemorySource;

    struct Fixture {
        cursor: BufferCursor,
        selection: Selection,
        layout: BufferLayout,
        cache: DataCache,
        zones: ZonesList,
        bookmarks: [u64; 10],
        entry_point: u64,
    }

    impl Fixture {
        fn new(file_len: usize) -> Self {
            let data = vec![0_u8; file_len];
            let mut layout = BufferLayout::default();
            layout.update_view_sizes(100, 11); // 16 cols × 10 rows
            Self {
                cursor: BufferCursor::default(),
                selection: Selection::new(),
                layout,
                cache: DataCache::new(Box::new(MemorySource::new(data)), 0),
                zones: ZonesList::new(),
                bookmarks: [INVALID_OFFSET; 10],
                entry_point: INVALID_OFFSET,
            }
        }

        fn apply(&mut self, action: NavAction) -> bool {
            let mut ctx = NavContext {
                cursor: &mut self.cursor,
                selection: &mut self.selection,
                layout: &self.layout,
                cache: &mut self.cache,
                zones: &self.zones,
                bookmarks: &self.bookmarks,
                entry_point: self.entry_point,
            };
            apply_navigation(action, &mut ctx)
        }
    }

    #[test]
    fn page_down_and_up() {
        let mut f = Fixture::new(10_000);
        // visible = 16 * 10 = 160.
        assert!(f.apply(NavAction::PageDown { select: false }));
        assert_eq!(f.cursor.current_pos, 160);
        assert!(f.apply(NavAction::PageDown { select: false }));
        assert_eq!(f.cursor.current_pos, 320);
        assert!(f.apply(NavAction::PageUp { select: false }));
        assert_eq!(f.cursor.current_pos, 160);
        // PageUp clamps at 0.
        f.apply(NavAction::PageUp { select: false });
        f.apply(NavAction::PageUp { select: false });
        assert_eq!(f.cursor.current_pos, 0);
    }

    #[test]
    fn ctrl_home_end() {
        let mut f = Fixture::new(5000);
        assert!(f.apply(NavAction::FileEnd { select: false }));
        assert_eq!(f.cursor.current_pos, 4999);
        assert!(f.apply(NavAction::FileStart { select: false }));
        assert_eq!(f.cursor.current_pos, 0);
    }

    #[test]
    fn zone_jump_to_bounds() {
        let mut f = Fixture::new(1000);
        let attr = CharAttribute::with_color(Color::Red, Color::Black);
        f.zones.add(100, 199, attr, "z");
        f.zones.set_viewport_cache((0, 1000));
        // Cursor inside the zone: Ctrl+PageUp → low, Ctrl+PageDown → high.
        f.cursor.current_pos = 150;
        assert!(f.apply(NavAction::ZoneJump {
            start_of_zone: true,
            select: false
        }));
        assert_eq!(f.cursor.current_pos, 100);
        f.cursor.current_pos = 150;
        assert!(f.apply(NavAction::ZoneJump {
            start_of_zone: false,
            select: false
        }));
        assert_eq!(f.cursor.current_pos, 199);
        // Outside any zone: no movement.
        f.cursor.current_pos = 500;
        f.apply(NavAction::ZoneJump {
            start_of_zone: true,
            select: false,
        });
        assert_eq!(f.cursor.current_pos, 500);
    }

    #[test]
    fn arrow_movement_and_selection_extend() {
        let mut f = Fixture::new(1000);
        f.apply(NavAction::MoveRight { select: false });
        f.apply(NavAction::MoveRight { select: false });
        assert_eq!(f.cursor.current_pos, 2);
        f.apply(NavAction::MoveDown { select: false });
        assert_eq!(f.cursor.current_pos, 18);
        f.apply(NavAction::MoveUp { select: false });
        assert_eq!(f.cursor.current_pos, 2);
        f.apply(NavAction::MoveLeft { select: false });
        assert_eq!(f.cursor.current_pos, 1);
        // Shift+Right extends the selection.
        f.apply(NavAction::MoveRight { select: true });
        assert_eq!(f.selection.get_selection(0), Some((1, 2)));
    }

    #[test]
    fn bookmark_and_entry_point_jumps() {
        let mut f = Fixture::new(1000);
        f.bookmarks[3] = 300;
        f.entry_point = 640;
        f.apply(NavAction::GotoBookmark { digit: 3 });
        assert_eq!(f.cursor.current_pos, 300);
        // Unset bookmark: no move.
        f.apply(NavAction::GotoBookmark { digit: 7 });
        assert_eq!(f.cursor.current_pos, 300);
        f.apply(NavAction::GoToEntryPoint);
        assert_eq!(f.cursor.current_pos, 640);
    }

    #[test]
    fn goto_selection_toggles_between_bounds() {
        let mut f = Fixture::new(1000);
        assert!(f.selection.set_selection(0, 100, 200));
        f.apply(NavAction::GotoSelection { index: 0 });
        assert_eq!(f.cursor.current_pos, 100);
        // Already at start → jump to end (C++ MoveToSelection).
        f.apply(NavAction::GotoSelection { index: 0 });
        assert_eq!(f.cursor.current_pos, 200);
    }

    #[test]
    fn key_mapping_matrix() {
        use KeyCode as K;
        let none = KeyModifier::None;
        let key = |c, m| Key::new(c, m);
        assert_eq!(
            navigation_for_key(key(K::PageDown, none)),
            Some(NavAction::PageDown { select: false })
        );
        assert_eq!(
            navigation_for_key(key(K::PageUp, KeyModifier::Shift)),
            Some(NavAction::PageUp { select: true })
        );
        assert_eq!(
            navigation_for_key(key(K::Home, KeyModifier::Ctrl)),
            Some(NavAction::FileStart { select: false })
        );
        assert_eq!(
            navigation_for_key(key(K::End, KeyModifier::Ctrl | KeyModifier::Shift)),
            Some(NavAction::FileEnd { select: true })
        );
        assert_eq!(
            navigation_for_key(key(K::PageUp, KeyModifier::Ctrl)),
            Some(NavAction::ZoneJump {
                start_of_zone: true,
                select: false
            })
        );
        assert_eq!(
            navigation_for_key(key(K::F7, none)),
            Some(NavAction::GoToEntryPoint)
        );
        assert_eq!(
            navigation_for_key(key(K::F7, KeyModifier::Ctrl)),
            Some(NavAction::FindNext)
        );
        assert_eq!(
            navigation_for_key(key(K::F7, KeyModifier::Ctrl | KeyModifier::Shift)),
            Some(NavAction::FindPrevious)
        );
        assert_eq!(
            navigation_for_key(key(K::F6, none)),
            Some(NavAction::ChangeColumnsCount)
        );
        assert_eq!(
            navigation_for_key(key(K::F3, KeyModifier::Alt)),
            Some(NavAction::ShowHideStrings)
        );
        assert_eq!(
            navigation_for_key(key(K::N2, KeyModifier::Alt)),
            Some(NavAction::GotoSelection { index: 1 })
        );
        assert_eq!(
            navigation_for_key(key(K::N5, none)),
            Some(NavAction::GotoBookmark { digit: 5 })
        );
        assert_eq!(
            navigation_for_key(key(K::D, KeyModifier::Ctrl)),
            Some(NavAction::DissasmDialog)
        );
        assert_eq!(navigation_for_key(key(K::X, none)), None);
    }

    #[test]
    fn column_cycle() {
        assert_eq!(next_columns_count(0), 8);
        assert_eq!(next_columns_count(8), 16);
        assert_eq!(next_columns_count(16), 32);
        assert_eq!(next_columns_count(32), 0);
    }

    #[test]
    fn display_actions_defer_to_shell() {
        let mut f = Fixture::new(100);
        assert!(!f.apply(NavAction::ChangeColumnsCount));
        assert!(!f.apply(NavAction::FindNext));
        assert!(!f.apply(NavAction::OpenSelection));
    }
}
