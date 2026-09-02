//! `cpp-parity-behavioral-bugs` — viewer-side quirks
//! (`docs/cpp_parity_quirks.md` §4–§5).

use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::cache::DataCache;
use gview_core::source::MemorySource;

use crate::grid_viewer::parse::{process_content, GridParseSettings};
use crate::text_viewer::input::text_action_for_key;

/// Quirk 4 — `TextViewer/Instance.cpp:1487-1490`: `ShowFindDialog()` is
/// `NOT_IMPLEMENTED(false)`. The Rust text viewer maps no key to a
/// find action: neither the `FindDialog` command key (Alt+F7) nor the
/// conventional Ctrl+F / F3.
#[test]
fn quirk_4_text_viewer_find_dialog_is_a_stub() {
    for key in [
        Key::new(KeyCode::F7, KeyModifier::Alt),
        Key::new(KeyCode::F, KeyModifier::Ctrl),
        Key::new(KeyCode::F3, KeyModifier::None),
    ] {
        assert!(text_action_for_key(key).is_none(), "{key:?} must not map to a find action");
    }
}

/// Quirk 5 — Grid `ProcessContent` (`02_VIEWER_GRID` §3.1): the C++
/// parser reads one cache window per row and splits a row that is
/// longer than the window. The Rust port **deliberately** streams the
/// object through the cache so such a row stays whole; this test pins
/// the fixed behaviour.
#[test]
fn quirk_5_grid_row_spanning_cache_window_stays_whole() {
    let row_len = 200 * 1024_usize;
    let mut data = vec![b'x'; row_len];
    data[70_000] = b',';
    data.push(b'\n');
    data.extend_from_slice(b"tail\n");
    // `requested_cache_size = 1` aligns up to the 64 KiB minimum.
    let mut cache = DataCache::new(Box::new(MemorySource::from_slice(&data)), 1);
    assert!(u64::from(cache.cache_size()) < row_len as u64);
    let content = process_content(&mut cache, &GridParseSettings::default());
    assert_eq!(content.rows, 2, "one long row plus the tail");
    assert_eq!(content.lines.first().copied(), Some((0, row_len as u64)));
    assert_eq!(content.tokens.first().map(Vec::len), Some(2));
}
