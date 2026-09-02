//! Pure state of the C++ `HashesDialog` (`Hashes.cpp`): the window
//! itself is built by the shell with `appcui::prelude::*` from this
//! model.
//!
//! Layout facts (verbatim from the constructor):
//! - window `"Hashes"`, `d:c,w:70,h:21`, `ProcessReturn`;
//! - picking width 70, showing width 160, showing height
//!   `outputs + 8`;
//! - radio boxes `"Compute for the &entire file"` /
//!   `"Compute for the &selection"` (selection disabled and *file*
//!   checked when the type plugin has no selection zones, otherwise
//!   *selection* checked);
//! - a check-box list with the 22 algorithms in `hashList` order,
//!   pre-checked from `[Generic.Hashes]`;
//! - `&Ok` / `&Cancel` buttons; Enter (`WindowAccept`) equals Ok;
//! - after Ok the result list has columns `Type` (w:17) and `Value`
//!   (w:130) and a `&Close` button.

use crate::compute::{HashFlags, HashKind, HASH_LIST};

/// Window caption.
pub const TITLE: &str = "Hashes";
/// Window layout while picking.
pub const LAYOUT: &str = "d:c,w:70,h:21";
/// `widthPicking`.
pub const WIDTH_PICKING: u32 = 70;
/// `widthShowing`.
pub const WIDTH_SHOWING: u32 = 160;
/// Rows added to the output count for the showing height.
pub const SHOWING_EXTRA_HEIGHT: u32 = 8;
/// Radio caption.
pub const COMPUTE_FOR_FILE_CAPTION: &str = "Compute for the &entire file";
/// Radio caption.
pub const COMPUTE_FOR_SELECTION_CAPTION: &str = "Compute for the &selection";
/// Result column captions.
pub const RESULT_COLUMNS: [&str; 2] = ["n:Type,w:17", "n:Value,w:130"];
/// Button captions.
pub const BUTTON_OK: &str = "&Ok";
/// Button captions.
pub const BUTTON_CANCEL: &str = "&Cancel";
/// Button captions.
pub const BUTTON_CLOSE: &str = "&Close";
/// `CMD_BUTTON_CLOSE`.
pub const CMD_BUTTON_CLOSE: i32 = 1;
/// `CMD_BUTTON_OK`.
pub const CMD_BUTTON_OK: i32 = 2;
/// `CMD_BUTTON_CANCEL`.
pub const CMD_BUTTON_CANCEL: i32 = 3;

/// Dialog state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashesDialogModel {
    /// `computeForFile` radio.
    pub compute_for_file: bool,
    /// Whether the selection radio is enabled (zones exist).
    pub selection_enabled: bool,
    /// Checked algorithms.
    pub checked: HashFlags,
}

impl HashesDialogModel {
    /// Initial state for `has_selection` zones and the persisted
    /// `[Generic.Hashes]` flags.
    #[must_use]
    pub const fn new(has_selection: bool, settings_flags: HashFlags) -> Self {
        Self {
            compute_for_file: !has_selection,
            selection_enabled: has_selection,
            checked: settings_flags,
        }
    }

    /// Check-box rows in display order: `(caption, checked)`.
    #[must_use]
    pub fn options(&self) -> Vec<(&'static str, bool)> {
        HASH_LIST
            .iter()
            .map(|k| (k.display_name(), self.checked.contains(*k)))
            .collect()
    }

    /// Toggles one algorithm.
    pub const fn set_checked(&mut self, kind: HashKind, checked: bool) {
        self.checked = if checked {
            self.checked.with(kind)
        } else {
            self.checked.without(kind)
        };
    }

    /// Selects the *entire file* / *selection* radio (the latter only
    /// when enabled).
    pub const fn set_compute_for_file(&mut self, for_file: bool) {
        if for_file || self.selection_enabled {
            self.compute_for_file = for_file;
        }
    }

    /// `SetFlagsFromCheckBoxes`: the flags Ok computes with.
    #[must_use]
    pub const fn flags(&self) -> HashFlags {
        self.checked
    }

    /// Window height once results are shown (`outputs.size() + 8`).
    #[must_use]
    pub const fn showing_height(output_count: usize) -> u32 {
        (output_count as u32).saturating_add(SHOWING_EXTRA_HEIGHT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_follows_selection() {
        let none = HashesDialogModel::new(false, HashFlags::ALL);
        assert!(none.compute_for_file && !none.selection_enabled);
        let some = HashesDialogModel::new(true, HashFlags::NONE);
        assert!(!some.compute_for_file && some.selection_enabled);
        assert_eq!(none.options().len(), 22);
        assert!(none.options().iter().all(|(_, c)| *c));
        assert!(some.options().iter().all(|(_, c)| !*c));
        assert_eq!(none.options().first().map(|o| o.0), Some("Adler32"));
    }

    #[test]
    fn toggles_and_radio_guard() {
        let mut model = HashesDialogModel::new(false, HashFlags::NONE);
        model.set_checked(HashKind::Sha256, true);
        model.set_checked(HashKind::Md5, true);
        model.set_checked(HashKind::Md5, false);
        assert_eq!(model.flags(), HashKind::Sha256.flag());
        // Selection radio stays off without zones.
        model.set_compute_for_file(false);
        assert!(model.compute_for_file);
        let mut with_zones = HashesDialogModel::new(true, HashFlags::NONE);
        with_zones.set_compute_for_file(true);
        assert!(with_zones.compute_for_file);
        with_zones.set_compute_for_file(false);
        assert!(!with_zones.compute_for_file);
        assert_eq!(HashesDialogModel::showing_height(22), 30);
        assert_eq!((WIDTH_PICKING, WIDTH_SHOWING), (70, 160));
    }
}
