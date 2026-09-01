//! Application-level key → command registry.
//!
//! C++ scatters key bindings across per-viewer `Config` structs
//! (e.g. `BufferViewer/Config.cpp:20-29`: F6 = change columns,
//! F2 = value format, Ctrl+F7 = find next, …) and dispatches in each
//! `OnKeyEvent`. The Rust port centralizes registration so conflicts
//! are **detected and logged instead of silently shadowing** a
//! binding (matrix task `keyboard-registry`; key routing per
//! `APPCUI_RS_UI_AND_ASYNC_GUIDE` §6.4).

use appcui::input::Key;

/// One registered binding.
#[derive(Clone, Debug)]
pub struct KeyBinding {
    /// The key combination.
    pub key: Key,
    /// Command identifier dispatched when the key is pressed.
    pub command_id: u32,
    /// Human-readable caption (command-bar label / conflict logs).
    pub caption: String,
}

/// A recorded registration conflict: `key` was already bound.
#[derive(Clone, Debug)]
pub struct KeyConflict {
    /// The contested key combination.
    pub key: Key,
    /// Caption of the binding that stays in effect.
    pub existing_caption: String,
    /// Command id of the binding that stays in effect.
    pub existing_command_id: u32,
    /// Caption of the rejected binding.
    pub rejected_caption: String,
    /// Command id of the rejected binding.
    pub rejected_command_id: u32,
}

impl std::fmt::Display for KeyConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "key {:?}+{:?} already bound to '{}' (cmd {}); rejected '{}' (cmd {})",
            self.key.modifier,
            self.key.code,
            self.existing_caption,
            self.existing_command_id,
            self.rejected_caption,
            self.rejected_command_id
        )
    }
}

/// Key → command registry with conflict tracking.
#[derive(Default)]
pub struct KeyboardRegistry {
    bindings: Vec<KeyBinding>,
    conflicts: Vec<KeyConflict>,
}

impl KeyboardRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `key` → `command_id`. If the key is already bound,
    /// the **first** binding stays in effect, the attempt is recorded
    /// in [`Self::conflicts`], and `false` is returned — a conflict is
    /// never silent.
    pub fn register(&mut self, key: Key, command_id: u32, caption: impl Into<String>) -> bool {
        let caption = caption.into();
        if let Some(existing) = self.bindings.iter().find(|b| b.key == key) {
            self.conflicts.push(KeyConflict {
                key,
                existing_caption: existing.caption.clone(),
                existing_command_id: existing.command_id,
                rejected_caption: caption,
                rejected_command_id: command_id,
            });
            return false;
        }
        self.bindings.push(KeyBinding {
            key,
            command_id,
            caption,
        });
        true
    }

    /// Command id bound to `key`, if any.
    #[must_use]
    pub fn dispatch(&self, key: Key) -> Option<u32> {
        self.bindings
            .iter()
            .find(|b| b.key == key)
            .map(|b| b.command_id)
    }

    /// All bindings, in registration order.
    #[must_use]
    pub fn bindings(&self) -> &[KeyBinding] {
        &self.bindings
    }

    /// All rejected registrations so far (empty when clean).
    #[must_use]
    pub fn conflicts(&self) -> &[KeyConflict] {
        &self.conflicts
    }

    /// Removes every binding and clears the conflict log (used when a
    /// different viewer takes over the command surface).
    pub fn clear(&mut self) {
        self.bindings.clear();
        self.conflicts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::input::{KeyCode, KeyModifier};

    // Command ids from the BufferViewer config surface.
    const CMD_CHANGE_COLUMNS: u32 = 0xBF_01;
    const CMD_FIND_NEXT: u32 = 0xBF_02;

    #[test]
    fn register_f6_and_dispatch() {
        let mut reg = KeyboardRegistry::new();
        let f6 = Key::new(KeyCode::F6, KeyModifier::None);
        assert!(reg.register(f6, CMD_CHANGE_COLUMNS, "ChangeColumnsCount"));
        assert_eq!(reg.dispatch(f6), Some(CMD_CHANGE_COLUMNS));
        assert_eq!(reg.bindings().len(), 1);
        assert!(reg.conflicts().is_empty());
    }

    #[test]
    fn modifier_distinguishes_bindings() {
        // F7 vs Ctrl+F7 vs Ctrl+Shift+F7 are distinct keys
        // (BufferViewer: GoToEntryPoint / FindNext / FindPrevious).
        let mut reg = KeyboardRegistry::new();
        let f7 = Key::new(KeyCode::F7, KeyModifier::None);
        let ctrl_f7 = Key::new(KeyCode::F7, KeyModifier::Ctrl);
        let ctrl_shift_f7 = Key::new(KeyCode::F7, KeyModifier::Ctrl | KeyModifier::Shift);
        assert!(reg.register(f7, 1, "GoToEntryPoint"));
        assert!(reg.register(ctrl_f7, 2, "FindNext"));
        assert!(reg.register(ctrl_shift_f7, 3, "FindPrevious"));
        assert_eq!(reg.dispatch(f7), Some(1));
        assert_eq!(reg.dispatch(ctrl_f7), Some(2));
        assert_eq!(reg.dispatch(ctrl_shift_f7), Some(3));
    }

    #[test]
    fn unbound_key_dispatches_none() {
        let reg = KeyboardRegistry::new();
        assert_eq!(reg.dispatch(Key::new(KeyCode::F2, KeyModifier::None)), None);
    }

    #[test]
    fn conflict_is_logged_not_silent() {
        let mut reg = KeyboardRegistry::new();
        let f6 = Key::new(KeyCode::F6, KeyModifier::None);
        assert!(reg.register(f6, CMD_CHANGE_COLUMNS, "ChangeColumnsCount"));
        // Second registration on the same key is rejected and logged;
        // the original binding still dispatches.
        assert!(!reg.register(f6, CMD_FIND_NEXT, "FindNext"));
        assert_eq!(reg.dispatch(f6), Some(CMD_CHANGE_COLUMNS));
        assert_eq!(reg.conflicts().len(), 1);
        let conflict = &reg.conflicts()[0];
        assert_eq!(conflict.existing_command_id, CMD_CHANGE_COLUMNS);
        assert_eq!(conflict.rejected_command_id, CMD_FIND_NEXT);
        let msg = conflict.to_string();
        assert!(msg.contains("ChangeColumnsCount"));
        assert!(msg.contains("FindNext"));
    }

    #[test]
    fn clear_resets_bindings_and_log() {
        let mut reg = KeyboardRegistry::new();
        let f6 = Key::new(KeyCode::F6, KeyModifier::None);
        reg.register(f6, 1, "a");
        reg.register(f6, 2, "b");
        reg.clear();
        assert!(reg.bindings().is_empty());
        assert!(reg.conflicts().is_empty());
        assert_eq!(reg.dispatch(f6), None);
    }
}
