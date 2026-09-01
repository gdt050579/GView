//! `FileWindow` key precedence and command dispatch.
//!
//! C++ anchors: `FileWindow::OnKeyEvent` (`FileWindow.cpp:184-221`)
//! and `OnEvent` (`FileWindow.cpp:222-282`); spec
//! `02_SMART_VIEWERS_DEEP` §E.1–E.2; key routing per
//! `APPCUI_RS_UI_AND_ASYNC_GUIDE` §6.4–6.5.
//! The routing logic is modeled as pure functions returning actions;
//! the `file-window-shell` task executes them against the real
//! controls.

use appcui::input::{Key, KeyCode, KeyModifier};

use super::layout::{
    CMD_FOR_TYPE_PLUGIN_START, CMD_SHOW_HORIZONTAL_PANEL, CMD_SHOW_VIEW_CONFIG_PANEL,
};

/// `InstanceCommands` ids (C++ `Internal.hpp:491-499`).
pub mod cmd {
    /// F4 — cycle to the next viewer tab.
    pub const CMD_NEXT_VIEW: u32 = 30_012_345;
    /// `GoTo` dialog.
    pub const CMD_GOTO: u32 = 30_012_346;
    /// Find dialog.
    pub const CMD_FIND: u32 = 30_012_347;
    /// Re-open the file with a manually selected type.
    pub const CMD_CHOSE_NEW_TYPE: u32 = 30_012_348;
    /// Key configurator window.
    pub const CMD_SHOW_KEY_CONFIGURATOR: u32 = 30_012_349;
    /// Copy dialog.
    pub const CMD_COPY_DIALOG: u32 = 30_012_350;
    /// Focus the view tab.
    pub const CMD_SWITCH_TO_VIEW: u32 = 30_012_351;
    /// Add-note dialog.
    pub const CMD_OPEN_ADD_NOTE: u32 = 30_012_352;
    /// Analysis engine window.
    pub const CMD_ANALYSIS_ENGINE: u32 = 30_012_353;
}

/// One named key binding (C++ `GView::KeyboardControl`).
#[derive(Clone, Copy, Debug)]
pub struct KeyboardControl {
    /// Bound key.
    pub key: Key,
    /// Caption shown in the command bar / key configurator.
    pub caption: &'static str,
    /// Explanation line.
    pub explanation: &'static str,
    /// Dispatched command id.
    pub command_id: u32,
}

const fn key(code: KeyCode, modifier: KeyModifier) -> Key {
    Key { code, modifier }
}

/// Ctrl+G → `GoTo` (C++ `FILE_WINDOW_COMMAND_GOTO`).
pub const FILE_WINDOW_COMMAND_GOTO: KeyboardControl = KeyboardControl {
    key: key(KeyCode::G, KeyModifier::Ctrl),
    caption: "GoToDialog",
    explanation: "Open the GoTo dialog",
    command_id: cmd::CMD_GOTO,
};
/// F5 → `GoTo` (C++ `INSTANCE_COMMAND_GOTO`).
pub const INSTANCE_COMMAND_GOTO: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F5, KeyModifier::None),
    caption: "GoToDialog",
    explanation: "Open the GoTo dialog",
    command_id: cmd::CMD_GOTO,
};
/// Ctrl+F → Find (C++ `FILE_WINDOW_COMMAND_FIND`).
pub const FILE_WINDOW_COMMAND_FIND: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F, KeyModifier::Ctrl),
    caption: "FindDialog",
    explanation: "Open the Find dialog",
    command_id: cmd::CMD_FIND,
};
/// Alt+F7 → Find (C++ `INSTANCE_COMMAND_FIND`).
pub const INSTANCE_COMMAND_FIND: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F7, KeyModifier::Alt),
    caption: "FindDialog",
    explanation: "Open the Find dialog",
    command_id: cmd::CMD_FIND,
};
/// Ctrl+C → Copy dialog (C++ `FILE_WINDOW_COMMAND_COPY`).
pub const FILE_WINDOW_COMMAND_COPY: KeyboardControl = KeyboardControl {
    key: key(KeyCode::C, KeyModifier::Ctrl),
    caption: "CopyDialog",
    explanation: "Open the CopyPaste dialog",
    command_id: cmd::CMD_COPY_DIALOG,
};
/// Ctrl+Insert → Copy dialog (C++ `FILE_WINDOW_COMMAND_INSERT`).
pub const FILE_WINDOW_COMMAND_INSERT: KeyboardControl = KeyboardControl {
    key: key(KeyCode::Insert, KeyModifier::Ctrl),
    caption: "CopyDialog",
    explanation: "Open the CopyPaste dialog",
    command_id: cmd::CMD_COPY_DIALOG,
};
/// F4 → next view (C++ `INSTANCE_CHANGE_VIEW`).
pub const INSTANCE_CHANGE_VIEW: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F4, KeyModifier::None),
    caption: "ChangeView",
    explanation: "Change the current viewer",
    command_id: cmd::CMD_NEXT_VIEW,
};
/// Alt+F → focus view (C++ `INSTANCE_SWITCH_TO_VIEW`).
pub const INSTANCE_SWITCH_TO_VIEW: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F, KeyModifier::Alt),
    caption: "SwitchToView",
    explanation: "Set focus on viewer",
    command_id: cmd::CMD_SWITCH_TO_VIEW,
};
/// Alt+F1 → choose type (C++ `INSTANCE_CHOOSE_TYPE`).
///
/// **C++ parity quirk** (`Internal.hpp:509`): the struct's
/// `CommandId` is `CMD_SWITCH_TO_VIEW`, while the command-bar handler
/// registers and dispatches `CMD_CHOSE_NEW_TYPE`. Preserved verbatim;
/// asserted by the `cpp-parity-behavioral-bugs` task.
pub const INSTANCE_CHOOSE_TYPE: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F1, KeyModifier::Alt),
    caption: "ChooseType",
    explanation: "Choose a new plugin type",
    command_id: cmd::CMD_SWITCH_TO_VIEW,
};
/// F1 → key configurator (C++ `INSTANCE_KEY_CONFIGURATOR`).
pub const INSTANCE_KEY_CONFIGURATOR: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F1, KeyModifier::None),
    caption: "ShowKeys",
    explanation: "Show available keys",
    command_id: cmd::CMD_SHOW_KEY_CONFIGURATOR,
};
/// Ctrl+F11 → add note (C++ `INSTANCE_OPEN_ADD_NOTE`).
pub const INSTANCE_OPEN_ADD_NOTE: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F11, KeyModifier::Ctrl),
    caption: "AddNote",
    explanation: "Add note to current window",
    command_id: cmd::CMD_OPEN_ADD_NOTE,
};
/// Alt+F12 → analysis engine (C++ `INSTANCE_ANALYSIS_ENGINE`).
pub const INSTANCE_ANALYSIS_ENGINE: KeyboardControl = KeyboardControl {
    key: key(KeyCode::F12, KeyModifier::Alt),
    caption: "AnalysisEngine",
    explanation: "Show the AnalysisEngine",
    command_id: cmd::CMD_ANALYSIS_ENGINE,
};

/// Action produced by routing a key through
/// `FileWindow::OnKeyEvent` (§E.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAction {
    /// Escape while the view lacks focus: focus the view tab.
    FocusView,
    /// A child in the delegation chain consumed the key.
    HandledByChain,
    /// Ctrl+G: open the `GoTo` dialog on the active viewer.
    ShowGoTo,
    /// Ctrl+F: open the Find dialog.
    ShowFind,
    /// Ctrl+C / Ctrl+Insert: open the Copy dialog.
    ShowCopy,
    /// Key not handled by the window (bubbles to the command bar).
    NotHandled,
}

/// Delegation results collected before the window's own shortcuts
/// run (C++ calls in `FileWindow.cpp:190-197`).
#[derive(Clone, Copy, Debug, Default)]
pub struct ChainDelegation {
    /// `Window::OnKeyEvent` (`AppCUI` chain → active viewer).
    pub window: bool,
    /// `verticalPanels->OnKeyEvent`.
    pub vertical_panels: bool,
    /// `horizontalPanels->OnKeyEvent`.
    pub horizontal_panels: bool,
}

impl ChainDelegation {
    /// `true` when any delegate consumed the key.
    #[must_use]
    pub const fn any(self) -> bool {
        self.window || self.vertical_panels || self.horizontal_panels
    }
}

/// Routes one key per the C++ precedence (`FileWindow.cpp:184-221`):
/// Escape-refocus → window chain → vertical panels → horizontal
/// panels → Alt+F → Ctrl+G → Ctrl+F → Ctrl+C/Ctrl+Insert.
#[must_use]
pub fn route_key(pressed: Key, view_has_focus: bool, chain: ChainDelegation) -> KeyAction {
    if pressed == key(KeyCode::Escape, KeyModifier::None) && !view_has_focus {
        return KeyAction::FocusView;
    }
    if chain.any() {
        return KeyAction::HandledByChain;
    }
    if pressed == INSTANCE_SWITCH_TO_VIEW.key {
        // C++ returns true even when the view already has focus.
        return KeyAction::FocusView;
    }
    if pressed == FILE_WINDOW_COMMAND_GOTO.key {
        return KeyAction::ShowGoTo;
    }
    if pressed == FILE_WINDOW_COMMAND_FIND.key {
        return KeyAction::ShowFind;
    }
    if pressed == FILE_WINDOW_COMMAND_COPY.key || pressed == FILE_WINDOW_COMMAND_INSERT.key {
        return KeyAction::ShowCopy;
    }
    KeyAction::NotHandled
}

/// Action produced by `FileWindow::OnEvent` command dispatch (§E.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandAction {
    /// `CMD_SHOW_VIEW_CONFIG_PANEL`: file properties dialog.
    ShowProperties,
    /// `CMD_NEXT_VIEW`: `view->GoToNextTabPage()`.
    NextView,
    /// `CMD_GOTO`.
    ShowGoTo,
    /// `CMD_FIND`.
    ShowFind,
    /// `CMD_CHOSE_NEW_TYPE` on a file object: re-open with type
    /// selection.
    ChooseNewType,
    /// `CMD_CHOSE_NEW_TYPE` on a non-file object: error message
    /// (C++ `FileWindow.cpp:244-246`).
    ChooseNewTypeUnsupported,
    /// `CMD_SHOW_KEY_CONFIGURATOR`.
    ShowKeyConfigurator,
    /// `CMD_OPEN_ADD_NOTE`.
    AddNote,
    /// `CMD_ANALYSIS_ENGINE`.
    ShowAnalysisEngine,
    /// `CMD_SHOW_HORIZONTAL_PANEL + n`: switch bottom panel `n`.
    ShowHorizontalPanel(usize),
    /// `CMD_FOR_TYPE_PLUGIN_START + idx`: run type-plugin command
    /// `idx`.
    RunTypePluginCommand(usize),
    /// Not a `FileWindow` command.
    NotHandled,
}

/// Dispatches a command id per `FileWindow::OnEvent`
/// (`FileWindow.cpp:226-271`).
///
/// `object_is_file` gates `CMD_CHOSE_NEW_TYPE`; `has_type_plugin`
/// gates the plugin command range (C++ checks
/// `typePlugin.IsValid()`).
#[must_use]
pub fn dispatch_command(id: u32, object_is_file: bool, has_type_plugin: bool) -> CommandAction {
    match id {
        CMD_SHOW_VIEW_CONFIG_PANEL => return CommandAction::ShowProperties,
        cmd::CMD_NEXT_VIEW => return CommandAction::NextView,
        cmd::CMD_GOTO => return CommandAction::ShowGoTo,
        cmd::CMD_FIND => return CommandAction::ShowFind,
        cmd::CMD_CHOSE_NEW_TYPE => {
            return if object_is_file {
                CommandAction::ChooseNewType
            } else {
                CommandAction::ChooseNewTypeUnsupported
            };
        }
        cmd::CMD_SHOW_KEY_CONFIGURATOR => return CommandAction::ShowKeyConfigurator,
        cmd::CMD_OPEN_ADD_NOTE => return CommandAction::AddNote,
        cmd::CMD_ANALYSIS_ENGINE => return CommandAction::ShowAnalysisEngine,
        _ => {}
    }
    if (CMD_SHOW_HORIZONTAL_PANEL..=CMD_SHOW_HORIZONTAL_PANEL.saturating_add(100)).contains(&id) {
        return CommandAction::ShowHorizontalPanel(
            id.saturating_sub(CMD_SHOW_HORIZONTAL_PANEL) as usize
        );
    }
    if has_type_plugin
        && (CMD_FOR_TYPE_PLUGIN_START..=CMD_FOR_TYPE_PLUGIN_START.saturating_add(1000))
            .contains(&id)
    {
        return CommandAction::RunTypePluginCommand(
            id.saturating_sub(CMD_FOR_TYPE_PLUGIN_START) as usize
        );
    }
    CommandAction::NotHandled
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESC: Key = key(KeyCode::Escape, KeyModifier::None);
    const F4: Key = key(KeyCode::F4, KeyModifier::None);

    const NO_CHAIN: ChainDelegation = ChainDelegation {
        window: false,
        vertical_panels: false,
        horizontal_panels: false,
    };

    #[test]
    fn escape_refocuses_view_when_unfocused() {
        assert_eq!(route_key(ESC, false, NO_CHAIN), KeyAction::FocusView);
        // With the view focused, Escape falls through the chain
        // (window chain handles it or it bubbles).
        assert_eq!(route_key(ESC, true, NO_CHAIN), KeyAction::NotHandled);
    }

    #[test]
    fn chain_handling_stops_routing() {
        // Any child claiming the key ends the sequence — even for
        // keys the window would otherwise act on.
        let goto = FILE_WINDOW_COMMAND_GOTO.key;
        for chain in [
            ChainDelegation {
                window: true,
                ..NO_CHAIN
            },
            ChainDelegation {
                vertical_panels: true,
                ..NO_CHAIN
            },
            ChainDelegation {
                horizontal_panels: true,
                ..NO_CHAIN
            },
        ] {
            assert_eq!(route_key(goto, true, chain), KeyAction::HandledByChain);
        }
        assert_eq!(route_key(goto, true, NO_CHAIN), KeyAction::ShowGoTo);
    }

    #[test]
    fn shortcut_keys_map_to_dialogs() {
        assert_eq!(
            route_key(INSTANCE_SWITCH_TO_VIEW.key, false, NO_CHAIN),
            KeyAction::FocusView
        );
        assert_eq!(
            route_key(FILE_WINDOW_COMMAND_FIND.key, true, NO_CHAIN),
            KeyAction::ShowFind
        );
        assert_eq!(
            route_key(FILE_WINDOW_COMMAND_COPY.key, true, NO_CHAIN),
            KeyAction::ShowCopy
        );
        assert_eq!(
            route_key(FILE_WINDOW_COMMAND_INSERT.key, true, NO_CHAIN),
            KeyAction::ShowCopy
        );
        assert_eq!(route_key(F4, true, NO_CHAIN), KeyAction::NotHandled);
    }

    #[test]
    fn f4_dispatches_next_view_command() {
        // F4 reaches the window as CMD_NEXT_VIEW via the command bar.
        assert_eq!(
            dispatch_command(cmd::CMD_NEXT_VIEW, true, true),
            CommandAction::NextView
        );
    }

    #[test]
    fn fixed_command_ids() {
        assert_eq!(
            dispatch_command(CMD_SHOW_VIEW_CONFIG_PANEL, true, false),
            CommandAction::ShowProperties
        );
        assert_eq!(
            dispatch_command(cmd::CMD_GOTO, true, false),
            CommandAction::ShowGoTo
        );
        assert_eq!(
            dispatch_command(cmd::CMD_FIND, true, false),
            CommandAction::ShowFind
        );
        assert_eq!(
            dispatch_command(cmd::CMD_SHOW_KEY_CONFIGURATOR, true, false),
            CommandAction::ShowKeyConfigurator
        );
        assert_eq!(
            dispatch_command(cmd::CMD_OPEN_ADD_NOTE, true, false),
            CommandAction::AddNote
        );
        assert_eq!(
            dispatch_command(cmd::CMD_ANALYSIS_ENGINE, true, false),
            CommandAction::ShowAnalysisEngine
        );
        assert_eq!(
            dispatch_command(12345, true, true),
            CommandAction::NotHandled
        );
    }

    #[test]
    fn choose_new_type_gated_on_file_objects() {
        assert_eq!(
            dispatch_command(cmd::CMD_CHOSE_NEW_TYPE, true, false),
            CommandAction::ChooseNewType
        );
        assert_eq!(
            dispatch_command(cmd::CMD_CHOSE_NEW_TYPE, false, false),
            CommandAction::ChooseNewTypeUnsupported
        );
    }

    #[test]
    fn type_plugin_command_range() {
        // Inclusive [start, start + 1000] and gated on plugin
        // validity (FileWindow.cpp:266-270).
        assert_eq!(
            dispatch_command(CMD_FOR_TYPE_PLUGIN_START, true, true),
            CommandAction::RunTypePluginCommand(0)
        );
        assert_eq!(
            dispatch_command(CMD_FOR_TYPE_PLUGIN_START + 1000, true, true),
            CommandAction::RunTypePluginCommand(1000)
        );
        assert_eq!(
            dispatch_command(CMD_FOR_TYPE_PLUGIN_START + 1001, true, true),
            CommandAction::NotHandled
        );
        assert_eq!(
            dispatch_command(CMD_FOR_TYPE_PLUGIN_START + 5, true, false),
            CommandAction::NotHandled
        );
    }

    #[test]
    fn horizontal_panel_range() {
        assert_eq!(
            dispatch_command(CMD_SHOW_HORIZONTAL_PANEL + 3, true, false),
            CommandAction::ShowHorizontalPanel(3)
        );
        assert_eq!(
            dispatch_command(CMD_SHOW_HORIZONTAL_PANEL + 100, true, false),
            CommandAction::ShowHorizontalPanel(100)
        );
        assert_eq!(
            dispatch_command(CMD_SHOW_HORIZONTAL_PANEL + 101, true, false),
            CommandAction::NotHandled
        );
    }

    #[test]
    fn instance_commands_match_cpp_ids() {
        assert_eq!(cmd::CMD_NEXT_VIEW, 30_012_345);
        assert_eq!(cmd::CMD_ANALYSIS_ENGINE, 30_012_353);
        assert_eq!(INSTANCE_CHANGE_VIEW.command_id, cmd::CMD_NEXT_VIEW);
        assert_eq!(INSTANCE_COMMAND_GOTO.command_id, cmd::CMD_GOTO);
        assert_eq!(INSTANCE_COMMAND_FIND.command_id, cmd::CMD_FIND);
        assert_eq!(
            INSTANCE_KEY_CONFIGURATOR.command_id,
            cmd::CMD_SHOW_KEY_CONFIGURATOR
        );
        assert_eq!(INSTANCE_OPEN_ADD_NOTE.command_id, cmd::CMD_OPEN_ADD_NOTE);
        assert_eq!(
            INSTANCE_ANALYSIS_ENGINE.command_id,
            cmd::CMD_ANALYSIS_ENGINE
        );
        // Parity quirk (Internal.hpp:509): CHOOSE_TYPE carries
        // CMD_SWITCH_TO_VIEW even though its handler is
        // CMD_CHOSE_NEW_TYPE.
        assert_eq!(INSTANCE_CHOOSE_TYPE.command_id, cmd::CMD_SWITCH_TO_VIEW);
    }
}
