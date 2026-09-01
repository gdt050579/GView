//! Command-bar rebuild for the focused `FileWindow`
//! (C++ `FileWindow::OnUpdateCommandBar`, `FileWindow.cpp:284-306`;
//! spec `02_SMART_VIEWERS_DEEP` §E.4–E.5;
//! `APPCUI_RS_UI_AND_ASYNC_GUIDE` §6.7).
//!
//! Rebuilt whenever focus changes: F4 carries the **current viewer's
//! name** as its caption, followed by the fixed instance commands and
//! one slot per type-plugin command
//! (`CMD_FOR_TYPE_PLUGIN_START + idx`). Generic-plugin slots are
//! appended by `Instance::UpdateCommandBar` (a later task).

use appcui::input::Key;

use super::events::{
    cmd, INSTANCE_ANALYSIS_ENGINE, INSTANCE_CHANGE_VIEW, INSTANCE_CHOOSE_TYPE,
    INSTANCE_COMMAND_FIND, INSTANCE_COMMAND_GOTO, INSTANCE_KEY_CONFIGURATOR,
    INSTANCE_OPEN_ADD_NOTE,
};
use super::layout::CMD_FOR_TYPE_PLUGIN_START;

/// One command-bar slot (key, caption, dispatched command id).
#[derive(Clone, Debug)]
pub struct CommandBarEntry {
    /// Bound key.
    pub key: Key,
    /// Displayed caption.
    pub caption: String,
    /// Command id dispatched on activation.
    pub command_id: u32,
}

/// A type-plugin command exposed on the bar
/// (C++ `typePlugin->GetCommands()` items).
#[derive(Clone, Debug)]
pub struct TypePluginCommand {
    /// Bound key.
    pub key: Key,
    /// Command name (caption and `RunCommand` argument).
    pub name: String,
}

/// Builds the command-bar entries for the focused window
/// (C++ `OnUpdateCommandBar` order, `FileWindow.cpp:286-302`).
///
/// `current_view_name` becomes the F4 caption — switching viewers
/// changes the label (§D.4/§E.4).
#[must_use]
pub fn build_command_bar(
    current_view_name: &str,
    type_plugin_commands: &[TypePluginCommand],
) -> Vec<CommandBarEntry> {
    let mut entries = Vec::with_capacity(7_usize.saturating_add(type_plugin_commands.len()));
    entries.push(CommandBarEntry {
        key: INSTANCE_CHANGE_VIEW.key,
        caption: current_view_name.to_owned(),
        command_id: cmd::CMD_NEXT_VIEW,
    });
    entries.push(CommandBarEntry {
        key: INSTANCE_COMMAND_GOTO.key,
        caption: INSTANCE_COMMAND_GOTO.caption.to_owned(),
        command_id: cmd::CMD_GOTO,
    });
    entries.push(CommandBarEntry {
        key: INSTANCE_COMMAND_FIND.key,
        caption: INSTANCE_COMMAND_FIND.caption.to_owned(),
        command_id: cmd::CMD_FIND,
    });
    // Note: registered with CMD_CHOSE_NEW_TYPE although the
    // KeyboardControl struct carries CMD_SWITCH_TO_VIEW (C++ parity
    // quirk, `FileWindow.cpp:289` vs `Internal.hpp:509`).
    entries.push(CommandBarEntry {
        key: INSTANCE_CHOOSE_TYPE.key,
        caption: INSTANCE_CHOOSE_TYPE.caption.to_owned(),
        command_id: cmd::CMD_CHOSE_NEW_TYPE,
    });
    entries.push(CommandBarEntry {
        key: INSTANCE_KEY_CONFIGURATOR.key,
        caption: INSTANCE_KEY_CONFIGURATOR.caption.to_owned(),
        command_id: cmd::CMD_SHOW_KEY_CONFIGURATOR,
    });
    entries.push(CommandBarEntry {
        key: INSTANCE_OPEN_ADD_NOTE.key,
        caption: INSTANCE_OPEN_ADD_NOTE.caption.to_owned(),
        command_id: cmd::CMD_OPEN_ADD_NOTE,
    });
    entries.push(CommandBarEntry {
        key: INSTANCE_ANALYSIS_ENGINE.key,
        caption: INSTANCE_ANALYSIS_ENGINE.caption.to_owned(),
        command_id: cmd::CMD_ANALYSIS_ENGINE,
    });
    for (idx, command) in type_plugin_commands.iter().enumerate() {
        entries.push(CommandBarEntry {
            key: command.key,
            caption: command.name.clone(),
            command_id: CMD_FOR_TYPE_PLUGIN_START.saturating_add(idx as u32),
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::input::{KeyCode, KeyModifier};

    fn find(entries: &[CommandBarEntry], id: u32) -> &CommandBarEntry {
        entries
            .iter()
            .find(|e| e.command_id == id)
            .expect("entry present")
    }

    #[test]
    fn f4_caption_follows_current_viewer() {
        let entries = build_command_bar("Buffer View", &[]);
        let f4 = find(&entries, cmd::CMD_NEXT_VIEW);
        assert_eq!(f4.caption, "Buffer View");
        assert_eq!(f4.key, Key::new(KeyCode::F4, KeyModifier::None));

        // Switching viewers rebuilds the bar with the new name.
        let entries = build_command_bar("Text View", &[]);
        assert_eq!(find(&entries, cmd::CMD_NEXT_VIEW).caption, "Text View");
    }

    #[test]
    fn instance_command_keys_map_to_cmd_ids() {
        let entries = build_command_bar("v", &[]);
        assert_eq!(entries.len(), 7);
        assert_eq!(
            find(&entries, cmd::CMD_GOTO).key,
            Key::new(KeyCode::F5, KeyModifier::None)
        );
        assert_eq!(
            find(&entries, cmd::CMD_FIND).key,
            Key::new(KeyCode::F7, KeyModifier::Alt)
        );
        assert_eq!(
            find(&entries, cmd::CMD_CHOSE_NEW_TYPE).key,
            Key::new(KeyCode::F1, KeyModifier::Alt)
        );
        assert_eq!(
            find(&entries, cmd::CMD_SHOW_KEY_CONFIGURATOR).key,
            Key::new(KeyCode::F1, KeyModifier::None)
        );
        assert_eq!(
            find(&entries, cmd::CMD_OPEN_ADD_NOTE).key,
            Key::new(KeyCode::F11, KeyModifier::Ctrl)
        );
        assert_eq!(
            find(&entries, cmd::CMD_ANALYSIS_ENGINE).key,
            Key::new(KeyCode::F12, KeyModifier::Alt)
        );
    }

    #[test]
    fn type_plugin_commands_chain_after_fixed_slots() {
        let plugin_commands = vec![
            TypePluginCommand {
                key: Key::new(KeyCode::F2, KeyModifier::None),
                name: "CheckSignature".to_owned(),
            },
            TypePluginCommand {
                key: Key::new(KeyCode::F3, KeyModifier::Ctrl),
                name: "DumpResources".to_owned(),
            },
        ];
        let entries = build_command_bar("PE", &plugin_commands);
        assert_eq!(entries.len(), 9);
        let first = find(&entries, CMD_FOR_TYPE_PLUGIN_START);
        assert_eq!(first.caption, "CheckSignature");
        let second = find(&entries, CMD_FOR_TYPE_PLUGIN_START + 1);
        assert_eq!(second.caption, "DumpResources");
        assert_eq!(second.key, Key::new(KeyCode::F3, KeyModifier::Ctrl));
        // Plugin slots come after the seven fixed entries, in order.
        assert_eq!(entries[7].command_id, CMD_FOR_TYPE_PLUGIN_START);
        assert_eq!(entries[8].command_id, CMD_FOR_TYPE_PLUGIN_START + 1);
    }
}
