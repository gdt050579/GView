//! `cpp-parity-behavioral-bugs` — application-shell quirks
//! (`docs/cpp_parity_quirks.md` §6).

use crate::file_window::command_bar::build_command_bar;
use crate::file_window::events::{cmd, INSTANCE_CHOOSE_TYPE, INSTANCE_SWITCH_TO_VIEW};

/// Quirk 6 — `Internal.hpp:509` vs `FileWindow.cpp:289`: the Alt+F1
/// `ChooseType` control carries `CMD_SWITCH_TO_VIEW` as its command id
/// (the same id as Alt+F `SwitchToView`), while the command bar
/// registers and dispatches `CMD_CHOSE_NEW_TYPE` for that key. Both
/// halves are preserved.
#[test]
fn quirk_6_instance_choose_type_command_id_mismatch() {
    assert_eq!(INSTANCE_CHOOSE_TYPE.command_id, cmd::CMD_SWITCH_TO_VIEW);
    assert_eq!(INSTANCE_CHOOSE_TYPE.command_id, INSTANCE_SWITCH_TO_VIEW.command_id);
    assert_ne!(INSTANCE_CHOOSE_TYPE.key, INSTANCE_SWITCH_TO_VIEW.key);

    let entries = build_command_bar("Buffer", &[]);
    let choose = entries
        .iter()
        .find(|e| e.key == INSTANCE_CHOOSE_TYPE.key)
        .expect("Alt+F1 is on the command bar");
    assert_eq!(choose.command_id, cmd::CMD_CHOSE_NEW_TYPE);
    assert_eq!(choose.caption, INSTANCE_CHOOSE_TYPE.caption);
    assert!(
        entries.iter().all(|e| e.command_id != cmd::CMD_SWITCH_TO_VIEW),
        "the struct's id never reaches the command bar"
    );
}
