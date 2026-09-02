//! `cpp-parity-behavioral-bugs` — application-shell quirks
//! (`docs/cpp_parity_quirks.md` §6).

use crate::cli::{parse, CliCommand};
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

/// Quirk 7 — `GView.cpp`: the help text advertises `updateConfig`, but
/// `commands[]` stores `"updateconfig"` and `GetCommandID` compares
/// case-sensitively, so the documented spelling is parsed as a file
/// name. The lowercase spelling does reach `CommandID::UpdateConfig`,
/// which then has no `case` in the `main` switch and dies in
/// `default:`. The parser preserves both halves; dispatching the
/// command is the port's deliberate fix (see the doc entry).
#[test]
fn quirk_7_update_config_command_is_unreachable_in_cpp() {
    let command_line = |token: &str| {
        vec![
            std::ffi::OsString::from("gview"),
            std::ffi::OsString::from(token),
        ]
    };

    // The advertised spelling is a path, not a command.
    let CliCommand::Open(args) = parse(command_line("updateConfig")).expect("parse") else {
        panic!("the camel-case spelling must fall through to an implicit open");
    };
    assert_eq!(
        args.paths,
        vec![std::path::PathBuf::from("updateConfig")],
        "C++ opens it as a file"
    );

    // The help text really does advertise the unreachable spelling.
    assert!(crate::cli::HELP_TEXT.contains("updateConfig"));
    assert!(!crate::cli::HELP_TEXT.contains("updateconfig"));

    // Only the lowercase table entry names the command.
    assert_eq!(
        parse(command_line("updateconfig")).expect("parse"),
        CliCommand::UpdateConfig
    );
}

/// Quirk 8 — `GViewApp.cpp:109` writes `CacheSize` while
/// `Instance.cpp:117` reads `Config.CacheSize`, so a generated file
/// never seeds the value it was meant to. `Internal.hpp:514` adds
/// `INSTANCE_ANALYSIS_ENGINE` to the seven bindings the loader reads,
/// while only six are ever written.
#[test]
fn quirk_8_cache_size_and_key_bindings_are_written_under_other_names() {
    use crate::settings::{
        render_gview_section, KEY_CACHE_SIZE_READ, KEY_CACHE_SIZE_WRITE, READ_KEY_COMMANDS,
        WRITTEN_KEY_COMMANDS,
    };

    assert_ne!(KEY_CACHE_SIZE_WRITE, KEY_CACHE_SIZE_READ);
    let generated = render_gview_section();
    assert!(
        generated.contains("CacheSize = "),
        "the writer uses the C++ key: {generated}"
    );
    assert!(
        !generated.contains(KEY_CACHE_SIZE_READ),
        "C++ never writes the key it reads: {generated}"
    );

    // Six written, seven read; the analysis engine is read-only.
    assert_eq!(WRITTEN_KEY_COMMANDS.len(), 6);
    assert_eq!(READ_KEY_COMMANDS.len(), 7);
    assert!(!generated.contains("Key.AnalysisEngine"), "{generated}");
    assert!(
        READ_KEY_COMMANDS
            .iter()
            .any(|c| c.caption == "AnalysisEngine"),
        "but the loader still looks for it"
    );
}

/// Quirk 11 — `Instance.cpp:63-73`: the `Close All e&xcept current`
/// menu entry carries `MenuCommands::CLOSE_ALL`, so it closes every
/// window. The port binds the same command to both entries.
#[test]
fn quirk_11_close_all_except_current_closes_everything() {
    use crate::desktop::{gviewdesktop::Commands, menu_id_for_command};
    use crate::instance::window_lifecycle::{menu, menu_action, InstanceAction};

    // The dedicated id exists and is preserved…
    assert_eq!(
        menu_id_for_command(Commands::CloseAllExceptCurrent),
        menu::CLOSE_ALL_EXCEPT_CURRENT
    );
    assert_ne!(menu::CLOSE_ALL_EXCEPT_CURRENT, menu::CLOSE_ALL);

    // …but neither id is dispatched by `Instance::OnEvent`, exactly as
    // in the C++ (the desktop services both itself).
    assert_eq!(menu_action(menu::CLOSE_ALL), InstanceAction::Unhandled);
    assert_eq!(menu_action(menu::CLOSE_ALL_EXCEPT_CURRENT), InstanceAction::Unhandled);
    assert_eq!(menu_action(menu::CLOSE), InstanceAction::Unhandled);
}
