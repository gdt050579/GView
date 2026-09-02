//! Command-line front end (spec `00_APP §1.2`).
//!
//! Ground truth: `GView/src/GView.cpp` — `commands[]`, the `help` raw
//! string, `GetCommandID`, `ProcessOpenCommand` and `main`.
//!
//! Shape of the C++ program, reproduced here:
//!
//! - `argv[1]` is matched **case-sensitively** against a fixed command
//!   table; anything that does not match (including `Help` or
//!   `updateConfig` in the wrong case) is treated as the first file
//!   name of an implicit `open` (`CommandID::Unknown` →
//!   `ProcessOpenCommand(argc, argv, 1)`).
//! - Options are scanned in a **separate pass before** any file is
//!   opened, so an unknown option aborts the run even when it appears
//!   after a valid file name.
//! - Every token that does not start with `-` is a path, in order.
//!
//! Parsing performs no I/O: the testing script named by `test` is read
//! by the caller, which maps an empty read to
//! [`CliError::UnreadableScript`] exactly as C++ does.
//!
//! # C++ parity notes
//!
//! - **`updateconfig` is recognised but never dispatched** by C++
//!   `main`: `CommandID::UpdateConfig` has no `case`, so it reaches
//!   `default:` and prints `Unable to process command: updateconfig`.
//!   The parser reports the command faithfully (it *is* in
//!   `commands[]`); the deliberate decision to implement it is
//!   recorded as quirk #7 in `docs/cpp_parity_quirks.md`.
//! - **`--type:` names longer than 16 characters are dropped.** C++
//!   stores the name in a `LocalString<16>`, whose `Set` fails without
//!   modifying the buffer, leaving the forced type empty while the
//!   method stays `ForceType`. Replicated by
//!   [`MAX_FORCED_TYPE_NAME_LEN`].
//! - **No-argument launch** opens the current folder in C++; folder
//!   windows are not ported (spec `00_APP §0.3 D7`), so it yields an
//!   `Open` with no paths and therefore an empty desktop.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::CliError;
use crate::instance::window_lifecycle::OpenMethod;

/// The C++ `help` raw string, verbatim (typos and trailing spaces
/// included). Extracted from `GView/src/GView.cpp`.
pub const HELP_TEXT: &str = r"
Use: GView <command> [File|Files|Folder] <options> 
Where <command> is on of:
   help                     Shows this help
                            Ex: 'GView help'

   open [fileName|path]     Opens one or multiple file names or folders
                            Ex: 'GView open a.exe b.pdf c.doc'

   reset                    Resets the entire configuration file (gview.ini)
                            and reload all existing plugins. Be carefull when
                            using this options as all your presets will be 
                            lost.
                            Ex: 'GView reset'        

   updateConfig             Updates current condiguration file (gview.ini) by
                            adding new plugins (if any). For old plugins new
                            configuration options will be added as well. 
                            Ex: 'GView updateConfig'
   
   test [fileName|path]     Opens a script for testing                     

   list-types               List all available types (as loaded from gview.ini).
                            Ex: 'GView list-types' 
And <options> are:
   --type:<type>            Specify the type of the file (if knwon)
                            Ex: 'GView open a.temp --type:PE'    
   --selectType             Specify the type of the file should be manually selected
                            Ex: 'GView open a.temp --selectType'   
";

/// First line of `ShowHelp()`.
pub const BANNER_TITLE: &str = "GView [A file/Process] viewer";

/// C++ `main` `default:` branch prefix for a recognised-but-undispatched
/// command.
pub const ERR_UNABLE_TO_PROCESS: &str = "Unable to process command: ";

/// Capacity of the C++ `LocalString<16> type` that holds `--type:`.
/// A longer name is silently discarded (see the module parity notes).
pub const MAX_FORCED_TYPE_NAME_LEN: usize = 16;

/// `--type:<name>` option prefix (matched case-insensitively).
pub const OPT_TYPE_PREFIX: &str = "--type:";

/// `--selectType` option (matched case-insensitively).
pub const OPT_SELECT_TYPE: &str = "--selectType";

/// Command names of the C++ `commands[]` table, in table order.
const COMMAND_TABLE: [(&str, CommandId); 6] = [
    ("help", CommandId::Help),
    ("open", CommandId::Open),
    ("reset", CommandId::Reset),
    ("list-types", CommandId::ListTypes),
    ("updateconfig", CommandId::UpdateConfig),
    ("test", CommandId::Test),
];

/// C++ `CommandID` (without its `Unknown` member, which this port
/// represents as `None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandId {
    Help,
    Open,
    Reset,
    ListTypes,
    UpdateConfig,
    Test,
}

/// Options shared by `open`, `test` and the implicit open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenArgs {
    /// Every non-option token, in command-line order.
    pub paths: Vec<PathBuf>,
    /// Identification method selected by the options.
    pub method: OpenMethod,
    /// Forced type name; empty unless `--type:` was given with a name
    /// of at most [`MAX_FORCED_TYPE_NAME_LEN`] characters.
    pub type_name: String,
}

impl Default for OpenArgs {
    /// C++ `ProcessOpenCommand`: no paths, `OpenMethod::FirstMatch`,
    /// no forced type.
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            method: OpenMethod::FirstMatch,
            type_name: String::new(),
        }
    }
}

/// Operands of the `test` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestArgs {
    /// The single file to analyse, plus the shared options.
    pub open: OpenArgs,
    /// The testing script; the caller reads it.
    pub script: PathBuf,
}

/// A parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    /// `help`
    Help,
    /// `open`, or an implicit open of unrecognised leading tokens.
    Open(OpenArgs),
    /// `reset`
    Reset,
    /// `list-types`
    ListTypes,
    /// `updateconfig`
    UpdateConfig,
    /// `test <file> <script>`
    Test(TestArgs),
}

/// True when C++ would treat the token as an option
/// (`argv[start][0] == '-'`).
fn is_option(text: &str) -> bool {
    text.starts_with('-')
}

/// C++ `String::StartsWith(prefix, ignoreCase = true)` followed by
/// `substr(prefix.len())`: the remainder keeps its original case.
fn strip_prefix_ignore_ascii_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| text.get(prefix.len()..))?
}

/// C++ `GetCommandID`: exact, case-sensitive comparison against the
/// command table.
fn command_id(token: &OsString) -> Option<CommandId> {
    let text = token.to_str()?;
    COMMAND_TABLE
        .iter()
        .find(|(name, _)| *name == text)
        .map(|(_, id)| *id)
}

/// C++ `ProcessOpenCommand` first pass: read every option, rejecting
/// anything unrecognised.
fn scan_options(argv: &[OsString], start: usize) -> Result<(OpenMethod, String), CliError> {
    let mut method = OpenMethod::FirstMatch;
    let mut type_name = String::new();
    for token in argv.iter().skip(start) {
        let text = token.to_string_lossy();
        if !is_option(&text) {
            continue;
        }
        if let Some(rest) = strip_prefix_ignore_ascii_case(&text, OPT_TYPE_PREFIX) {
            method = OpenMethod::ForceType;
            // `LocalString<16>::Set` fails (leaving the name empty)
            // when the value does not fit.
            type_name = if rest.chars().count() > MAX_FORCED_TYPE_NAME_LEN {
                String::new()
            } else {
                rest.to_owned()
            };
            continue;
        }
        if text.eq_ignore_ascii_case(OPT_SELECT_TYPE) {
            method = OpenMethod::Select;
            continue;
        }
        return Err(CliError::UnknownOption(text.into_owned()));
    }
    Ok((method, type_name))
}

/// C++ `ProcessOpenCommand` with `isTesting == false`.
fn parse_open(argv: &[OsString], start: usize) -> Result<OpenArgs, CliError> {
    let (method, type_name) = scan_options(argv, start)?;
    let paths = argv
        .iter()
        .skip(start)
        .filter(|token| !is_option(&token.to_string_lossy()))
        .map(PathBuf::from)
        .collect();
    Ok(OpenArgs {
        paths,
        method,
        type_name,
    })
}

/// C++ `main` `CommandID::Test` plus `ProcessOpenCommand` with
/// `isTesting == true`.
fn parse_test(argv: &[OsString]) -> Result<CliCommand, CliError> {
    // C++ `if (argc < 4)`.
    if argv.len() < 4 {
        return Err(CliError::MissingTestArgs);
    }
    let (method, type_name) = scan_options(argv, 2)?;

    // C++ walks the operands once: the first token that is not an
    // option becomes the file; the very next token — option or not —
    // is read as the script and the walk stops.
    let mut file: Option<PathBuf> = None;
    let mut script: Option<PathBuf> = None;
    for token in argv.iter().skip(2) {
        if file.is_none() && !is_option(&token.to_string_lossy()) {
            file = Some(PathBuf::from(token));
            continue;
        }
        script = Some(PathBuf::from(token));
        break;
    }
    let Some(file) = file else {
        return Err(CliError::MissingTestFile);
    };
    Ok(CliCommand::Test(TestArgs {
        open: OpenArgs {
            paths: vec![file],
            method,
            type_name,
        },
        // Unreachable with `argc >= 4` and a file found, but an empty
        // path reproduces the C++ "empty script content" outcome.
        script: script.unwrap_or_default(),
    }))
}

/// Parses a full argument vector, `argv[0]` (the program name)
/// included, as C++ `main` receives it.
///
/// # Errors
///
/// [`CliError::UnknownOption`] for an unrecognised `-…` token,
/// [`CliError::MissingTestArgs`] / [`CliError::MissingTestFile`] for a
/// malformed `test` invocation.
pub fn parse<I>(tokens: I) -> Result<CliCommand, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let argv: Vec<OsString> = tokens.into_iter().collect();
    let Some(command_token) = argv.get(1) else {
        // C++ `argc < 2` opens "."; folder windows are not ported.
        return Ok(CliCommand::Open(OpenArgs::default()));
    };
    match command_id(command_token) {
        Some(CommandId::Help) => Ok(CliCommand::Help),
        Some(CommandId::Reset) => Ok(CliCommand::Reset),
        Some(CommandId::ListTypes) => Ok(CliCommand::ListTypes),
        Some(CommandId::UpdateConfig) => Ok(CliCommand::UpdateConfig),
        Some(CommandId::Open) => parse_open(&argv, 2).map(CliCommand::Open),
        Some(CommandId::Test) => parse_test(&argv),
        None => parse_open(&argv, 1).map(CliCommand::Open),
    }
}

/// The three header lines of C++ `ShowHelp()`.
#[must_use]
pub fn help_banner(version: &str, build_date: &str) -> String {
    format!("{BANNER_TITLE}\nBuild on: {build_date}\nVersion : {version}\n")
}

/// Everything `ShowHelp()` writes: the banner then the help text,
/// each followed by a newline (C++ `std::endl`).
#[must_use]
pub fn help_message(version: &str, build_date: &str) -> String {
    format!("{}{HELP_TEXT}\n", help_banner(version, build_date))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(tokens: &[&str]) -> Vec<OsString> {
        std::iter::once(OsString::from("gview"))
            .chain(tokens.iter().map(OsString::from))
            .collect()
    }

    fn open_of(cmd: CliCommand) -> OpenArgs {
        match cmd {
            CliCommand::Open(args) => args,
            other => panic!("expected an open command, got {other:?}"),
        }
    }

    fn paths(args: &OpenArgs) -> Vec<String> {
        args.paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn no_arguments_opens_nothing() {
        let cmd = parse(argv(&[])).expect("parse");
        let args = open_of(cmd);
        assert!(args.paths.is_empty());
        assert_eq!(args.method, OpenMethod::FirstMatch);
        assert!(args.type_name.is_empty());
    }

    #[test]
    fn only_the_program_name_is_also_an_empty_open() {
        let cmd = parse(vec![OsString::from("gview")]).expect("parse");
        assert_eq!(open_of(cmd).paths.len(), 0);
    }

    #[test]
    fn help_is_recognised() {
        assert_eq!(parse(argv(&["help"])).expect("parse"), CliCommand::Help);
    }

    #[test]
    fn reset_and_list_types_are_recognised() {
        assert_eq!(parse(argv(&["reset"])).expect("parse"), CliCommand::Reset);
        assert_eq!(
            parse(argv(&["list-types"])).expect("parse"),
            CliCommand::ListTypes
        );
    }

    #[test]
    fn command_matching_is_case_sensitive() {
        // C++ compares the u16 string views directly.
        let args = open_of(parse(argv(&["Help"])).expect("parse"));
        assert_eq!(paths(&args), vec!["Help"]);
    }

    #[test]
    fn updateconfig_is_exact_but_updateconfig_camel_case_is_a_path() {
        assert_eq!(
            parse(argv(&["updateconfig"])).expect("parse"),
            CliCommand::UpdateConfig
        );
        let args = open_of(parse(argv(&["updateConfig"])).expect("parse"));
        assert_eq!(paths(&args), vec!["updateConfig"]);
    }

    #[test]
    fn unknown_command_becomes_the_first_path() {
        let args = open_of(parse(argv(&["x.bin"])).expect("parse"));
        assert_eq!(paths(&args), vec!["x.bin"]);
        assert_eq!(args.method, OpenMethod::FirstMatch);
    }

    #[test]
    fn unknown_command_keeps_following_paths_and_options() {
        let args = open_of(parse(argv(&["a.exe", "b.dll", "--selectType"])).expect("parse"));
        assert_eq!(paths(&args), vec!["a.exe", "b.dll"]);
        assert_eq!(args.method, OpenMethod::Select);
    }

    #[test]
    fn open_collects_every_path_and_the_forced_type() {
        let args = open_of(parse(argv(&["open", "a", "b", "--type:PE", "c"])).expect("parse"));
        assert_eq!(paths(&args), vec!["a", "b", "c"]);
        assert_eq!(args.method, OpenMethod::ForceType);
        assert_eq!(args.type_name, "PE");
    }

    #[test]
    fn type_prefix_is_case_insensitive_and_keeps_the_value_case() {
        let args = open_of(parse(argv(&["open", "--TYPE:pe", "a"])).expect("parse"));
        assert_eq!(args.method, OpenMethod::ForceType);
        assert_eq!(args.type_name, "pe");
    }

    #[test]
    fn select_type_is_case_insensitive() {
        for token in ["--selectType", "--SELECTTYPE", "--selecttype"] {
            let args = open_of(parse(argv(&["open", token, "a"])).expect("parse"));
            assert_eq!(args.method, OpenMethod::Select, "for {token}");
        }
    }

    #[test]
    fn a_long_forced_type_name_is_dropped_like_local_string_16() {
        let short = "A".repeat(MAX_FORCED_TYPE_NAME_LEN);
        let long = "A".repeat(MAX_FORCED_TYPE_NAME_LEN + 1);
        let fits = open_of(parse(argv(&["open", &format!("--type:{short}"), "a"])).expect("parse"));
        assert_eq!(fits.type_name, short);
        let dropped =
            open_of(parse(argv(&["open", &format!("--type:{long}"), "a"])).expect("parse"));
        assert_eq!(dropped.method, OpenMethod::ForceType);
        assert!(dropped.type_name.is_empty());
    }

    #[test]
    fn the_last_option_wins_for_the_method() {
        let args = open_of(parse(argv(&["open", "--type:PE", "--selectType", "a"])).expect("parse"));
        assert_eq!(args.method, OpenMethod::Select);
        // C++ leaves the already-stored name untouched.
        assert_eq!(args.type_name, "PE");
    }

    #[test]
    fn an_unknown_option_is_rejected() {
        let err = parse(argv(&["open", "--bogus"])).expect_err("must fail");
        assert_eq!(err, CliError::UnknownOption(String::from("--bogus")));
    }

    #[test]
    fn a_bare_dash_is_an_unknown_option() {
        let err = parse(argv(&["open", "-"])).expect_err("must fail");
        assert_eq!(err, CliError::UnknownOption(String::from("-")));
    }

    #[test]
    fn options_are_scanned_before_any_file_is_opened() {
        // The bad option trails a valid file, yet C++ still aborts.
        let err = parse(argv(&["open", "good.exe", "--bogus"])).expect_err("must fail");
        assert_eq!(err, CliError::UnknownOption(String::from("--bogus")));
    }

    #[test]
    fn an_empty_argument_is_a_path_not_an_option() {
        let args = open_of(parse(argv(&["open", ""])).expect("parse"));
        assert_eq!(args.paths.len(), 1);
    }

    #[test]
    fn test_requires_two_operands() {
        assert_eq!(
            parse(argv(&["test", "f"])).expect_err("must fail"),
            CliError::MissingTestArgs
        );
        assert_eq!(
            parse(argv(&["test"])).expect_err("must fail"),
            CliError::MissingTestArgs
        );
    }

    #[test]
    fn test_takes_the_file_then_the_script() {
        let CliCommand::Test(args) = parse(argv(&["test", "f.exe", "s.txt"])).expect("parse") else {
            panic!("expected a test command");
        };
        assert_eq!(paths(&args.open), vec!["f.exe"]);
        assert_eq!(args.script, PathBuf::from("s.txt"));
        assert_eq!(args.open.method, OpenMethod::FirstMatch);
    }

    #[test]
    fn test_with_a_leading_option_finds_no_file() {
        // C++ consumes "--selectType" as the script and never sets
        // foundFile.
        assert_eq!(
            parse(argv(&["test", "--selectType", "f.exe", "s.txt"])).expect_err("must fail"),
            CliError::MissingTestFile
        );
    }

    #[test]
    fn test_reads_the_token_after_the_file_even_when_it_is_an_option() {
        let CliCommand::Test(args) =
            parse(argv(&["test", "f.exe", "--selectType"])).expect("parse")
        else {
            panic!("expected a test command");
        };
        assert_eq!(args.script, PathBuf::from("--selectType"));
        assert_eq!(args.open.method, OpenMethod::Select);
    }

    #[test]
    fn test_rejects_an_unknown_option_before_looking_for_the_file() {
        assert_eq!(
            parse(argv(&["test", "f.exe", "--bogus"])).expect_err("must fail"),
            CliError::UnknownOption(String::from("--bogus"))
        );
    }

    #[test]
    fn non_utf8_option_is_reported_lossily() {
        let bad = non_utf8_option();
        let err = parse(vec![OsString::from("gview"), OsString::from("open"), bad])
            .expect_err("must fail");
        match err {
            CliError::UnknownOption(text) => {
                assert!(text.starts_with('-'), "{text}");
                assert!(text.contains('\u{FFFD}'), "expected lossy text, got {text:?}");
            }
            other => panic!("expected UnknownOption, got {other:?}"),
        }
    }

    #[test]
    fn non_utf8_path_is_preserved() {
        let bad = non_utf8_path();
        let cmd = parse(vec![
            OsString::from("gview"),
            OsString::from("open"),
            bad.clone(),
        ])
        .expect("parse");
        let args = open_of(cmd);
        assert_eq!(args.paths, vec![PathBuf::from(bad)]);
    }

    #[cfg(windows)]
    fn non_utf8_option() -> OsString {
        use std::os::windows::ffi::OsStringExt;
        // '-' followed by an unpaired surrogate.
        OsString::from_wide(&[0x002D, 0x002D, 0xD800])
    }

    #[cfg(not(windows))]
    fn non_utf8_option() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b'-', b'-', 0xFF])
    }

    #[cfg(windows)]
    fn non_utf8_path() -> OsString {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[0x0061, 0xD800, 0x0062])
    }

    #[cfg(not(windows))]
    fn non_utf8_path() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b'a', 0xFF, b'b'])
    }

    #[test]
    fn help_text_is_the_cpp_raw_string() {
        assert!(HELP_TEXT.starts_with("\nUse: GView <command> [File|Files|Folder] <options> \n"));
        // Typos preserved verbatim from the C++ source.
        assert!(HELP_TEXT.contains("Be carefull when"));
        assert!(HELP_TEXT.contains("condiguration file"));
        assert!(HELP_TEXT.contains("if knwon"));
        assert!(HELP_TEXT.contains("--selectType"));
        assert!(HELP_TEXT.ends_with("Ex: 'GView open a.temp --selectType'   \n"));
    }

    #[test]
    fn help_banner_matches_show_help() {
        let banner = help_banner("1.2.3", "Jan  1 2026 00:00:00");
        let mut lines = banner.lines();
        assert_eq!(lines.next(), Some("GView [A file/Process] viewer"));
        assert_eq!(lines.next(), Some("Build on: Jan  1 2026 00:00:00"));
        assert_eq!(lines.next(), Some("Version : 1.2.3"));
        assert_eq!(lines.next(), None);
        assert!(help_message("1.2.3", "d").ends_with("--selectType'   \n\n"));
    }
}
