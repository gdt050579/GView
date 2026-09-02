//! The application-level error type (spec `00_APP §8`).
//!
//! Every failure in the orchestration layer — CLI parsing, settings
//! bootstrap, registry composition, the open pipeline and the `AppCUI`
//! bootstrap — is reported as an [`AppError`]. Nothing in this layer
//! returns `bool` for failure, unlike the C++ `CHECK` / `RETURNERROR`
//! macros it ports (`GViewCore/src/App/Instance.cpp`).
//!
//! Message parity: where C++ prints a specific string the same string
//! is produced here, character for character, so the terminal output
//! and the error dialog match the original tool. The constants below
//! pin those strings; [`crate::instance::window_lifecycle::InstanceError`]
//! already carries the three `Instance::Add` / `AddFileWindow`
//! messages and is simply forwarded.
//!
//! [`CliError`] lives here rather than in [`crate::cli`] so that the
//! error type has no forward dependency on the CLI module.

use std::path::PathBuf;

use gview_core::config::ConfigError;
use gview_plugin::type_plugin::PluginError;

use crate::instance::window_lifecycle::InstanceError;

/// C++ `Instance::Init`: `CHECK(AppCUI::Application::Init(initData),
/// false, "Fail to initialize AppCUI framework !")` (`Instance.cpp:171`).
pub const ERR_APPCUI_INIT: &str = "Fail to initialize AppCUI framework !";

/// C++ `GView.cpp` `ProcessOpenCommand`: printed before the hint line
/// when an unrecognised `-…` token is supplied.
pub const ERR_UNKNOWN_OPTION: &str = "Unknown option: ";

/// C++ `GView.cpp` `ProcessOpenCommand`: the hint printed right after
/// [`ERR_UNKNOWN_OPTION`].
pub const ERR_OPTIONS_HINT: &str = "Type 'GView help' for a detailed list of available options";

/// C++ `GView.cpp` `main`, `CommandID::Test` with fewer than 4 argv
/// entries.
pub const ERR_TEST_ARGS: &str = "The program should have 3 arguments: test <fileToAnalyze> <scriptToRun>";

/// C++ `GView.cpp` `ProcessOpenCommand`: `if (!foundFile)`.
pub const ERR_TEST_MISSING_FILE: &str = "Missing file to test";

/// C++ `GView.cpp` `ProcessOpenCommand`: `if (testingContent.empty())`.
pub const ERR_TEST_SCRIPT_UNREADABLE: &str = "Unable to read testing script file";

/// Command-line parsing failures (spec `00_APP §1.2.4`).
///
/// Every variant renders exactly what the C++ front end prints for the
/// same condition, so `main` only has to write the `Display` output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliError {
    /// A `-…` token that is neither `--type:<name>` nor `--selectType`.
    /// Rendered as two lines, matching the two C++ `std::cout` writes.
    UnknownOption(String),
    /// `test` was given fewer than two operands.
    MissingTestArgs,
    /// `test` was given only options and no file to analyse.
    MissingTestFile,
    /// The testing script could not be read (missing or empty).
    UnreadableScript(PathBuf),
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownOption(token) => {
                write!(f, "{ERR_UNKNOWN_OPTION}{token}\n{ERR_OPTIONS_HINT}")
            }
            Self::MissingTestArgs => f.write_str(ERR_TEST_ARGS),
            Self::MissingTestFile => f.write_str(ERR_TEST_MISSING_FILE),
            Self::UnreadableScript(_) => f.write_str(ERR_TEST_SCRIPT_UNREADABLE),
        }
    }
}

impl std::error::Error for CliError {}

/// Anything that can stop the application from starting or from
/// opening an object (spec `00_APP §8`).
#[derive(Debug)]
pub enum AppError {
    /// The command line could not be parsed.
    Cli(CliError),
    /// `gview.ini` could not be read or parsed.
    Config {
        /// The settings file involved.
        path: PathBuf,
        /// Why it could not be used.
        source: ConfigError,
    },
    /// A plugin could not be registered (duplicate name, bad pattern).
    Registry(PluginError),
    /// The open pipeline failed (`Instance::Add` and friends).
    Open(InstanceError),
    /// `AppCUI` could not be initialised.
    Ui(appcui::system::Error),
    /// An I/O operation outside the cache failed; `context` names it.
    Io {
        /// Short description of what was attempted.
        context: &'static str,
        /// The underlying failure.
        source: std::io::Error,
    },
}

impl AppError {
    /// Wraps an I/O failure with the operation that produced it.
    #[must_use]
    pub const fn io(context: &'static str, source: std::io::Error) -> Self {
        Self::Io { context, source }
    }

    /// Wraps a settings failure with the file it came from.
    #[must_use]
    pub const fn config(path: PathBuf, source: ConfigError) -> Self {
        Self::Config { path, source }
    }
}

impl core::fmt::Display for AppError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cli(e) => write!(f, "{e}"),
            Self::Config { path, source } => {
                write!(f, "Fail to read configuration: {} ({source})", path.display())
            }
            Self::Registry(e) => write!(f, "Fail to load plugin: {e}"),
            Self::Open(e) => write!(f, "{e}"),
            Self::Ui(e) => write!(f, "{ERR_APPCUI_INIT} ({e})"),
            Self::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cli(e) => Some(e),
            Self::Config { source, .. } => Some(source),
            Self::Registry(e) => Some(e),
            Self::Open(e) => Some(e),
            Self::Ui(e) => Some(e),
            Self::Io { source, .. } => Some(source),
        }
    }
}

impl From<CliError> for AppError {
    fn from(value: CliError) -> Self {
        Self::Cli(value)
    }
}

impl From<PluginError> for AppError {
    fn from(value: PluginError) -> Self {
        Self::Registry(value)
    }
}

impl From<InstanceError> for AppError {
    fn from(value: InstanceError) -> Self {
        Self::Open(value)
    }
}

impl From<appcui::system::Error> for AppError {
    fn from(value: appcui::system::Error) -> Self {
        Self::Ui(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;
    use std::io::{Error as IoError, ErrorKind};
    use std::path::Path;

    fn io_error() -> IoError {
        IoError::new(ErrorKind::NotFound, "no such file")
    }

    #[test]
    fn cli_unknown_option_prints_the_two_cpp_lines() {
        let text = CliError::UnknownOption(String::from("--bogus")).to_string();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("Unknown option: --bogus"));
        assert_eq!(
            lines.next(),
            Some("Type 'GView help' for a detailed list of available options")
        );
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn cli_test_messages_match_cpp() {
        assert_eq!(
            CliError::MissingTestArgs.to_string(),
            "The program should have 3 arguments: test <fileToAnalyze> <scriptToRun>"
        );
        assert_eq!(CliError::MissingTestFile.to_string(), "Missing file to test");
        assert_eq!(
            CliError::UnreadableScript(PathBuf::from("s.txt")).to_string(),
            "Unable to read testing script file"
        );
    }

    #[test]
    fn open_file_failure_keeps_the_cpp_wording() {
        let err = AppError::from(InstanceError::OpenFile {
            path: PathBuf::from("/tmp/a.exe"),
            source: io_error(),
        });
        let text = err.to_string();
        assert!(
            text.starts_with("Fail to open file: "),
            "expected the C++ prefix, got {text:?}"
        );
        assert!(text.contains("a.exe"), "{text}");
        assert!(err.source().is_some());
    }

    #[test]
    fn open_canceled_keeps_the_cpp_wording() {
        let err = AppError::from(InstanceError::OpenCanceled);
        assert_eq!(
            err.to_string(),
            "Unable to identify a valid plugin open canceled !"
        );
    }

    #[test]
    fn populate_failure_keeps_the_cpp_wording() {
        let err = AppError::from(InstanceError::PopulateFailed(PluginError::Window(
            String::from("bad header"),
        )));
        assert!(
            err.to_string().starts_with("Failed to populate file window!"),
            "{err}"
        );
    }

    #[test]
    fn folder_open_is_reported_not_silently_ignored() {
        let err = AppError::from(InstanceError::FolderUnsupported(PathBuf::from("/tmp")));
        assert!(err.to_string().contains("folder"), "{err}");
    }

    #[test]
    fn registry_failure_names_the_plugin() {
        let err = AppError::from(PluginError::DuplicateName(String::from("PE")));
        let text = err.to_string();
        assert!(text.starts_with("Fail to load plugin: "), "{text}");
        assert!(text.contains("PE"), "{text}");
        assert!(err.source().is_some());
    }

    #[test]
    fn config_failure_names_the_file() {
        let err = AppError::config(
            PathBuf::from("/etc/gview.ini"),
            ConfigError::FileTooLarge { size: 1 << 30 },
        );
        let text = err.to_string();
        assert!(text.starts_with("Fail to read configuration: "), "{text}");
        assert!(text.contains("gview.ini"), "{text}");
        assert!(err.source().is_some());
    }

    #[test]
    fn io_failure_carries_its_context() {
        let err = AppError::io("cannot locate the executable", io_error());
        assert_eq!(
            err.to_string(),
            "cannot locate the executable: no such file"
        );
        assert!(err.source().is_some());
    }

    /// `appcui::system::Error` has no public constructor (`Error::new`
    /// is `pub(crate)`), so the `Ui` arm is pinned by asserting the
    /// literal it formats with instead of by building one.
    #[test]
    fn appcui_init_message_matches_cpp() {
        assert_eq!(ERR_APPCUI_INIT, "Fail to initialize AppCUI framework !");
    }

    #[test]
    fn config_error_from_a_missing_file_is_wrapped() {
        let missing = Path::new("this-file-does-not-exist-gview.ini");
        let Err(source) = gview_core::config::Config::load_from_file(missing) else {
            panic!("loading a missing config must fail");
        };
        let err = AppError::config(missing.to_path_buf(), source);
        assert!(err.source().is_some());
        assert!(err.to_string().contains("this-file-does-not-exist-gview.ini"));
    }
}
