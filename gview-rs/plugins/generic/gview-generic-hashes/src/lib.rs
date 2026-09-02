//! `GView` Hashes generic plugin (spec `04_SERVICES` §2,
//! `APPCUI_RS_UI_AND_ASYNC_GUIDE` §4 / §5.1; C++
//! `GenericPlugins/Hashes/src/Hashes.cpp`).
//!
//! Three commands (`UpdateSettings`):
//!
//! | `Command.<name>` | Key | Behaviour |
//! |------------------|-----|-----------|
//! | `Hashes` | Shift+F5 | `HashesDialog`: pick algorithms, compute for the file or the type plugin's selection zones, list `Type` / `Value` |
//! | `ComputeMD5` | Ctrl+Shift+F5 | MD5 of file / selection, copied to the clipboard |
//! | `ComputeSHA256` | Ctrl+Shift+F6 | SHA-256 likewise |
//!
//! [`compute`] is the streaming engine (`ComputeHash`), [`settings`]
//! the `[Generic.Hashes]` `Types.*` persistence and [`dialog`] the
//! pure state of `HashesDialog`. The `AppCUI` window, the progress
//! dialog and the clipboard live in the application shell: `run`
//! records everything the shell needs to show in [`HashRun`].
//!
//! The C++ `ComputeHash` reads through `ProgressStatus` on the UI
//! thread; the engine takes a [`compute::ProgressSink`] so the shell
//! can back it with a `ProgressBar` or a `BackgroundTask` connector
//! (guide §5.1) and cancel mid-way.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod compute;
pub mod dialog;
pub mod settings;

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::object::Object;
use gview_plugin::generic_plugin::{GenericPlugin, GenericPluginMetadata};
use gview_plugin::type_plugin::{CommandDef, PluginError, SelectionZone};

use crate::compute::{compute_hashes, HashFlags, HashKind, NoProgress, ProgressSink};

/// Plugin name (`Generic.Hashes` section).
pub const PLUGIN_NAME: &str = "Hashes";
/// `CMD_SHORT_NAME_HASHES`.
pub const CMD_HASHES: &str = "Hashes";
/// `CMD_SHORT_NAME_COMPUTE_MD5`.
pub const CMD_COMPUTE_MD5: &str = "ComputeMD5";
/// `CMD_SHORT_NAME_COMPUTE_SHA256`.
pub const CMD_COMPUTE_SHA256: &str = "ComputeSHA256";
/// `"Failed computing MD5!"`.
pub const FAILED_MD5: &str = "Failed computing MD5!";
/// `"Failed computing SHA256!"`.
pub const FAILED_SHA256: &str = "Failed computing SHA256!";
/// Notification title after `ComputeMD5`.
pub const MD5_COPIED_TITLE: &str = "MD5 copied to clipboard!";
/// Notification title after `ComputeSHA256`.
pub const SHA256_COPIED_TITLE: &str = "SHA256 copied to clipboard!";
/// Error box title.
pub const ERROR_TITLE: &str = "Error!";

/// What one `Run` produced, for the shell to display.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HashRun {
    /// Command that ran.
    pub command: String,
    /// `Type → Value` (uppercase hex), sorted like the C++ `std::map`.
    pub outputs: BTreeMap<String, String>,
    /// `(title, text)` of the `ShowNotification` box, when the command
    /// shows one.
    pub notification: Option<(String, String)>,
    /// Text the shell copies to the clipboard (`Clipboard::SetText`).
    pub clipboard: Option<String>,
}

/// The Hashes generic plugin.
#[derive(Debug, Default)]
pub struct HashesPlugin {
    zones: Mutex<Vec<SelectionZone>>,
    flags: Mutex<HashFlags>,
    last_run: Mutex<Option<HashRun>>,
}

impl HashesPlugin {
    /// Plugin with every algorithm enabled (the `UpdateSettings`
    /// defaults) and no selection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            zones: Mutex::new(Vec::new()),
            flags: Mutex::new(HashFlags::ALL),
            last_run: Mutex::new(None),
        }
    }

    /// Selection zones of the current type plugin
    /// (`GetContentType()->GetSelectionZone(i)`); the shell refreshes
    /// them before dispatching a command.
    pub fn set_selection_zones(&self, zones: Vec<SelectionZone>) {
        *self.zones.lock().unwrap_or_else(PoisonError::into_inner) = zones;
    }

    /// Current selection zones.
    #[must_use]
    pub fn selection_zones(&self) -> Vec<SelectionZone> {
        self.zones.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Algorithms the `Hashes` command computes (`HashesDialog::flags`,
    /// loaded from `[Generic.Hashes]` by the shell / dialog).
    pub fn set_flags(&self, flags: HashFlags) {
        *self.flags.lock().unwrap_or_else(PoisonError::into_inner) = flags;
    }

    /// Current algorithm set.
    #[must_use]
    pub fn flags(&self) -> HashFlags {
        *self.flags.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Result of the last successful [`GenericPlugin::run`].
    #[must_use]
    pub fn last_run(&self) -> Option<HashRun> {
        self.last_run.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Runs `command` with an explicit progress sink (the trait `run`
    /// uses [`NoProgress`]).
    ///
    /// # Errors
    ///
    /// [`PluginError::UnknownCommand`] for other names;
    /// [`PluginError::Window`] carrying the C++ error-box text when the
    /// computation fails or is cancelled.
    pub fn run_with_progress(
        &self,
        command: &str,
        object: &mut Object,
        progress: &mut dyn ProgressSink,
    ) -> Result<HashRun, PluginError> {
        let zones = self.selection_zones();
        let compute_for_file = zones.is_empty();
        let run = match command {
            CMD_HASHES => {
                let outputs = compute_hashes(object.data_mut(), self.flags(), compute_for_file, &zones, progress)
                    .map_err(|e| PluginError::Window(e.to_string()))?;
                HashRun {
                    command: command.to_owned(),
                    outputs,
                    notification: None,
                    clipboard: None,
                }
            }
            CMD_COMPUTE_MD5 => {
                self.single(command, object, HashKind::Md5, FAILED_MD5, MD5_COPIED_TITLE, progress)?
            }
            CMD_COMPUTE_SHA256 => self.single(
                command,
                object,
                HashKind::Sha256,
                FAILED_SHA256,
                SHA256_COPIED_TITLE,
                progress,
            )?,
            other => return Err(PluginError::UnknownCommand(other.to_owned())),
        };
        *self.last_run.lock().unwrap_or_else(PoisonError::into_inner) = Some(run.clone());
        Ok(run)
    }

    /// `ComputeMD5` / `ComputeSHA256`: one algorithm, result copied to
    /// the clipboard and shown in a notification; any failure (or a
    /// result count other than one) is the verbatim error text.
    fn single(
        &self,
        command: &str,
        object: &mut Object,
        kind: HashKind,
        failure: &str,
        title: &str,
        progress: &mut dyn ProgressSink,
    ) -> Result<HashRun, PluginError> {
        let zones = self.selection_zones();
        let compute_for_file = zones.is_empty();
        let outputs = compute_hashes(object.data_mut(), kind.flag(), compute_for_file, &zones, progress)
            .map_err(|_| PluginError::Window(failure.to_owned()))?;
        if outputs.len() != 1 {
            return Err(PluginError::Window(failure.to_owned()));
        }
        let value = outputs.values().next().cloned().unwrap_or_default();
        Ok(HashRun {
            command: command.to_owned(),
            outputs,
            notification: Some((title.to_owned(), value.clone())),
            clipboard: Some(value),
        })
    }
}

impl GenericPlugin for HashesPlugin {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn metadata() -> GenericPluginMetadata {
        GenericPluginMetadata {
            description: String::new(),
            commands: vec![
                CommandDef {
                    name: CMD_HASHES.to_owned(),
                    key: Key::new(KeyCode::F5, KeyModifier::Shift),
                    description: String::new(),
                    command_id: 0,
                },
                CommandDef {
                    name: CMD_COMPUTE_MD5.to_owned(),
                    key: Key::new(KeyCode::F5, KeyModifier::Ctrl | KeyModifier::Shift),
                    description: String::new(),
                    command_id: 1,
                },
                CommandDef {
                    name: CMD_COMPUTE_SHA256.to_owned(),
                    key: Key::new(KeyCode::F6, KeyModifier::Ctrl | KeyModifier::Shift),
                    description: String::new(),
                    command_id: 2,
                },
            ],
        }
    }

    fn run(&self, command: &str, object: &mut Object) -> Result<(), PluginError> {
        self.run_with_progress(command, object, &mut NoProgress).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_plugin::generic_plugin::GenericPluginDescriptor;

    fn object(data: &[u8]) -> Object {
        Object::from_buffer(data, "sample.bin", 0)
    }

    #[test]
    fn metadata_matches_update_settings() {
        let meta = HashesPlugin::metadata();
        assert!(meta.description.is_empty());
        let names: Vec<&str> = meta.commands.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["Hashes", "ComputeMD5", "ComputeSHA256"]);
        assert_eq!(meta.command("Hashes").map(|c| c.key), Some(Key::new(KeyCode::F5, KeyModifier::Shift)));
        assert_eq!(
            meta.command("ComputeMD5").map(|c| c.key),
            Some(Key::new(KeyCode::F5, KeyModifier::Ctrl | KeyModifier::Shift))
        );
        assert_eq!(
            meta.command("ComputeSHA256").map(|c| c.key),
            Some(Key::new(KeyCode::F6, KeyModifier::Ctrl | KeyModifier::Shift))
        );
        let descriptor = GenericPluginDescriptor::of::<HashesPlugin>(PLUGIN_NAME);
        assert_eq!((descriptor.create)().name(), "Hashes");
    }

    #[test]
    fn compute_md5_copies_to_clipboard() {
        let plugin = HashesPlugin::new();
        let mut obj = object(b"abc");
        plugin.run(CMD_COMPUTE_MD5, &mut obj).expect("md5");
        let run = plugin.last_run().expect("recorded");
        let md5 = "900150983CD24FB0D6963F7D28E17F72";
        assert_eq!(run.outputs.get("MD5").map(String::as_str), Some(md5));
        assert_eq!(run.clipboard.as_deref(), Some(md5));
        assert_eq!(run.notification, Some(("MD5 copied to clipboard!".to_owned(), md5.to_owned())));
    }

    #[test]
    fn compute_sha256_for_selection() {
        let plugin = HashesPlugin::new();
        // Selecting bytes 1..=3 of "xabcx" hashes "abc".
        plugin.set_selection_zones(vec![SelectionZone { start: 1, end: 3 }]);
        let mut obj = object(b"xabcx");
        let run = plugin
            .run_with_progress(CMD_COMPUTE_SHA256, &mut obj, &mut NoProgress)
            .expect("sha256");
        assert_eq!(
            run.outputs.get("SHA256").map(String::as_str),
            Some("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
        );
        assert_eq!(run.notification.map(|n| n.0), Some("SHA256 copied to clipboard!".to_owned()));
        assert_eq!(plugin.selection_zones().len(), 1);
    }

    #[test]
    fn hashes_command_uses_flags() {
        let plugin = HashesPlugin::new();
        plugin.set_flags(HashKind::Adler32.flag() | HashKind::Crc32JamCrc.flag());
        assert_eq!(plugin.flags(), HashKind::Adler32.flag() | HashKind::Crc32JamCrc.flag());
        let mut obj = object(b"abc");
        plugin.run(CMD_HASHES, &mut obj).expect("hashes");
        let run = plugin.last_run().expect("recorded");
        let keys: Vec<&str> = run.outputs.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["Adler32", "CRC32 (JAMCRC(-1))"]);
        assert!(run.notification.is_none() && run.clipboard.is_none());
    }

    #[test]
    fn errors_are_verbatim() {
        let plugin = HashesPlugin::new();
        let mut obj = object(b"abc");
        assert_eq!(
            plugin.run("Nope", &mut obj),
            Err(PluginError::UnknownCommand("Nope".to_owned()))
        );
        // An empty object cannot be read (C++ `CopyToBuffer` of 0 bytes
        // is invalid) → the verbatim failure text.
        let mut empty = object(b"");
        assert_eq!(
            plugin.run(CMD_COMPUTE_MD5, &mut empty),
            Err(PluginError::Window("Failed computing MD5!".to_owned()))
        );
        assert_eq!(
            plugin.run(CMD_COMPUTE_SHA256, &mut empty),
            Err(PluginError::Window("Failed computing SHA256!".to_owned()))
        );
        assert!(plugin.last_run().is_none());
    }
}
