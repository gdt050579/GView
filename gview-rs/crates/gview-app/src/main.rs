//! `GView` application binary: CLI entry point and desktop harness.
//!
//! The UI shell (`FileWindow`, viewers, command bar) is added by later
//! tasks; this entry point currently reports the build identity so the
//! scaffold is runnable end to end.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod buffer_find;
pub mod cli;
pub mod desktop;
pub mod error;
pub mod error_dialog;
pub mod file_window;
pub mod find_dialog;
pub mod instance;
pub mod keyboard;
pub mod open_file;
pub mod open_pipeline;
pub mod registry;
pub mod settings;

#[cfg(test)]
mod cpp_parity_quirks;

/// Serialises the tests that build an `AppCUI` application.
///
/// `App` is a process-wide singleton (`AppCUI-rs`
/// `system/app.rs::APP_CREATED_MUTEX`, released only by `App::run`),
/// while `cargo test` runs tests on parallel threads — two UI tests
/// overlapping would fail with "App has already been created".
#[cfg(test)]
pub(crate) static UI_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn main() {
    println!("GView-rs {}", env!("CARGO_PKG_VERSION"));
}
