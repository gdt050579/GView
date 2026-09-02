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
pub mod file_window;
pub mod find_dialog;
pub mod instance;
pub mod keyboard;
pub mod open_file;

fn main() {
    println!("GView-rs {}", env!("CARGO_PKG_VERSION"));
}
