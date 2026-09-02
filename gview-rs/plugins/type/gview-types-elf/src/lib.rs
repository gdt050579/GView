//! `GView` ELF type plugin (spec `06_TYPE_PLUGINS` §ELF; C++
//! `Types/ELF/`).
//!
//! [`validate`] is the `Validate` export (`elf.cpp:14-20`); header
//! parsing and window population arrive in their own tasks.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod validate;
