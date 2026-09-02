//! `GView` ELF type plugin (spec `06_TYPE_PLUGINS` §ELF; C++
//! `Types/ELF/`).
//!
//! [`validate`] is the `Validate` export (`elf.cpp:14-20`), [`parse`]
//! the header / table parser and address translation (`ELFFile::Update`,
//! `ConvertAddress` & co.) and [`populate`] the `PopulateWindow` /
//! `TypeInterface` implementation (buffer viewer zones, panels, opcode
//! colouring, `UpdateSettings`).

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod parse;
pub mod populate;
pub mod validate;
