//! `GView` Mach-O type plugin (spec `06_TYPE_PLUGINS` §Mach-O; C++
//! `Types/MachO/`).
//!
//! [`validate`] is the `Validate` export (`MachO.cpp:33-51`, `Mac.hpp`
//! magics), [`parse`] the header / load-command / fat-archive parser
//! (`MachOFile::Update`) and [`populate`] the `PopulateWindow` /
//! `TypeInterface` implementation (buffer and container viewers,
//! panels, opcode colouring, `UpdateSettings`).

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
