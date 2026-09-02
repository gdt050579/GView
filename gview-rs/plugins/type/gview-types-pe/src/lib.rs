//! `GView` PE type plugin (spec `06_TYPE_PLUGINS` §PE; C++
//! `Types/PE/`).
//!
//! [`validate`] is the `Validate` export (`pe.cpp:17-28`), [`header`]
//! the header parser and address translation (`PEFile::Update`,
//! `RVAToFA` & co.); the window population arrives in its own task.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod header;
pub mod populate;
pub mod validate;
