//! `GView` ZIP type plugin (spec `06_TYPE_PLUGINS` §ZIP; C++
//! `Types/ZIP/`).
//!
//! [`validate`] is the `Validate` export (`zip.cpp:33-51`);
//! [`container`] the container-viewer VFS (`ZIPFile::BeginIteration` /
//! `PopulateItem`), extract-on-demand (`OnOpenItem`) and the
//! `PopulateWindow` / `TypeInterface` implementation.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod container;
pub mod validate;
