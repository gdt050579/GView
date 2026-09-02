//! `GView` native plugin engine (spec `03_DUAL_PLUGIN_SYSTEM_AND_FFI`
//! §6–§7).
//!
//! Port of `GViewCore/src/Type/`: [`matcher`] (`Matcher.cpp` and the
//! `magic:` / `startswith:` / `linestartswith:` matchers), [`fnv`]
//! (`Plugin.cpp` `ExtensionToHash`), the native [`type_plugin`] /
//! [`generic_plugin`] traits and metadata that replace the C++
//! `.tpl` / `.gpl` exports, and [`ini_emit`] (the `UpdateSettings`
//! INI regeneration in `GViewApp.cpp`).

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod fnv;
pub mod generic_plugin;
pub mod ini_emit;
pub mod matcher;
pub mod type_plugin;
