//! `GView` core data model: `Object`, `DataCache`, `Selection`, `ZonesList`.
//!
//! Port of `GViewCore/` core utilities. Behavior parity with the C++
//! implementation is authoritative; see `specs/01_CORE_DATA_MODEL_AND_CACHE.md`.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod cache;
pub mod config;
pub mod constants;
pub mod object;
pub mod offset;
pub mod selection;
pub mod source;
pub mod zones;
