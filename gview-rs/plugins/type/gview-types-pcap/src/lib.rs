//! `GView` PCAP type plugin (spec `06_TYPE_PLUGINS` §PCAP; C++
//! `Types/PCAP/`).
//!
//! [`validate`] is the `Validate` export (`PCAP.cpp:35-44`), [`parse`]
//! the global header and packet-record walk (`PCAPFile::Update`) and
//! [`populate`] the `PopulateWindow` / `TypeInterface` implementation
//! (`StreamView` container, buffer zones, packet table, panels).

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
