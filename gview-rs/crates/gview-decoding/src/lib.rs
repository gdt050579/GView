//! `GView` decoding utilities (spec `04_SERVICES` §4).
//!
//! Port of `GViewCore/src/Decoding/`: [`base64`] (`Base64.cpp`) and
//! [`zlib`] (`zlib.cpp`, via `flate2`). Every decoder enforces an
//! output-size cap before allocating (spec §4.4 / §9.2).

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod base64;
pub mod lzxpress;
pub mod zip;
pub mod zlib;
