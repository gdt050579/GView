//! Cell-level rendering primitives shared by the smart viewers.
//!
//! [`cell`] provides a pre-allocated character grid for paint staging
//! (zero allocations inside paint loops); [`color`] provides the
//! C++-parity RGB → 16-color quantization used by the image viewer.

pub mod cell;
pub mod color;

pub use cell::CellBuffer;
pub use color::rgb_to_16color;
