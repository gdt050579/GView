//! `TextViewer` (plain-text viewer) — C++ `TextViewer/`.
//!
//! [`line_index`] builds the logical line table; wrap, viewport and
//! input arrive in their own matrix tasks.

pub mod input;
pub mod line_index;
pub mod viewport;
pub mod wrap;
