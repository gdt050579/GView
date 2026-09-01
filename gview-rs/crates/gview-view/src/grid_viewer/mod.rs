//! `GridViewer` (tabular/CSV viewer) — C++ `GridViewer/`.
//!
//! [`parse`] holds the streaming `ProcessContent` engine; [`grid`]
//! adds `PopulateGrid`, the sort delegation model and cell export.

pub mod grid;
pub mod parse;
