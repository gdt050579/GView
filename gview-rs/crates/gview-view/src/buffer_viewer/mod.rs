//! `BufferViewer` (hex/binary viewer) — C++ `BufferViewer/`.
//!
//! Split across matrix tasks: [`layout`] holds the viewport and
//! scrolling math; [`paint`], [`color`], [`input`] and the Dissasm
//! overlay dialog model ([`dissasm_dialog`]) each come from their own
//! task; find integration lives in the app crate.

pub mod color;
pub mod dissasm_dialog;
pub mod input;
pub mod layout;
pub mod paint;
