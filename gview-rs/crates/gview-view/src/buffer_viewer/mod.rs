//! `BufferViewer` (hex/binary viewer) — C++ `BufferViewer/`.
//!
//! Split across matrix tasks: [`layout`] holds the viewport and
//! scrolling math; paint, color resolution, input and find
//! integration arrive in their own tasks.

pub mod color;
pub mod input;
pub mod layout;
pub mod paint;
