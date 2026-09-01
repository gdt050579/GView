//! `ImageViewer` (terminal image rendering) — C++ `ImageViewer/` +
//! `AppCUI/.../Renderer.cpp` paint routines.
//!
//! [`quantize`] holds the pixel model and RGB → 16-color mapping;
//! [`render`] adds the zoom cycle and the half-block paint loops.

pub mod quantize;
pub mod render;
