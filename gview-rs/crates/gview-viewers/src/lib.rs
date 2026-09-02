//! `GView` smart-viewer controls (spec `00_APP §6`, design decision
//! `§0.3 D2`).
//!
//! `gview-view` holds the UI-free state machines (layout, cursor,
//! paint loop, key matrix) ported from the C++ viewers; this crate
//! holds the `AppCUI-rs` controls that *own* that state and drive it
//! from `OnPaint` / `OnKeyPressed` / `OnResize` / `OnMouseEvent`. The
//! split keeps `gview-view` testable without a terminal and keeps
//! `gview-app` from growing seven paint loops.
//!
//! What is here so far (the scaffold of the `viewers-crate-scaffold`
//! task):
//!
//! | Module | Role |
//! |--------|------|
//! | [`cursor_info`] | [`CursorSnapshot`] / [`SharedCursorInfo`] — the fixed-size hand-off to the window's bottom bar (`§5.3.5`) |
//! | [`surface_sink`] | [`SurfaceRowSink`] — the zero-allocation `RowSink` that draws a buffer row into a `Surface` (`§6.2`) |
//! | [`unavailable`] | [`UnavailableView`] — the defined placeholder page for a viewer kind this build lacks (`§5.3.4`) |
//!
//! The seven viewer controls themselves land in the following tasks
//! (`buffer_view`, `text_view`, `container_view`, `dissasm_view`, then
//! `grid_view`, `lexical_view`, `image_view`).
//!
//! Hot-path rules for everything in this crate (`§6.3`): no allocation
//! in `on_paint` / `on_key_pressed` / `on_resize` / `on_mouse_event`,
//! no direct indexing of the cache slice, no `unwrap` on the object
//! mutex, and no dependency on `gview-app`.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod buffer_view;
pub mod container_view;
pub mod cursor_info;
pub mod dissasm_view;
pub mod surface_sink;
pub mod text_view;
pub mod unavailable;

pub use buffer_view::{BufferView, BufferViewSettings, FindProvider};
pub use container_view::{ContainerColumn, ContainerView, ContainerViewSettings};
pub use cursor_info::{CursorSnapshot, SharedCursorInfo, NAME_CAPACITY};
pub use dissasm_view::{DissasmView, DissasmViewSettings};
pub use surface_sink::{ByteColors, RowColors, SurfaceRowSink, HEX_DIGITS};
pub use text_view::{TextView, TextViewSettings};
pub use unavailable::{UnavailableView, UNAVAILABLE_SUFFIX};
