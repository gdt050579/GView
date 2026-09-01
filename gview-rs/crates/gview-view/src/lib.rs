//! `GView` view layer: renderers and (in later tasks) the
//! `ViewControl` / `SmartViewer` traits shared by all viewers.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod buffer_viewer;
pub mod image_viewer;
pub mod lexical_viewer;
pub mod renderer;
pub mod text_viewer;
pub mod traits;
pub mod view_control;
