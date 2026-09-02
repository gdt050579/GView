//! `DissasmViewer` (disassembly viewer) — C++ `DissasmViewer/`.
//!
//! [`zone`] holds the `ParseZone` model; [`offset_table`],
//! [`line_lookup`], [`pre_cache`], [`static_analysis`], [`arrows`],
//! [`jumps`], [`struct_collapse`], [`code_collapse`], [`input`],
//! [`cache_io`] and [`jclass`] port the individual engines;
//! [`assistant_query`] wires Ctrl+K / Ctrl+L to the LLM prompt builder.

pub mod arrows;
pub mod assistant_query;
pub mod cache_io;
pub mod code_collapse;
pub mod input;
pub mod jclass;
pub mod jumps;
pub mod line_lookup;
pub mod offset_table;
pub mod pre_cache;
pub mod static_analysis;
pub mod struct_collapse;
pub mod zone;
