//! `DissasmViewer` (disassembly viewer) — C++ `DissasmViewer/`.
//!
//! [`zone`] holds the `ParseZone` model; the offset table, line
//! lookup, pre-cache, static analysis, arrows, jumps and collapse
//! engines arrive with their own matrix tasks.

pub mod arrows;
pub mod jumps;
pub mod line_lookup;
pub mod offset_table;
pub mod pre_cache;
pub mod static_analysis;
pub mod struct_collapse;
pub mod zone;
