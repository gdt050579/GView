//! `GView` C-ABI plugin shim (spec `03_DUAL_PLUGIN_SYSTEM_AND_FFI`
//! §3–§5).
//!
//! The only workspace crate allowed to use `unsafe`: it loads legacy
//! C++ `.tpl` type plugins with `libloading` ([`load`]), wraps every
//! export call in `catch_unwind`, bridges the `WindowInterface`
//! vtable ([`window_iface`]) and isolates plugin faults
//! ([`isolate`]).
//!
//! Every `unsafe` block carries a `// SAFETY:` note describing the
//! pointer validity, alignment and lifetime it relies on.

#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod isolate;
pub mod load;
pub mod window_iface;
