//! `Instance`: the application-level orchestrator
//! (C++ `GViewCore/src/App/Instance.cpp`, `Internal.hpp:523-533`).
//!
//! Split across tasks: [`window_lifecycle`] identifies the type
//! plugin, builds the per-object window model, populates it and adds
//! it to the desktop model; the open-file dialog flow and the `AppCUI`
//! shell wiring arrive in their own matrix tasks.

pub mod window_lifecycle;
