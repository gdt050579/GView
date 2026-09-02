//! `ContainerViewer` (archive/VFS tree) — C++ `ContainerViewer/`.
//!
//! [`tree`] holds the lazy `PopulateItem` tree model; [`open`] the
//! leaf open / extract-on-demand flow with the §12 security guards
//! (zip-slip paths, decompression bombs, entry caps).

pub mod open;
pub mod tree;
