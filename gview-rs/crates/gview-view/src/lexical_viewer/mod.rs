//! `LexicalViewer` (syntax-highlighted viewer) — C++ `LexicalViewer/`.
//!
//! [`parse`] holds the token model and parse pipeline; folding, paint
//! culling and input arrive in their own matrix tasks.

pub mod fold;
pub mod input;
pub mod paint;
pub mod parse;
