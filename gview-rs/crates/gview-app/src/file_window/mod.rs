//! `FileWindow`: the per-object window hosting the smart viewers
//! (C++ `GViewCore/src/App/FileWindow.cpp`, `Internal.hpp:746-797`).
//!
//! Split across tasks: [`layout`] builds the splitter/tab tree; view
//! container, panel dock, event routing and the command bar arrive in
//! their own matrix tasks.

pub mod command_bar;
pub mod events;
pub mod layout;
pub mod panels;
pub mod view_container;
