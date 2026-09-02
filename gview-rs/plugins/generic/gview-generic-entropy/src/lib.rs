//! `GView` `EntropyVisualizer` generic plugin (spec `04_SERVICES`
//! §3.2, `APPCUI_RS_UI_AND_ASYNC_GUIDE` §4 / §5.1; C++
//! `GenericPlugins/EntropyVisualizer/src/{Plugin,EntropyVisualizer}.cpp`).
//!
//! One command, `Command.EntropyVisualizer = F12`, opens the
//! `"Entropy Visualizer"` window (`d:c,w:100%,h:98%`): a block canvas
//! (80% wide) plus a side panel with the mode combo box (`Entropy
//! type`, hot key `E`), the `Block size` selector (hot key `B`,
//! minimum 4), the `Alpha (Renyi) /10` selector and a legend canvas.
//!
//! [`model`] holds everything the window needs that is not `AppCUI`:
//! block sizing, block layout, per-block values and colors for every
//! mode, the legend rows and the embedded-object zone painting. The
//! shell builds the controls and, following guide §5.1, may compute
//! [`model::block_values`] on a `BackgroundTask` for large files.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod model;

use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::object::Object;
use gview_plugin::generic_plugin::{GenericPlugin, GenericPluginMetadata};
use gview_plugin::type_plugin::{CommandDef, PluginError};

/// Plugin name (`Generic.EntropyVisualizer` section).
pub const PLUGIN_NAME: &str = "EntropyVisualizer";
/// The single command (`Run` compares against it).
pub const CMD_ENTROPY_VISUALIZER: &str = "EntropyVisualizer";
/// Window caption.
pub const WINDOW_TITLE: &str = "Entropy Visualizer";
/// Window layout.
pub const WINDOW_LAYOUT: &str = "d:c,w:100%,h:98%";
/// Entropy canvas layout.
pub const CANVAS_LAYOUT: &str = "d:lb,w:80%,h:100%";
/// Legend canvas layout.
pub const LEGEND_LAYOUT: &str = "x:81%,y:9,w:19%,h:20%";
/// `"Entropy type"` label.
pub const ENTROPY_TYPE_LABEL: &str = "Entropy type";
/// `"Block size"` label.
pub const BLOCK_SIZE_LABEL: &str = "Block size";
/// `"Alpha (Renyi) /10"` label.
pub const ALPHA_LABEL: &str = "Alpha (Renyi) /10";
/// Alpha selector range.
pub const ALPHA_SELECTOR_RANGE: (i64, i64) = (-99, 99);
/// Alpha selector initial value.
pub const ALPHA_SELECTOR_INITIAL: i64 = 0;

/// The `EntropyVisualizer` generic plugin (stateless: the window owns
/// its [`model::EntropyView`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct EntropyVisualizerPlugin;

impl GenericPlugin for EntropyVisualizerPlugin {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn metadata() -> GenericPluginMetadata {
        GenericPluginMetadata {
            description: String::new(),
            commands: vec![CommandDef {
                name: CMD_ENTROPY_VISUALIZER.to_owned(),
                key: Key::new(KeyCode::F12, KeyModifier::None),
                description: String::new(),
                command_id: 0,
            }],
        }
    }

    /// `Run`: accepts only `EntropyVisualizer` (the shell then opens
    /// the window over `object`); other names are unknown.
    fn run(&self, command: &str, _object: &mut Object) -> Result<(), PluginError> {
        if command == CMD_ENTROPY_VISUALIZER {
            Ok(())
        } else {
            Err(PluginError::UnknownCommand(command.to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_plugin::generic_plugin::GenericPluginDescriptor;

    #[test]
    fn metadata_and_run() {
        let meta = EntropyVisualizerPlugin::metadata();
        assert_eq!(meta.commands.len(), 1);
        assert_eq!(
            meta.command("EntropyVisualizer").map(|c| c.key),
            Some(Key::new(KeyCode::F12, KeyModifier::None))
        );
        let plugin = EntropyVisualizerPlugin;
        let mut obj = Object::from_buffer(b"abc", "a", 0);
        assert_eq!(plugin.run("EntropyVisualizer", &mut obj), Ok(()));
        assert_eq!(
            plugin.run("Hashes", &mut obj),
            Err(PluginError::UnknownCommand("Hashes".to_owned()))
        );
        let descriptor = GenericPluginDescriptor::of::<EntropyVisualizerPlugin>(PLUGIN_NAME);
        assert_eq!((descriptor.create)().name(), "EntropyVisualizer");
    }
}
