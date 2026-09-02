//! The `GENERIC` fallback type plugin (spec `06_TYPE_PLUGINS` Required
//! exports; `02_SMART_VIEWERS_DEEP` §F.3; C++
//! `GViewCore/src/Type/DefaultTypePlugin.cpp`).
//!
//! `DefaultTypePlugin` is what the application uses when no registered
//! type plugin claims the data (`IdentifyTypePlugin` → `defaultPlugin`).
//! Its C++ exports:
//!
//! - `Validate` — always `true` ("always match everything");
//! - `CreateInstance` — a `DefaultType` named `GENERIC`, with an empty
//!   `RunCommand`, an `UpdateKeys` that registers nothing and a
//!   `GetSmartAssistantContext` of `Name` + `ContentSize`;
//! - `PopulateWindow` — the `&Information` panel (a `Field` / `Value`
//!   list), then a **text viewer when the first 4096 bytes are not
//!   binary** (`CharacterEncoding::AnalyzeBufferForEncoding`), then a
//!   **buffer viewer as the default view**; the buffer viewer is
//!   always created, so an unknown file always opens as raw hex.
//!
//! There is no `UpdateSettings`: the default plugin has no patterns,
//! extensions or priority ([`PluginMetadata::default`]) and is never
//! put in the registry.

use std::sync::{Mutex, PoisonError};

use gview_view::text_viewer::line_index::{analyze_encoding, Encoding};
use gview_view::traits::SharedObject;
use serde_json::Value as JsonValue;

use crate::type_plugin::{
    KeyRegistry, PanelRequest, PluginError, PluginMetadata, TypePlugin, ViewerKind, ViewerRequest, WindowHandle,
};

/// C++ `GetTypeName()`.
pub const TYPE_NAME: &str = "GENERIC";
/// `DefaultInformationPanel` caption.
pub const INFORMATION_CAPTION: &str = "&Information";
/// Panel identifier for the shell.
pub const INFORMATION_PANEL_ID: &str = "default.information";
/// `DefaultInformationPanel` list columns.
pub const INFORMATION_COLUMNS: [&str; 2] = ["n:Field,a:l,w:10", "n:Value,a:l,w:100"];
/// Bytes probed to decide on a text viewer (`Get(0, 4096, false)`).
pub const TEXT_PROBE_SIZE: u32 = 4096;

/// C++ `DefaultType` / `DefaultTypePlugin`: the `GENERIC` fallback used
/// when no plugin claims the data.
#[derive(Default)]
pub struct DefaultTypePlugin {
    object: Mutex<Option<SharedObject>>,
}

impl core::fmt::Debug for DefaultTypePlugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bound = self.object.lock().is_ok_and(|o| o.is_some());
        f.debug_struct("DefaultTypePlugin").field("object_bound", &bound).finish()
    }
}

impl DefaultTypePlugin {
    /// Bytes probed to decide on a text viewer (`Get(0, 4096, false)`).
    pub const TEXT_PROBE_SIZE: u32 = TEXT_PROBE_SIZE;

    /// The head of the object (`Get(0, 4096, false)`: shorter at the
    /// end of the data, empty when nothing can be read).
    #[must_use]
    pub fn probe(object: &SharedObject) -> Vec<u8> {
        let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .data_mut()
            .copy_to_vec(0, TEXT_PROBE_SIZE, false)
            .unwrap_or_default()
    }

    /// Whether `PopulateWindow` adds a text viewer for this head
    /// (`enc != CharacterEncoding::Encoding::Binary`).
    #[must_use]
    pub fn wants_text_viewer(probe: &[u8]) -> bool {
        analyze_encoding(probe).encoding != Encoding::Binary
    }
}

impl TypePlugin for DefaultTypePlugin {
    fn name(&self) -> &'static str {
        TYPE_NAME
    }

    /// C++ `Validate`: always match everything.
    fn validate(_buf: &[u8], _extension: &str) -> bool {
        true
    }

    fn create_instance() -> Box<Self> {
        Box::default()
    }

    /// No `UpdateSettings` in C++: empty metadata.
    fn metadata() -> PluginMetadata {
        PluginMetadata::default()
    }

    /// C++ `PopulateWindow` (`DefaultTypePlugin.cpp:72-92`).
    fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
        let object = win.object();
        *self.object.lock().unwrap_or_else(PoisonError::into_inner) = Some(SharedObject::clone(&object));

        // 1. info panel
        win.add_panel(
            PanelRequest {
                caption: String::from(INFORMATION_CAPTION),
                panel_id: String::from(INFORMATION_PANEL_ID),
            },
            true,
        );

        // 2. views: text viewer when the head is not binary
        if Self::wants_text_viewer(&Self::probe(&object)) {
            win.create_viewer(ViewerRequest::new(ViewerKind::Text))?;
        }
        // 3. buffer viewer as the default view
        win.create_viewer(ViewerRequest::new(ViewerKind::Buffer))?;
        Ok(())
    }

    /// C++ `RunCommand`: empty.
    fn run_command(&mut self, _command: &str) {}

    /// C++ `UpdateKeys`: nothing registered.
    fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}

    /// C++ `GetSmartAssistantContext`: `Name` and `ContentSize`.
    fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
        let bound = self
            .object
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(SharedObject::clone)
            .ok_or_else(|| PluginError::Assistant(String::from("no object bound")))?;
        let object = bound.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(serde_json::json!({
            "Name": object.name(),
            "ContentSize": object.data().size(),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::type_plugin::CommandDef;
    use gview_core::object::Object;
    use std::sync::Arc;

    #[derive(Default)]
    struct MockWindow {
        object: Option<SharedObject>,
        viewers: Vec<ViewerKind>,
        panels: Vec<(String, String, bool)>,
    }

    impl WindowHandle for MockWindow {
        fn object(&self) -> SharedObject {
            self.object
                .clone()
                .unwrap_or_else(|| Arc::new(Mutex::new(Object::from_buffer(b"", "x", 0))))
        }
        fn add_panel(&mut self, panel: PanelRequest, vertical: bool) -> bool {
            self.panels.push((panel.caption, panel.panel_id, vertical));
            true
        }
        fn create_viewer(&mut self, request: ViewerRequest) -> Result<u32, PluginError> {
            assert!(request.buffer.is_none() && request.dissasm.is_none() && request.container.is_none());
            self.viewers.push(request.kind);
            Ok(self.viewers.len() as u32 - 1)
        }
        fn views_count(&self) -> u32 {
            self.viewers.len() as u32
        }
        fn set_view_by_index(&mut self, _index: u32) -> bool {
            true
        }
        fn current_view(&self) -> Option<u32> {
            None
        }
    }

    fn window_for(data: &[u8], name: &str) -> MockWindow {
        MockWindow {
            object: Some(Arc::new(Mutex::new(Object::from_buffer(data, name, 0)))),
            ..MockWindow::default()
        }
    }

    #[test]
    fn unknown_binary_file_opens_as_raw_buffer_viewer() {
        let blob: Vec<u8> = [0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0x00, 0x80].repeat(125);
        let plugin = DefaultTypePlugin::create_instance();
        let mut win = window_for(&blob, "unknown.bin");
        plugin.populate_window(&mut win).expect("populate");
        assert_eq!(win.viewers, [ViewerKind::Buffer], "raw BufferViewer only");
        assert_eq!(
            win.panels,
            [(String::from("&Information"), String::from("default.information"), true)]
        );
        assert!(format!("{plugin:?}").contains("object_bound: true"));
    }

    #[test]
    fn text_files_get_a_text_viewer_before_the_buffer_viewer() {
        let plugin = DefaultTypePlugin::create_instance();
        let mut win = window_for(b"hello, world\nsecond line\n", "note.txt");
        plugin.populate_window(&mut win).expect("populate");
        assert_eq!(win.viewers, [ViewerKind::Text, ViewerKind::Buffer]);
        // UTF-16 with a BOM is text too.
        let mut utf16 = vec![0xFF, 0xFE];
        for ch in "unicode text".encode_utf16() {
            utf16.extend_from_slice(&ch.to_le_bytes());
        }
        let mut win = window_for(&utf16, "u16.txt");
        plugin.populate_window(&mut win).expect("populate");
        assert_eq!(win.viewers, [ViewerKind::Text, ViewerKind::Buffer]);
        assert!(DefaultTypePlugin::wants_text_viewer(b"plain"));
        assert!(!DefaultTypePlugin::wants_text_viewer(&[0, 1, 2, 3, 0xFF, 0xFE, 0x00, 0x80]));
    }

    #[test]
    fn always_succeeds_for_any_buffer() {
        let plugin = DefaultTypePlugin::create_instance();
        for data in [&b"x"[..], b"\x00", b"MZ", b"\x7fELF\x02", &[0xFF; 5000]] {
            let mut win = window_for(data, "any");
            plugin.populate_window(&mut win).expect("non-empty buffers always populate");
            assert_eq!(win.viewers.last(), Some(&ViewerKind::Buffer));
            assert_eq!(win.panels.len(), 1);
        }
        // Even an empty object populates (the probe is simply empty).
        let mut win = window_for(b"", "empty");
        plugin.populate_window(&mut win).expect("empty populates too");
        assert_eq!(win.viewers.last(), Some(&ViewerKind::Buffer));
        // The probe is capped at 4096 bytes.
        let big = vec![b'a'; 10_000];
        let object: SharedObject = Arc::new(Mutex::new(Object::from_buffer(&big, "big", 0)));
        assert_eq!(DefaultTypePlugin::probe(&object).len(), TEXT_PROBE_SIZE as usize);
        assert_eq!(DefaultTypePlugin::TEXT_PROBE_SIZE, 4096);
    }

    #[test]
    fn exports_validate_metadata_keys_and_assistant_context() {
        struct Keys(Vec<String>);
        impl KeyRegistry for Keys {
            fn register_key(&mut self, command: &CommandDef) -> bool {
                self.0.push(command.name.clone());
                true
            }
        }
        assert!(DefaultTypePlugin::validate(b"", ""));
        assert!(DefaultTypePlugin::validate(b"anything", ".whatever"));
        assert_eq!(DefaultTypePlugin::metadata(), PluginMetadata::default());
        assert!(DefaultTypePlugin::metadata().pattern.is_empty());
        let mut plugin = DefaultTypePlugin::create_instance();
        assert_eq!(plugin.name(), "GENERIC");
        assert!(plugin.smart_assistant_context("", "").is_err());
        assert!(format!("{plugin:?}").contains("object_bound: false"));
        plugin.run_command("Nothing");
        let mut keys = Keys(Vec::new());
        plugin.register_keys(&mut keys);
        assert!(keys.0.is_empty());
        let mut win = window_for(b"some text", "ctx.txt");
        plugin.populate_window(&mut win).expect("populate");
        let ctx = plugin.smart_assistant_context("p", "d").expect("ctx");
        assert_eq!(ctx["Name"], "ctx.txt");
        assert_eq!(ctx["ContentSize"], 9);
        assert_eq!(ctx.as_object().map(serde_json::Map::len), Some(2));
        assert_eq!(INFORMATION_COLUMNS[0], "n:Field,a:l,w:10");
    }
}
