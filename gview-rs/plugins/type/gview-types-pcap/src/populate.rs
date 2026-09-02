//! The PCAP type plugin: `PopulateWindow` and the `TypeInterface`
//! methods.
//!
//! Spec `06_TYPE_PLUGINS` §PCAP `PopulateWindow` / `SmartAssistant`;
//! C++ `PCAP.cpp` `CreateBufferView` / `CreateContainerView` /
//! `PopulateWindow` / `UpdateSettings`, `PCAPFile.cpp`
//! `GetPropertiesForContainerView` / `GetSmartAssistantContext` /
//! `BeginIteration` / `PopulateItem`, `Panels/Packets.cpp` `Update`.
//!
//! The spec sketches "a `GridViewer` for the packet list"; the C++
//! actually builds (C++ wins):
//!
//! 1. `pcap->Update()` — [`PcapFile::parse_cache`];
//! 2. the **container viewer** `StreamView` (`PCAP_ICON`, seven
//!    stream columns, the `PCAP Version` / `Total packets` / `Total
//!    streams` / `Protocols` properties) whose tree lists the TCP / UDP
//!    streams the `StreamManager` reassembles;
//! 3. the buffer viewer: a `Header` zone (Magenta on `DarkBlue`) and
//!    one `Packet_i` zone per record, `sizeof(PacketHeader) + inclLen`
//!    bytes, alternating `DarkGreen` / `DarkRed` on `DarkBlue`;
//! 4. the `Information` (right) and `Packets` (bottom) panels; the
//!    packet table is [`packet_rows`] — `#`, `Timestamp`, `Seconds`,
//!    `Microseconds`, `Octets Saved`, `Actual Length`, in hex or
//!    decimal like the panel's F2 toggle.
//!
//! The `StreamManager` (Ethernet / IPv4 / IPv6 / TCP / UDP stream
//! reassembly and the HTTP payload parser, `StreamManager.cpp` /
//! `Internal.hpp`) is not ported yet: the `StreamView` tree is empty,
//! `Total streams` is `0` and `Protocols` is empty. The analysis-engine
//! facts (`InitPredicates`, `SendInitialPredicates`) belong to the HDF
//! tasks.

use std::sync::{Mutex, PoisonError};

use appcui::graphics::{CharAttribute, CharFlags, Color};
use gview_core::zones::ZonesList;
use gview_plugin::type_plugin::{
    BufferViewerRequest, ContainerViewerRequest, KeyRegistry, PanelRequest, Pattern, PluginError, PluginMetadata,
    TypePlugin, ViewerRequest, WindowHandle,
};
use gview_view::buffer_viewer::dissasm_dialog::DissasmSettings;
use gview_view::container_viewer::tree::{EnumerateInterface, TreeItemId, TreeNode};
use gview_view::traits::SharedObject;
use serde_json::Value as JsonValue;

use crate::parse::{format_timestamp, PcapError, PcapFile, HEADER_SIZE};
use crate::validate::{validate, MAGIC_IDENTICAL, MAGIC_SWAPPED};

/// `UpdateSettings` `Description`.
pub const DESCRIPTION: &str = "Network Packet capture file format";
/// `UpdateSettings` `Extension`.
pub const EXTENSION: &str = "pcap";
/// `UpdateSettings` `Priority`.
pub const PRIORITY: u32 = 1;
/// `SetName("StreamView")`.
pub const STREAM_VIEW_NAME: &str = "StreamView";
/// `PCAP_ICON` (16×16, `PCAP.cpp:16-31`).
pub const PCAP_ICON: &str = concat!(
    "WWWWWWW.WWWWWWW.",
    "W.....W.W.......",
    "W.....W.W.......",
    "W.....W.W.......",
    "WWWWWWW.W.......",
    "W.......W.......",
    "W.......WWWWWWW.",
    "................",
    "WWWWWWW.WWWWWWW.",
    "W.....W.W.....W.",
    "W.....W.W.....W.",
    "W.....W.W.....W.",
    "WWWWWWW.WWWWWWW.",
    "W.....W.W.......",
    "W.....W.W.......",
    "W.....W.W.......",
);
/// `CreateContainerView` columns.
pub const STREAM_COLUMNS: [&str; 7] = [
    "n:&ID,a:l,w:8",
    "n:&Connection,a:l,w:50",
    "n:&IpProt.,a:c,w:8",
    "n:&Transport,a:c,w:12",
    "n:&Payload,a:r,w:9",
    "n:&AppLayer,a:c,w:10",
    "n:&Summary,a:l,w:50",
];
/// `Panels::Packets` list columns.
pub const PACKET_COLUMNS: [&str; 6] = [
    "n:#,a:r,w:6",
    "n:Timestamp,a:r,w:20",
    "n:Seconds,a:r,w:16",
    "n:Microseconds,a:r,w:16",
    "n:Octets Saved,a:r,w:16",
    "n:Actual Length,a:r,w:16",
];
/// The panels `PopulateWindow` adds, in order: `(caption, id, vertical)`.
pub const PANELS: [(&str, &str, bool); 2] = [
    ("Informa&tion", "pcap.information", true),
    ("&Packets", "pcap.packets", false),
];

fn attr(fore: Color, back: Color) -> CharAttribute {
    CharAttribute::new(fore, back, CharFlags::None)
}

/// `PCAP.cpp` zone colours.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PcapColors {
    /// `Header` zone (Magenta on `DarkBlue`).
    pub header: CharAttribute,
    /// Even packets (`DarkGreenBlue`).
    pub packet_even: CharAttribute,
    /// Odd packets (`DarkRedBlue`).
    pub packet_odd: CharAttribute,
}

impl Default for PcapColors {
    fn default() -> Self {
        Self {
            header: attr(Color::Magenta, Color::DarkBlue),
            packet_even: attr(Color::DarkGreen, Color::DarkBlue),
            packet_odd: attr(Color::DarkRed, Color::DarkBlue),
        }
    }
}

/// The `BufferViewer::Settings` of `CreateBufferView` (`PCAP.cpp:57-75`).
#[must_use]
pub fn buffer_view_request(pcap: &PcapFile, colors: &PcapColors) -> BufferViewerRequest {
    let mut zones = ZonesList::new();
    zones.add_sized(0, HEADER_SIZE as u64, colors.header, "Header");
    for (count, record) in pcap.packets.iter().enumerate() {
        let color = if count % 2 == 0 { colors.packet_even } else { colors.packet_odd };
        zones.add_sized(record.offset, record.header.record_size(), color, format!("Packet_{count}"));
    }
    BufferViewerRequest {
        zones,
        bookmarks: Vec::new(),
        entry_point: None,
        translation_methods: Vec::new(),
        dissasm_settings: DissasmSettings::default(),
        position_to_color: false,
    }
}

/// C++ `GetPropertiesForContainerView`: `(name, value)` rows.
#[must_use]
pub fn container_properties(pcap: &PcapFile) -> Vec<(String, String)> {
    vec![
        (
            String::from("PCAP Version"),
            format!("{}.{}", pcap.header.version_major, pcap.header.version_minor),
        ),
        (String::from("Total packets"), pcap.packet_count().to_string()),
        (String::from("Total streams"), String::from("0")),
        (String::from("Protocols"), String::new()),
    ]
}

/// The `ContainerViewer::Settings` of `CreateContainerView`
/// (`PCAP.cpp:77-104`).
#[must_use]
pub fn container_view_request(pcap: &PcapFile) -> ContainerViewerRequest {
    ContainerViewerRequest {
        icon: Some(String::from(PCAP_ICON)),
        columns: STREAM_COLUMNS.iter().map(|c| (*c).to_owned()).collect(),
        properties: container_properties(pcap),
        ..ContainerViewerRequest::default()
    }
}

/// `Panels::Packets::GetValue`: decimal with thousands separators
/// (`Base == 10`) or `0x` hex.
#[must_use]
pub fn format_value(value: u64, hex: bool) -> String {
    if hex {
        return format!("{value:#x}");
    }
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, ch) in digits.chars().enumerate() {
        let remaining = digits.len().saturating_sub(i);
        if i > 0 && remaining % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// `Panels::Packets::Update`: one row per record with the six columns
/// (`hex` mirrors the panel's F2 base toggle; the panel starts in hex).
#[must_use]
pub fn packet_rows(pcap: &PcapFile, hex: bool) -> Vec<Vec<String>> {
    pcap.packets
        .iter()
        .enumerate()
        .map(|(i, record)| {
            let h = record.header;
            vec![
                format_value(i as u64, hex),
                format_timestamp(h.timestamp_seconds()),
                format_value(u64::from(h.ts_sec), hex),
                format_value(u64::from(h.ts_usec), hex),
                format_value(u64::from(h.incl_len), hex),
                format_value(u64::from(h.orig_len), hex),
            ]
        })
        .collect()
}

/// The PCAP `TypeInterface` (C++ `PCAP::PCAPFile` as a type instance).
pub struct PcapPlugin {
    colors: PcapColors,
    state: Mutex<Option<PcapFile>>,
    object: Mutex<Option<SharedObject>>,
    last_command: Mutex<Option<String>>,
}

impl Default for PcapPlugin {
    fn default() -> Self {
        Self {
            colors: PcapColors::default(),
            state: Mutex::new(None),
            object: Mutex::new(None),
            last_command: Mutex::new(None),
        }
    }
}

impl core::fmt::Debug for PcapPlugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let packets = self
            .state
            .lock()
            .ok()
            .and_then(|s| s.as_ref().map(PcapFile::packet_count));
        f.debug_struct("PcapPlugin").field("packets", &packets).finish_non_exhaustive()
    }
}

impl PcapPlugin {
    /// The parsed capture after `PopulateWindow`.
    #[must_use]
    pub fn file(&self) -> Option<PcapFile> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The last `RunCommand` name (the C++ `RunCommand` is empty).
    #[must_use]
    pub fn last_command(&self) -> Option<String> {
        self.last_command.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// `Panels::Packets` rows for the current capture.
    #[must_use]
    pub fn packet_rows(&self, hex: bool) -> Vec<Vec<String>> {
        self.file().map(|p| packet_rows(&p, hex)).unwrap_or_default()
    }
}

impl EnumerateInterface for PcapPlugin {
    /// C++ `BeginIteration`: nothing until the `StreamManager` is
    /// ported (`streamManager.empty()`).
    fn begin_iteration(&mut self, _path: &str, _parent: TreeItemId) -> bool {
        false
    }

    /// C++ `PopulateItem`: never reached without streams.
    fn populate_item(&mut self, _child: &mut TreeNode) -> bool {
        false
    }
}

impl TypePlugin for PcapPlugin {
    fn name(&self) -> &'static str {
        "PCAP"
    }

    fn validate(buf: &[u8], extension: &str) -> bool {
        validate(buf, extension)
    }

    fn create_instance() -> Box<Self> {
        Box::default()
    }

    /// C++ `UpdateSettings` (`PCAP.cpp:222-228`).
    fn metadata() -> PluginMetadata {
        PluginMetadata {
            pattern: vec![
                Pattern::Magic(MAGIC_SWAPPED.to_le_bytes().to_vec()),
                Pattern::Magic(MAGIC_IDENTICAL.to_le_bytes().to_vec()),
            ],
            priority: PRIORITY,
            description: String::from(DESCRIPTION),
            extensions: vec![String::from(EXTENSION)],
            commands: Vec::new(),
            opcodes_mask: None,
        }
    }

    /// C++ `PopulateWindow` (`PCAP.cpp:184-220`): container viewer,
    /// buffer viewer, `Information` and `Packets` panels.
    fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
        let object = win.object();
        let pcap = {
            let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            PcapFile::parse_cache(guard.data_mut()).map_err(|e: PcapError| PluginError::Window(e.to_string()))?
        };
        *self.object.lock().unwrap_or_else(PoisonError::into_inner) = Some(SharedObject::clone(&object));
        win.create_viewer(ViewerRequest::container(container_view_request(&pcap)).named(STREAM_VIEW_NAME))?;
        win.create_viewer(ViewerRequest::buffer(buffer_view_request(&pcap, &self.colors)))?;
        for (caption, id, vertical) in PANELS {
            win.add_panel(
                PanelRequest {
                    caption: String::from(caption),
                    panel_id: String::from(id),
                },
                vertical,
            );
        }
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = Some(pcap);
        Ok(())
    }

    fn run_command(&mut self, command: &str) {
        *self.last_command.lock().unwrap_or_else(PoisonError::into_inner) = Some(command.to_owned());
    }

    /// C++ `UpdateKeys`: nothing registered.
    fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}

    /// C++ `GetSmartAssistantContext`: `Name`, `ContentSize`,
    /// `TotalPackets`, `TotalStreams`.
    fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
        let pcap = self
            .file()
            .ok_or_else(|| PluginError::Assistant(String::from("PopulateWindow was not called")))?;
        let bound = self
            .object
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(SharedObject::clone)
            .ok_or_else(|| PluginError::Assistant(String::from("no object bound")))?;
        let (name, size) = {
            let object = bound.lock().unwrap_or_else(PoisonError::into_inner);
            (object.name().to_owned(), object.data().size())
        };
        Ok(serde_json::json!({
            "Name": name,
            "ContentSize": size,
            "TotalPackets": pcap.packet_count(),
            "TotalStreams": 0,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::parse::tests::{global_header, packet, sample};
    use gview_core::object::Object;
    use gview_plugin::type_plugin::ViewerKind;
    use gview_view::container_viewer::tree::ContainerTree;
    use std::sync::{Arc, Mutex as StdMutex};

    #[derive(Default)]
    struct MockWindow {
        object: Option<SharedObject>,
        viewers: Vec<ViewerRequest>,
        panels: Vec<(String, bool)>,
    }

    impl WindowHandle for MockWindow {
        fn object(&self) -> SharedObject {
            self.object
                .clone()
                .unwrap_or_else(|| Arc::new(StdMutex::new(Object::from_buffer(b"", "x", 0))))
        }
        fn add_panel(&mut self, panel: PanelRequest, vertical: bool) -> bool {
            self.panels.push((panel.caption, vertical));
            true
        }
        fn create_viewer(&mut self, request: ViewerRequest) -> Result<u32, PluginError> {
            self.viewers.push(request);
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

    fn window_for(image: &[u8], name: &str) -> MockWindow {
        MockWindow {
            object: Some(Arc::new(StdMutex::new(Object::from_buffer(image, name, 0)))),
            ..MockWindow::default()
        }
    }

    fn zones(request: &BufferViewerRequest) -> Vec<(String, u64, u64)> {
        (0..request.zones.count())
            .filter_map(|i| request.zones.zone(i).map(|z| (z.name.clone(), z.low, z.high)))
            .collect()
    }

    #[test]
    fn populate_creates_stream_view_buffer_zones_and_panels() {
        let image = sample();
        let plugin = PcapPlugin::create_instance();
        let mut win = window_for(&image, "cap.pcap");
        plugin.populate_window(&mut win).expect("populate");

        assert_eq!(win.viewers.len(), 2);
        assert_eq!(win.viewers[0].kind, ViewerKind::Container);
        assert_eq!(win.viewers[0].custom_name.as_deref(), Some("StreamView"));
        let container = win.viewers[0].container.as_ref().expect("container");
        assert_eq!(container.icon.as_deref().map(str::len), Some(256));
        assert_eq!(container.columns.len(), 7);
        assert_eq!(container.columns[1], "n:&Connection,a:l,w:50");
        assert_eq!(
            container.properties,
            [
                (String::from("PCAP Version"), String::from("2.4")),
                (String::from("Total packets"), String::from("3")),
                (String::from("Total streams"), String::from("0")),
                (String::from("Protocols"), String::new()),
            ]
        );
        assert_eq!(win.viewers[1].kind, ViewerKind::Buffer);
        let buffer = win.viewers[1].buffer.as_ref().expect("buffer");
        let z = zones(buffer);
        assert_eq!(z[0], (String::from("Header"), 0, 23));
        assert_eq!(z[1], (String::from("Packet_0"), 24, 24 + 76 - 1));
        assert_eq!(z[2], (String::from("Packet_1"), 100, 100 + 58 - 1));
        assert_eq!(z[3], (String::from("Packet_2"), 158, 158 + 30 - 1));
        assert_eq!(z.len(), 4);
        let colors = PcapColors::default();
        assert_eq!(buffer.zones.zone(0).map(|zz| zz.color), Some(colors.header));
        assert_eq!(buffer.zones.zone(1).map(|zz| zz.color), Some(colors.packet_even));
        assert_eq!(buffer.zones.zone(2).map(|zz| zz.color), Some(colors.packet_odd));
        assert_eq!(buffer.zones.zone(3).map(|zz| zz.color), Some(colors.packet_even));
        assert!(!buffer.position_to_color);
        assert_eq!(buffer.entry_point, None);
        assert_eq!(win.panels, [(String::from("Informa&tion"), true), (String::from("&Packets"), false)]);
        assert_eq!(plugin.file().map(|p| p.packet_count()), Some(3));
        assert!(format!("{plugin:?}").contains("packets: Some(3)"));
    }

    #[test]
    fn stream_view_is_empty_until_the_stream_manager_lands() {
        let image = sample();
        let mut plugin = PcapPlugin::create_instance();
        let mut win = window_for(&image, "cap.pcap");
        plugin.populate_window(&mut win).expect("populate");
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        assert!(tree.populate_item(root, &mut *plugin, &mut |_| false));
        assert!(tree.children(root).is_empty());
        let mut node = TreeNode::default();
        assert!(!plugin.populate_item(&mut node));
    }

    #[test]
    fn packet_rows_match_the_packets_panel() {
        let image = sample();
        let plugin = PcapPlugin::create_instance();
        assert!(plugin.packet_rows(true).is_empty());
        let mut win = window_for(&image, "cap.pcap");
        plugin.populate_window(&mut win).expect("populate");
        let hex = plugin.packet_rows(true);
        assert_eq!(hex.len(), 3);
        assert_eq!(hex[0], ["0x0", "2023-11-14 22:13:20", "0x6553f100", "0x5", "0x3c", "0x3c"]);
        assert_eq!(hex[1][0], "0x1");
        assert_eq!(hex[1][1], "2023-11-14 22:13:21");
        assert_eq!(hex[1][3], "0xf423f");
        let dec = plugin.packet_rows(false);
        assert_eq!(dec[0], ["0", "2023-11-14 22:13:20", "1,700,000,000", "5", "60", "60"]);
        assert_eq!(dec[1][3], "999,999");
        assert_eq!(dec[2][4], "14");
        assert_eq!(format_value(0, false), "0");
        assert_eq!(format_value(999, false), "999");
        assert_eq!(format_value(1000, false), "1,000");
        assert_eq!(format_value(1_234_567, false), "1,234,567");
        assert_eq!(format_value(255, true), "0xff");
        assert_eq!(PACKET_COLUMNS[5], "n:Actual Length,a:r,w:16");
    }

    #[test]
    fn header_only_or_garbage_captures_fail_populate() {
        let plugin = PcapPlugin::create_instance();
        let mut win = window_for(&global_header(false, 1, 1), "empty.pcap");
        let err = plugin.populate_window(&mut win).expect_err("no data");
        assert!(matches!(err, PluginError::Window(_)));
        assert!(win.viewers.is_empty());
        assert!(plugin.file().is_none());
        let mut win = window_for(b"\xD4\xC3\xB2\xA1\x02\x00", "short.pcap");
        assert!(plugin.populate_window(&mut win).is_err());
        // A swapped capture with one record populates normally.
        let mut image = global_header(true, 1, 0x40);
        image.extend(packet(3, 4, 5, 5, &[0; 5]));
        let mut win = window_for(&image, "be.pcap");
        plugin.populate_window(&mut win).expect("populate");
        assert_eq!(plugin.file().map(|p| p.swapped), Some(true));
        let z = zones(win.viewers[1].buffer.as_ref().expect("buffer"));
        assert_eq!(z[1], (String::from("Packet_0"), 24, 24 + 21 - 1));
    }

    #[test]
    fn metadata_keys_and_assistant_context() {
        struct Keys(Vec<String>);
        impl KeyRegistry for Keys {
            fn register_key(&mut self, command: &gview_plugin::type_plugin::CommandDef) -> bool {
                self.0.push(command.name.clone());
                true
            }
        }
        let meta = PcapPlugin::metadata();
        let inis: Vec<String> = meta.pattern.iter().map(Pattern::to_ini_string).collect();
        assert_eq!(inis, ["magic:A1 B2 C3 D4", "magic:D4 C3 B2 A1"]);
        assert_eq!(meta.extensions, ["pcap"]);
        assert_eq!(meta.priority, 1);
        assert_eq!(meta.description, DESCRIPTION);
        assert!(meta.commands.is_empty());
        assert_eq!(meta.opcodes_mask, None);
        assert!(PcapPlugin::validate(&sample(), ".pcap"));

        let mut plugin = PcapPlugin::create_instance();
        assert_eq!(plugin.name(), "PCAP");
        assert!(plugin.smart_assistant_context("", "").is_err());
        plugin.run_command("Nothing");
        assert_eq!(plugin.last_command().as_deref(), Some("Nothing"));
        let mut keys = Keys(Vec::new());
        plugin.register_keys(&mut keys);
        assert!(keys.0.is_empty());

        let image = sample();
        let mut win = window_for(&image, "ctx.pcap");
        plugin.populate_window(&mut win).expect("populate");
        let ctx = plugin.smart_assistant_context("what", "what").expect("ctx");
        assert_eq!(ctx["Name"], "ctx.pcap");
        assert_eq!(ctx["ContentSize"], image.len() as u64);
        assert_eq!(ctx["TotalPackets"], 3);
        assert_eq!(ctx["TotalStreams"], 0);
        assert_eq!(PCAP_ICON.len(), 256);
        assert_eq!(STREAM_VIEW_NAME, "StreamView");
        assert_eq!(PANELS[1].1, "pcap.packets");
    }
}
