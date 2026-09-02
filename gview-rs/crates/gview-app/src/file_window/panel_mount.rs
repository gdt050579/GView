//! Panel mounting: turning a plugin's [`PanelContent`] into the
//! `AppCUI` `ListView` that fills one panel tab page
//! (spec `00_APP §5.2 (2)`, `§5.4`; design decision `§0.3 D3`).
//!
//! C++ anchor: `GViewCore/src/App/FileWindow.cpp` `AddPanel`
//! (L107-123) plus the panels themselves — `Types/PE/src/Panels/Information.cpp`
//! builds `Factory::ListView::Create(this, …, { "n:Field,w:30", "n:Value,w:100" })`
//! inside a `TabPage` subclass. A Rust plugin cannot build controls
//! (`TypePlugin: Send + Sync`, every `AppCUI` control is `!Send`), so
//! it returns the *content* and this module renders it:
//!
//! | [`PanelContent`] | Control |
//! |------------------|---------|
//! | `KeyValue(rows)` | `ListView<KeyValueRow>` with the C++ `Field` / `Value` columns |
//! | `Table { columns, rows }` | `ListView<TableRow>` with the declared columns |
//! | `None` | the [`InformationFallback`] — `Name` / `Path` / `Size` / `Type` |
//!
//! Every row is built **once, at mount time**; `ListItem::render_method`
//! then hands the `ListView` a borrowed `&str` per cell, so painting a
//! panel allocates nothing (`§6.3`).

use appcui::prelude::*;

use gview_core::object::Object;
use gview_plugin::panel::{Align, ColumnDef, PanelContent};

/// C++ `Information` panel column captions and widths
/// (`Information.cpp`: `"n:Field,w:30"`, `"n:Value,w:100"`).
pub const FIELD_COLUMN: (&str, u8) = ("Field", 30);
/// Value column of the same panel.
pub const VALUE_COLUMN: (&str, u8) = ("Value", 100);
/// Caption used for a table column a plugin left unnamed.
pub const UNNAMED_COLUMN: &str = "?";

/// One `Field` / `Value` row of a [`PanelContent::KeyValue`] panel.
pub struct KeyValueRow {
    field: String,
    value: String,
}

impl KeyValueRow {
    /// A row from a `(field, value)` pair.
    #[must_use]
    pub const fn new(field: String, value: String) -> Self {
        Self { field, value }
    }

    /// The `Field` cell.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The `Value` cell.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl ListItem for KeyValueRow {
    fn columns_count() -> u16 {
        2
    }

    fn column(index: u16) -> Column {
        let (caption, width) = if index == 0 { FIELD_COLUMN } else { VALUE_COLUMN };
        Column::new(caption, width, TextAlignment::Left)
    }

    fn render_method(&self, column_index: u16) -> Option<RenderMethod<'_>> {
        match column_index {
            0 => Some(RenderMethod::Text(&self.field)),
            1 => Some(RenderMethod::Text(&self.value)),
            _ => None,
        }
    }

    fn matches(&self, text: &str) -> bool {
        self.field.contains(text) || self.value.contains(text)
    }
}

/// One row of a [`PanelContent::Table`] panel.
///
/// The columns are plugin-declared, so they are added to the
/// `ListView` at mount time rather than through
/// [`ListItem::columns_count`]; a row shorter than the header renders
/// its missing cells empty and extra cells are ignored, so a truncated
/// parse never panics.
pub struct TableRow {
    cells: Vec<String>,
}

impl TableRow {
    /// A row from its cells, in column order.
    #[must_use]
    pub const fn new(cells: Vec<String>) -> Self {
        Self { cells }
    }

    /// Cell `index`, or `""` when the row is shorter than the header.
    #[must_use]
    pub fn cell(&self, index: usize) -> &str {
        self.cells.get(index).map_or("", String::as_str)
    }

    /// Number of cells this row carries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.cells.len()
    }

    /// `true` when the row has no cells.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

impl ListItem for TableRow {
    /// The header is built from the plugin's `ColumnDef`s at mount
    /// time (`ListView::add_column`), not from the item type.
    fn columns_count() -> u16 {
        0
    }

    fn render_method(&self, column_index: u16) -> Option<RenderMethod<'_>> {
        self.cells.get(column_index as usize).map(|cell| RenderMethod::Text(cell))
    }

    fn matches(&self, text: &str) -> bool {
        self.cells.iter().any(|cell| cell.contains(text))
    }
}

/// The generic `Information` panel every window can show
/// (`00_APP §5.4.2`): what the shell knows about the object without
/// asking the plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InformationFallback {
    /// `Object::GetName()`.
    pub name: String,
    /// The object's path (empty for a buffer object).
    pub path: String,
    /// `DataCache::GetSize()`.
    pub size: u64,
    /// The type plugin's name (`GENERIC` for the default fallback).
    pub type_name: String,
}

impl InformationFallback {
    /// Reads the fallback rows off the window's object and plugin.
    #[must_use]
    pub fn new(object: &Object, type_name: &str) -> Self {
        Self {
            name: object.name().to_owned(),
            path: object.path().display().to_string(),
            size: object.data().size(),
            type_name: type_name.to_owned(),
        }
    }

    /// The rows as a [`PanelContent`], in the C++ `Information` order.
    ///
    /// `Size` uses the `NumericFormatter` decimal grouping every C++
    /// `Information` panel applies (`"%s bytes"`).
    #[must_use]
    pub fn content(&self) -> PanelContent {
        PanelContent::KeyValue(vec![
            (String::from("Name"), self.name.clone()),
            (String::from("Path"), self.path.clone()),
            (
                String::from("Size"),
                format!("{} bytes", gview_plugin::panel::fmt::dec(self.size)),
            ),
            (String::from("Type"), self.type_name.clone()),
        ])
    }
}

/// A panel control mounted on one tab page.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MountedPanel {
    /// Two-column `Field` / `Value` list (C++ `Information`).
    KeyValue(Handle<ListView<KeyValueRow>>),
    /// N-column table (C++ `Sections`, `Imports`, …).
    Table(Handle<ListView<TableRow>>),
}

impl MountedPanel {
    /// `true` when `handle` addresses this page's control.
    #[must_use]
    pub fn matches<T>(self, handle: Handle<T>) -> bool {
        match self {
            Self::KeyValue(h) => h == handle,
            Self::Table(h) => h == handle,
        }
    }

    /// Shape of the mounted panel, for diagnostics and tests.
    #[must_use]
    pub const fn kind_name(self) -> &'static str {
        match self {
            Self::KeyValue(_) => "KeyValue",
            Self::Table(_) => "Table",
        }
    }
}

/// Mounts the panel content for tab page `page`
/// (C++ `FileWindow::AddPanel` + the plugin's `TabPage` subclass).
///
/// `content` is what `TypePlugin::panel_content(panel_id)` returned;
/// `None` mounts `fallback` so a plugin that implements no panel still
/// shows the object's identity (`00_APP §5.4.2`).
pub fn mount_panel(
    tab: &mut Tab,
    page: u32,
    content: Option<PanelContent>,
    fallback: &InformationFallback,
) -> MountedPanel {
    match content.unwrap_or_else(|| fallback.content()) {
        PanelContent::KeyValue(rows) => {
            let mut list: ListView<KeyValueRow> = ListView::with_capacity(
                rows.len().max(1),
                layout!("d:f"),
                listview::Flags::ScrollBars | listview::Flags::SearchBar,
            );
            for (field, value) in rows {
                list.add(KeyValueRow::new(field, value));
            }
            MountedPanel::KeyValue(tab.add(page, list))
        }
        PanelContent::Table { columns, rows } => {
            let mut list: ListView<TableRow> = ListView::with_capacity(
                rows.len().max(1),
                layout!("d:f"),
                listview::Flags::ScrollBars | listview::Flags::SearchBar,
            );
            for column in &columns {
                list.add_column(to_column(column));
            }
            for cells in rows {
                list.add(TableRow::new(cells));
            }
            MountedPanel::Table(tab.add(page, list))
        }
    }
}

/// `ColumnDef` → `AppCUI` `Column` (the Rust form of the C++
/// `"n:<caption>,a:<align>,w:<width>"` layout string).
///
/// `Column::new` takes a `u8` width, so a plugin asking for more than
/// 255 cells is clamped rather than truncated by a cast; an empty
/// caption becomes [`UNNAMED_COLUMN`] so the header stays clickable.
fn to_column(def: &ColumnDef) -> Column {
    let caption = if def.caption.is_empty() {
        UNNAMED_COLUMN
    } else {
        def.caption.as_str()
    };
    let width = u8::try_from(def.width).unwrap_or(u8::MAX);
    Column::new(caption, width, to_alignment(def.align))
}

/// `Align` → `AppCUI` `TextAlignment` (C++ `a:l` / `a:c` / `a:r`).
const fn to_alignment(align: Align) -> TextAlignment {
    match align {
        Align::Left => TextAlignment::Left,
        Align::Center => TextAlignment::Center,
        Align::Right => TextAlignment::Right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_window::events::CommandAction;
    use crate::file_window::{FileWindow, CURSOR_INFO_CAPTION};
    use crate::file_window::layout::CMD_SHOW_HORIZONTAL_PANEL;
    use crate::instance::window_lifecycle::{CancelSelector, Instance, OpenMethod};
    use gview_core::constants::DEFAULT_CACHE_SIZE;
    use gview_plugin::generic_plugin::GenericPluginRegistry;
    use gview_plugin::type_plugin::{
        KeyRegistry, PanelRequest, Pattern, PluginError, PluginMetadata, TypePlugin, TypePluginRegistry,
        ViewerKind, ViewerRequest, WindowHandle,
    };
    use serde_json::Value as JsonValue;

    fn fallback() -> InformationFallback {
        InformationFallback::new(&Object::from_buffer(&[0_u8; 1024], "sample.exe", 0), "PE")
    }

    #[test]
    fn the_fallback_shows_name_path_size_and_type() {
        // A file object: the path row carries the real path.
        let dir = std::env::temp_dir().join("gview_panel_mount_fallback");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("sample.exe");
        std::fs::write(&path, [0_u8; 2048]).expect("fixture");
        let object = Object::open_file(&path, DEFAULT_CACHE_SIZE).expect("open");
        let info = InformationFallback::new(&object, "PE");
        let PanelContent::KeyValue(rows) = info.content() else {
            panic!("the fallback is a key/value panel");
        };
        let fields: Vec<&str> = rows.iter().map(|(field, _)| field.as_str()).collect();
        assert_eq!(fields, ["Name", "Path", "Size", "Type"]);
        assert_eq!(rows[0].1, "sample.exe");
        assert_eq!(rows[1].1, path.display().to_string());
        // C++ `NumericFormatter` groups the decimal size in threes.
        assert_eq!(rows[2].1, "2,048 bytes");
        assert_eq!(rows[3].1, "PE");
        let _ = std::fs::remove_file(&path);

        // A buffer object has no path: the row is empty, never absent.
        let buffer = Object::from_buffer(&[1_u8, 2, 3], "blob", 0);
        let PanelContent::KeyValue(rows) = InformationFallback::new(&buffer, "GENERIC").content() else {
            panic!("the fallback is a key/value panel");
        };
        assert_eq!(rows[1].1, "");
        assert_eq!(rows[2].1, "3 bytes");
        assert_eq!(rows[3].1, "GENERIC");
    }

    #[test]
    fn key_value_rows_expose_the_cpp_columns() {
        assert_eq!(KeyValueRow::columns_count(), 2);
        assert_eq!(KeyValueRow::column(0).name(), "Field");
        assert_eq!(KeyValueRow::column(0).width(), 30);
        assert_eq!(KeyValueRow::column(1).name(), "Value");
        assert_eq!(KeyValueRow::column(1).width(), 100);

        let row = KeyValueRow::new(String::from("File"), String::from("sample.exe"));
        assert_eq!(row.field(), "File");
        assert_eq!(row.value(), "sample.exe");
        assert!(matches!(row.render_method(0), Some(RenderMethod::Text("File"))));
        assert!(matches!(row.render_method(1), Some(RenderMethod::Text("sample.exe"))));
        assert!(row.render_method(2).is_none());
        assert!(row.matches("sample"));
        assert!(!row.matches("elf"));
    }

    #[test]
    fn table_rows_tolerate_short_and_long_rows() {
        // The header is declared at mount time, not by the item type.
        assert_eq!(TableRow::columns_count(), 0);

        let row = TableRow::new(vec![String::from(".text"), String::from("0x1000")]);
        assert_eq!(row.len(), 2);
        assert!(!row.is_empty());
        assert_eq!(row.cell(0), ".text");
        assert_eq!(row.cell(9), "", "a missing cell renders empty");
        assert!(matches!(row.render_method(1), Some(RenderMethod::Text("0x1000"))));
        assert!(row.render_method(7).is_none());
        assert!(row.matches("text"));

        let empty = TableRow::new(Vec::new());
        assert!(empty.is_empty());
        assert!(empty.render_method(0).is_none());
    }

    #[test]
    fn column_definitions_map_to_appcui_columns() {
        let left = to_column(&ColumnDef::new("Name", 20));
        assert_eq!(left.name(), "Name");
        assert_eq!(left.width(), 20);
        assert_eq!(left.alignment(), TextAlignment::Left);

        let right = to_column(&ColumnDef::aligned("FilePoz", 12, Align::Right));
        assert_eq!(right.alignment(), TextAlignment::Right);
        let center = to_column(&ColumnDef::aligned("Flags", 8, Align::Center));
        assert_eq!(center.alignment(), TextAlignment::Center);

        // Hostile widths and captions are clamped, never truncated by a
        // cast or left blank.
        let wide = to_column(&ColumnDef::new("", 4_000));
        assert_eq!(wide.name(), UNNAMED_COLUMN);
        assert_eq!(wide.width(), u8::MAX);
    }

    /// A plugin with one `Information` panel it fills and one it does
    /// not, so the window mounts both the content and the fallback.
    struct MockPe;

    impl TypePlugin for MockPe {
        fn name(&self) -> &'static str {
            "PE"
        }
        fn validate(buf: &[u8], _extension: &str) -> bool {
            buf.starts_with(b"MZ")
        }
        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }
        fn metadata() -> PluginMetadata {
            PluginMetadata {
                pattern: vec![Pattern::Magic(vec![0x4D, 0x5A])],
                ..PluginMetadata::default()
            }
        }
        fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            win.add_panel(
                PanelRequest {
                    caption: String::from("&Information"),
                    panel_id: String::from("pe.information"),
                },
                true,
            );
            win.add_panel(
                PanelRequest {
                    caption: String::from("&Sections"),
                    panel_id: String::from("pe.sections"),
                },
                false,
            );
            win.add_panel(
                PanelRequest {
                    caption: String::from("&Notes"),
                    panel_id: String::from("pe.notes"),
                },
                false,
            );
            win.create_viewer(ViewerRequest::new(ViewerKind::Buffer))?;
            Ok(())
        }
        fn run_command(&mut self, _command: &str) {}
        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
        fn smart_assistant_context(&self, _p: &str, _d: &str) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }
        fn panel_content(&self, panel_id: &str) -> Option<PanelContent> {
            match panel_id {
                "pe.information" => Some(PanelContent::key_value([
                    ("File", "sample.exe"),
                    ("Machine", "x86"),
                ])),
                "pe.sections" => Some(PanelContent::Table {
                    columns: vec![ColumnDef::new("Name", 12), ColumnDef::aligned("Size", 10, Align::Right)],
                    rows: vec![vec![String::from(".text"), String::from("0x1000")]],
                }),
                // `pe.notes` is declared but has no content: the shell
                // falls back to the generic Information panel.
                _ => None,
            }
        }
    }

    /// The window mounts every declared panel and routes the bottom-bar
    /// commands (`00_APP §5.2 (2)`, `§5.4.2`).
    #[test]
    fn the_window_mounts_plugin_panels_and_switches_bottom_pages() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(100, 40, "Paint.Enable(false)\nPaint('panels')")
            .build()
            .expect("debug app");

        let mut types = TypePluginRegistry::new();
        types.register_type::<MockPe>("PE").expect("pe");
        let mut inst = Instance::new(types, GenericPluginRegistry::new(), DEFAULT_CACHE_SIZE);
        let index = inst
            .add_buffer_window(b"MZ\x90\x00", "sample.exe", OpenMethod::BestMatch, "", &mut CancelSelector)
            .expect("open");
        let model = inst.take_window(index).expect("model");
        let mut win = FileWindow::new(model, Vec::new(), Vec::new(), false);

        // One sidebar panel, two bottom panels after cursor information.
        assert_eq!(win.vertical_panels().len(), 1);
        assert_eq!(win.horizontal_panels().len(), 2);
        assert_eq!(win.vertical_panels()[0].kind_name(), "KeyValue");
        assert_eq!(win.horizontal_panels()[0].kind_name(), "Table");
        // `pe.notes` returned `None`: the generic Information fallback.
        assert_eq!(win.horizontal_panels()[1].kind_name(), "KeyValue");

        let MountedPanel::KeyValue(information) = win.vertical_panels()[0] else {
            panic!("the Information panel is a key/value list");
        };
        {
            let list = win.control(information).expect("information list");
            assert_eq!(list.items_count(), 2);
            assert_eq!(list.item(0).map(KeyValueRow::field), Some("File"));
            assert_eq!(list.item(1).map(KeyValueRow::value), Some("x86"));
            assert_eq!(list.column(0).map(Column::name), Some("Field"));
            assert_eq!(list.column(1).map(Column::name), Some("Value"));
        }

        let MountedPanel::Table(sections) = win.horizontal_panels()[0] else {
            panic!("the Sections panel is a table");
        };
        {
            let list = win.control(sections).expect("sections list");
            assert_eq!(list.items_count(), 1);
            assert_eq!(list.column(1).map(Column::alignment), Some(TextAlignment::Right));
        }

        let MountedPanel::KeyValue(notes) = win.horizontal_panels()[1] else {
            panic!("the fallback is a key/value list");
        };
        {
            let list = win.control(notes).expect("fallback list");
            let fields: Vec<&str> = (0..list.items_count())
                .filter_map(|i| list.item(i).map(KeyValueRow::field))
                .collect();
            assert_eq!(fields, ["Name", "Path", "Size", "Type"]);
        }

        // `&Information` keeps `I` as its Alt hot key: the caption
        // parser consumed the `&` and `Tab::OnKeyPressed` matches
        // Alt+I against the page (`Caption::hotkey`).
        let vertical_tab = win.layout().vertical_panels;
        {
            let tab = win.control_mut(vertical_tab).expect("vertical panels tab");
            assert_eq!(tab.tab_caption(0), Some("Information"));
            assert!(matches!(
                OnKeyPressed::on_key_pressed(tab, Key::new(KeyCode::I, KeyModifier::Alt), '\0'),
                EventProcessStatus::Processed
            ));
            // No page owns Alt+Z.
            assert!(matches!(
                OnKeyPressed::on_key_pressed(tab, Key::new(KeyCode::Z, KeyModifier::Alt), '\0'),
                EventProcessStatus::Ignored
            ));
        }

        // Bottom pages: cursor information first, then the plugin panels
        // in `AddPanel` order.
        let horizontal_tab = win.layout().horizontal_panels;
        {
            let tab = win.control(horizontal_tab).expect("horizontal panels tab");
            assert_eq!(tab.tab_caption(0), Some(CURSOR_INFO_CAPTION));
            assert_eq!(tab.tab_caption(1), Some("Sections"));
            assert_eq!(tab.tab_caption(2), Some("Notes"));
        }

        // `HPanel1` switches to the first plugin panel; the dock records
        // it and un-checks the cursor-information bar item.
        assert_eq!(
            win.on_command_id(CMD_SHOW_HORIZONTAL_PANEL + 1),
            CommandAction::ShowHorizontalPanel(1)
        );
        {
            let model = win.model();
            let guard = model.lock().expect("model");
            assert_eq!(guard.panels().current_horizontal(), 1);
            assert!(!guard.panels().cursor_info_checked());
            drop(guard);
        }
        // Cursor information is page 0 and stays reachable.
        assert!(win.show_horizontal_panel(0));
        assert!(win.model().lock().expect("model").panels().cursor_info_checked());
        // There is no page 3.
        assert!(!win.show_horizontal_panel(3));

        app.add_window(win);
        app.run();
    }

    #[test]
    fn both_shapes_and_the_fallback_mount_a_list_view() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(80, 25, "Paint.Enable(false)\nPaint('panels')")
            .build()
            .expect("debug app");
        let mut win = Window::new("panels", layout!("d:f"), window::Flags::None);
        let tab_handle = win.add(Tab::new(layout!("d:f"), tab::Flags::None));
        let info = fallback();

        let (key_value, table, missing) = {
            let tab = win.control_mut(tab_handle).expect("tab");

            let page = tab.add_tab("&Information");
            let key_value = mount_panel(
                tab,
                page,
                Some(PanelContent::key_value([("File", "sample.exe"), ("Size", "1,024 bytes")])),
                &info,
            );

            let page = tab.add_tab("&Sections");
            let table = mount_panel(
                tab,
                page,
                Some(PanelContent::Table {
                    columns: vec![ColumnDef::new("Name", 12), ColumnDef::aligned("Size", 10, Align::Right)],
                    rows: vec![
                        vec![String::from(".text"), String::from("0x1000")],
                        vec![String::from(".data")],
                    ],
                }),
                &info,
            );

            // A plugin with no content for this id: the fallback.
            let page = tab.add_tab("&Other");
            let missing = mount_panel(tab, page, None, &info);
            (key_value, table, missing)
        };

        assert_eq!(key_value.kind_name(), "KeyValue");
        assert_eq!(table.kind_name(), "Table");
        assert_eq!(missing.kind_name(), "KeyValue");
        assert!(!key_value.matches(Handle::<()>::None));

        // The `&` hot-key marker is consumed by the caption parser.
        {
            let tab = win.control(tab_handle).expect("tab");
            assert_eq!(tab.tab_caption(0), Some("Information"));
            assert_eq!(tab.tab_caption(1), Some("Sections"));
        }

        // Rows and columns landed in the controls.
        let MountedPanel::KeyValue(handle) = key_value else {
            panic!("key/value panel");
        };
        {
            let list = win.control(handle).expect("key/value list");
            assert_eq!(list.items_count(), 2);
            assert_eq!(list.item(0).map(KeyValueRow::field), Some("File"));
            assert_eq!(list.item(1).map(KeyValueRow::value), Some("1,024 bytes"));
            assert_eq!(list.column(0).map(Column::name), Some("Field"));
            assert_eq!(list.column(1).map(Column::name), Some("Value"));
        }

        let MountedPanel::Table(handle) = table else {
            panic!("table panel");
        };
        {
            let list = win.control(handle).expect("table list");
            assert_eq!(list.items_count(), 2);
            assert_eq!(list.column(0).map(Column::name), Some("Name"));
            assert_eq!(list.column(1).map(Column::alignment), Some(TextAlignment::Right));
            // The short row renders its missing cell as empty.
            assert_eq!(list.item(1).map(|row| row.cell(1)), Some(""));
        }

        let MountedPanel::KeyValue(handle) = missing else {
            panic!("fallback panel");
        };
        {
            let list = win.control(handle).expect("fallback list");
            assert_eq!(list.items_count(), 4);
            assert_eq!(list.item(0).map(KeyValueRow::field), Some("Name"));
            assert_eq!(list.item(3).map(KeyValueRow::value), Some("PE"));
        }

        app.add_window(win);
        app.run();
    }
}
