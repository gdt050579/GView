//! The archive / VFS tree viewer control.
//!
//! Spec `00_APP §6.2`; `02_VIEWER_CONTAINER` §3 (enumeration), §4
//! (columns) and §5 (open flow). C++ anchor:
//! `GViewCore/src/View/ContainerViewer/Instance.cpp` — the constructor
//! (L40-76: icon, property list, tree, columns), `PopulateItem`
//! (L99-112), `OnTreeViewItemToggle` (L113-125),
//! `OnTreeViewItemPressed` (L126-142) and `OnKeyEvent`.
//!
//! # Why this is a custom control and not `TreeView<TreeNode>`
//!
//! `00_APP §5.3.2` sketches this page as an `AppCUI` `TreeView<TreeNode>`
//! plus a `ListView` of properties. That is not implementable against
//! the current `AppCUI-rs`: `TreeView<T>` takes its columns from the
//! **associated** functions `ListItem::columns_count()` /
//! `ListItem::column(i)`, so they are fixed per Rust type at compile
//! time, while a container plugin supplies its columns as runtime
//! layout strings (`ContainerViewerRequest::columns`, e.g.
//! `"n:&Filename,a:l,w:80"`). The C++ `TreeView::AddColumn(layout)` has
//! no `AppCUI-rs` counterpart, and `AppCUI-rs` source wins on UI API
//! conflicts (`CLAUDE.md §3`).
//!
//! So this control owns the [`ContainerTree`] directly and paints the
//! tree and the property list itself — the same pattern the other six
//! viewers use, with the plugin's runtime columns honoured and no
//! second copy of the tree to keep in sync. See quirk #10.

use std::sync::{Mutex, PoisonError};

use appcui::prelude::*;

use gview_plugin::type_plugin::ContainerViewerRequest;
use gview_view::container_viewer::open::{
    entry_cap, on_tree_view_item_pressed, OpenItemInterface, OpenRequest, MAX_ENTRIES_PER_DIRECTORY,
};
use gview_view::container_viewer::tree::{ContainerTree, EnumerateInterface, TreeItemId};
use gview_view::traits::{SharedObject, SmartViewer, ViewerSettings};
use gview_view::view_control::ViewControl;

use crate::cursor_info::{CursorSnapshot, SharedCursorInfo};

/// Rows the C++ reserves for the icon and the property list before the
/// tree starts (`Instance.cpp:44-50`: `h:8` for both, tree at `t:8`).
pub const PROPERTIES_HEIGHT: u32 = 8;
/// Fallback caption when a plugin column layout has no `n:` field.
pub const UNNAMED_COLUMN: &str = "?";
/// Widest cursor bar this control formats without allocating.
const CURSOR_BAR_CAPACITY: usize = 96;

/// One parsed column of `ContainerViewerRequest::columns`.
///
/// The plugin ships `AppCUI` layout strings (`n:<caption>,a:<l|c|r>,w:<n>`);
/// the C++ hands them straight to `TreeView::AddColumn`, and this is
/// the Rust parse of the same grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerColumn {
    /// `n:` caption, with the `&` hot-key marker stripped for paint.
    pub caption: String,
    /// `w:` width in cells (default 10, as `AppCUI` does).
    pub width: u16,
}

impl ContainerColumn {
    /// Parses one `n:…,a:…,w:…` layout string.
    #[must_use]
    pub fn parse(layout: &str) -> Self {
        let mut caption = String::new();
        let mut width = 10_u16;
        for field in layout.split(',') {
            let Some((key, value)) = field.split_once(':') else {
                continue;
            };
            match key.trim() {
                "n" => caption = value.replace('&', ""),
                "w" => width = value.trim().parse().unwrap_or(10),
                _ => {}
            }
        }
        if caption.is_empty() {
            caption = String::from(UNNAMED_COLUMN);
        }
        Self { caption, width }
    }
}

/// What the `FileWindow` hands a [`ContainerView`] at mount
/// (`00_APP §5.3.2`): the plugin's `ContainerViewerRequest` plus the
/// two container hooks of `§5.3.3`.
pub struct ContainerViewSettings {
    /// The plugin's `ContainerViewer::Settings`, moved in whole.
    pub request: ContainerViewerRequest,
    /// `SetEnumerateCallback` result; without one the tree stays at
    /// its root, exactly as the C++ skips `AddItem` when
    /// `settings->enumInterface` is null (`Instance.cpp:67`).
    pub enumerator: Option<Box<dyn EnumerateInterface + Send>>,
    /// `SetOpenItemCallback` result.
    pub opener: Option<Box<dyn OpenItemInterface + Send>>,
    /// Entries one directory may enumerate before the walk is cut
    /// short (§12.4; the C++ has no cap).
    pub entry_limit: u32,
    /// The window's bottom-bar slot (`00_APP §5.3.5`).
    pub cursor_info: SharedCursorInfo,
    /// `CreateViewer<T>(name)` override.
    pub custom_name: Option<String>,
}

impl Default for ContainerViewSettings {
    fn default() -> Self {
        Self {
            request: ContainerViewerRequest::default(),
            enumerator: None,
            opener: None,
            entry_limit: MAX_ENTRIES_PER_DIRECTORY,
            cursor_info: SharedCursorInfo::new(),
            custom_name: None,
        }
    }
}

impl core::fmt::Debug for ContainerViewSettings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContainerViewSettings")
            .field("columns", &self.request.columns.len())
            .field("properties", &self.request.properties.len())
            .field("has_enumerator", &self.enumerator.is_some())
            .field("has_opener", &self.opener.is_some())
            .finish_non_exhaustive()
    }
}

impl ViewerSettings for ContainerViewSettings {
    fn custom_name(&self) -> Option<&str> {
        self.custom_name.as_deref()
    }

    fn set_custom_name(&mut self, name: &str) {
        self.custom_name = Some(name.to_owned());
    }
}

/// The archive / VFS tree viewer (C++ `ContainerViewer::Instance`).
#[CustomControl(overwrite = OnPaint+OnKeyPressed+OnResize+OnMouseEvent, emit = OpenEntry+FocusView)]
pub struct ContainerView {
    object: SharedObject,
    tree: Mutex<ContainerTree>,
    enumerator: Mutex<Option<Box<dyn EnumerateInterface + Send>>>,
    opener: Mutex<Option<Box<dyn OpenItemInterface + Send>>>,
    /// Parsed `ContainerViewerRequest::columns`.
    columns: Vec<ContainerColumn>,
    /// `AddProperty(key, value)` rows.
    properties: Vec<(String, String)>,
    entry_limit: u32,
    /// Flattened visible rows, rebuilt whenever the fold state changes
    /// (never in paint — `00_APP §6.3`).
    rows: Vec<TreeItemId>,
    /// Index into [`Self::rows`] of the highlighted item.
    current_row: usize,
    /// First visible row.
    scroll_row: usize,
    control_width: u32,
    control_height: u32,
    name: String,
    cursor_info: SharedCursorInfo,
    /// The last `Enter` result, for the window to service.
    pending_open: Option<OpenRequest>,
    /// Scratch for `paint_cursor_information`.
    cursor_bar: [u8; CURSOR_BAR_CAPACITY],
}

impl ContainerView {
    /// The parsed plugin columns.
    #[must_use]
    pub fn columns(&self) -> &[ContainerColumn] {
        &self.columns
    }

    /// The plugin's property rows.
    #[must_use]
    pub fn properties(&self) -> &[(String, String)] {
        &self.properties
    }

    /// Currently visible tree rows, top to bottom.
    #[must_use]
    pub fn rows(&self) -> &[TreeItemId] {
        &self.rows
    }

    /// The highlighted item, if the tree has any rows.
    #[must_use]
    pub fn current_item(&self) -> Option<TreeItemId> {
        self.rows.get(self.current_row).copied()
    }

    /// Path of the highlighted item (C++ `currentPath`).
    #[must_use]
    pub fn current_path(&self) -> String {
        let mut tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
        let path = self.current_item().map_or_else(String::new, |id| {
            tree.update_path_for_item(id);
            tree.current_path.clone()
        });
        drop(tree);
        path
    }

    /// The `Enter` result the window has not serviced yet.
    #[must_use]
    pub const fn pending_open(&self) -> Option<&OpenRequest> {
        self.pending_open.as_ref()
    }

    /// Takes the pending `Enter` result.
    pub const fn take_pending_open(&mut self) -> Option<OpenRequest> {
        self.pending_open.take()
    }

    /// Column captions of the tree header.
    #[must_use]
    pub fn column_captions(&self) -> Vec<&str> {
        self.columns.iter().map(|c| c.caption.as_str()).collect()
    }

    /// C++ `PopulateItem` (`Instance.cpp:99-112`) plus the §12.4 entry
    /// cap. Idempotent: [`ContainerTree::populate_item`] returns early
    /// for a node that was already enumerated.
    fn populate(&self, id: TreeItemId) {
        let mut tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
        let mut enumerator = self.enumerator.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(enumerator) = enumerator.as_deref_mut() {
            let mut cap = entry_cap(self.entry_limit);
            tree.populate_item(id, enumerator, &mut cap);
        }
        drop(enumerator);
        drop(tree);
    }

    /// Rebuilds the flattened row list from the tree's fold state
    /// (the C++ `TreeView` keeps this internally).
    fn rebuild_rows(&mut self) {
        let tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
        let mut rows = core::mem::take(&mut self.rows);
        rows.clear();
        let _ = &tree;
        // The root itself is a row (C++ adds the separator item and
        // unfolds it); its subtree follows when unfolded.
        flatten(&tree, tree.root(), &mut rows);
        drop(tree);
        self.rows = rows;
        if self.current_row >= self.rows.len() {
            self.current_row = self.rows.len().saturating_sub(1);
        }
        self.ensure_current_visible();
    }

    /// Scrolls so the highlighted row is inside the tree band.
    fn ensure_current_visible(&mut self) {
        let visible = self.tree_rows().max(1) as usize;
        if self.current_row < self.scroll_row {
            self.scroll_row = self.current_row;
        } else if self.current_row >= self.scroll_row.saturating_add(visible) {
            self.scroll_row = self
                .current_row
                .saturating_sub(visible.saturating_sub(1));
        }
    }

    /// Rows the tree band can show (the control height minus the
    /// property block and the column header).
    const fn tree_rows(&self) -> u32 {
        self.control_height
            .saturating_sub(PROPERTIES_HEIGHT)
            .saturating_sub(1)
    }

    /// C++ `OnTreeViewItemToggle` (`Instance.cpp:113-125`): unfolding
    /// an item populates it lazily, folding just hides its subtree.
    pub fn toggle_current(&mut self) -> bool {
        let Some(id) = self.current_item() else {
            return false;
        };
        let expandable = {
            let tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
            let expandable = tree.node(id).is_some_and(|node| node.expandable);
            drop(tree);
            expandable
        };
        if !expandable {
            return false;
        }
        let now_folded = {
            let mut tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
            let folded = tree.node(id).is_none_or(|node| node.folded);
            if let Some(node) = tree.node_mut(id) {
                node.folded = !folded;
            }
            drop(tree);
            !folded
        };
        if !now_folded {
            self.populate(id);
        }
        self.rebuild_rows();
        self.publish();
        true
    }

    /// C++ `OnTreeViewItemPressed` (`Instance.cpp:126-142`): only a
    /// leaf is opened, and the plugin's `OnOpenItem` decides.
    pub fn open_current(&mut self) -> bool {
        let Some(id) = self.current_item() else {
            return false;
        };
        let request = {
            let mut tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
            let mut opener = self.opener.lock().unwrap_or_else(PoisonError::into_inner);
            let request = opener
                .as_deref_mut()
                .and_then(|opener| on_tree_view_item_pressed(&mut tree, id, opener));
            drop(opener);
            drop(tree);
            request
        };
        let opened = request.is_some();
        if opened {
            self.pending_open = request;
            self.raise_event(containerview::Events::OpenEntry);
        }
        opened
    }

    /// The bottom-bar snapshot: the tree has no byte cursor, so it
    /// publishes the current path in the name slot.
    fn snapshot(&self) -> CursorSnapshot {
        let mut snapshot = CursorSnapshot::with_name(&self.name);
        snapshot.base = 10;
        snapshot.offset = self.current_row as u64;
        snapshot.size = self.rows.len() as u64;
        snapshot
    }

    /// Publishes the current row to the window's bottom bar.
    fn publish(&self) {
        self.cursor_info.write(self.snapshot());
    }

    /// Paints the property block (C++ `propList`, `Instance.cpp:47`).
    fn paint_properties(&self, surface: &mut Surface, theme: &Theme) {
        for (row, (key, value)) in self.properties.iter().enumerate() {
            let y = row as u32;
            if y >= PROPERTIES_HEIGHT {
                break;
            }
            surface.write_string(0, y.cast_signed(), key, theme.text.highlighted, false);
            surface.write_string(22, y.cast_signed(), value, theme.text.normal, false);
        }
    }

    /// Paints the column header of the tree band.
    fn paint_header(&self, surface: &mut Surface, theme: &Theme) {
        let y = PROPERTIES_HEIGHT.cast_signed();
        surface.fill_horizontal_line(
            0,
            y,
            self.control_width.cast_signed(),
            Character::with_attributes(' ', theme.header.text.normal),
        );
        let mut x = 0_u32;
        for column in &self.columns {
            surface.write_string(
                x.cast_signed(),
                y,
                &column.caption,
                theme.header.text.normal,
                false,
            );
            x = x.saturating_add(u32::from(column.width)).saturating_add(1);
            if x >= self.control_width {
                break;
            }
        }
    }
}

/// Depth-first walk of the unfolded part of the tree.
///
/// Bounded by the node count: [`ContainerTree`] stores its nodes in a
/// `Vec` and a child is always appended after its parent, so a cycle
/// cannot form and the walk terminates. The explicit stack keeps a
/// deeply nested archive from overflowing the call stack.
fn flatten(tree: &ContainerTree, root: TreeItemId, out: &mut Vec<TreeItemId>) {
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        out.push(id);
        let Some(node) = tree.node(id) else {
            continue;
        };
        if node.folded {
            continue;
        }
        // Push in reverse so children come out in order.
        for child in tree.children(id).iter().rev() {
            stack.push(*child);
        }
    }
}

impl SmartViewer for ContainerView {
    type Settings = ContainerViewSettings;

    fn from_settings(object: SharedObject, settings: Self::Settings) -> Self {
        let ContainerViewSettings {
            request,
            enumerator,
            opener,
            entry_limit,
            cursor_info,
            custom_name,
        } = settings;
        let columns = request.columns.iter().map(|c| ContainerColumn::parse(c)).collect();
        let mut tree = ContainerTree::new(request.path_separator);
        // C++ `Instance.cpp:67-71`: the root exists only when the
        // plugin supplied an enumerator, and it starts unfolded.
        let root = tree.root();
        tree.unfold(root);
        let mut view = Self {
            base: ControlBase::with_focus_overlay(layout!("d:f")),
            object,
            tree: Mutex::new(tree),
            enumerator: Mutex::new(enumerator),
            opener: Mutex::new(opener),
            columns,
            properties: request.properties,
            entry_limit,
            rows: Vec::new(),
            current_row: 0,
            scroll_row: 0,
            control_width: 1,
            control_height: 1,
            name: custom_name.unwrap_or_else(|| String::from("Container")),
            cursor_info,
            pending_open: None,
            cursor_bar: [b' '; CURSOR_BAR_CAPACITY],
        };
        view.rebuild_rows();
        view.publish();
        view
    }
}

impl ViewControl for ContainerView {
    fn name(&self) -> &str {
        &self.name
    }

    /// The tree has no byte cursor: the C++ `ContainerViewer::GoTo` is
    /// the base implementation, which refuses.
    fn go_to(&mut self, _offset: u64) -> bool {
        false
    }

    fn select(&mut self, _offset: u64, _size: u64) -> bool {
        false
    }

    fn show_goto_dialog(&mut self) -> bool {
        false
    }

    fn show_find_dialog(&mut self) -> bool {
        false
    }

    fn show_copy_dialog(&mut self) -> bool {
        false
    }

    /// The bar shows the current path and the row counter.
    fn paint_cursor_information(&mut self, surface: &mut Surface, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        let path = self.current_path();
        let mut len = 0_usize;
        for byte in path.as_bytes().iter().chain(b"  ") {
            if let Some(slot) = self.cursor_bar.get_mut(len) {
                *slot = *byte;
                len = len.saturating_add(1);
            }
        }
        let text = self.cursor_bar.get(..len).unwrap_or(&[]);
        surface.write_ascii(0, 0, text, CharAttribute::default(), false);
    }
}

impl OnResize for ContainerView {
    fn on_resize(&mut self, _old: Size, new: Size) {
        self.control_width = new.width.max(1);
        self.control_height = new.height.max(1);
        self.ensure_current_visible();
        self.publish();
    }
}

impl OnPaint for ContainerView {
    fn on_paint(&self, surface: &mut Surface, theme: &Theme) {
        surface.clear(Character::with_attributes(' ', theme.editor.normal));
        self.paint_properties(surface, theme);
        self.paint_header(surface, theme);

        let tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
        let first_row = PROPERTIES_HEIGHT.saturating_add(1);
        let visible = self.tree_rows();
        for offset in 0..visible {
            let Some(id) = self.rows.get(self.scroll_row.saturating_add(offset as usize)) else {
                break;
            };
            let Some(node) = tree.node(*id) else {
                continue;
            };
            let y = first_row.saturating_add(offset).cast_signed();
            let selected = self.scroll_row.saturating_add(offset as usize) == self.current_row;
            let attr = if selected {
                theme.editor.pressed_or_selected
            } else if node.priority {
                theme.text.highlighted
            } else {
                theme.text.normal
            };
            if selected {
                surface.fill_horizontal_line(
                    0,
                    y,
                    self.control_width.cast_signed(),
                    Character::with_attributes(' ', attr),
                );
            }
            // The fold marker sits in front of the first column, as the
            // C++ `TreeView` draws it.
            let marker = if node.expandable {
                if node.folded {
                    '+'
                } else {
                    '-'
                }
            } else {
                ' '
            };
            surface.write_char(0, y, Character::with_attributes(marker, attr));
            let mut x = 2_u32;
            for (index, column) in self.columns.iter().enumerate() {
                let text = node.texts.get(index).map_or("", String::as_str);
                surface.write_string(x.cast_signed(), y, text, attr, false);
                x = x.saturating_add(u32::from(column.width)).saturating_add(1);
                if x >= self.control_width {
                    break;
                }
            }
        }
        drop(tree);
    }
}

impl OnKeyPressed for ContainerView {
    fn on_key_pressed(&mut self, key: Key, _character: char) -> EventProcessStatus {
        if key == Key::new(KeyCode::Escape, KeyModifier::None) {
            self.raise_event(containerview::Events::FocusView);
            return EventProcessStatus::Processed;
        }
        let handled = if key == Key::new(KeyCode::Down, KeyModifier::None) {
            self.current_row = self
                .current_row
                .saturating_add(1)
                .min(self.rows.len().saturating_sub(1));
            self.ensure_current_visible();
            true
        } else if key == Key::new(KeyCode::Up, KeyModifier::None) {
            self.current_row = self.current_row.saturating_sub(1);
            self.ensure_current_visible();
            true
        } else if key == Key::new(KeyCode::Home, KeyModifier::None) {
            self.current_row = 0;
            self.ensure_current_visible();
            true
        } else if key == Key::new(KeyCode::End, KeyModifier::None) {
            self.current_row = self.rows.len().saturating_sub(1);
            self.ensure_current_visible();
            true
        } else if key == Key::new(KeyCode::PageDown, KeyModifier::None) {
            let page = self.tree_rows().max(1) as usize;
            self.current_row = self
                .current_row
                .saturating_add(page)
                .min(self.rows.len().saturating_sub(1));
            self.ensure_current_visible();
            true
        } else if key == Key::new(KeyCode::PageUp, KeyModifier::None) {
            let page = self.tree_rows().max(1) as usize;
            self.current_row = self.current_row.saturating_sub(page);
            self.ensure_current_visible();
            true
        } else if key == Key::new(KeyCode::Space, KeyModifier::None)
            || key == Key::new(KeyCode::Right, KeyModifier::None)
            || key == Key::new(KeyCode::Left, KeyModifier::None)
        {
            self.toggle_current()
        } else if key == Key::new(KeyCode::Enter, KeyModifier::None) {
            // A folder toggles, a leaf opens (C++ leaf-only rule).
            self.toggle_current() || self.open_current()
        } else {
            false
        };
        if handled {
            self.publish();
            self.request_update();
            EventProcessStatus::Processed
        } else {
            EventProcessStatus::Ignored
        }
    }
}

impl OnMouseEvent for ContainerView {
    fn on_mouse_event(&mut self, event: &MouseEvent) -> EventProcessStatus {
        let handled = match event {
            MouseEvent::Wheel(MouseWheelDirection::Down) => {
                let last = self.rows.len().saturating_sub(1);
                self.scroll_row = self.scroll_row.saturating_add(1).min(last);
                true
            }
            MouseEvent::Wheel(MouseWheelDirection::Up) => {
                self.scroll_row = self.scroll_row.saturating_sub(1);
                true
            }
            MouseEvent::Pressed(data) => {
                let first_row = PROPERTIES_HEIGHT.saturating_add(1).cast_signed();
                if data.y < first_row {
                    false
                } else {
                    let offset = data.y.saturating_sub(first_row).unsigned_abs() as usize;
                    let row = self.scroll_row.saturating_add(offset);
                    if row < self.rows.len() {
                        self.current_row = row;
                        true
                    } else {
                        false
                    }
                }
            }
            MouseEvent::DoubleClick(_) => self.toggle_current() || self.open_current(),
            _ => false,
        };
        if handled {
            self.publish();
            self.request_update();
            EventProcessStatus::Processed
        } else {
            EventProcessStatus::Ignored
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ContainerColumn, ContainerView, ContainerViewSettings, PROPERTIES_HEIGHT};
    use crate::cursor_info::SharedCursorInfo;
    use appcui::prelude::*;
    use gview_core::object::Object;
    use gview_plugin::type_plugin::ContainerViewerRequest;
    use gview_view::container_viewer::open::{EntryKind, OpenItemInterface, OpenRequest};
    use gview_view::container_viewer::tree::{EnumerateInterface, TreeItemId, TreeNode};
    use gview_view::traits::{SharedObject, SmartViewer};
    use gview_view::view_control::ViewControl;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    fn processed(status: EventProcessStatus) -> bool {
        status == EventProcessStatus::Processed
    }

    fn object_of() -> SharedObject {
        Arc::new(StdMutex::new(Object::from_buffer(b"PK\x03\x04", "a.zip", 0)))
    }

    /// A two-level mock VFS: root holds `docs/` and `img/` (dirs) plus
    /// `a.txt`, `b.txt` and `c.txt`; `docs/` holds `inner.txt`.
    #[derive(Default)]
    struct MockVfs {
        path: String,
        cursor: usize,
        /// How many times `begin_iteration` ran per path.
        begins: Arc<StdMutex<Vec<String>>>,
    }

    impl MockVfs {
        fn entries(path: &str) -> Vec<(&'static str, bool)> {
            match path {
                "" => vec![
                    ("docs", true),
                    ("img", true),
                    ("a.txt", false),
                    ("b.txt", false),
                    ("c.txt", false),
                ],
                "docs" => vec![("inner.txt", false)],
                _ => Vec::new(),
            }
        }
    }

    impl EnumerateInterface for MockVfs {
        fn begin_iteration(&mut self, path: &str, _parent: TreeItemId) -> bool {
            self.begins
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(path.to_owned());
            self.path = path.to_owned();
            self.cursor = 0;
            !Self::entries(path).is_empty()
        }

        fn populate_item(&mut self, child: &mut TreeNode) -> bool {
            let entries = Self::entries(&self.path);
            let Some((name, is_dir)) = entries.get(self.cursor) else {
                return false;
            };
            child.set_text(0, name);
            child.set_text(1, if *is_dir { "<DIR>" } else { "file" });
            child.expandable = *is_dir;
            child.priority = *is_dir;
            self.cursor = self.cursor.saturating_add(1);
            self.cursor != entries.len()
        }
    }

    /// Counts `on_open_item` calls and always opens.
    struct MockOpener {
        calls: Arc<AtomicUsize>,
    }

    impl OpenItemInterface for MockOpener {
        fn on_open_item(&mut self, path: &str, _item: TreeItemId, node: &TreeNode) -> Option<OpenRequest> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Some(OpenRequest {
                name: node.name().to_owned(),
                path: PathBuf::from(path),
                bytes: b"payload".to_vec(),
                creation_process: String::from("extraction and decompression"),
                kind: EntryKind::File,
            })
        }
    }

    fn request() -> ContainerViewerRequest {
        ContainerViewerRequest {
            columns: vec![
                String::from("n:&Filename,a:l,w:40"),
                String::from("n:Type,a:r,w:10"),
            ],
            properties: vec![
                (String::from("Format"), String::from("ZIP")),
                (String::from("Items"), String::from("5")),
            ],
            ..ContainerViewerRequest::default()
        }
    }

    struct Fixture {
        view: ContainerView,
        begins: Arc<StdMutex<Vec<String>>>,
        opens: Arc<AtomicUsize>,
    }

    fn fixture(size: Size) -> Fixture {
        let begins = Arc::new(StdMutex::new(Vec::new()));
        let opens = Arc::new(AtomicUsize::new(0));
        let settings = ContainerViewSettings {
            request: request(),
            enumerator: Some(Box::new(MockVfs {
                begins: Arc::clone(&begins),
                ..MockVfs::default()
            })),
            opener: Some(Box::new(MockOpener {
                calls: Arc::clone(&opens),
            })),
            ..ContainerViewSettings::default()
        };
        let mut view = ContainerView::from_settings(object_of(), settings);
        OnResize::on_resize(&mut view, Size::new(0, 0), size);
        Fixture { view, begins, opens }
    }

    fn read(surface: &Surface, x: u32, y: u32, len: usize) -> String {
        (0..len)
            .filter_map(|i| {
                surface
                    .char(x.saturating_add(i as u32).cast_signed(), y.cast_signed())
                    .map(|c| c.code)
            })
            .collect()
    }

    #[test]
    fn column_layout_strings_parse_into_captions_and_widths() {
        let column = ContainerColumn::parse("n:&Filename,a:l,w:80");
        assert_eq!(column.caption, "Filename", "the hot-key marker is stripped");
        assert_eq!(column.width, 80);
        // Missing fields fall back the way `AppCUI` does.
        let bare = ContainerColumn::parse("a:r");
        assert_eq!(bare.caption, "?");
        assert_eq!(bare.width, 10);
        assert_eq!(ContainerColumn::parse("n:Size,w:bogus").width, 10);
    }

    #[test]
    fn the_root_is_populated_lazily_and_only_once() {
        let mut fixture = fixture(Size::new(80, 20));
        // Construction unfolds the root but has not enumerated it.
        assert_eq!(fixture.view.rows().len(), 1, "only the root");
        assert!(fixture.begins.lock().expect("lock").is_empty());

        // Toggling the root enumerates it: 2 dirs + 3 files.
        assert!(fixture.view.toggle_current());
        // Folding then unfolding again must not re-enumerate.
        let rows_after_fold = fixture.view.rows().len();
        assert_eq!(rows_after_fold, 1, "folded: only the root");
        assert!(fixture.view.toggle_current());
        assert_eq!(fixture.view.rows().len(), 6, "root + 5 entries");
        assert_eq!(
            fixture.begins.lock().expect("lock").len(),
            1,
            "populate_item ran exactly once for the root"
        );
    }

    #[test]
    fn expanding_a_directory_calls_populate_item_exactly_once() {
        let mut fixture = fixture(Size::new(80, 20));
        fixture.view.toggle_current(); // fold the root
        fixture.view.toggle_current(); // unfold + enumerate
        assert_eq!(fixture.view.rows().len(), 6);

        // Row 1 is `docs/`.
        OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert!(fixture.view.toggle_current(), "docs is expandable");
        assert_eq!(fixture.view.rows().len(), 7, "docs/inner.txt appeared");
        let begins = fixture.begins.lock().expect("lock").clone();
        assert_eq!(begins, ["", "docs"], "one begin_iteration per directory");

        // Fold and unfold again: still one enumeration for `docs`.
        assert!(fixture.view.toggle_current());
        assert!(fixture.view.toggle_current());
        assert_eq!(fixture.begins.lock().expect("lock").len(), 2);
        assert_eq!(fixture.view.rows().len(), 7);
    }

    #[test]
    fn enter_on_a_leaf_raises_open_entry() {
        let mut fixture = fixture(Size::new(80, 20));
        fixture.view.toggle_current();
        fixture.view.toggle_current();
        // Move to `a.txt` (root, docs, img, a.txt → three Downs).
        for _ in 0..3 {
            OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        }
        assert!(fixture.view.pending_open().is_none());
        assert!(processed(OnKeyPressed::on_key_pressed(
            &mut fixture.view,
            Key::new(KeyCode::Enter, KeyModifier::None),
            '\0'
        )));
        let request = fixture.view.take_pending_open().expect("open request");
        assert_eq!(request.name, "a.txt");
        assert_eq!(request.bytes, b"payload");
        assert_eq!(fixture.opens.load(Ordering::Relaxed), 1);
        assert!(fixture.view.pending_open().is_none(), "taken once");
    }

    #[test]
    fn enter_on_a_directory_toggles_instead_of_opening() {
        let mut fixture = fixture(Size::new(80, 20));
        fixture.view.toggle_current();
        fixture.view.toggle_current();
        OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        // `docs/` is a folder: Enter expands it, nothing is opened.
        OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Enter, KeyModifier::None), '\0');
        assert_eq!(fixture.opens.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.view.rows().len(), 7);
        assert!(fixture.view.pending_open().is_none());
    }

    #[test]
    fn the_entry_cap_stops_a_runaway_directory_without_panicking() {
        /// Never says "no more entries".
        struct Endless;
        impl EnumerateInterface for Endless {
            fn begin_iteration(&mut self, _path: &str, _parent: TreeItemId) -> bool {
                true
            }
            fn populate_item(&mut self, child: &mut TreeNode) -> bool {
                child.set_text(0, "x");
                child.expandable = true;
                true
            }
        }
        let settings = ContainerViewSettings {
            request: request(),
            enumerator: Some(Box::new(Endless)),
            entry_limit: 32,
            ..ContainerViewSettings::default()
        };
        let mut view = ContainerView::from_settings(object_of(), settings);
        OnResize::on_resize(&mut view, Size::new(0, 0), Size::new(80, 20));
        view.toggle_current();
        view.toggle_current();
        // The cap cut the walk short instead of looping forever.
        assert!(view.rows().len() <= 34, "capped: {}", view.rows().len());
        assert!(view.rows().len() > 1, "some entries were added");

        // Descending repeatedly stays bounded and never panics.
        for _ in 0..20 {
            OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
            view.toggle_current();
        }
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(80, 20);
        OnPaint::on_paint(&view, &mut surface, &theme);
    }

    #[test]
    fn a_plugin_without_an_enumerator_shows_only_the_root() {
        let settings = ContainerViewSettings {
            request: request(),
            ..ContainerViewSettings::default()
        };
        let mut view = ContainerView::from_settings(object_of(), settings);
        OnResize::on_resize(&mut view, Size::new(0, 0), Size::new(80, 20));
        assert_eq!(view.rows().len(), 1);
        // The root is expandable (C++ adds it as a folder), but with no
        // enumerator the toggle adds nothing.
        assert!(view.toggle_current(), "the root folds and unfolds");
        assert!(view.toggle_current());
        assert_eq!(view.rows().len(), 1, "nothing to enumerate");
        assert!(!view.open_current(), "no opener");
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(80, 20);
        OnPaint::on_paint(&view, &mut surface, &theme);
    }

    #[test]
    fn paints_the_properties_header_and_the_tree() {
        let mut fixture = fixture(Size::new(80, 24));
        fixture.view.toggle_current();
        fixture.view.toggle_current();
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(80, 24);
        OnPaint::on_paint(&fixture.view, &mut surface, &theme);

        // Property rows at the top.
        assert_eq!(read(&surface, 0, 0, 6), "Format");
        assert_eq!(read(&surface, 22, 0, 3), "ZIP");
        assert_eq!(read(&surface, 0, 1, 5), "Items");
        // Column header under them.
        assert_eq!(read(&surface, 0, PROPERTIES_HEIGHT, 8), "Filename");
        // The tree starts one row lower; row 0 is the root separator.
        let first = PROPERTIES_HEIGHT.saturating_add(1);
        assert_eq!(read(&surface, 0, first, 1), "-", "the root is unfolded");
        assert_eq!(read(&surface, 2, first.saturating_add(1), 4), "docs");
        assert_eq!(read(&surface, 2, first.saturating_add(3), 5), "a.txt");
    }

    #[test]
    fn navigation_keys_move_and_clamp_the_highlight() {
        let mut fixture = fixture(Size::new(80, 24));
        fixture.view.toggle_current();
        fixture.view.toggle_current();
        assert_eq!(fixture.view.rows().len(), 6);

        OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::End, KeyModifier::None), '\0');
        assert_eq!(fixture.view.current_item(), fixture.view.rows().last().copied());
        OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Home, KeyModifier::None), '\0');
        assert_eq!(fixture.view.current_item(), fixture.view.rows().first().copied());
        // Up at the top and Down at the bottom clamp.
        OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Up, KeyModifier::None), '\0');
        assert_eq!(fixture.view.current_item(), fixture.view.rows().first().copied());
        for _ in 0..20 {
            OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        }
        assert_eq!(fixture.view.current_item(), fixture.view.rows().last().copied());
        // An unhandled key bubbles.
        assert!(!processed(OnKeyPressed::on_key_pressed(
            &mut fixture.view,
            Key::new(KeyCode::F12, KeyModifier::Alt),
            '\0'
        )));
    }

    #[test]
    fn the_current_path_follows_the_highlight() {
        let mut fixture = fixture(Size::new(80, 24));
        fixture.view.toggle_current();
        fixture.view.toggle_current();
        assert_eq!(fixture.view.current_path(), "", "the root has no path");
        OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert_eq!(fixture.view.current_path(), "docs");
        fixture.view.toggle_current();
        OnKeyPressed::on_key_pressed(&mut fixture.view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert_eq!(fixture.view.current_path(), "docs/inner.txt");

        let mut bar = Surface::new(60, 1);
        fixture.view.paint_cursor_information(&mut bar, 60, 1);
        assert_eq!(read(&bar, 0, 0, 14), "docs/inner.txt");
        let mut empty = Surface::new(1, 1);
        fixture.view.paint_cursor_information(&mut empty, 0, 0);
    }

    #[test]
    fn view_control_byte_operations_are_refused() {
        let mut fixture = fixture(Size::new(80, 20));
        assert!(!fixture.view.go_to(0x10));
        assert!(!fixture.view.select(0, 4));
        assert!(!fixture.view.show_goto_dialog());
        assert!(!fixture.view.show_find_dialog());
        assert!(!fixture.view.show_copy_dialog());
        assert_eq!(ViewControl::name(&fixture.view), "Container");
    }

    #[test]
    fn a_click_selects_a_row_and_the_wheel_scrolls() {
        let mut fixture = fixture(Size::new(80, 14));
        fixture.view.toggle_current();
        fixture.view.toggle_current();
        let first_row = PROPERTIES_HEIGHT.saturating_add(1).cast_signed();
        let event = MouseEvent::Pressed(MouseEventData {
            x: 4,
            y: first_row.saturating_add(2),
            button: MouseButton::Left,
            modifier: KeyModifier::None,
        });
        assert!(processed(OnMouseEvent::on_mouse_event(&mut fixture.view, &event)));
        assert_eq!(fixture.view.current_item(), fixture.view.rows().get(2).copied());
        // A click in the property band is ignored.
        let above = MouseEvent::Pressed(MouseEventData {
            x: 4,
            y: 1,
            button: MouseButton::Left,
            modifier: KeyModifier::None,
        });
        assert!(!processed(OnMouseEvent::on_mouse_event(&mut fixture.view, &above)));
        // The wheel scrolls the band.
        assert!(processed(OnMouseEvent::on_mouse_event(
            &mut fixture.view,
            &MouseEvent::Wheel(MouseWheelDirection::Down)
        )));
    }

    #[test]
    fn the_bottom_bar_slot_carries_the_row_counter() {
        let info = SharedCursorInfo::new();
        let settings = ContainerViewSettings {
            request: request(),
            enumerator: Some(Box::new(MockVfs::default())),
            cursor_info: info.clone(),
            ..ContainerViewSettings::default()
        };
        let mut view = ContainerView::from_settings(object_of(), settings);
        OnResize::on_resize(&mut view, Size::new(0, 0), Size::new(80, 20));
        assert_eq!(info.read().name_str(), "Container");
        view.toggle_current();
        view.toggle_current();
        assert_eq!(info.read().size, 6, "root + five entries");
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert_eq!(info.read().offset, 1);
    }

    #[test]
    fn debug_app_paints_the_tree() {
        let script = "
            Paint.Enable(false)
            Paint('container view with the mock VFS')
            CheckHash(0x90B4F9C13485A788)
        ";
        let mut app = App::debug(80, 24, script).build().expect("debug app");
        let mut window = Window::new("Test", layout!("a:c,w:76,h:22"), window::Flags::None);
        let mut fixture = fixture(Size::new(74, 20));
        fixture.view.toggle_current();
        fixture.view.toggle_current();
        window.add(fixture.view);
        app.add_window(window);
        app.run();
    }
}
