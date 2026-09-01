//! Panel dock: vertical sidebar panels vs. horizontal bottom-bar
//! panels (C++ `FileWindow::AddPanel`, `FileWindow.cpp:107-123`;
//! auto-collapse `FileWindow.cpp:272-278`; spec
//! `02_SMART_VIEWERS_DEEP` §D).
//!
//! Vertical panels go to the `verticalPanels` list tab. Horizontal
//! panels go to the `horizontalPanels` tab **and** get a bottom-bar
//! single-choice item with id `lastHorizontalPanelID++`. Index 0 is
//! always the cursor-information panel (id
//! `CMD_SHOW_HORIZONTAL_PANEL`). The concrete tab controls attach in
//! the `file-window-shell` task; this module owns the bookkeeping and
//! command handling.

use super::layout::CMD_SHOW_HORIZONTAL_PANEL;

/// One bottom-bar single-choice item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BottomBarItem {
    /// Item caption (panel tab text; `"<->"` for cursor info).
    pub caption: String,
    /// Dispatched command id (`CMD_SHOW_HORIZONTAL_PANEL + index`).
    pub command_id: u32,
}

/// Result of routing a command id through the dock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelCommand {
    /// Switch `horizontalPanels` to tab `index` and focus it.
    ShowHorizontalPanel(usize),
    /// The id is not a panel command.
    NotHandled,
}

/// Panel bookkeeping for one `FileWindow`.
pub struct PanelDock {
    vertical_captions: Vec<String>,
    horizontal_captions: Vec<String>,
    bottom_bar: Vec<BottomBarItem>,
    last_horizontal_panel_id: u32,
    current_horizontal: usize,
    cursor_info_checked: bool,
}

impl Default for PanelDock {
    fn default() -> Self {
        Self::new()
    }
}

impl PanelDock {
    /// Dock with the cursor-information panel pre-registered at
    /// horizontal index 0 (C++ ctor: `CursorInformation` +
    /// `AddSingleChoiceItem("<->", CMD_SHOW_HORIZONTAL_PANEL, true)`,
    /// `FileWindow.cpp:53-66`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            vertical_captions: Vec::new(),
            horizontal_captions: vec!["<->".to_owned()],
            bottom_bar: vec![BottomBarItem {
                caption: "<->".to_owned(),
                command_id: CMD_SHOW_HORIZONTAL_PANEL,
            }],
            // C++: lastHorizontalPanelID = CMD_SHOW_HORIZONTAL_PANEL + 1
            last_horizontal_panel_id: CMD_SHOW_HORIZONTAL_PANEL.saturating_add(1),
            current_horizontal: 0,
            cursor_info_checked: true,
        }
    }

    /// Adds a plugin panel (C++ `AddPanel(page, verticalPosition)`).
    ///
    /// `vertical == true`: sidebar list tab only. `vertical == false`:
    /// bottom tab plus a bottom-bar item whose id is
    /// `lastHorizontalPanelID++`.
    pub fn add_panel(&mut self, caption: &str, vertical: bool) -> bool {
        if vertical {
            self.vertical_captions.push(caption.to_owned());
            return true;
        }
        let id = self.last_horizontal_panel_id;
        self.last_horizontal_panel_id = id.saturating_add(1);
        self.horizontal_captions.push(caption.to_owned());
        self.bottom_bar.push(BottomBarItem {
            caption: caption.to_owned(),
            command_id: id,
        });
        true
    }

    /// Routes a command id (C++ `OnEvent`,
    /// `FileWindow.cpp:260-265`): ids in
    /// `[CMD_SHOW_HORIZONTAL_PANEL, CMD_SHOW_HORIZONTAL_PANEL + 100]`
    /// switch the horizontal tab.
    pub const fn handle_command(&mut self, id: u32) -> PanelCommand {
        if id < CMD_SHOW_HORIZONTAL_PANEL || id > CMD_SHOW_HORIZONTAL_PANEL.saturating_add(100) {
            return PanelCommand::NotHandled;
        }
        let index = (id.saturating_sub(CMD_SHOW_HORIZONTAL_PANEL)) as usize;
        if index < self.horizontal_captions.len() {
            self.current_horizontal = index;
            self.cursor_info_checked = index == 0;
        }
        PanelCommand::ShowHorizontalPanel(index)
    }

    /// Splitter auto-collapse (C++ `Event::SplitterPanelAutoCollapsed`
    /// on `horizontal`, `FileWindow.cpp:272-278`): back to the cursor
    /// info tab (index 0) and re-check its bottom-bar item.
    pub const fn on_horizontal_auto_collapse(&mut self) {
        self.current_horizontal = 0;
        self.cursor_info_checked = true;
    }

    /// Currently shown horizontal tab index.
    #[must_use]
    pub const fn current_horizontal(&self) -> usize {
        self.current_horizontal
    }

    /// `true` while the cursor-info bottom-bar item is checked.
    #[must_use]
    pub const fn cursor_info_checked(&self) -> bool {
        self.cursor_info_checked
    }

    /// Bottom-bar items in registration order.
    #[must_use]
    pub fn bottom_bar_items(&self) -> &[BottomBarItem] {
        &self.bottom_bar
    }

    /// Number of vertical (sidebar) panels.
    #[must_use]
    pub const fn vertical_count(&self) -> usize {
        self.vertical_captions.len()
    }

    /// Number of horizontal panels including cursor info.
    #[must_use]
    pub const fn horizontal_count(&self) -> usize {
        self.horizontal_captions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_info_is_horizontal_index_zero() {
        let dock = PanelDock::new();
        assert_eq!(dock.horizontal_count(), 1);
        assert_eq!(dock.vertical_count(), 0);
        assert_eq!(
            dock.bottom_bar_items(),
            &[BottomBarItem {
                caption: "<->".to_owned(),
                command_id: CMD_SHOW_HORIZONTAL_PANEL,
            }]
        );
        assert!(dock.cursor_info_checked());
    }

    #[test]
    fn vertical_panel_adds_no_bottom_bar_item() {
        let mut dock = PanelDock::new();
        assert!(dock.add_panel("Sections", true));
        assert_eq!(dock.vertical_count(), 1);
        assert_eq!(dock.bottom_bar_items().len(), 1); // still only "<->"
    }

    #[test]
    fn horizontal_panel_adds_bottom_bar_item_with_incrementing_id() {
        let mut dock = PanelDock::new();
        assert!(dock.add_panel("Strings", false));
        assert!(dock.add_panel("Hashes", false));
        let items = dock.bottom_bar_items();
        assert_eq!(items.len(), 3);
        // lastHorizontalPanelID starts at base + 1 and increments.
        assert_eq!(items[1].command_id, CMD_SHOW_HORIZONTAL_PANEL + 1);
        assert_eq!(items[1].caption, "Strings");
        assert_eq!(items[2].command_id, CMD_SHOW_HORIZONTAL_PANEL + 2);
        assert_eq!(items[2].caption, "Hashes");
        assert_eq!(dock.horizontal_count(), 3);
    }

    #[test]
    fn command_range_switches_horizontal_tab() {
        let mut dock = PanelDock::new();
        dock.add_panel("Strings", false);
        assert_eq!(
            dock.handle_command(CMD_SHOW_HORIZONTAL_PANEL + 1),
            PanelCommand::ShowHorizontalPanel(1)
        );
        assert_eq!(dock.current_horizontal(), 1);
        assert!(!dock.cursor_info_checked());
        // Back to cursor info.
        assert_eq!(
            dock.handle_command(CMD_SHOW_HORIZONTAL_PANEL),
            PanelCommand::ShowHorizontalPanel(0)
        );
        assert!(dock.cursor_info_checked());
    }

    #[test]
    fn command_range_bounds_are_inclusive_plus_100() {
        let mut dock = PanelDock::new();
        // In-range but non-existent tab: C++ still enters the branch.
        assert_eq!(
            dock.handle_command(CMD_SHOW_HORIZONTAL_PANEL + 100),
            PanelCommand::ShowHorizontalPanel(100)
        );
        // Outside range.
        assert_eq!(
            dock.handle_command(CMD_SHOW_HORIZONTAL_PANEL + 101),
            PanelCommand::NotHandled
        );
        assert_eq!(
            dock.handle_command(CMD_SHOW_HORIZONTAL_PANEL - 1),
            PanelCommand::NotHandled
        );
    }

    #[test]
    fn auto_collapse_resets_to_cursor_info() {
        let mut dock = PanelDock::new();
        dock.add_panel("Strings", false);
        dock.handle_command(CMD_SHOW_HORIZONTAL_PANEL + 1);
        assert_eq!(dock.current_horizontal(), 1);
        dock.on_horizontal_auto_collapse();
        assert_eq!(dock.current_horizontal(), 0);
        assert!(dock.cursor_info_checked());
    }
}
