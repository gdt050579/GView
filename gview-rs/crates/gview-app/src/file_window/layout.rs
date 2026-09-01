//! `FileWindow` splitter/tab layout
//! (C++ ctor `FileWindow.cpp:36-79`; spec `02_SMART_VIEWERS_DEEP`
//! §B.1–B.2; `APPCUI_RS_UI_AND_ASYNC_GUIDE` §2.3, §5.4).
//!
//! Control hierarchy (§B.2):
//!
//! ```text
//! Window
//! └─ horizontal HSplitter (bottom panel = cursor info, min 1 line)
//!    ├─ top:    vertical VSplitter
//!    │          ├─ left:  view Tab (hidden tabs)      ← smart viewers
//!    │          └─ right: verticalPanels Tab (list)   ← plugin panels
//!    └─ bottom: horizontalPanels Tab (hidden tabs)    ← cursor info + panels
//! ```
//!
//! API mapping (AppCUI-rs source wins on UI API conflicts):
//! - C++ `SplitterFlags::Horizontal|Vertical` → `HSplitter`/`VSplitter`.
//! - C++ `SetPanel2Bounderies(1)` → `set_min_height(Panel::Bottom, 1)`.
//! - C++ `SetSecondPanelSize(1)` → splitter positioned at 100%; the
//!   1-line minimum clamps the bottom panel to exactly one row.
//! - C++ `TabFlags::HideTabs` → `tab::Type::HiddenTabs`;
//!   C++ `TabFlags::ListView` (vertical panel list) → `tab::Type::OnLeft`
//!   (closest AppCUI-rs tab presentation; there is no `ListView` type).
//! - C++ `AutoCollapsePanel2` + `SetDefaultPanelSize` have no direct
//!   AppCUI-rs splitter API; the expand/collapse behavior is handled
//!   by the `file-window-panel-dock` task using the `DEFAULT_*` sizes
//!   below.

use appcui::prelude::*;

/// Top-bar ≡ menu → view configuration panel
/// (C++ `CMD_SHOW_VIEW_CONFIG_PANEL`, `FileWindow.cpp:16`).
pub const CMD_SHOW_VIEW_CONFIG_PANEL: u32 = 2_000_000;
/// Bottom-bar cursor-info toggle base; horizontal panels use
/// `base + n` (C++ `CMD_SHOW_HORIZONTAL_PANEL`, `FileWindow.cpp:17`).
pub const CMD_SHOW_HORIZONTAL_PANEL: u32 = 2_001_000;
/// First command id reserved for type-plugin commands
/// (C++ `CMD_FOR_TYPE_PLUGIN_START`, `FileWindow.cpp:18`).
pub const CMD_FOR_TYPE_PLUGIN_START: u32 = 50_000_000;

/// Cursor-info bar height (C++ `defaultCursorViewSize`,
/// `FileWindow.cpp:69`).
pub const DEFAULT_CURSOR_VIEW_SIZE: u32 = 2;
/// Vertical panel width on expansion (C++
/// `defaultVerticalPanelsSize`, `FileWindow.cpp:70`).
pub const DEFAULT_VERTICAL_PANELS_SIZE: u32 = 8;
/// Horizontal panel height on expansion (C++
/// `defaultHorizontalPanelsSize`, `FileWindow.cpp:71`).
pub const DEFAULT_HORIZONTAL_PANELS_SIZE: u32 = 40;
/// Vertical splitter default panel size upon extension
/// (C++ `vertical->SetDefaultPanelSize(64)`, `FileWindow.cpp:45`).
pub const VERTICAL_DEFAULT_PANEL_SIZE: u32 = 64;
/// Horizontal splitter default panel size upon extension
/// (C++ `horizontal->SetDefaultPanelSize(10)`, `FileWindow.cpp:46`).
pub const HORIZONTAL_DEFAULT_PANEL_SIZE: u32 = 10;
/// Minimum bottom-panel height of the horizontal splitter
/// (C++ `SetPanel2Bounderies(1)`, `FileWindow.cpp:43`).
pub const HORIZONTAL_PANEL2_MIN_SIZE: u32 = 1;
/// Maximum number of view tab pages (C++ `CreateChildControl<Tab>`
/// page limit, `FileWindow.cpp:49-51`).
pub const MAX_TAB_PAGES: u32 = 16;

/// Handles to the layout controls, mirroring the C++ `FileWindow`
/// references (`Internal.hpp:746-759`).
pub struct FileWindowLayout {
    /// Root horizontal splitter.
    pub horizontal: Handle<HSplitter>,
    /// Vertical splitter inside the horizontal top panel.
    pub vertical: Handle<VSplitter>,
    /// `view` tab hosting the smart viewers (hidden tab bar).
    pub view: Handle<Tab>,
    /// `verticalPanels` tab (plugin side panels).
    pub vertical_panels: Handle<Tab>,
    /// `horizontalPanels` tab (cursor info at index 0 + plugin
    /// bottom panels).
    pub horizontal_panels: Handle<Tab>,
}

impl FileWindowLayout {
    /// `true` when every control was created and attached.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.horizontal.is_none()
            && !self.vertical.is_none()
            && !self.view.is_none()
            && !self.vertical_panels.is_none()
            && !self.horizontal_panels.is_none()
    }
}

/// Builds the §B.2 control tree inside `window`
/// (C++ ctor wiring, `FileWindow.cpp:40-55`).
pub fn build_layout(window: &mut Window) -> FileWindowLayout {
    // Root: horizontal splitter at 100% — the 1-line bottom minimum
    // leaves exactly one row for the cursor bar (SetSecondPanelSize(1)
    // + SetPanel2Bounderies(1)).
    let mut horizontal = HSplitter::new(
        1.0_f32,
        layout!("d:f"),
        hsplitter::ResizeBehavior::PreserveBottomPanelSize,
        hsplitter::Flags::None,
    );
    horizontal.set_min_height(hsplitter::Panel::Bottom, HORIZONTAL_PANEL2_MIN_SIZE as u16);

    // Vertical splitter fills the top panel; the right (panels) side
    // starts collapsed (AutoCollapsePanel2 initial state).
    let mut vertical = VSplitter::new(
        1.0_f32,
        layout!("d:f"),
        vsplitter::ResizeBehavior::PreserveRightPanelSize,
        vsplitter::Flags::None,
    );

    let view_tab = Tab::with_type(
        layout!("d:f"),
        tab::Flags::TransparentBackground,
        tab::Type::HiddenTabs,
    );
    let vertical_panels_tab = Tab::with_type(
        layout!("d:f"),
        tab::Flags::TransparentBackground,
        tab::Type::OnLeft,
    );
    let horizontal_panels_tab = Tab::with_type(
        layout!("d:f"),
        tab::Flags::TransparentBackground,
        tab::Type::HiddenTabs,
    );

    let view = vertical.add(vsplitter::Panel::Left, view_tab);
    let vertical_panels = vertical.add(vsplitter::Panel::Right, vertical_panels_tab);
    let vertical_handle = horizontal.add(hsplitter::Panel::Top, vertical);
    let horizontal_panels = horizontal.add(hsplitter::Panel::Bottom, horizontal_panels_tab);
    let horizontal_handle = window.add(horizontal);

    FileWindowLayout {
        horizontal: horizontal_handle,
        vertical: vertical_handle,
        view,
        vertical_panels,
        horizontal_panels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_cpp() {
        assert_eq!(CMD_SHOW_VIEW_CONFIG_PANEL, 2_000_000);
        assert_eq!(CMD_SHOW_HORIZONTAL_PANEL, 2_001_000);
        assert_eq!(CMD_FOR_TYPE_PLUGIN_START, 50_000_000);
        assert_eq!(DEFAULT_CURSOR_VIEW_SIZE, 2);
        assert_eq!(DEFAULT_VERTICAL_PANELS_SIZE, 8);
        assert_eq!(DEFAULT_HORIZONTAL_PANELS_SIZE, 40);
        assert_eq!(VERTICAL_DEFAULT_PANEL_SIZE, 64);
        assert_eq!(HORIZONTAL_DEFAULT_PANEL_SIZE, 10);
        assert_eq!(HORIZONTAL_PANEL2_MIN_SIZE, 1);
        assert_eq!(MAX_TAB_PAGES, 16);
    }

    #[test]
    fn ctor_builds_full_tree() {
        // Single UI test (App::debug uses process-global state).
        let script = "
            Paint.Enable(false)
            Paint('layout built')
        ";
        let mut app = App::debug(80, 30, script).build().expect("debug app");
        let mut window = window!("Test,a:c,w:70,h:25,flags: Sizeable");
        let layout = build_layout(&mut window);
        assert!(layout.is_complete(), "all five controls must attach");
        app.add_window(window);
        app.run();
    }
}
