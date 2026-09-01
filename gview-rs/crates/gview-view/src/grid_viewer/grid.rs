//! `GridViewer` grid population, sorting delegation and cell export
//! (spec `02_VIEWER_GRID` §4, §5.1, §8).
//!
//! C++ anchors: `Instance::PopulateGrid`
//! (`GridViewer/Instance.cpp:219-255`), `Instance::OnEvent`
//! (`Instance.cpp:140-210`), command table
//! (`GridViewer.hpp:14-37`); `AppCUI` sort internals
//! `GridControlContext::SortColumn` / `ToggleSorting` / `Grid::Sort`
//! (`AppCUI/.../Grid.cpp:2041-2082`, `720-729`).
//!
//! Sorting is **delegated** to the grid widget (§5.1): `GViewCore`
//! calls `grid->Sort()` at the end of `PopulateGrid`. The `AppCUI`
//! behavior modeled by [`SortState`] for the Rust widget: one
//! ascending/descending flag per column (default `false` =
//! descending), flipped by a header click; `Sort()` sorts **every
//! column independently** by cell text — the `AppCUI` implementation
//! does not keep rows together (preserved quirk).

use gview_core::cache::DataCache;

use super::parse::GridContent;

/// C++ `COMMAND_ID_*` (`GridViewer.hpp:14-19`).
pub const COMMAND_ID_REPLACE_HEADER_WITH_1ST_ROW: u32 = 0x1000;
/// Toggle horizontal grid lines.
pub const COMMAND_ID_TOGGLE_HORIZONTAL_LINES: u32 = 0x1001;
/// Toggle vertical grid lines.
pub const COMMAND_ID_TOGGLE_VERTICAL_LINES: u32 = 0x1002;
/// Open the selected cell in a buffer window.
pub const COMMAND_ID_VIEW_CELL_CONTENT: u32 = 0x1003;
/// Export the selected cell to a file.
pub const COMMAND_ID_EXPORT_CELL_CONTENT: u32 = 0x1004;
/// Export the selected column to a folder.
pub const COMMAND_ID_EXPORT_COLUMN_CONTENT: u32 = 0x1005;

/// The §8 command set (Ctrl+F's find dialog is deliberately **not**
/// bound in C++ `OnKeyEvent` — no command exists for it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GridCommand {
    /// Space — `firstRowAsHeader = !firstRowAsHeader` + repopulate.
    ReplaceHeader,
    /// H — toggle horizontal lines.
    ToggleHorizontalLines,
    /// V — toggle vertical lines.
    ToggleVerticalLines,
    /// Enter — decoded cell bytes open in a buffer window.
    ViewCellContent,
    /// Ctrl+S — write the selected cell to a file.
    ExportCellContent,
    /// Ctrl+Alt+S — export all cells of the column to a folder.
    ExportColumnContent,
}

/// Maps a command bar / key command ID (C++ `OnEvent` dispatch).
#[must_use]
pub const fn command_from_id(id: u32) -> Option<GridCommand> {
    match id {
        COMMAND_ID_REPLACE_HEADER_WITH_1ST_ROW => Some(GridCommand::ReplaceHeader),
        COMMAND_ID_TOGGLE_HORIZONTAL_LINES => Some(GridCommand::ToggleHorizontalLines),
        COMMAND_ID_TOGGLE_VERTICAL_LINES => Some(GridCommand::ToggleVerticalLines),
        COMMAND_ID_VIEW_CELL_CONTENT => Some(GridCommand::ViewCellContent),
        COMMAND_ID_EXPORT_CELL_CONTENT => Some(GridCommand::ExportCellContent),
        COMMAND_ID_EXPORT_COLUMN_CONTENT => Some(GridCommand::ExportColumnContent),
        _ => None,
    }
}

/// The `AppCUI` `Grid` surface `PopulateGrid` drives (C++ calls on
/// `Reference<Grid>`); the AppCUI-rs-backed widget and test mocks
/// implement it.
pub trait GridWidget {
    /// `(columns, rows)` (C++ `GetGridDimensions`).
    fn grid_dimensions(&self) -> (u32, u32);
    /// C++ `SetGridDimensions({cols, rows})`.
    fn set_grid_dimensions(&mut self, cols: u32, rows: u32);
    /// C++ `UpdateHeaderValues`.
    fn update_header_values(&mut self, headers: Vec<String>);
    /// C++ `SetDefaultHeaderValues` (`AppCUI`: `Index`, `Column_N`).
    fn set_default_header_values(&mut self);
    /// C++ `UpdateCell(col, row, value)`.
    fn update_cell(&mut self, col: u32, row: u32, value: String);
    /// C++ `Grid::Sort()` — sorting logic is widget-internal (§5.1).
    fn sort(&mut self);
    /// C++ `ToggleHorizontalLines`.
    fn toggle_horizontal_lines(&mut self);
    /// C++ `ToggleVerticalLines`.
    fn toggle_vertical_lines(&mut self);
}

/// Reads one token range through the cache as lossy UTF-8 (spec §4
/// `decode_as_utf8_lossy`); empty and past-EOF ranges resolve to the
/// available bytes.
fn cell_text(cache: &mut DataCache, start: u64, end: u64) -> String {
    let len = end.saturating_sub(start);
    if len == 0 {
        return String::new();
    }
    let len = u32::try_from(len).unwrap_or(u32::MAX);
    cache.get(start, len, false).map_or_else(
        |_| String::new(),
        |bytes| String::from_utf8_lossy(bytes).into_owned(),
    )
}

/// C++ `Instance::PopulateGrid` (`Instance.cpp:219-255`).
///
/// Optional first-row header, dimension sync, per-cell cache reads,
/// then the widget-internal `Sort()`. The C++ column index expression
/// `row.size() - abs(distance(row.end(), itRow))` is the plain
/// enumeration index.
pub fn populate_grid(
    cache: &mut DataCache,
    content: &GridContent,
    first_row_as_header: bool,
    grid: &mut impl GridWidget,
) {
    let mut rows = content.tokens.iter().enumerate();

    if first_row_as_header {
        if let Some((_, header)) = rows.next() {
            let mut header_texts = Vec::with_capacity(header.len());
            for &(start, end) in header {
                header_texts.push(cell_text(cache, start, end));
            }
            grid.update_header_values(header_texts);
        }
    } else {
        grid.set_default_header_values();
    }

    let header_rows = u64::from(first_row_as_header);
    let data_rows = content.rows.saturating_sub(header_rows) as u32;
    if data_rows != grid.grid_dimensions().1 {
        grid.set_grid_dimensions(content.cols as u32, data_rows);
    }

    for (i, row) in rows {
        for (j, &(start, end)) in row.iter().enumerate() {
            let value = cell_text(cache, start, end);
            grid.update_cell(j as u32, (i as u64).saturating_sub(header_rows) as u32, value);
        }
    }

    grid.sort();
}

/// Per-column sort direction state (`AppCUI` `GridControlContext`:
/// `columnsSort` + `ToggleSorting` + `SortColumn`,
/// `Grid.cpp:2041-2082`).
///
/// `vector<bool>` semantics preserved: every column starts `false`
/// (**descending**); a header click flips its flag and re-sorts that
/// column.
#[derive(Clone, Debug, Default)]
pub struct SortState {
    ascending: Vec<bool>,
}

impl SortState {
    /// State for `cols` columns, all initially descending.
    #[must_use]
    pub fn new(cols: u32) -> Self {
        Self {
            ascending: vec![false; cols as usize],
        }
    }

    /// `true` when the column currently sorts ascending.
    #[must_use]
    pub fn is_ascending(&self, col: u32) -> bool {
        self.ascending.get(col as usize).copied().unwrap_or(false)
    }

    /// Header click (C++ `ToggleSorting`, `Grid.cpp:2052`): flips the
    /// column's flag and sorts that one column. Out-of-range columns
    /// are ignored.
    pub fn toggle(&mut self, col: u32, cells: &mut [Vec<String>]) {
        let Some(flag) = self.ascending.get_mut(col as usize) else {
            return;
        };
        *flag = !*flag;
        self.sort_column(col, cells);
    }

    /// C++ `SortColumn` (`Grid.cpp:2061-2082`): sorts **only** this
    /// column's cells by text — the `AppCUI` implementation does not
    /// reorder sibling columns (preserved quirk).
    pub fn sort_column(&self, col: u32, cells: &mut [Vec<String>]) {
        let Some(column) = cells.get_mut(col as usize) else {
            return;
        };
        if column.is_empty() {
            return;
        }
        if self.is_ascending(col) {
            column.sort();
        } else {
            column.sort_by(|a, b| b.cmp(a));
        }
    }

    /// C++ `Grid::Sort()` with the `Sort` flag set
    /// (`Grid.cpp:720-729`): every column sorted independently in its
    /// current direction.
    pub fn sort_all(&self, cells: &mut [Vec<String>]) {
        for col in 0..cells.len() {
            self.sort_column(col as u32, cells);
        }
    }
}

/// Cell-export errors.
#[derive(Debug)]
pub enum ExportError {
    /// The base name contains path separators or `..` (spec §11.2:
    /// no directory traversal in export filenames).
    InvalidBaseName,
    /// Filesystem failure.
    Io(std::io::Error),
}

/// C++ Ctrl+S export (`Instance.cpp:162-176`).
///
/// Writes `content` to `<dir>/<base>_<timestamp>` in binary mode and
/// returns the path. The base name is validated against directory
/// traversal (spec §11.2) — the C++ code performs no such check.
///
/// # Errors
///
/// [`ExportError::InvalidBaseName`] for a traversal-capable base
/// name; [`ExportError::Io`] when the write fails.
pub fn export_cell(
    content: &[u8],
    dir: &std::path::Path,
    base_name: &str,
    timestamp: u64,
) -> Result<std::path::PathBuf, ExportError> {
    if base_name.is_empty()
        || base_name.contains(['/', '\\'])
        || base_name.contains("..")
        || base_name.contains(':')
    {
        return Err(ExportError::InvalidBaseName);
    }
    let path = dir.join(format!("{base_name}_{timestamp}"));
    std::fs::write(&path, content).map_err(ExportError::Io)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grid_viewer::parse::{process_content, GridParseSettings};
    use gview_core::source::MemorySource;

    /// Column-major cell store mirroring the `AppCUI` grid model.
    #[derive(Default)]
    struct MockGrid {
        cols: u32,
        rows: u32,
        headers: Vec<String>,
        default_headers: bool,
        cells: Vec<(u32, u32, String)>,
        sorted: u32,
        h_lines: bool,
        v_lines: bool,
    }

    impl GridWidget for MockGrid {
        fn grid_dimensions(&self) -> (u32, u32) {
            (self.cols, self.rows)
        }
        fn set_grid_dimensions(&mut self, cols: u32, rows: u32) {
            self.cols = cols;
            self.rows = rows;
        }
        fn update_header_values(&mut self, headers: Vec<String>) {
            self.headers = headers;
            self.default_headers = false;
        }
        fn set_default_header_values(&mut self) {
            self.default_headers = true;
        }
        fn update_cell(&mut self, col: u32, row: u32, value: String) {
            self.cells.push((col, row, value));
        }
        fn sort(&mut self) {
            self.sorted = self.sorted.saturating_add(1);
        }
        fn toggle_horizontal_lines(&mut self) {
            self.h_lines = !self.h_lines;
        }
        fn toggle_vertical_lines(&mut self) {
            self.v_lines = !self.v_lines;
        }
    }

    fn parsed(data: &[u8]) -> (DataCache, GridContent) {
        let mut cache = DataCache::new(Box::new(MemorySource::from_slice(data)), 1);
        let content = process_content(&mut cache, &GridParseSettings::default());
        (cache, content)
    }

    #[test]
    fn populate_grid_fills_mock_without_header() {
        let (mut cache, content) = parsed(b"a,b\ncc,d\n");
        let mut grid = MockGrid::default();
        populate_grid(&mut cache, &content, false, &mut grid);
        assert!(grid.default_headers);
        assert_eq!((grid.cols, grid.rows), (2, 2));
        // Last-column cells carry the newline (C++ token parity).
        assert_eq!(
            grid.cells,
            vec![
                (0, 0, "a".to_owned()),
                (1, 0, "b\n".to_owned()),
                (0, 1, "cc".to_owned()),
                (1, 1, "d\n".to_owned()),
            ]
        );
        // PopulateGrid always ends with the widget-internal Sort().
        assert_eq!(grid.sorted, 1);
    }

    #[test]
    fn populate_grid_first_row_as_header() {
        let (mut cache, content) = parsed(b"name,age\nbob,7\n");
        let mut grid = MockGrid::default();
        populate_grid(&mut cache, &content, true, &mut grid);
        assert!(!grid.default_headers);
        assert_eq!(grid.headers, vec!["name".to_owned(), "age\n".to_owned()]);
        // One data row: header row consumed, row indices shift by 1.
        assert_eq!((grid.cols, grid.rows), (2, 1));
        assert_eq!(
            grid.cells,
            vec![(0, 0, "bob".to_owned()), (1, 0, "7\n".to_owned())]
        );
    }

    #[test]
    fn populate_grid_skips_resize_when_dimensions_match() {
        let (mut cache, content) = parsed(b"a,b\n");
        let mut grid = MockGrid {
            cols: 99, // stale, but rows already match → no resize (C++)
            rows: 1,
            ..MockGrid::default()
        };
        populate_grid(&mut cache, &content, false, &mut grid);
        assert_eq!(grid.cols, 99);
    }

    #[test]
    fn command_ids_map_to_actions() {
        assert_eq!(command_from_id(0x1000), Some(GridCommand::ReplaceHeader));
        assert_eq!(
            command_from_id(0x1001),
            Some(GridCommand::ToggleHorizontalLines)
        );
        assert_eq!(
            command_from_id(0x1002),
            Some(GridCommand::ToggleVerticalLines)
        );
        assert_eq!(command_from_id(0x1003), Some(GridCommand::ViewCellContent));
        assert_eq!(
            command_from_id(0x1004),
            Some(GridCommand::ExportCellContent)
        );
        assert_eq!(
            command_from_id(0x1005),
            Some(GridCommand::ExportColumnContent)
        );
        assert_eq!(command_from_id(0x0FFF), None);
    }

    #[test]
    fn sort_state_machine_toggles_per_column() {
        let mut cells = vec![
            vec!["b".to_owned(), "a".to_owned(), "c".to_owned()],
            vec!["2".to_owned(), "3".to_owned(), "1".to_owned()],
        ];
        let mut state = SortState::new(2);
        // Initial direction is descending (vector<bool> default).
        assert!(!state.is_ascending(0));
        state.sort_all(&mut cells);
        assert_eq!(cells[0], vec!["c", "b", "a"]);
        assert_eq!(cells[1], vec!["3", "2", "1"]);
        // Header click flips column 0 to ascending and re-sorts ONLY
        // that column (`AppCUI` quirk: sibling columns untouched).
        state.toggle(0, &mut cells);
        assert!(state.is_ascending(0));
        assert_eq!(cells[0], vec!["a", "b", "c"]);
        assert_eq!(cells[1], vec!["3", "2", "1"]);
        // Second click flips back to descending.
        state.toggle(0, &mut cells);
        assert!(!state.is_ascending(0));
        assert_eq!(cells[0], vec!["c", "b", "a"]);
        // Out-of-range toggle is ignored, no panic.
        state.toggle(99, &mut cells);
    }

    #[test]
    fn export_cell_writes_timestamped_file() {
        let dir = std::env::temp_dir();
        let path = export_cell(b"payload", &dir, "gview_grid_export_test", 1_234_567)
            .expect("export succeeds");
        assert!(path.ends_with("gview_grid_export_test_1234567"));
        let written = std::fs::read(&path).expect("file readable");
        assert_eq!(written, b"payload");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn export_cell_rejects_traversal_names() {
        let dir = std::env::temp_dir();
        for bad in ["../escape", "a/b", "a\\b", "", "c:evil"] {
            assert!(matches!(
                export_cell(b"x", &dir, bad, 1),
                Err(ExportError::InvalidBaseName)
            ));
        }
    }
}
