//! UI-free panel content model (spec `00_APP §5.4.1`, design decision
//! `§0.3 D3`).
//!
//! The C++ panels (`Types/PE/src/Panels/Information.cpp`,
//! `Types/PE/src/Panels/Sections.cpp`, …) are `TabPage` subclasses that
//! build `AppCUI` `ListView`s directly from the parsed file state. That
//! is impossible in the Rust port: [`TypePlugin`](crate::type_plugin::TypePlugin)
//! is `Send + Sync` while every `AppCUI` control is `!Send`, and
//! plugins must not link the UI crate at all (`D2`/`D3`).
//!
//! Instead a plugin returns *content*:
//!
//! | C++ panel shape | Rust |
//! |-----------------|------|
//! | `ListView` with `n:Field,w:30` + `n:Value,w:100` (`Information`) | [`PanelContent::KeyValue`] |
//! | `ListView` with N declared columns (`Sections`, `Imports`, …) | [`PanelContent::Table`] |
//!
//! The shell (`gview-app`'s `panel_mount`) turns the content into the
//! actual `ListView` exactly once, at mount time; nothing here
//! allocates during paint.
//!
//! Panel ids are `"<format>.<panel>"` in lowercase ASCII, e.g.
//! `"pe.information"`, `"zip.information"`. A plugin returns [`None`]
//! for every id it does not implement (including ids belonging to other
//! formats), and the shell falls back to the generic `Information`
//! panel described in `00_APP §5.4.2`.


/// Horizontal alignment of a table column, mirroring the `a:` field of
/// the `AppCUI` column layout string used by the C++ panels
/// (`"n:FilePoz,a:r,w:12"`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Align {
    /// `a:l` — the C++ default when no `a:` field is present.
    #[default]
    Left,
    /// `a:c`.
    Center,
    /// `a:r`.
    Right,
}

impl Align {
    /// The single-letter `AppCUI` layout code (`l`, `c`, `r`).
    #[must_use]
    pub const fn layout_code(self) -> char {
        match self {
            Self::Left => 'l',
            Self::Center => 'c',
            Self::Right => 'r',
        }
    }
}

impl core::fmt::Display for Align {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Left => "Left",
            Self::Center => "Center",
            Self::Right => "Right",
        })
    }
}

/// One column of a [`PanelContent::Table`] (`n:<caption>,a:<align>,w:<width>`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ColumnDef {
    /// Column caption as shown in the header.
    pub caption: String,
    /// Column width in cells.
    pub width: u16,
    /// Horizontal alignment of the cell text.
    pub align: Align,
}

impl ColumnDef {
    /// A left-aligned column.
    #[must_use]
    pub fn new(caption: impl Into<String>, width: u16) -> Self {
        Self {
            caption: caption.into(),
            width,
            align: Align::Left,
        }
    }

    /// A column with an explicit alignment.
    #[must_use]
    pub fn aligned(caption: impl Into<String>, width: u16, align: Align) -> Self {
        Self {
            caption: caption.into(),
            width,
            align,
        }
    }
}

/// The content of one plugin panel.
///
/// `Clone + Debug + PartialEq + Send` so the value can be produced on a
/// background worker, compared in tests and moved onto the UI thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PanelContent {
    /// Two-column `Field` / `Value` list — the C++ `Information`
    /// panels. Order is significant: it is the exact order in which the
    /// C++ `UpdateGeneralInformation` calls `AddItem`.
    KeyValue(Vec<(String, String)>),
    /// N-column table — `Sections`, `Imports`, `Exports`, `Resources`, …
    ///
    /// Every row is expected to hold `columns.len()` cells; the shell
    /// tolerates shorter rows by rendering the missing cells as empty
    /// and ignores extra cells, so a truncated parse never panics.
    Table {
        /// Column headers, left to right.
        columns: Vec<ColumnDef>,
        /// Row cells, in column order.
        rows: Vec<Vec<String>>,
    },
}

impl PanelContent {
    /// Builds a [`PanelContent::KeyValue`] from any iterator of pairs.
    pub fn key_value<K, V, I>(rows: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        Self::KeyValue(rows.into_iter().map(|(k, v)| (k.into(), v.into())).collect())
    }

    /// Number of rows in either shape.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::KeyValue(rows) => rows.len(),
            Self::Table { rows, .. } => rows.len(),
        }
    }

    /// `true` when the panel has no rows (the shell then still shows
    /// the panel, with an empty list, exactly like C++ does after a
    /// `DeleteAllItems` with nothing to add).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The column definitions the shell must create: the fixed
    /// `Field` / `Value` pair for [`Self::KeyValue`] (C++
    /// `"n:Field,w:30"`, `"n:Value,w:100"`), or the declared columns.
    #[must_use]
    pub fn columns(&self) -> Vec<ColumnDef> {
        match self {
            Self::KeyValue(_) => vec![ColumnDef::new("Field", 30), ColumnDef::new("Value", 100)],
            Self::Table { columns, .. } => columns.clone(),
        }
    }
}

/// C++ `AppCUI::Utils::NumericFormatter` parity helpers, shared by
/// every type plugin's [`PanelContent`] builder.
///
/// The C++ panels format values with two `NumericFormat` presets that
/// recur verbatim across `Types/*/src/Panels/Information.cpp`:
///
/// | C++ | Here |
/// |-----|------|
/// | `{ NumericFormatFlags::None, 10, 3, ',' }` | [`dec`] |
/// | `{ NumericFormatFlags::HexPrefix, 16 }` | [`hex`] |
/// | `{ NumericFormatFlags::HexPrefix, 16, 0, ' ', N }` | [`hex_digits`] |
///
/// `NumericFormatter` emits **upper-case** hex digits
/// (`NumericFormatter.cpp` `BaseLettersUpperCase`) with no leading
/// zeros unless `DigitsCount` asks for them, and groups decimal digits
/// from the right.
pub mod fmt {
    /// C++ `nf.ToString(v, { None, 10, 3, ',' })` — decimal grouped in
    /// threes: `1024` → `1,024`.
    #[must_use]
    pub fn dec(value: u64) -> String {
        let digits = value.to_string();
        let bytes = digits.as_bytes();
        // 3 digits + 1 separator per group, +3 for the leftover group.
        let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
        for (index, byte) in bytes.iter().enumerate() {
            let remaining = bytes.len().saturating_sub(index);
            if index > 0 && remaining % 3 == 0 {
                out.push(',');
            }
            out.push(char::from(*byte));
        }
        out
    }

    /// C++ `nf.ToString(v, { None, 10, 3, ',' })` for a **signed**
    /// value: `ToStringSigned` prefixes a minus sign and groups the
    /// magnitude (`NumericFormatter.cpp:298-310`).
    #[must_use]
    pub fn dec_signed(value: i64) -> String {
        if value < 0 {
            format!("-{}", dec(value.unsigned_abs()))
        } else {
            dec(value.unsigned_abs())
        }
    }

    /// C++ `nf.ToString(v, { HexPrefix, 16 })` — `0x` plus upper-case
    /// hex with no padding: `1024` → `0x400`.
    #[must_use]
    pub fn hex(value: u64) -> String {
        format!("{value:#X}").replacen("0X", "0x", 1)
    }

    /// C++ `nf.ToString(v, { HexPrefix, 16, 0, ' ', digits })` — as
    /// [`hex`] but zero-padded to at least `digits` hex digits.
    #[must_use]
    pub fn hex_digits(value: u64, digits: usize) -> String {
        let body = format!("{value:X}");
        let pad = digits.saturating_sub(body.len());
        let mut out = String::with_capacity(body.len().saturating_add(pad).saturating_add(2));
        out.push_str("0x");
        for _ in 0..pad {
            out.push('0');
        }
        out.push_str(&body);
        out
    }

    /// C++ `printf("%-<width>s", text)` — left-justified in `width`
    /// columns, never truncated (`printf` does not truncate either).
    #[must_use]
    pub fn pad(text: &str, width: usize) -> String {
        let mut out = String::with_capacity(width.max(text.len()));
        out.push_str(text);
        for _ in 0..width.saturating_sub(text.chars().count()) {
            out.push(' ');
        }
        out
    }

    /// The `"%-<width>s (%s)"` pattern the ELF / Mach-O / ZIP / PCAP
    /// panels use for every numeric field: the decimal form padded to
    /// `width`, then the hex form in parentheses.
    #[must_use]
    pub fn dec_and_hex(value: u64, width: usize) -> String {
        format!("{} ({})", pad(&dec(value), width), hex(value))
    }
}

#[cfg(test)]
mod tests {
    use super::{Align, ColumnDef, PanelContent};
    use crate::type_plugin::{
        KeyRegistry, PluginError, PluginMetadata, SelectionZone, TypePlugin, WindowHandle,
    };
    use serde_json::Value as JsonValue;

    /// Compile-time proof of the `Send` (and `Sync`) requirement from
    /// `00_APP §5.4.1` — the content may be produced off the UI thread.
    const fn assert_send_sync<T: Send + Sync>() {}
    const _: () = assert_send_sync::<PanelContent>();
    const _: () = assert_send_sync::<ColumnDef>();
    const _: () = assert_send_sync::<Align>();

    /// A plugin that implements exactly one panel id, like the real
    /// type plugins do.
    struct MockPlugin;

    impl TypePlugin for MockPlugin {
        fn name(&self) -> &'static str {
            "MOCK"
        }

        fn validate(_buf: &[u8], _extension: &str) -> bool {
            true
        }

        fn create_instance() -> Box<Self> {
            Box::new(Self)
        }

        fn metadata() -> PluginMetadata {
            PluginMetadata::default()
        }

        fn populate_window(&self, _win: &mut dyn WindowHandle) -> Result<(), PluginError> {
            Ok(())
        }

        fn run_command(&mut self, _command: &str) {}

        fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}

        fn smart_assistant_context(
            &self,
            _prompt: &str,
            _display: &str,
        ) -> Result<JsonValue, PluginError> {
            Ok(JsonValue::Null)
        }

        fn panel_content(&self, panel_id: &str) -> Option<PanelContent> {
            if panel_id == "mock.information" {
                Some(PanelContent::key_value([
                    ("File", "sample.bin"),
                    ("Size", "1,024 bytes"),
                ]))
            } else {
                None
            }
        }
    }

    #[test]
    fn panel_content_known_id_returns_key_value() {
        let plugin = MockPlugin;
        let content = plugin.panel_content("mock.information").expect("panel");
        assert_eq!(
            content,
            PanelContent::KeyValue(vec![
                ("File".to_owned(), "sample.bin".to_owned()),
                ("Size".to_owned(), "1,024 bytes".to_owned()),
            ])
        );
        assert_eq!(content.len(), 2);
        assert!(!content.is_empty());
    }

    #[test]
    fn panel_content_unknown_id_returns_none() {
        let plugin = MockPlugin;
        assert!(plugin.panel_content("mock.sections").is_none());
        assert!(plugin.panel_content("").is_none());
        assert!(plugin.panel_content("pe.information").is_none());
    }

    #[test]
    fn default_panel_content_is_none() {
        /// A plugin that never overrides `panel_content`.
        struct Bare;

        impl TypePlugin for Bare {
            fn name(&self) -> &'static str {
                "BARE"
            }
            fn validate(_buf: &[u8], _extension: &str) -> bool {
                false
            }
            fn create_instance() -> Box<Self> {
                Box::new(Self)
            }
            fn metadata() -> PluginMetadata {
                PluginMetadata::default()
            }
            fn populate_window(&self, _win: &mut dyn WindowHandle) -> Result<(), PluginError> {
                Ok(())
            }
            fn run_command(&mut self, _command: &str) {}
            fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}
            fn smart_assistant_context(
                &self,
                _prompt: &str,
                _display: &str,
            ) -> Result<JsonValue, PluginError> {
                Ok(JsonValue::Null)
            }
        }

        assert!(Bare.panel_content("bare.information").is_none());
        assert_eq!(Bare.selection_zones_count(), 0);
        assert_eq!(Bare.selection_zone(0), SelectionZone::default());
    }

    #[test]
    fn key_value_columns_match_cpp_information_panel() {
        let content = PanelContent::KeyValue(Vec::new());
        assert!(content.is_empty());
        assert_eq!(
            content.columns(),
            vec![ColumnDef::new("Field", 30), ColumnDef::new("Value", 100)]
        );
    }

    #[test]
    fn table_columns_are_returned_verbatim() {
        let columns = vec![
            ColumnDef::new("Name", 8),
            ColumnDef::aligned("FilePoz", 12, Align::Right),
        ];
        let content = PanelContent::Table {
            columns: columns.clone(),
            rows: vec![vec![".text".to_owned(), "0x400".to_owned()]],
        };
        assert_eq!(content.columns(), columns);
        assert_eq!(content.len(), 1);
    }

    #[test]
    fn align_layout_codes_match_appcui() {
        assert_eq!(Align::default(), Align::Left);
        assert_eq!(Align::Left.layout_code(), 'l');
        assert_eq!(Align::Center.layout_code(), 'c');
        assert_eq!(Align::Right.layout_code(), 'r');
        assert_eq!(Align::Right.to_string(), "Right");
    }

    #[test]
    fn numeric_formatting_matches_appcui() {
        use super::fmt;
        assert_eq!(fmt::dec(0), "0");
        assert_eq!(fmt::dec(999), "999");
        assert_eq!(fmt::dec(1_024), "1,024");
        assert_eq!(fmt::dec(1_000_000), "1,000,000");
        assert_eq!(fmt::dec(u64::MAX), "18,446,744,073,709,551,615");
        assert_eq!(fmt::hex(0), "0x0");
        assert_eq!(fmt::hex(0x400), "0x400");
        assert_eq!(fmt::hex(0x00AB_CDEF), "0xABCDEF");
        assert_eq!(fmt::hex_digits(4, 4), "0x0004");
        assert_eq!(fmt::hex_digits(0xA1B2_C3D4, 4), "0xA1B2C3D4", "never truncated");
        assert_eq!(fmt::pad("abc", 6), "abc   ");
        assert_eq!(fmt::pad("abcdefg", 3), "abcdefg", "printf does not truncate");
        assert_eq!(fmt::dec_and_hex(1_024, 14), "1,024          (0x400)");
    }

    #[test]
    fn panel_content_is_clonable_and_comparable() {
        let content = PanelContent::key_value([("a", "b")]);
        let clone = content.clone();
        assert_eq!(content, clone);
        assert_ne!(content, PanelContent::key_value([("a", "c")]));
    }
}
