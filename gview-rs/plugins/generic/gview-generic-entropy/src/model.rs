//! Entropy visualizer model (C++ `Plugin.cpp`).
//!
//! | C++ | Rust |
//! |-----|------|
//! | `InitializeBlocksForCanvas` | [`initial_block_size`] |
//! | `DrawEntropy` loop | [`blocks_count`], [`canvas_height`], [`block_position`], [`block_values`], [`block_color`] |
//! | `ShannonEntropyValueToColor` & co. | [`shannon_value_color`], [`data_type_color`], [`data_type_name_color`], [`embedded_object_color`] |
//! | `DrawEmbeddedObjects` | [`zone_color`], [`embedded_block_colors`] |
//! | `DrawEntropyLegend` / `DrawEmbeddedObjectsLegend` | [`legend`] |
//! | `ResizeLegendCanvas` | [`legend_height`] |
//! | `OnEvent` alpha update | [`renyi_alpha_from_selector`] |
//!
//! C++ quirks kept: the Rényi alpha is `selectorValue / 10` in
//! **integer** arithmetic (so values `-9..=9` all give `0`); the
//! embedded-objects legend height is `12 + 8`; an unknown zone name
//! paints with the `Executable` color (the "bad.. TODO" default) while
//! the background of that mode is the `""` color (Gray); blocks past
//! the canvas are simply not painted.

use appcui::graphics::{Color, SpecialChar};
use gview_core::cache::DataCache;
use gview_core::zones::{Zone, ZonesList};
use gview_entropy::{compute_epsilon, renyi_entropy, shannon_entropy};

/// `BLOCK_SPECIAL_CHARACTER`.
pub const BLOCK_SPECIAL_CHARACTER: SpecialChar = SpecialChar::Block75;
/// `CANVAS_ENTROPY_BACKGROUND`.
pub const CANVAS_ENTROPY_BACKGROUND: Color = Color::Black;
/// `SHANNON_ENTROPY_MAX_VALUE`.
pub const SHANNON_ENTROPY_MAX_VALUE: u32 = 8;
/// `SHANNON_ENTROPY_DATA_TYPE_MAX_VALUE`.
pub const SHANNON_ENTROPY_DATA_TYPE_MAX_VALUE: u32 = 2;
/// `SHANNON_ENTROPY_LEGEND_DATA_TYPE_HEIGHT`.
pub const SHANNON_ENTROPY_LEGEND_DATA_TYPE_HEIGHT: u32 = 10;
/// `SHANNON_ENTROPY_LEGEND_HEIGHT`.
pub const SHANNON_ENTROPY_LEGEND_HEIGHT: u32 = 13;
/// `EMBEDDED_OBJECTS_MAX_VALUE`.
pub const EMBEDDED_OBJECTS_MAX_VALUE: u32 = 6;
/// `EMBEDDED_OBJECTS_LEGEND_HEIGHT` (`12 + 8`).
pub const EMBEDDED_OBJECTS_LEGEND_HEIGHT: u32 = 20;
/// `MINIMUM_BLOCK_SIZE`.
pub const MINIMUM_BLOCK_SIZE: u32 = 4;
/// Initial value of the block-size selector.
pub const DEFAULT_BLOCK_SIZE: u32 = 32;
/// `renyiAlpha` before the selector is touched.
pub const DEFAULT_RENYI_ALPHA: f64 = 0.5;

/// Combo-box entries (`COMBO_BOX_ITEM_*` user data), in the order the
/// C++ adds them (a separator sits after Rényi).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VisualizerMode {
    /// `"Shannon Entropy"` (0).
    ShannonEntropy,
    /// `"Renyi Entropy"` (1).
    RenyiEntropy,
    /// `"Shannon Entropy Data Type"` (2).
    ShannonEntropyDataType,
    /// `"Embedded Objects"` (3).
    EmbeddedObjects,
}

impl VisualizerMode {
    /// All modes in combo order.
    pub const ALL: [Self; 4] = [
        Self::ShannonEntropy,
        Self::RenyiEntropy,
        Self::ShannonEntropyDataType,
        Self::EmbeddedObjects,
    ];

    /// Combo caption.
    #[must_use]
    pub const fn option_name(self) -> &'static str {
        match self {
            Self::ShannonEntropy => "Shannon Entropy",
            Self::RenyiEntropy => "Renyi Entropy",
            Self::ShannonEntropyDataType => "Shannon Entropy Data Type",
            Self::EmbeddedObjects => "Embedded Objects",
        }
    }

    /// `COMBO_BOX_ITEM_*` user data.
    #[must_use]
    pub const fn item_id(self) -> u32 {
        match self {
            Self::ShannonEntropy => 0,
            Self::RenyiEntropy => 1,
            Self::ShannonEntropyDataType => 2,
            Self::EmbeddedObjects => 3,
        }
    }

    /// Mode from the combo user data.
    #[must_use]
    pub const fn from_item_id(id: u32) -> Option<Self> {
        match id {
            0 => Some(Self::ShannonEntropy),
            1 => Some(Self::RenyiEntropy),
            2 => Some(Self::ShannonEntropyDataType),
            3 => Some(Self::EmbeddedObjects),
            _ => None,
        }
    }

    /// The `EntropyType` the drawing uses (`None` for embedded
    /// objects).
    #[must_use]
    pub const fn entropy_type(self) -> Option<EntropyType> {
        match self {
            Self::ShannonEntropy => Some(EntropyType::Shannon),
            Self::RenyiEntropy => Some(EntropyType::Renyi),
            Self::ShannonEntropyDataType => Some(EntropyType::ShannonDataType),
            Self::EmbeddedObjects => None,
        }
    }

    /// Whether a separator precedes this entry in the combo.
    #[must_use]
    pub const fn separator_before(self) -> bool {
        matches!(self, Self::ShannonEntropyDataType)
    }
}

/// C++ `EntropyType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyType {
    /// `Shannon = 0`.
    Shannon,
    /// `ShannonDataType = 1`.
    ShannonDataType,
    /// `Renyi = 2`.
    Renyi,
}

/// `ShannonEntropyValueToColor(int32)`: the 0–8 palette (negative →
/// Black, above 8 → Pink).
#[must_use]
pub const fn shannon_value_color(value: i32) -> Color {
    match value {
        0 => Color::White,
        1 => Color::Silver,
        2 => Color::Gray,
        3 => Color::Olive,
        4 => Color::Yellow,
        5 => Color::DarkGreen,
        6 => Color::DarkRed,
        7 => Color::Magenta,
        8 => Color::Red,
        v if v < 0 => Color::Black,
        _ => Color::Pink,
    }
}

/// `ShannonEntropyDataTypeValueToColor(value, epsilon)`.
#[must_use]
pub fn data_type_color(value: f64, epsilon: f64) -> Color {
    if value >= 8.0 - epsilon && value < 8.0 {
        Color::Green
    } else if value > 6.0 && value < 8.0 - epsilon {
        Color::Red
    } else {
        Color::Gray
    }
}

/// Data-type legend names.
pub const DATA_TYPE_NAMES: [&str; 3] = ["Plain", "Binary", "Encrypted"];

/// `ShannonEntropyDataTypeValueToColorName(name)`.
#[must_use]
pub fn data_type_name_color(name: &str) -> Color {
    match name {
        "Plain" => Color::Gray,
        "Binary" => Color::Red,
        "Encrypted" => Color::Green,
        _ => Color::Black,
    }
}

/// Embedded-object legend names.
pub const EMBEDDED_OBJECT_NAMES: [&str; 7] = [
    "Archive",
    "Cryptographic",
    "Executable",
    "HTML Object",
    "Image",
    "Multimedia",
    "Special Strings",
];

/// `EmbeddedObjectValueToColor(name)` (unknown → Gray).
#[must_use]
pub fn embedded_object_color(name: &str) -> Color {
    match name {
        "Archive" => Color::White,
        "Cryptographic" => Color::Silver,
        "Executable" => Color::Red,
        "HTML Object" => Color::Olive,
        "Image" => Color::Yellow,
        "Multimedia" => Color::DarkGreen,
        "Special Strings" => Color::Aqua,
        _ => Color::Gray,
    }
}

/// The `DrawEmbeddedObjects` zone-name mapping: a `BufferViewer`
/// highlighting zone name → embedded-object category (unknown names
/// fall back to `Executable`, as the C++ default does).
#[must_use]
pub const fn zone_category(zone_name: &str) -> &'static str {
    match zone_name.as_bytes() {
        b"Email Address" | b"Filepath" | b"IP Address" | b"Registry" | b"URL" | b"Wallet" => "Special Strings",
        b"IFrame" | b"PHP" | b"Script" | b"XML" => "HTML Object",
        b"PNG" => "Image",
        _ => "Executable",
    }
}

/// Color a highlighting zone paints with.
#[must_use]
pub fn zone_color(zone_name: &str) -> Color {
    embedded_object_color(zone_category(zone_name))
}

/// `InitializeBlocksForCanvas`: doubles the block size from
/// [`MINIMUM_BLOCK_SIZE`] until the blocks fit in `canvas_height`
/// rows of `canvas_width` blocks.
#[must_use]
pub fn initial_block_size(object_size: u64, canvas_width: u32, canvas_height: u32) -> u32 {
    let width = u64::from(canvas_width.max(1));
    let mut block_size: u64 = u64::from(MINIMUM_BLOCK_SIZE);
    loop {
        let blocks = object_size.checked_div(block_size).unwrap_or(0);
        let rows = blocks.checked_div(width).unwrap_or(0).saturating_add(1);
        let next = block_size.saturating_mul(2);
        if rows <= u64::from(canvas_height) || next > u64::from(u32::MAX) {
            return block_size as u32;
        }
        block_size = next;
    }
}

/// `size / blockSize + 1`.
#[must_use]
pub fn blocks_count(object_size: u64, block_size: u32) -> u32 {
    object_size
        .checked_div(u64::from(block_size))
        .unwrap_or(0)
        .saturating_add(1)
        .min(u64::from(u32::MAX)) as u32
}

/// `max(blocksCount / maxX + 1 + 1, canvasHeight)`.
#[must_use]
pub fn canvas_height(blocks: u32, max_x: u32, current_height: u32) -> u32 {
    blocks
        .checked_div(max_x)
        .unwrap_or(0)
        .saturating_add(2)
        .max(current_height)
}

/// `(x, y)` of block `index` when rows wrap at `max_x`.
#[must_use]
pub fn block_position(index: u32, max_x: u32) -> (u32, u32) {
    let max_x = max_x.max(1);
    (
        index.checked_rem(max_x).unwrap_or(0),
        index.checked_div(max_x).unwrap_or(0),
    )
}

/// `alphaSelector->GetValue() / 10` — integer division, then widened.
#[must_use]
#[allow(clippy::cast_precision_loss)] // |value| <= 99 by the selector range
pub const fn renyi_alpha_from_selector(value: i64) -> f64 {
    (value / 10) as f64
}

/// Entropy of every block (`DrawEntropy`'s value loop): blocks past
/// the end read as empty (`0.0`).
pub fn block_values(cache: &mut DataCache, block_size: u32, kind: EntropyType, renyi_alpha: f64) -> Vec<f64> {
    let block_size = block_size.max(1);
    let count = blocks_count(cache.size(), block_size);
    let mut values = Vec::with_capacity(count as usize);
    for i in 0..count {
        let offset = u64::from(i).saturating_mul(u64::from(block_size));
        let value = cache.get(offset, block_size, false).map_or(0.0, |bytes| match kind {
            EntropyType::Shannon | EntropyType::ShannonDataType => shannon_entropy(bytes),
            EntropyType::Renyi => renyi_entropy(bytes, renyi_alpha),
        });
        values.push(value);
    }
    values
}

/// Foreground color of one block (`DrawEntropy`'s color switch);
/// `epsilon` is `ComputeEpsilon(blockSize)`.
#[must_use]
pub fn block_color(kind: EntropyType, value: f64, epsilon: f64) -> Color {
    match kind {
        EntropyType::Shannon | EntropyType::Renyi => shannon_value_color(value.round() as i32),
        EntropyType::ShannonDataType => data_type_color(value, epsilon),
    }
}

/// Colors of every block for an entropy mode.
pub fn entropy_block_colors(cache: &mut DataCache, block_size: u32, kind: EntropyType, renyi_alpha: f64) -> Vec<Color> {
    let epsilon = compute_epsilon(block_size.max(1) as usize);
    block_values(cache, block_size, kind, renyi_alpha)
        .into_iter()
        .map(|v| block_color(kind, v, epsilon))
        .collect()
}

/// `DrawEmbeddedObjects`: every block starts as the `""` color and each
/// zone paints `low / blockSize ..= high / blockSize` with its
/// category color, later zones overwriting earlier ones.
#[must_use]
pub fn embedded_block_colors<'a>(zones: impl IntoIterator<Item = &'a Zone>, object_size: u64, block_size: u32) -> Vec<Color> {
    let block_size = u64::from(block_size.max(1));
    let count = blocks_count(object_size, block_size as u32) as usize;
    let mut colors = vec![embedded_object_color(""); count];
    for zone in zones {
        let start = zone.low.checked_div(block_size).unwrap_or(0);
        let end = zone.high.checked_div(block_size).unwrap_or(0);
        let color = zone_color(&zone.name);
        let mut block = start;
        while block <= end {
            match usize::try_from(block).ok().and_then(|b| colors.get_mut(b)) {
                Some(slot) => *slot = color,
                None => break,
            }
            block = block.saturating_add(1);
        }
    }
    colors
}

/// All zones of a [`ZonesList`] in index order.
pub fn zones_of(list: &ZonesList) -> impl Iterator<Item = &Zone> {
    (0..).map_while(move |i| list.zone(i))
}

/// One legend row: a caption line followed by a full-width strip of
/// blocks in `color` (the C++ writes the caption at `y` and the strip
/// at `y + 1`), or a plain text line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegendRow {
    /// `WriteSingleLineText` + horizontal line (the title).
    Title(&'static str),
    /// `"<digit> => "` followed by a strip on the same line.
    InlineStrip {
        /// Text at the line start.
        caption: String,
        /// Strip color.
        color: Color,
    },
    /// Caption on one line, strip on the next.
    NamedStrip {
        /// Category name.
        caption: &'static str,
        /// Strip color.
        color: Color,
    },
}

/// Legend title per mode (`"Shanon"` spelling verbatim).
#[must_use]
pub const fn legend_title(mode: VisualizerMode) -> &'static str {
    match mode {
        VisualizerMode::ShannonEntropy => "Shanon Legend [0-8]",
        VisualizerMode::ShannonEntropyDataType => "Shanon Data Type Legend",
        VisualizerMode::RenyiEntropy => "Renyi Legend [0-8]",
        VisualizerMode::EmbeddedObjects => "Embedded objects",
    }
}

/// `DrawEntropyLegend` / `DrawEmbeddedObjectsLegend` rows.
#[must_use]
pub fn legend(mode: VisualizerMode) -> Vec<LegendRow> {
    let mut rows = vec![LegendRow::Title(legend_title(mode))];
    match mode {
        VisualizerMode::ShannonEntropy | VisualizerMode::RenyiEntropy => {
            for i in 0..=SHANNON_ENTROPY_MAX_VALUE {
                rows.push(LegendRow::InlineStrip {
                    caption: format!("{i} => "),
                    color: shannon_value_color(i32::try_from(i).unwrap_or(i32::MAX)),
                });
            }
        }
        VisualizerMode::ShannonEntropyDataType => {
            for name in DATA_TYPE_NAMES {
                rows.push(LegendRow::NamedStrip {
                    caption: name,
                    color: data_type_name_color(name),
                });
            }
        }
        VisualizerMode::EmbeddedObjects => {
            for name in EMBEDDED_OBJECT_NAMES {
                rows.push(LegendRow::NamedStrip {
                    caption: name,
                    color: embedded_object_color(name),
                });
            }
            rows.push(LegendRow::NamedStrip {
                caption: "Unknown",
                color: embedded_object_color(""),
            });
        }
    }
    rows
}

/// `ResizeLegendCanvas`: the legend height for a mode (`None` keeps
/// the current height — the Rényi entry is not resized in C++).
#[must_use]
pub const fn legend_height(mode: VisualizerMode) -> Option<u32> {
    match mode {
        VisualizerMode::ShannonEntropy => Some(SHANNON_ENTROPY_LEGEND_HEIGHT),
        VisualizerMode::ShannonEntropyDataType => Some(SHANNON_ENTROPY_LEGEND_DATA_TYPE_HEIGHT),
        VisualizerMode::EmbeddedObjects => Some(EMBEDDED_OBJECTS_LEGEND_HEIGHT),
        VisualizerMode::RenyiEntropy => None,
    }
}

/// Window state (`Plugin` members).
#[derive(Clone, Debug, PartialEq)]
pub struct EntropyView {
    /// Selected combo entry.
    pub mode: VisualizerMode,
    /// `blockSize`.
    pub block_size: u32,
    /// `renyiAlpha`.
    pub renyi_alpha: f64,
}

impl EntropyView {
    /// Initial state: Shannon mode, block size from
    /// [`initial_block_size`], alpha `0.5`.
    #[must_use]
    pub fn new(object_size: u64, canvas_width: u32, canvas_height: u32) -> Self {
        Self {
            mode: VisualizerMode::ShannonEntropy,
            block_size: initial_block_size(object_size, canvas_width, canvas_height),
            renyi_alpha: DEFAULT_RENYI_ALPHA,
        }
    }

    /// `NumericSelectorValueChanged` on the block-size selector
    /// (clamped to [`MINIMUM_BLOCK_SIZE`]).
    pub const fn set_block_size(&mut self, value: u32) {
        self.block_size = if value < MINIMUM_BLOCK_SIZE {
            MINIMUM_BLOCK_SIZE
        } else {
            value
        };
    }

    /// `NumericSelectorValueChanged` on the alpha selector.
    pub const fn set_alpha_selector(&mut self, value: i64) {
        self.renyi_alpha = renyi_alpha_from_selector(value);
    }

    /// Block colors for the current mode; `zones` feeds the
    /// embedded-objects mode (the `Buffer View` highlighting zones,
    /// `None` when another view is active → nothing to draw).
    pub fn block_colors(&self, cache: &mut DataCache, zones: Option<&ZonesList>) -> Vec<Color> {
        match self.mode.entropy_type() {
            Some(kind) => entropy_block_colors(cache, self.block_size, kind, self.renyi_alpha),
            None => zones.map_or_else(Vec::new, |z| embedded_block_colors(zones_of(z), cache.size(), self.block_size)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::graphics::CharAttribute;
    use gview_core::source::MemorySource;

    fn cache_over(data: &[u8]) -> DataCache {
        DataCache::new(Box::new(MemorySource::from_slice(data)), 0)
    }

    #[test]
    fn block_size_min_4_and_doubling() {
        assert_eq!(initial_block_size(0, 80, 20), 4);
        assert_eq!(initial_block_size(100, 80, 20), 4);
        // 100_000 bytes on an 80x20 canvas: 4 → rows 313; 8 → 157; 16 → 79;
        // 32 → 40; 64 → 20 rows fit.
        assert_eq!(initial_block_size(100_000, 80, 20), 64);
        assert_eq!(initial_block_size(100_000, 0, 0), initial_block_size(100_000, 1, 0));
        let mut view = EntropyView::new(100_000, 80, 20);
        assert_eq!(view.block_size, 64);
        assert_eq!(view.mode, VisualizerMode::ShannonEntropy);
        view.set_block_size(1);
        assert_eq!(view.block_size, MINIMUM_BLOCK_SIZE);
        view.set_block_size(1000);
        assert_eq!(view.block_size, 1000);
    }

    #[test]
    fn block_layout() {
        assert_eq!(blocks_count(0, 32), 1);
        assert_eq!(blocks_count(64, 32), 3);
        assert_eq!(blocks_count(65, 32), 3);
        assert_eq!(canvas_height(3, 80, 20), 20);
        assert_eq!(canvas_height(1000, 80, 5), 14);
        assert_eq!(block_position(0, 80), (0, 0));
        assert_eq!(block_position(79, 80), (79, 0));
        assert_eq!(block_position(80, 80), (0, 1));
        assert_eq!(block_position(5, 0), (0, 5));
    }

    #[test]
    fn palette_and_classification() {
        assert_eq!(shannon_value_color(0), Color::White);
        assert_eq!(shannon_value_color(8), Color::Red);
        assert_eq!(shannon_value_color(-1), Color::Black);
        assert_eq!(shannon_value_color(9), Color::Pink);
        let eps = compute_epsilon(32);
        assert_eq!(data_type_color(7.9, eps), Color::Green);
        // epsilon(32) = 1.7 → the binary band is 6.0 < v < 6.3.
        assert_eq!(data_type_color(6.1, eps), Color::Red);
        assert_eq!(data_type_color(6.5, eps), Color::Green);
        assert_eq!(data_type_color(2.0, eps), Color::Gray);
        assert_eq!(data_type_color(8.0, eps), Color::Gray);
        assert_eq!(data_type_name_color("Encrypted"), Color::Green);
        assert_eq!(data_type_name_color("x"), Color::Black);
        assert_eq!(block_color(EntropyType::Shannon, 4.4, eps), Color::Yellow);
        assert_eq!(block_color(EntropyType::Renyi, 4.6, eps), Color::DarkGreen);
        assert_eq!(block_color(EntropyType::ShannonDataType, 7.9, eps), Color::Green);
    }

    #[test]
    fn block_values_over_cache() {
        let mut data = vec![0u8; 64];
        data.extend(0..64u8);
        let mut cache = cache_over(&data);
        let values = block_values(&mut cache, 64, EntropyType::Shannon, 0.5);
        assert_eq!(values.len(), 3);
        assert!(values.first().is_some_and(|v| v.abs() < 1e-9));
        assert!(values.get(1).is_some_and(|v| (v - 6.0).abs() < 1e-9));
        assert!(values.get(2).is_some_and(|v| v.abs() < 1e-9), "past the end reads as empty");
        let colors = entropy_block_colors(&mut cache, 64, EntropyType::Shannon, 0.5);
        assert_eq!(colors, vec![Color::White, Color::DarkRed, Color::White]);
        let renyi = block_values(&mut cache, 64, EntropyType::Renyi, 2.0);
        assert!(renyi.get(1).is_some_and(|v| (v - 6.0).abs() < 1e-9));
    }

    #[test]
    fn zone_color_mode() {
        assert_eq!(zone_category("URL"), "Special Strings");
        assert_eq!(zone_category("PNG"), "Image");
        assert_eq!(zone_category("XML"), "HTML Object");
        assert_eq!(zone_category("MZPE"), "Executable");
        assert_eq!(zone_category("whatever"), "Executable");
        assert_eq!(zone_color("IP Address"), Color::Aqua);
        assert_eq!(embedded_object_color(""), Color::Gray);
        assert_eq!(embedded_object_color("Multimedia"), Color::DarkGreen);

        let mut zones = ZonesList::new();
        zones.add(0, 63, CharAttribute::default(), "PNG");
        zones.add(100, 131, CharAttribute::default(), "URL");
        zones.add(120, 125, CharAttribute::default(), "Mystery");
        let colors = embedded_block_colors(zones_of(&zones), 200, 32);
        // blocks: 0..=6 (200/32 + 1)
        assert_eq!(colors.len(), 7);
        assert_eq!(colors.first(), Some(&Color::Yellow));
        assert_eq!(colors.get(1), Some(&Color::Yellow));
        assert_eq!(colors.get(2), Some(&Color::Gray));
        // "URL" covers blocks 3..=4, then "Mystery" repaints block 3.
        assert_eq!(colors.get(3), Some(&Color::Red));
        assert_eq!(colors.get(4), Some(&Color::Aqua));
        assert_eq!(colors.get(6), Some(&Color::Gray));
        // A zone past the end is clipped.
        let mut far = ZonesList::new();
        far.add(1000, 5000, CharAttribute::default(), "PNG");
        assert_eq!(embedded_block_colors(zones_of(&far), 200, 32).len(), 7);

        let mut cache = cache_over(&[0u8; 200]);
        let mut view = EntropyView::new(200, 80, 20);
        view.mode = VisualizerMode::EmbeddedObjects;
        view.set_block_size(32);
        assert_eq!(view.block_colors(&mut cache, Some(&zones)), colors);
        assert!(view.block_colors(&mut cache, None).is_empty());
        view.mode = VisualizerMode::ShannonEntropy;
        assert_eq!(view.block_colors(&mut cache, None).len(), 7);
    }

    #[test]
    fn legend_rows_and_heights() {
        let shannon = legend(VisualizerMode::ShannonEntropy);
        assert_eq!(shannon.len(), 10);
        assert_eq!(shannon.first(), Some(&LegendRow::Title("Shanon Legend [0-8]")));
        assert_eq!(
            shannon.get(1),
            Some(&LegendRow::InlineStrip {
                caption: "0 => ".to_owned(),
                color: Color::White
            })
        );
        let data_type = legend(VisualizerMode::ShannonEntropyDataType);
        assert_eq!(data_type.len(), 4);
        let embedded = legend(VisualizerMode::EmbeddedObjects);
        assert_eq!(embedded.len(), 9);
        assert_eq!(
            embedded.last(),
            Some(&LegendRow::NamedStrip {
                caption: "Unknown",
                color: Color::Gray
            })
        );
        assert_eq!(legend_title(VisualizerMode::RenyiEntropy), "Renyi Legend [0-8]");
        assert_eq!(legend_height(VisualizerMode::ShannonEntropy), Some(13));
        assert_eq!(legend_height(VisualizerMode::ShannonEntropyDataType), Some(10));
        assert_eq!(legend_height(VisualizerMode::EmbeddedObjects), Some(20));
        assert_eq!(legend_height(VisualizerMode::RenyiEntropy), None);
    }

    #[test]
    fn combo_and_alpha_quirk() {
        for mode in VisualizerMode::ALL {
            assert_eq!(VisualizerMode::from_item_id(mode.item_id()), Some(mode));
        }
        assert_eq!(VisualizerMode::from_item_id(9), None);
        assert!(VisualizerMode::ShannonEntropyDataType.separator_before());
        assert_eq!(VisualizerMode::RenyiEntropy.option_name(), "Renyi Entropy");
        assert_eq!(VisualizerMode::EmbeddedObjects.entropy_type(), None);
        // Integer division: 5 / 10 == 0, 25 / 10 == 2, -15 / 10 == -1.
        assert!((renyi_alpha_from_selector(5) - 0.0).abs() < f64::EPSILON);
        assert!((renyi_alpha_from_selector(25) - 2.0).abs() < f64::EPSILON);
        assert!((renyi_alpha_from_selector(-15) + 1.0).abs() < f64::EPSILON);
        let mut view = EntropyView::new(10, 80, 20);
        assert!((view.renyi_alpha - 0.5).abs() < f64::EPSILON);
        view.set_alpha_selector(30);
        assert!((view.renyi_alpha - 3.0).abs() < f64::EPSILON);
    }
}
