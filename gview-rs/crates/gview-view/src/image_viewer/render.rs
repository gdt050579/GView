//! `ImageViewer` scaling and terminal rendering
//! (spec `02_VIEWER_IMAGE` §4–§5: half-block `Paint_SmallBlocks`, not
//! Braille).
//!
//! C++ anchors: `Instance::NextPreviousScale`
//! (`ImageViewer/Instance.cpp:38-59`), `Paint_SmallBlocks`
//! (`Renderer.cpp:1492-1522`), `Paint_LargeBlocks`
//! (`Renderer.cpp:1523-1545`), `Paint_GrayScale`
//! (`Renderer.cpp:1546-1566`), `PixelTo64Color`
//! (`Renderer.cpp:1428-1476`), `PixelToGrayScaleCharacter`
//! (`Renderer.cpp:1477-1491`), `_console_colors_`
//! (`Renderer.cpp:1358-1375`), `Renderer::ComputeRenderingSize`
//! (`Renderer.cpp:1567-1595`).
//!
//! One terminal cell covers `rap x rap` source pixels (averaged);
//! small-block mode packs two pixel rows per cell via the upper-half
//! block glyph, so zooming changes `rap` uniformly in X and Y and the
//! aspect ratio is preserved (§5.6).

use appcui::graphics::{CharFlags, Character, Color, SpecialChar};

use super::quantize::{pixel_to_16_color, DecodedImage, Rgba8};
use crate::renderer::cell::CellBuffer;

/// Zoom level (C++ `ImageScaleMethod`); the discriminant is the `rap`
/// downsample factor (spec §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageScale {
    /// 100% — 1 source pixel per cell column.
    NoScale = 1,
    /// 50%.
    Scale50 = 2,
    /// 33%.
    Scale33 = 3,
    /// 25%.
    Scale25 = 4,
    /// 20%.
    Scale20 = 5,
    /// 10%.
    Scale10 = 10,
    /// 5%.
    Scale5 = 20,
}

impl ImageScale {
    /// The downsample factor: each cell covers `rap x rap` pixels.
    #[must_use]
    pub const fn rap(self) -> u32 {
        self as u32
    }

    /// C++ `Instance::NextPreviousScale`
    /// (`ImageViewer/Instance.cpp:38-59`): `next == true` zooms in
    /// (smaller `rap`), `false` zooms out. Clamps at `NoScale` and
    /// `Scale5`.
    #[must_use]
    pub const fn next_previous_scale(self, next: bool) -> Self {
        match self {
            Self::NoScale => {
                if next {
                    Self::NoScale
                } else {
                    Self::Scale50
                }
            }
            Self::Scale50 => {
                if next {
                    Self::NoScale
                } else {
                    Self::Scale33
                }
            }
            Self::Scale33 => {
                if next {
                    Self::Scale50
                } else {
                    Self::Scale25
                }
            }
            Self::Scale25 => {
                if next {
                    Self::Scale33
                } else {
                    Self::Scale20
                }
            }
            Self::Scale20 => {
                if next {
                    Self::Scale25
                } else {
                    Self::Scale10
                }
            }
            Self::Scale10 => {
                if next {
                    Self::Scale20
                } else {
                    Self::Scale5
                }
            }
            Self::Scale5 => {
                if next {
                    Self::Scale10
                } else {
                    Self::Scale5
                }
            }
        }
    }
}

/// Rendering method (C++ `ImageRenderingMethod`).
///
/// The viewer always uses [`Self::Pixel16SmallBlock`] (`RedrawImage`,
/// `ImageViewer/Instance.cpp:60-63`); the other methods exist in the
/// renderer but are not wired to keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageRenderMethod {
    /// 16-color half-block cells (1 column x 2 pixel rows).
    Pixel16SmallBlock,
    /// 64-color blend blocks (2 columns per pixel).
    Pixel64LargeBlock,
    /// Luminance block shades.
    GrayScale,
    /// `NOT_IMPLEMENTED` in C++.
    AsciiArt,
}

/// The 16 console colors with their reference RGB values
/// (C++ `_console_colors_`, `Renderer.cpp:1358-1375`).
const CONSOLE_COLORS: [(u8, u8, u8, Color); 16] = [
    (0, 0, 0, Color::Black),
    (0, 0, 128, Color::DarkBlue),
    (0, 128, 0, Color::DarkGreen),
    (0, 128, 128, Color::Teal),
    (128, 0, 0, Color::DarkRed),
    (128, 0, 128, Color::Magenta),
    (128, 128, 0, Color::Olive),
    (192, 192, 192, Color::Silver),
    (128, 128, 128, Color::Gray),
    (0, 0, 255, Color::Blue),
    (0, 255, 0, Color::Green),
    (0, 255, 255, Color::Aqua),
    (255, 0, 0, Color::Red),
    (255, 0, 255, Color::Pink),
    (255, 255, 0, Color::Yellow),
    (255, 255, 255, Color::White),
];

/// Paint target for the image render loops; `CellBuffer` implements
/// it, and tests record calls.
pub trait ImageCanvas {
    /// Writes a plain character (C++ `Renderer::WriteCharacter`).
    fn write_character(&mut self, x: i32, y: i32, ch: char, fg: Color, bg: Color);
    /// Writes one special glyph
    /// (C++ `Renderer::WriteSpecialCharacter`).
    fn write_special_char(&mut self, x: i32, y: i32, ch: SpecialChar, fg: Color, bg: Color);
}

impl ImageCanvas for CellBuffer {
    fn write_character(&mut self, x: i32, y: i32, ch: char, fg: Color, bg: Color) {
        if x < 0 || y < 0 {
            return;
        }
        self.write_char(
            x.cast_unsigned(),
            y.cast_unsigned(),
            Character::new(ch, fg, bg, CharFlags::None),
        );
    }

    fn write_special_char(&mut self, x: i32, y: i32, ch: SpecialChar, fg: Color, bg: Color) {
        if x < 0 || y < 0 {
            return;
        }
        self.write_char(
            x.cast_unsigned(),
            y.cast_unsigned(),
            Character::new(ch, fg, bg, CharFlags::None),
        );
    }
}

/// C++ `Renderer::ComputeRenderingSize` (`Renderer.cpp:1567-1595`).
///
/// **Truncating** integer division (§5.5), clamped to at least 1x1.
/// `AsciiArt` is `NOT_IMPLEMENTED` in C++ and returns `Size()` (0x0)
/// **without** the min clamp — preserved.
#[must_use]
pub fn compute_rendering_size(
    img: &DecodedImage,
    method: ImageRenderMethod,
    scale: ImageScale,
) -> (u32, u32) {
    let rap = scale.rap();
    let w = img.width();
    let h = img.height();
    let (w, h) = match method {
        ImageRenderMethod::Pixel16SmallBlock => (
            w.checked_div(rap).unwrap_or(0),
            h.checked_div(rap.saturating_mul(2)).unwrap_or(0),
        ),
        ImageRenderMethod::Pixel64LargeBlock | ImageRenderMethod::GrayScale => (
            w.saturating_mul(2).checked_div(rap).unwrap_or(0),
            h.checked_div(rap).unwrap_or(0),
        ),
        ImageRenderMethod::AsciiArt => return (0, 0),
    };
    (u32::max(w, 1), u32::max(h, 1))
}

/// C++ `PixelTo64Color` (`Renderer.cpp:1428-1476`).
///
/// Linear search over all pairs of the 16 console colors x 4 blend
/// ratios (25/50/75/100%) minimizing the channel-difference sum; ties
/// resolve to the **last** candidate scanned (C++ `df <= BestDiff`),
/// and a perfect match returns immediately. Returns
/// `(foreground, background, glyph)`.
#[must_use]
pub fn pixel_to_64_color(pixel: Rgba8) -> (Color, Color, SpecialChar) {
    let r = u32::from(pixel.r);
    let g = u32::from(pixel.g);
    let b = u32::from(pixel.b);
    let mut best_diff = u32::MAX;
    let mut best = (Color::Black, Color::Black, SpecialChar::Block100);
    for cc1 in &CONSOLE_COLORS {
        for cc2 in &CONSOLE_COLORS {
            for proc in 1_u32..=4 {
                let inv = 4_u32.saturating_sub(proc);
                let blend = |a: u8, b: u8| {
                    u32::from(a)
                        .saturating_mul(proc)
                        .saturating_add(u32::from(b).saturating_mul(inv))
                        .checked_div(4)
                        .unwrap_or(0)
                };
                let compose_r = blend(cc1.0, cc2.0);
                let compose_g = blend(cc1.1, cc2.1);
                let compose_b = blend(cc1.2, cc2.2);
                let df = r
                    .abs_diff(compose_r)
                    .saturating_add(g.abs_diff(compose_g))
                    .saturating_add(b.abs_diff(compose_b));
                if df <= best_diff {
                    best_diff = df;
                    let glyph = match proc {
                        1 => SpecialChar::Block25,
                        2 => SpecialChar::Block50,
                        3 => SpecialChar::Block75,
                        _ => SpecialChar::Block100,
                    };
                    best = (cc1.3, cc2.3, glyph);
                    if best_diff == 0 {
                        return best;
                    }
                }
            }
        }
    }
    best
}

/// C++ `PixelToGrayScaleCharacter` (`Renderer.cpp:1477-1491`):
/// luminance percentage → block shade on white/black (§5.4).
#[must_use]
pub const fn pixel_to_gray_scale_char(pixel: Rgba8) -> (Color, Color, SpecialChar) {
    let val = pixel.to_gray_scale();
    let glyph = if val < 12 {
        SpecialChar::Block0
    } else if val < 37 {
        SpecialChar::Block25
    } else if val < 62 {
        SpecialChar::Block50
    } else if val < 87 {
        SpecialChar::Block75
    } else {
        SpecialChar::Block100
    };
    (Color::White, Color::Black, glyph)
}

/// C++ `Paint_SmallBlocks` (`Renderer.cpp:1492-1522`), §5.1.
///
/// One cell per column, two pixel rows per cell. Foreground = top
/// pixel, background = bottom pixel; equal colors collapse to a space
/// (black) or a solid block, otherwise the upper-half block glyph.
/// Out-of-range bottom reads (odd heights) quantize the C++ default
/// pixel — black.
pub fn paint_small_blocks(
    img: &DecodedImage,
    scale: ImageScale,
    canvas: &mut impl ImageCanvas,
    x: i32,
    y: i32,
) {
    let rap = scale.rap();
    let x_step = rap;
    let y_step = rap.saturating_mul(2);
    let (w, h) = (img.width(), img.height());
    let mut img_y = 0_u32;
    let mut cell_y = y;
    while img_y < h {
        let mut img_x = 0_u32;
        let mut px = x;
        while img_x < w {
            let (top, bottom) = if rap == 1 {
                (
                    pixel_to_16_color(img.pixel_or_default(img_x, img_y)),
                    pixel_to_16_color(img.pixel_or_default(img_x, img_y.saturating_add(1))),
                )
            } else {
                (
                    pixel_to_16_color(img.square_average_color(img_x, img_y, rap)),
                    pixel_to_16_color(img.square_average_color(
                        img_x,
                        img_y.saturating_add(rap),
                        rap,
                    )),
                )
            };
            if top == bottom {
                if bottom == Color::Black {
                    canvas.write_character(px, cell_y, ' ', top, bottom);
                } else {
                    canvas.write_special_char(px, cell_y, SpecialChar::Block100, top, bottom);
                }
            } else {
                canvas.write_special_char(px, cell_y, SpecialChar::BlockUpperHalf, top, bottom);
            }
            img_x = img_x.saturating_add(x_step);
            px = px.saturating_add(1);
        }
        img_y = img_y.saturating_add(y_step);
        cell_y = cell_y.saturating_add(1);
    }
}

/// C++ `Paint_LargeBlocks` (`Renderer.cpp:1523-1545`), §5.3: one
/// terminal cell pair (2 columns) per pixel block, blended via
/// [`pixel_to_64_color`].
pub fn paint_large_blocks(
    img: &DecodedImage,
    scale: ImageScale,
    canvas: &mut impl ImageCanvas,
    x: i32,
    y: i32,
) {
    paint_double_wide(img, scale, canvas, x, y, pixel_to_64_color);
}

/// C++ `Paint_GrayScale` (`Renderer.cpp:1546-1566`), §5.4: same
/// geometry as large blocks, glyph from luminance.
pub fn paint_gray_scale(
    img: &DecodedImage,
    scale: ImageScale,
    canvas: &mut impl ImageCanvas,
    x: i32,
    y: i32,
) {
    paint_double_wide(img, scale, canvas, x, y, pixel_to_gray_scale_char);
}

/// Shared loop of `Paint_LargeBlocks` / `Paint_GrayScale`: `rap`
/// pixel steps, two cells per block filled with the same glyph
/// (C++ `FillHorizontalLineWithSpecialChar(px, y, px + 1, ...)`).
fn paint_double_wide(
    img: &DecodedImage,
    scale: ImageScale,
    canvas: &mut impl ImageCanvas,
    x: i32,
    y: i32,
    to_cell: impl Fn(Rgba8) -> (Color, Color, SpecialChar),
) {
    let rap = scale.rap();
    let (w, h) = (img.width(), img.height());
    let mut img_y = 0_u32;
    let mut cell_y = y;
    while img_y < h {
        let mut img_x = 0_u32;
        let mut px = x;
        while img_x < w {
            let pixel = if rap == 1 {
                img.pixel_or_default(img_x, img_y)
            } else {
                img.square_average_color(img_x, img_y, rap)
            };
            let (fg, bg, glyph) = to_cell(pixel);
            canvas.write_special_char(px, cell_y, glyph, fg, bg);
            canvas.write_special_char(px.saturating_add(1), cell_y, glyph, fg, bg);
            img_x = img_x.saturating_add(rap);
            px = px.saturating_add(2);
        }
        img_y = img_y.saturating_add(rap);
        cell_y = cell_y.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_viewer::quantize::Rgba8;

    // `SpecialChar` has no `PartialEq` in AppCUI-rs; glyphs are
    // recorded and compared through `char::from`.
    fn glyph_char(ch: SpecialChar) -> char {
        char::from(ch)
    }

    struct Recording {
        cells: Vec<(i32, i32, char, Color, Color)>,
        specials: Vec<(i32, i32, char, Color, Color)>,
    }

    impl Recording {
        fn new() -> Self {
            Self {
                cells: Vec::new(),
                specials: Vec::new(),
            }
        }
    }

    impl ImageCanvas for Recording {
        fn write_character(&mut self, x: i32, y: i32, ch: char, fg: Color, bg: Color) {
            self.cells.push((x, y, ch, fg, bg));
        }
        fn write_special_char(&mut self, x: i32, y: i32, ch: SpecialChar, fg: Color, bg: Color) {
            self.specials.push((x, y, char::from(ch), fg, bg));
        }
    }

    fn image(width: u32, height: u32, pixels: Vec<Rgba8>) -> DecodedImage {
        DecodedImage::new(width, height, pixels).expect("valid test image")
    }

    #[test]
    fn scale_cycle_matches_cpp() {
        use ImageScale as S;
        // Zoom out (next = false) descends the whole chain.
        assert_eq!(S::NoScale.next_previous_scale(false), S::Scale50);
        assert_eq!(S::Scale50.next_previous_scale(false), S::Scale33);
        assert_eq!(S::Scale33.next_previous_scale(false), S::Scale25);
        assert_eq!(S::Scale25.next_previous_scale(false), S::Scale20);
        assert_eq!(S::Scale20.next_previous_scale(false), S::Scale10);
        assert_eq!(S::Scale10.next_previous_scale(false), S::Scale5);
        // Clamps at both ends.
        assert_eq!(S::Scale5.next_previous_scale(false), S::Scale5);
        assert_eq!(S::NoScale.next_previous_scale(true), S::NoScale);
        // Zoom in ascends.
        assert_eq!(S::Scale5.next_previous_scale(true), S::Scale10);
        assert_eq!(S::Scale10.next_previous_scale(true), S::Scale20);
        assert_eq!(S::Scale50.next_previous_scale(true), S::NoScale);
        // rap values per §4.
        assert_eq!(S::NoScale.rap(), 1);
        assert_eq!(S::Scale33.rap(), 3);
        assert_eq!(S::Scale5.rap(), 20);
    }

    #[test]
    fn compute_rendering_size_truncates_and_clamps() {
        let img = image(5, 5, vec![Rgba8::TRANSPARENT; 25]);
        // Small block: 5/2 = 2, 5/4 = 1 (truncating).
        assert_eq!(
            compute_rendering_size(&img, ImageRenderMethod::Pixel16SmallBlock, ImageScale::Scale50),
            (2, 1)
        );
        // Large block / grayscale: (5*2)/2 = 5, 5/2 = 2.
        assert_eq!(
            compute_rendering_size(&img, ImageRenderMethod::Pixel64LargeBlock, ImageScale::Scale50),
            (5, 2)
        );
        assert_eq!(
            compute_rendering_size(&img, ImageRenderMethod::GrayScale, ImageScale::Scale50),
            (5, 2)
        );
        // Tiny image at heavy zoom clamps to 1x1.
        assert_eq!(
            compute_rendering_size(&img, ImageRenderMethod::Pixel16SmallBlock, ImageScale::Scale5),
            (1, 1)
        );
        // AsciiArt: C++ NOT_IMPLEMENTED returns Size() with no clamp.
        assert_eq!(
            compute_rendering_size(&img, ImageRenderMethod::AsciiArt, ImageScale::NoScale),
            (0, 0)
        );
    }

    #[test]
    fn aspect_ratio_preserved_across_zoom() {
        let img = image(8, 8, vec![Rgba8::TRANSPARENT; 64]);
        // Small blocks halve the height (two pixel rows per cell), so
        // the w:h cell ratio stays 2:1 at every rap.
        for scale in [ImageScale::NoScale, ImageScale::Scale50, ImageScale::Scale25] {
            let (w, h) = compute_rendering_size(&img, ImageRenderMethod::Pixel16SmallBlock, scale);
            assert_eq!(w, h * 2, "scale {scale:?}");
        }
    }

    #[test]
    fn small_block_2x1_maps_to_upper_half_glyph() {
        // 1x2 image: red on top, blue below → one upper-half-block
        // cell with fg=Red (top), bg=Blue (bottom).
        let img = image(1, 2, vec![Rgba8::new(255, 0, 0), Rgba8::new(0, 0, 255)]);
        let mut canvas = Recording::new();
        paint_small_blocks(&img, ImageScale::NoScale, &mut canvas, 0, 0);
        assert_eq!(
            canvas.specials,
            vec![(
                0,
                0,
                glyph_char(SpecialChar::BlockUpperHalf),
                Color::Red,
                Color::Blue
            )]
        );
        assert!(canvas.cells.is_empty());
    }

    #[test]
    fn equal_colors_collapse_to_space_or_solid_block() {
        // Both rows black → space; both rows red → solid block.
        let img = image(
            2,
            2,
            vec![
                Rgba8::new(0, 0, 0),
                Rgba8::new(255, 0, 0),
                Rgba8::new(0, 0, 0),
                Rgba8::new(255, 0, 0),
            ],
        );
        let mut canvas = Recording::new();
        paint_small_blocks(&img, ImageScale::NoScale, &mut canvas, 0, 0);
        assert_eq!(canvas.cells, vec![(0, 0, ' ', Color::Black, Color::Black)]);
        assert_eq!(
            canvas.specials,
            vec![(
                1,
                0,
                glyph_char(SpecialChar::Block100),
                Color::Red,
                Color::Red
            )]
        );
    }

    #[test]
    fn odd_height_bottom_row_reads_black_default() {
        // 1x1 red image: the bottom read at y=1 is out of range and
        // quantizes the C++ default pixel (black).
        let img = image(1, 1, vec![Rgba8::new(255, 0, 0)]);
        let mut canvas = Recording::new();
        paint_small_blocks(&img, ImageScale::NoScale, &mut canvas, 0, 0);
        assert_eq!(
            canvas.specials,
            vec![(
                0,
                0,
                glyph_char(SpecialChar::BlockUpperHalf),
                Color::Red,
                Color::Black
            )]
        );
    }

    #[test]
    fn rap_2_averages_2x2_squares() {
        // 2x4 image, rap 2: top cell half = rows 0-1 (all white),
        // bottom half = rows 2-3 (all black) → single half block
        // white-on-black.
        let mut pixels = vec![Rgba8::new(255, 255, 255); 4];
        pixels.extend(vec![Rgba8::new(0, 0, 0); 4]);
        let img = image(2, 4, pixels);
        let mut canvas = Recording::new();
        paint_small_blocks(&img, ImageScale::Scale50, &mut canvas, 0, 0);
        assert_eq!(
            canvas.specials,
            vec![(
                0,
                0,
                glyph_char(SpecialChar::BlockUpperHalf),
                Color::White,
                Color::Black
            )]
        );
    }

    #[test]
    fn paint_respects_origin_offset() {
        let img = image(2, 2, vec![Rgba8::new(255, 255, 255); 4]);
        let mut canvas = Recording::new();
        paint_small_blocks(&img, ImageScale::NoScale, &mut canvas, 5, 3);
        let positions: Vec<(i32, i32)> = canvas
            .specials
            .iter()
            .map(|&(x, y, _, _, _)| (x, y))
            .collect();
        assert_eq!(positions, vec![(5, 3), (6, 3)]);
    }

    #[test]
    fn pixel_to_64_color_exact_and_blend() {
        // Pure red matches console Red at 100% over Black (first
        // perfect hit in scan order).
        let (fg, bg, glyph) = pixel_to_64_color(Rgba8::new(255, 0, 0));
        assert_eq!(fg, Color::Red);
        assert_eq!(bg, Color::Black);
        assert_eq!(glyph_char(glyph), glyph_char(SpecialChar::Block100));
        // (64,0,0) is a perfect 50% Black-over-DarkRed blend — the
        // first exact composition in C++ scan order.
        let (fg, bg, glyph) = pixel_to_64_color(Rgba8::new(64, 0, 0));
        assert_eq!(fg, Color::Black);
        assert_eq!(bg, Color::DarkRed);
        assert_eq!(glyph_char(glyph), glyph_char(SpecialChar::Block50));
        // Pure black: first candidate (Black x Black, 25%) is already
        // perfect.
        let (fg, bg, glyph) = pixel_to_64_color(Rgba8::new(0, 0, 0));
        assert_eq!(fg, Color::Black);
        assert_eq!(bg, Color::Black);
        assert_eq!(glyph_char(glyph), glyph_char(SpecialChar::Block25));
    }

    #[test]
    fn gray_scale_thresholds() {
        // to_gray_scale is a percentage; §5.4 boundaries 12/37/62/87.
        let glyph = |v: u8| glyph_char(pixel_to_gray_scale_char(Rgba8::new(v, v, v)).2);
        assert_eq!(glyph(0), glyph_char(SpecialChar::Block0));
        assert_eq!(glyph(30), glyph_char(SpecialChar::Block0)); // 11%
        assert_eq!(glyph(31), glyph_char(SpecialChar::Block25)); // 12%
        assert_eq!(glyph(128), glyph_char(SpecialChar::Block50)); // 50%
        assert_eq!(glyph(200), glyph_char(SpecialChar::Block75)); // 78%
        assert_eq!(glyph(255), glyph_char(SpecialChar::Block100)); // 100%
        let (fg, bg, _) = pixel_to_gray_scale_char(Rgba8::new(0, 0, 0));
        assert_eq!((fg, bg), (Color::White, Color::Black));
    }

    #[test]
    fn large_blocks_fill_two_cells_per_pixel() {
        let img = image(2, 1, vec![Rgba8::new(255, 0, 0), Rgba8::new(255, 255, 255)]);
        let mut canvas = Recording::new();
        paint_large_blocks(&img, ImageScale::NoScale, &mut canvas, 0, 0);
        let positions: Vec<(i32, i32)> = canvas
            .specials
            .iter()
            .map(|&(x, y, _, _, _)| (x, y))
            .collect();
        assert_eq!(positions, vec![(0, 0), (1, 0), (2, 0), (3, 0)]);
        // Both cells of a pair share glyph and colors.
        assert_eq!(canvas.specials[0].2, canvas.specials[1].2);
        assert_eq!(canvas.specials[0].3, Color::Red);
    }

    #[test]
    fn gray_scale_paint_uses_same_geometry() {
        let img = image(1, 2, vec![Rgba8::new(255, 255, 255), Rgba8::new(0, 0, 0)]);
        let mut canvas = Recording::new();
        paint_gray_scale(&img, ImageScale::NoScale, &mut canvas, 0, 0);
        assert_eq!(
            canvas.specials,
            vec![
                (
                    0,
                    0,
                    glyph_char(SpecialChar::Block100),
                    Color::White,
                    Color::Black
                ),
                (
                    1,
                    0,
                    glyph_char(SpecialChar::Block100),
                    Color::White,
                    Color::Black
                ),
                (
                    0,
                    1,
                    glyph_char(SpecialChar::Block0),
                    Color::White,
                    Color::Black
                ),
                (
                    1,
                    1,
                    glyph_char(SpecialChar::Block0),
                    Color::White,
                    Color::Black
                ),
            ]
        );
    }

    #[test]
    fn cell_buffer_canvas_clips_negative_and_out_of_range() {
        let img = image(1, 2, vec![Rgba8::new(255, 0, 0), Rgba8::new(0, 0, 255)]);
        let mut buffer = CellBuffer::new(4, 4);
        // Negative origin: writes are dropped, no panic.
        paint_small_blocks(&img, ImageScale::NoScale, &mut buffer, -10, -10);
        // In-range origin lands in the grid.
        paint_small_blocks(&img, ImageScale::NoScale, &mut buffer, 1, 2);
        let cell = buffer.get(1, 2).expect("in range");
        assert_eq!(cell.foreground, Color::Red);
        assert_eq!(cell.background, Color::Blue);
    }
}
