//! `ImageViewer` pixel model and RGB → 16-color quantization
//! (spec `02_VIEWER_IMAGE` §5.2, §8, §10).
//!
//! C++ anchors: `Pixel` (`AppCUI.hpp:2820-2843`), `Image::GetPixel` /
//! `Image::ComputeSquareAverageColor` (`Image.cpp:181-230`),
//! `RGB_to_16Color` + `_color_map_16_` + `Channel_To_Index16`
//! (`Renderer.cpp:1376-1419`).
//!
//! The 27-entry palette and channel thresholds live in
//! [`crate::renderer::color`] (delivered with the renderer cell
//! buffer); this module adds the image-side surface: the RGBA pixel,
//! the bounds-checked [`DecodedImage`] container with the §10
//! overflow/size guards, and the pixel-level quantization entry
//! points used by the paint loops.

use appcui::graphics::Color;

use crate::renderer::color::rgb_to_16color;

/// Hard cap on the decoded pixel buffer (spec §10: reject images
/// larger than 256 MiB — 4 bytes per RGBA pixel).
pub const MAX_IMAGE_BYTES: u64 = 256 * 1024 * 1024;

/// Errors from building a [`DecodedImage`] (spec §10: malformed input
/// returns an error, never panics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// Zero width or height.
    InvalidDimensions,
    /// `width * height` overflows or the pixel buffer would exceed
    /// [`MAX_IMAGE_BYTES`].
    TooLarge,
    /// The supplied pixel vector does not hold `width * height`
    /// entries.
    PixelCountMismatch,
}

/// One RGBA pixel (C++ `AppCUI::Graphics::Pixel`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rgba8 {
    /// Red channel.
    pub r: u8,
    /// Green channel.
    pub g: u8,
    /// Blue channel.
    pub b: u8,
    /// Alpha channel.
    pub a: u8,
}

impl Rgba8 {
    /// The C++ `Pixel()` default: all channels zero (transparent
    /// black) — also the out-of-range `GetPixel` fallback.
    pub const TRANSPARENT: Self = Self {
        r: 0,
        g: 0,
        b: 0,
        a: 0,
    };

    /// Opaque pixel (C++ `Pixel(red, green, blue)`: alpha forced to
    /// 255).
    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// C++ `Pixel::ToGrayScale` (`AppCUI.hpp:2839-2842`): luminance as
    /// a **percentage** `0..=100`, not `0..=255` — the §5.4 grayscale
    /// thresholds (12/37/62/87) are calibrated against this range.
    #[must_use]
    pub const fn to_gray_scale(self) -> u32 {
        // (R + B + G) * 100 / 765 — max 76_500 before the division,
        // far below u32::MAX.
        (self.r as u32)
            .saturating_add(self.b as u32)
            .saturating_add(self.g as u32)
            .saturating_mul(100)
            / (255 * 3)
    }
}

/// Quantizes one pixel to the nearest of the 16 console colors
/// (C++ `RGB_to_16Color`, `Renderer.cpp:1413-1419`); the alpha channel
/// is ignored, exactly as in C++.
#[must_use]
pub const fn pixel_to_16_color(pixel: Rgba8) -> Color {
    rgb_to_16color(pixel.r, pixel.g, pixel.b)
}

/// A decoded RGBA image (C++ `AppCUI::Graphics::Image`), with the
/// spec §10 allocation guards enforced at construction.
#[derive(Clone, Debug)]
pub struct DecodedImage {
    width: u32,
    height: u32,
    pixels: Vec<Rgba8>,
}

impl DecodedImage {
    /// Validates dimensions and takes ownership of the pixel buffer.
    ///
    /// # Errors
    ///
    /// [`ImageError::InvalidDimensions`] for a zero dimension,
    /// [`ImageError::TooLarge`] when `width * height` overflows or the
    /// buffer would exceed [`MAX_IMAGE_BYTES`], and
    /// [`ImageError::PixelCountMismatch`] when `pixels.len()` differs
    /// from `width * height`.
    pub fn new(width: u32, height: u32, pixels: Vec<Rgba8>) -> Result<Self, ImageError> {
        if width == 0 || height == 0 {
            return Err(ImageError::InvalidDimensions);
        }
        let count = u64::from(width)
            .checked_mul(u64::from(height))
            .ok_or(ImageError::TooLarge)?;
        let bytes = count
            .checked_mul(core::mem::size_of::<Rgba8>() as u64)
            .ok_or(ImageError::TooLarge)?;
        if bytes > MAX_IMAGE_BYTES {
            return Err(ImageError::TooLarge);
        }
        if pixels.len() as u64 != count {
            return Err(ImageError::PixelCountMismatch);
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    /// Image width in pixels (C++ `GetWidth`).
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Image height in pixels (C++ `GetHeight`).
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Bounds-checked pixel read.
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<Rgba8> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let index = (y as usize)
            .checked_mul(self.width as usize)?
            .checked_add(x as usize)?;
        self.pixels.get(index).copied()
    }

    /// C++ `Image::GetPixel(x, y, invalidIndexValue = {})`
    /// (`Image.cpp:181-185`): out-of-range coordinates return the
    /// transparent-black default pixel.
    #[must_use]
    pub fn pixel_or_default(&self, x: u32, y: u32) -> Rgba8 {
        self.pixel(x, y).unwrap_or(Rgba8::TRANSPARENT)
    }

    /// C++ `Image::ComputeSquareAverageColor(x, y, sz)`
    /// (`Image.cpp:192-230`): averages the `sz × sz` square anchored
    /// at `(x, y)`, clamped to the image edges. Out-of-range anchors
    /// or `sz == 0` return `Pixel(0)` (transparent black); a valid
    /// average is returned opaque (`Pixel(r, g, b)` sets alpha 255).
    /// Alpha is excluded from the average, exactly as in C++.
    #[must_use]
    pub fn square_average_color(&self, x: u32, y: u32, sz: u32) -> Rgba8 {
        if x >= self.width || y >= self.height || sz == 0 {
            return Rgba8::TRANSPARENT;
        }
        let e_x = u32::min(x.saturating_add(sz), self.width);
        let e_y = u32::min(y.saturating_add(sz), self.height);
        let x_size = e_x.saturating_sub(x);
        let y_size = e_y.saturating_sub(y);
        if x_size == 0 || y_size == 0 {
            return Rgba8::TRANSPARENT;
        }
        let mut sum_r = 0_u64;
        let mut sum_g = 0_u64;
        let mut sum_b = 0_u64;
        for row in y..e_y {
            for col in x..e_x {
                let p = self.pixel_or_default(col, row);
                sum_r = sum_r.saturating_add(u64::from(p.r));
                sum_g = sum_g.saturating_add(u64::from(p.g));
                sum_b = sum_b.saturating_add(u64::from(p.b));
            }
        }
        let total = u64::from(x_size).saturating_mul(u64::from(y_size));
        let avg = |sum: u64| sum.checked_div(total).unwrap_or(0) as u8;
        Rgba8::new(avg(sum_r), avg(sum_g), avg(sum_b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(width: u32, height: u32, pixel: Rgba8) -> DecodedImage {
        DecodedImage::new(width, height, vec![pixel; width.saturating_mul(height) as usize])
            .expect("valid test image")
    }

    #[test]
    fn golden_rgb_to_palette_vectors() {
        // Spec §5.2 formula through the pixel-level entry point.
        assert_eq!(pixel_to_16_color(Rgba8::new(0, 0, 0)), Color::Black);
        assert_eq!(pixel_to_16_color(Rgba8::new(255, 255, 255)), Color::White);
        assert_eq!(pixel_to_16_color(Rgba8::new(255, 0, 0)), Color::Red);
        assert_eq!(pixel_to_16_color(Rgba8::new(0, 255, 0)), Color::Green);
        assert_eq!(pixel_to_16_color(Rgba8::new(0, 0, 255)), Color::Blue);
        assert_eq!(pixel_to_16_color(Rgba8::new(128, 128, 128)), Color::Gray);
        assert_eq!(pixel_to_16_color(Rgba8::new(255, 255, 0)), Color::Yellow);
        assert_eq!(pixel_to_16_color(Rgba8::new(0, 255, 255)), Color::Aqua);
        assert_eq!(pixel_to_16_color(Rgba8::new(255, 0, 255)), Color::Pink);
        // Channel boundaries: 64 → low, 65 → mid, 191 → mid, 192 → hi.
        assert_eq!(pixel_to_16_color(Rgba8::new(64, 64, 64)), Color::Black);
        assert_eq!(pixel_to_16_color(Rgba8::new(65, 65, 65)), Color::Gray);
        assert_eq!(pixel_to_16_color(Rgba8::new(191, 191, 191)), Color::Gray);
        assert_eq!(pixel_to_16_color(Rgba8::new(192, 192, 192)), Color::White);
    }

    #[test]
    fn alpha_is_ignored_by_quantization() {
        let mut p = Rgba8::new(255, 0, 0);
        p.a = 0;
        assert_eq!(pixel_to_16_color(p), Color::Red);
    }

    #[test]
    fn gray_scale_is_a_percentage() {
        assert_eq!(Rgba8::new(0, 0, 0).to_gray_scale(), 0);
        assert_eq!(Rgba8::new(255, 255, 255).to_gray_scale(), 100);
        // (128*3*100)/765 = 50 (truncating).
        assert_eq!(Rgba8::new(128, 128, 128).to_gray_scale(), 50);
    }

    #[test]
    fn pixel_access_is_bounds_checked() {
        let img = solid(2, 2, Rgba8::new(10, 20, 30));
        assert_eq!(img.pixel(1, 1), Some(Rgba8::new(10, 20, 30)));
        assert_eq!(img.pixel(2, 0), None);
        assert_eq!(img.pixel(0, 2), None);
        // C++ GetPixel default: transparent black outside the image.
        assert_eq!(img.pixel_or_default(5, 5), Rgba8::TRANSPARENT);
    }

    #[test]
    fn square_average_of_uniform_block() {
        let img = solid(4, 4, Rgba8::new(100, 150, 200));
        let avg = img.square_average_color(0, 0, 2);
        assert_eq!(avg, Rgba8::new(100, 150, 200));
        assert_eq!(avg.a, 255); // C++ Pixel(r,g,b) is opaque
    }

    #[test]
    fn square_average_mixes_2x2() {
        // 2×2: black, white / black, white → average 127 (255*2/4).
        let pixels = vec![
            Rgba8::new(0, 0, 0),
            Rgba8::new(255, 255, 255),
            Rgba8::new(0, 0, 0),
            Rgba8::new(255, 255, 255),
        ];
        let img = DecodedImage::new(2, 2, pixels).expect("valid");
        assert_eq!(img.square_average_color(0, 0, 2), Rgba8::new(127, 127, 127));
    }

    #[test]
    fn square_average_clamps_at_edges() {
        // 3-wide image, rap 2 anchored at x=2: only column 2 counted.
        let pixels = vec![
            Rgba8::new(0, 0, 0),
            Rgba8::new(0, 0, 0),
            Rgba8::new(90, 90, 90),
            Rgba8::new(0, 0, 0),
            Rgba8::new(0, 0, 0),
            Rgba8::new(90, 90, 90),
        ];
        let img = DecodedImage::new(3, 2, pixels).expect("valid");
        assert_eq!(img.square_average_color(2, 0, 2), Rgba8::new(90, 90, 90));
    }

    #[test]
    fn square_average_invalid_inputs_return_transparent() {
        let img = solid(2, 2, Rgba8::new(50, 50, 50));
        assert_eq!(img.square_average_color(2, 0, 1), Rgba8::TRANSPARENT);
        assert_eq!(img.square_average_color(0, 2, 1), Rgba8::TRANSPARENT);
        assert_eq!(img.square_average_color(0, 0, 0), Rgba8::TRANSPARENT);
    }

    #[test]
    fn huge_dimension_rejected_without_panic() {
        // width * height overflows u32 multiplication.
        assert_eq!(
            DecodedImage::new(u32::MAX, u32::MAX, Vec::new()).unwrap_err(),
            ImageError::TooLarge
        );
        // Fits in u64 but exceeds the 256 MiB pixel-buffer cap.
        assert_eq!(
            DecodedImage::new(65_536, 65_536, Vec::new()).unwrap_err(),
            ImageError::TooLarge
        );
    }

    #[test]
    fn zero_dimensions_and_short_buffers_rejected() {
        assert_eq!(
            DecodedImage::new(0, 4, Vec::new()).unwrap_err(),
            ImageError::InvalidDimensions
        );
        assert_eq!(
            DecodedImage::new(4, 0, Vec::new()).unwrap_err(),
            ImageError::InvalidDimensions
        );
        assert_eq!(
            DecodedImage::new(2, 2, vec![Rgba8::TRANSPARENT; 3]).unwrap_err(),
            ImageError::PixelCountMismatch
        );
    }
}
