//! RGB → 16-color quantization (C++ `RGB_to_16Color`,
//! `AppCUI/.../Renderer.cpp:1376-1419`; spec `02_VIEWER_IMAGE` §5.2).

use appcui::graphics::Color;

/// The 27-entry (3×3×3) → 16-color palette from
/// `Renderer.cpp:1376-1404`, indexed by `r*9 + g*3 + b` with each
/// channel quantized to 0..=2. Entries marked `[Aprox]` in C++ are
/// deliberate approximations — preserved verbatim.
const COLOR_MAP_16: [Color; 27] = [
    /* 0*/ Color::Black, // (0, 0, 0)
    /* 1*/ Color::DarkBlue, // (0, 0, 1)
    /* 2*/ Color::Blue, // (0, 0, 2)
    /* 3*/ Color::DarkGreen, // (0, 1, 0)
    /* 4*/ Color::Teal, // (0, 1, 1)
    /* 5*/ Color::Teal, // (0, 1, 2) [Aprox]
    /* 6*/ Color::Green, // (0, 2, 0)
    /* 7*/ Color::Teal, // (0, 2, 1) [Aprox]
    /* 8*/ Color::Aqua, // (0, 2, 2)
    /* 9*/ Color::DarkRed, // (1, 0, 0)
    /*10*/ Color::Magenta, // (1, 0, 1)
    /*11*/ Color::Magenta, // (1, 0, 2) [Aprox]
    /*12*/ Color::Olive, // (1, 1, 0)
    /*13*/ Color::Gray, // (1, 1, 1)
    /*14*/ Color::Gray, // (1, 1, 2) [Aprox]
    /*15*/ Color::Olive, // (1, 2, 0) [Aprox]
    /*16*/ Color::Gray, // (1, 2, 1) [Aprox]
    /*17*/ Color::Silver, // (1, 2, 2) [Aprox]
    /*18*/ Color::Red, // (2, 0, 0)
    /*19*/ Color::Magenta, // (2, 0, 1) [Aprox]
    /*20*/ Color::Pink, // (2, 0, 2)
    /*21*/ Color::Olive, // (2, 1, 0) [Aprox]
    /*22*/ Color::Gray, // (2, 1, 1) [Aprox]
    /*23*/ Color::Silver, // (2, 1, 2) [Aprox]
    /*24*/ Color::Yellow, // (2, 2, 0)
    /*25*/ Color::Silver, // (2, 2, 1) [Aprox]
    /*26*/ Color::White, // (2, 2, 2)
];

/// Quantizes one 0–255 channel to 0..=2
/// (C++ `Channel_To_Index16`, `Renderer.cpp:1405-1412`):
/// `<= 64 → 0`, `< 192 → 1`, `>= 192 → 2`.
#[must_use]
pub const fn channel_to_index16(value: u8) -> usize {
    if value <= 64 {
        0
    } else if value < 192 {
        1
    } else {
        2
    }
}

/// Maps an RGB pixel to the nearest of the 16 console colors
/// (C++ `RGB_to_16Color`, `Renderer.cpp:1413-1419`).
#[must_use]
// Each channel index is 0..=2, so `r*9 + g*3 + b` is at most 26: the
// arithmetic cannot overflow and the table index is always in bounds.
#[allow(clippy::arithmetic_side_effects)]
pub const fn rgb_to_16color(red: u8, green: u8, blue: u8) -> Color {
    let index =
        channel_to_index16(red) * 9 + channel_to_index16(green) * 3 + channel_to_index16(blue);
    COLOR_MAP_16[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_thresholds() {
        assert_eq!(channel_to_index16(0), 0);
        assert_eq!(channel_to_index16(64), 0);
        assert_eq!(channel_to_index16(65), 1);
        assert_eq!(channel_to_index16(191), 1);
        assert_eq!(channel_to_index16(192), 2);
        assert_eq!(channel_to_index16(255), 2);
    }

    #[test]
    fn golden_rgb_vectors() {
        // Pure and boundary colors against the C++ table.
        assert_eq!(rgb_to_16color(0, 0, 0), Color::Black);
        assert_eq!(rgb_to_16color(255, 255, 255), Color::White);
        assert_eq!(rgb_to_16color(255, 0, 0), Color::Red);
        assert_eq!(rgb_to_16color(0, 255, 0), Color::Green);
        assert_eq!(rgb_to_16color(0, 0, 255), Color::Blue);
        assert_eq!(rgb_to_16color(128, 0, 0), Color::DarkRed);
        assert_eq!(rgb_to_16color(0, 128, 0), Color::DarkGreen);
        assert_eq!(rgb_to_16color(0, 0, 128), Color::DarkBlue);
        assert_eq!(rgb_to_16color(128, 128, 0), Color::Olive);
        assert_eq!(rgb_to_16color(0, 128, 128), Color::Teal);
        assert_eq!(rgb_to_16color(128, 0, 128), Color::Magenta);
        assert_eq!(rgb_to_16color(128, 128, 128), Color::Gray);
        assert_eq!(rgb_to_16color(255, 255, 0), Color::Yellow);
        assert_eq!(rgb_to_16color(0, 255, 255), Color::Aqua);
        assert_eq!(rgb_to_16color(255, 0, 255), Color::Pink);
        assert_eq!(rgb_to_16color(128, 255, 255), Color::Silver);
    }

    #[test]
    fn approx_entries_match_cpp() {
        // The [Aprox] rows are intentional C++ choices.
        assert_eq!(rgb_to_16color(0, 128, 255), Color::Teal); // (0,1,2)
        assert_eq!(rgb_to_16color(0, 255, 128), Color::Teal); // (0,2,1)
        assert_eq!(rgb_to_16color(128, 0, 255), Color::Magenta); // (1,0,2)
        assert_eq!(rgb_to_16color(128, 128, 255), Color::Gray); // (1,1,2)
        assert_eq!(rgb_to_16color(128, 255, 0), Color::Olive); // (1,2,0)
        assert_eq!(rgb_to_16color(128, 255, 128), Color::Gray); // (1,2,1)
        assert_eq!(rgb_to_16color(255, 0, 128), Color::Magenta); // (2,0,1)
        assert_eq!(rgb_to_16color(255, 128, 0), Color::Olive); // (2,1,0)
        assert_eq!(rgb_to_16color(255, 128, 128), Color::Gray); // (2,1,1)
        assert_eq!(rgb_to_16color(255, 128, 255), Color::Silver); // (2,1,2)
        assert_eq!(rgb_to_16color(255, 255, 128), Color::Silver); // (2,2,1)
    }

    #[test]
    fn every_index_reachable_and_total() {
        // All 27 combinations produce a valid palette color; sweep the
        // whole quantized space.
        for r in [0_u8, 128, 255] {
            for g in [0_u8, 128, 255] {
                for b in [0_u8, 128, 255] {
                    let c = rgb_to_16color(r, g, b);
                    assert!(!matches!(c, Color::Transparent));
                }
            }
        }
    }
}
