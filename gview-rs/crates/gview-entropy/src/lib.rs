//! `GView` entropy calculators (spec `04_SERVICES` §3).
//!
//! C++ anchors: `GView::Entropy::ShannonEntropy` / `RenyiEntropy`
//! (`Entropy.cpp:30-78`), `ComputeEpsilon` + classification
//! (`GenericPlugins/EntropyVisualizer/src/Plugin.cpp:37-47`).
//!
//! Formulas (§3.1):
//!
//! ```text
//! H      = -Σ p(x) · log2 p(x)                 (Shannon)
//! H_α    = (1 / (1 - α)) · log2(Σ p(x)^α)      (Rényi, α ≠ 1)
//! α == 1 → Shannon
//! ```
//!
//! Frequencies are `u64` counts as the spec mandates. (The C++ source
//! counts into `std::array<char, 256>`, which silently wraps past 127
//! occurrences of one byte and can yield NaN; the spec's `[u64; 256]`
//! definition is followed and the divergence noted here.) An empty
//! buffer yields `0.0` for both measures (the C++ Rényi path would
//! evaluate `log(0)`).

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]
// Probabilities are counts / length in f64: the integer → float casts
// are the algorithm (counts never approach 2^52 for a real buffer).
#![allow(clippy::cast_precision_loss)]

/// C++ `MAX_NUMBER_OF_BYTES`.
pub const MAX_NUMBER_OF_BYTES: usize = 256;

/// C++ `SetFrequencies`: byte histogram.
#[must_use]
pub fn set_frequencies(data: &[u8]) -> [u64; MAX_NUMBER_OF_BYTES] {
    let mut frequency = [0_u64; MAX_NUMBER_OF_BYTES];
    for &byte in data {
        if let Some(slot) = frequency.get_mut(usize::from(byte)) {
            *slot = slot.saturating_add(1);
        }
    }
    frequency
}

// Keep the C++ evaluation order (`entropy -= p * log2(p)`) rather than
// a fused multiply-add so results match the reference bit-for-bit.
#[allow(clippy::suboptimal_flops)]
fn shannon_from_frequencies(frequency: &[u64; MAX_NUMBER_OF_BYTES], length: usize) -> f64 {
    if length == 0 {
        return 0.0;
    }
    let total = length as f64;
    let mut entropy = 0.0_f64;
    for &f in frequency {
        if f == 0 {
            continue;
        }
        let probability = f as f64 / total;
        entropy -= probability * probability.log2();
    }
    entropy
}

/// C++ `ShannonEntropy` (`Entropy.cpp:30-50`): bits per byte in
/// `0.0..=8.0`.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    let frequency = set_frequencies(data);
    shannon_from_frequencies(&frequency, data.len())
}

/// C++ `RenyiEntropy` (`Entropy.cpp:60-78`): `alpha == 1.0` falls
/// back to Shannon; otherwise `(1 / (1 - α)) · ln(Σ p^α) / ln 2`.
#[must_use]
#[allow(clippy::float_cmp)] // C++ tests `alpha == 1.0` exactly
pub fn renyi_entropy(data: &[u8], alpha: f64) -> f64 {
    let frequency = set_frequencies(data);
    if alpha == 1.0 {
        return shannon_from_frequencies(&frequency, data.len());
    }
    if data.is_empty() {
        return 0.0;
    }
    let total = data.len() as f64;
    let mut sum = 0.0_f64;
    for &f in &frequency {
        if f > 0 {
            let probability = f as f64 / total;
            sum += probability.powf(alpha);
        }
    }
    ((1.0 / (1.0 - alpha)) * sum.ln()) / std::f64::consts::LN_2
}

/// Visualizer classification (spec §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataClass {
    /// `≤ 6.0` or `≥ 8.0` (Gray).
    PlainText,
    /// `6.0 < H < 8.0 - ε` (Red).
    Binary,
    /// `8.0 - ε ≤ H < 8.0` (Green).
    Encrypted,
}

/// C++ `ComputeEpsilon(sample_size)` (`Plugin.cpp`):
/// `2.0 - (log2(sample_size) - 2.0) / 10`.
#[must_use]
pub fn compute_epsilon(sample_size: usize) -> f64 {
    2.0 - ((sample_size as f64).log2() - 2.0) / 10.0
}

/// The `Plugin.cpp:37-47` band test.
#[must_use]
pub fn classify_data_type(entropy: f64, block_size: usize) -> DataClass {
    let epsilon = compute_epsilon(block_size);
    if entropy >= 8.0 - epsilon && entropy < 8.0 {
        DataClass::Encrypted
    } else if entropy > 6.0 && entropy < 8.0 - epsilon {
        DataClass::Binary
    } else {
        DataClass::PlainText
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn uniform_buffer_is_8_bits() {
        let data: Vec<u8> = (0..=255).collect();
        assert!(close(shannon_entropy(&data), 8.0));
        // Repeating the uniform distribution keeps 8 bits.
        let doubled: Vec<u8> = data.iter().chain(data.iter()).copied().collect();
        assert!(close(shannon_entropy(&doubled), 8.0));
    }

    #[test]
    fn constant_and_empty_buffers_are_zero() {
        assert!(close(shannon_entropy(&[0x41; 100]), 0.0));
        assert!(close(shannon_entropy(&[]), 0.0));
        assert!(close(renyi_entropy(&[], 2.0), 0.0));
        assert!(close(renyi_entropy(&[7; 10], 2.0), 0.0));
    }

    #[test]
    fn two_symbol_buffer_is_one_bit() {
        let data = [0_u8, 1, 0, 1, 0, 1, 0, 1];
        assert!(close(shannon_entropy(&data), 1.0));
        // Rényi of a uniform distribution equals log2(n) for any α.
        assert!(close(renyi_entropy(&data, 2.0), 1.0));
        assert!(close(renyi_entropy(&data, 0.5), 1.0));
    }

    #[test]
    fn alpha_one_falls_back_to_shannon() {
        let data = b"the quick brown fox jumps over the lazy dog";
        assert!(close(renyi_entropy(data, 1.0), shannon_entropy(data)));
        // Rényi is non-increasing in α (H_α ≥ H_α' for α ≤ α').
        let h05 = renyi_entropy(data, 0.5);
        let h1 = renyi_entropy(data, 1.0);
        let h2 = renyi_entropy(data, 2.0);
        assert!(h05 >= h1 && h1 >= h2);
    }

    #[test]
    fn counts_above_127_do_not_wrap() {
        // 200 identical bytes plus one other: a `char` histogram
        // would wrap; u64 counts give a small positive entropy.
        let mut data = vec![0xAA_u8; 200];
        data.push(0x55);
        let h = shannon_entropy(&data);
        assert!(h > 0.0 && h < 0.1 && !h.is_nan());
    }

    #[test]
    fn classification_bands() {
        // block 32 → ε = 2 - (5 - 2)/10 = 1.7 → encrypted band [6.3, 8).
        assert!(close(compute_epsilon(32), 1.7));
        assert_eq!(classify_data_type(7.0, 32), DataClass::Encrypted);
        assert_eq!(classify_data_type(6.2, 32), DataClass::Binary);
        assert_eq!(classify_data_type(6.0, 32), DataClass::PlainText);
        assert_eq!(classify_data_type(8.0, 32), DataClass::PlainText);
        assert_eq!(classify_data_type(3.5, 32), DataClass::PlainText);
    }
}
