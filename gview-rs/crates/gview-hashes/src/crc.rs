//! CRC family + Adler-32 (spec `04_SERVICES` §2.2–§2.4).
//!
//! C++ anchors: `CRC32.cpp`, `CRC64.cpp`, `CRC16.cpp`, `Adler32.cpp`
//! and the class declarations in `GView.hpp:331-427`.
//!
//! Semantics preserved from C++:
//!
//! - **CRC32**: reflected table (poly `0xEDB88320`), init `~0`;
//!   `Final` XORs the `CRC32Type` value. Because
//!   `CRC32Type::JAMCRC == 0xFFFFFFFF`, the variant *named* JAMCRC is
//!   the standard CRC-32 (with final inversion) and `JAMCRC_0` is the
//!   true JAMCRC (no inversion). Hex: `%.8X`.
//! - **CRC64**: MSB-first table (ECMA-182 poly
//!   `0x42F0E1EBA9EA3693`), init = type value, final XOR = type value
//!   (`ECMA_182` = 0, `WE` = all ones). Hex: `%.16llX`.
//! - **CRC16**: MSB-first table, poly `0x1021`, init `0`, no final
//!   XOR (CRC-16/XMODEM despite the "CCITT" name). Hex is `%.8X` of
//!   the 32-bit holder — 8 characters (quirk preserved).
//! - **Adler-32**: base 65521, 8-byte unrolled update; result
//!   `(b << 16) + a`. Hex `%.8X`.
//!
//! Tables are generated at compile time from the polynomials (the
//! C++ sources embed the same tables verbatim).

use crate::{to_upper_hex, Hasher};

/// C++ `CRC32Type` (`GView.hpp:377`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Crc32Type {
    /// `0xFFFFFFFF` final XOR → standard CRC-32 output.
    JamCrc = 0xFFFF_FFFF,
    /// No final XOR → the actual JAMCRC value.
    JamCrc0 = 0x0000_0000,
}

/// C++ `CRC64Type` (`GView.hpp:403`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Crc64Type {
    /// Init / final XOR all ones (CRC-64/WE).
    We = 0xFFFF_FFFF_FFFF_FFFF,
    /// Init / final XOR zero (CRC-64/ECMA-182).
    Ecma182 = 0x0000_0000_0000_0000,
}

/// C++ `ADLER32_BASE`.
pub const ADLER32_BASE: u32 = 65521;
/// C++ `ADLER32_MODULO_VALUE` — unroll width.
pub const ADLER32_MODULO_VALUE: u32 = 8;

// Bounded 256x8 table builders: index/bit counters cannot overflow.
#[allow(clippy::arithmetic_side_effects)]
const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

#[allow(clippy::arithmetic_side_effects)]
const fn make_crc64_table() -> [u64; 256] {
    let mut table = [0_u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u64) << 56;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000_0000_0000_0000 != 0 {
                (crc << 1) ^ 0x42F0_E1EB_A9EA_3693
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

#[allow(clippy::arithmetic_side_effects)]
const fn make_crc16_table() -> [u16; 256] {
    let mut table = [0_u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// C++ `CRC32Table` (`CRC32.cpp:5-32`).
pub static CRC32_TABLE: [u32; 256] = make_crc32_table();
/// C++ `CRC64Table` (`CRC64.cpp:5+`).
pub static CRC64_TABLE: [u64; 256] = make_crc64_table();
/// C++ `CRC16FalseTable` (`CRC16.cpp:5+`).
pub static CRC16_TABLE: [u16; 256] = make_crc16_table();

/// C++ `GView::Hashes::CRC32`.
#[derive(Clone, Copy, Debug)]
pub struct Crc32 {
    value: u32,
    kind: Crc32Type,
}

impl Crc32 {
    /// C++ `Init(type)`: `value = ~0`.
    #[must_use]
    pub const fn new(kind: Crc32Type) -> Self {
        Self { value: !0, kind }
    }

    /// C++ `GetName(type)`.
    #[must_use]
    pub const fn name(kind: Crc32Type) -> &'static str {
        match kind {
            Crc32Type::JamCrc => "CRC32 (JAMCRC(-1))",
            Crc32Type::JamCrc0 => "CRC32 (JAMCRC(0))",
        }
    }

    /// C++ `Update` (`CRC32.cpp:43-56`): reflected table step.
    pub fn update(&mut self, input: &[u8]) {
        let mut crc = self.value;
        for &byte in input {
            let index = ((crc & 0xFF) ^ u32::from(byte)) as usize;
            crc = CRC32_TABLE.get(index).copied().unwrap_or(0) ^ (crc >> 8);
        }
        self.value = crc;
    }

    /// C++ `Final(hash)`: `value ^ type`. Does not mutate — repeatable.
    #[must_use]
    pub const fn finalize(&self) -> u32 {
        self.value ^ (self.kind as u32)
    }

    /// C++ `GetHexValue`: `%.8X` of the final value.
    #[must_use]
    pub fn hex_value(&self) -> String {
        format!("{:08X}", self.finalize())
    }
}

impl Hasher for Crc32 {
    fn update(&mut self, data: &[u8]) {
        Self::update(self, data);
    }
    fn finalize(&mut self) -> Vec<u8> {
        Self::finalize(self).to_be_bytes().to_vec()
    }
    fn hex_digest(&mut self) -> String {
        self.hex_value()
    }
}

/// C++ `GView::Hashes::CRC64`.
#[derive(Clone, Copy, Debug)]
pub struct Crc64 {
    value: u64,
    kind: Crc64Type,
    finalized: bool,
}

impl Crc64 {
    /// C++ `Init(type)`: `value = type`.
    #[must_use]
    pub const fn new(kind: Crc64Type) -> Self {
        Self {
            value: kind as u64,
            kind,
            finalized: false,
        }
    }

    /// C++ `GetName(type)`.
    #[must_use]
    pub const fn name(kind: Crc64Type) -> &'static str {
        match kind {
            Crc64Type::Ecma182 => "CRC64 (ECMA_182)",
            Crc64Type::We => "CRC64 (WE)",
        }
    }

    /// C++ `Update` (`CRC64.cpp`): MSB-first table step. Input after
    /// `finalize` is ignored (the C++ `Final` clears `init` and
    /// further `Final` calls fail).
    pub fn update(&mut self, input: &[u8]) {
        if self.finalized {
            return;
        }
        let mut crc = self.value;
        for &byte in input {
            let index = (((crc >> 56) as u8) ^ byte) as usize;
            crc = CRC64_TABLE.get(index).copied().unwrap_or(0) ^ (crc << 8);
        }
        self.value = crc;
    }

    /// C++ private `Final()`: XORs the type value **once** (later
    /// calls are no-ops, matching the `init` guard).
    pub const fn finalize(&mut self) -> u64 {
        if !self.finalized {
            self.value ^= self.kind as u64;
            self.finalized = true;
        }
        self.value
    }

    /// C++ `GetHexValue`: finalizes, then `%.16llX`.
    pub fn hex_value(&mut self) -> String {
        format!("{:016X}", self.finalize())
    }
}

impl Hasher for Crc64 {
    fn update(&mut self, data: &[u8]) {
        Self::update(self, data);
    }
    fn finalize(&mut self) -> Vec<u8> {
        Self::finalize(self).to_be_bytes().to_vec()
    }
    fn hex_digest(&mut self) -> String {
        self.hex_value()
    }
}

/// C++ `GView::Hashes::CRC16` ("CCITT" — actually CRC-16/XMODEM:
/// init 0).
#[derive(Clone, Copy, Debug, Default)]
pub struct Crc16 {
    value: u16,
}

impl Crc16 {
    /// C++ `Init`: `value = 0`.
    #[must_use]
    pub const fn new() -> Self {
        Self { value: 0 }
    }

    /// C++ `GetName`.
    #[must_use]
    pub const fn name() -> &'static str {
        "CRC16 (CCITT)"
    }

    /// C++ `Update` (`CRC16.cpp`): `table[(value >> 8) ^ byte] ^
    /// (value << 8)`.
    pub fn update(&mut self, input: &[u8]) {
        for &byte in input {
            let j = usize::from(((self.value >> 8) as u8) ^ byte);
            self.value = (self.value << 8) ^ CRC16_TABLE.get(j).copied().unwrap_or(0);
        }
    }

    /// C++ `Final(hash)`.
    #[must_use]
    pub const fn finalize(&self) -> u16 {
        self.value
    }

    /// C++ `GetHexValue`: `%.8X` of the `uint32` holder — 8
    /// characters, zero-padded (quirk preserved).
    #[must_use]
    pub fn hex_value(&self) -> String {
        format!("{:08X}", u32::from(self.value))
    }
}

impl Hasher for Crc16 {
    fn update(&mut self, data: &[u8]) {
        Self::update(self, data);
    }
    fn finalize(&mut self) -> Vec<u8> {
        Self::finalize(self).to_be_bytes().to_vec()
    }
    fn hex_digest(&mut self) -> String {
        self.hex_value()
    }
}

/// C++ `GView::Hashes::Adler32`.
#[derive(Clone, Copy, Debug)]
pub struct Adler32 {
    a: u16,
    b: u16,
}

impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Adler32 {
    /// C++ `Init`: `a = 1, b = 0`.
    #[must_use]
    pub const fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    /// C++ `GetName`.
    #[must_use]
    pub const fn name() -> &'static str {
        "Adler32"
    }

    /// C++ `Update` (`Adler32.cpp:17-70`): leading remainder bytes,
    /// then 8-byte unrolled blocks, reducing `s1` by one subtraction
    /// and `s2` by modulo after each block.
    pub fn update(&mut self, input: &[u8]) {
        let mut s1 = u32::from(self.a);
        let mut s2 = u32::from(self.b);
        let block = ADLER32_MODULO_VALUE as usize;
        let head = input.len() % 8;
        let (lead, rest) = input.split_at(head.min(input.len()));
        if !lead.is_empty() {
            for &byte in lead {
                s1 = s1.wrapping_add(u32::from(byte));
                s2 = s2.wrapping_add(s1);
            }
            if s1 >= ADLER32_BASE {
                s1 = s1.wrapping_sub(ADLER32_BASE);
            }
            s2 %= ADLER32_BASE;
        }
        for chunk in rest.chunks_exact(block) {
            for &byte in chunk {
                s1 = s1.wrapping_add(u32::from(byte));
                s2 = s2.wrapping_add(s1);
            }
            if s1 >= ADLER32_BASE {
                s1 = s1.wrapping_sub(ADLER32_BASE);
            }
            s2 %= ADLER32_BASE;
        }
        self.a = s1 as u16;
        self.b = s2 as u16;
    }

    /// C++ `Final(hash)`: `(b << 16) + a`.
    #[must_use]
    pub const fn finalize(&self) -> u32 {
        ((self.b as u32) << 16).wrapping_add(self.a as u32)
    }

    /// C++ `GetHexValue`: `%.8X`.
    #[must_use]
    pub fn hex_value(&self) -> String {
        format!("{:08X}", self.finalize())
    }
}

impl Hasher for Adler32 {
    fn update(&mut self, data: &[u8]) {
        Self::update(self, data);
    }
    fn finalize(&mut self) -> Vec<u8> {
        Self::finalize(self).to_be_bytes().to_vec()
    }
    fn hex_digest(&mut self) -> String {
        self.hex_value()
    }
}

/// Uppercase hex helper re-export for callers formatting raw bytes.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    to_upper_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECK: &[u8] = b"123456789";

    #[test]
    fn crc32_jamcrc_variants_match_rfc_vectors() {
        // "JAMCRC" (type 0xFFFFFFFF) == standard CRC-32 check value.
        let mut c = Crc32::new(Crc32Type::JamCrc);
        c.update(CHECK);
        assert_eq!(c.finalize(), 0xCBF4_3926);
        assert_eq!(c.hex_value(), "CBF43926");
        // JAMCRC_0 == the real JAMCRC check value (no inversion).
        let mut c0 = Crc32::new(Crc32Type::JamCrc0);
        c0.update(CHECK);
        assert_eq!(c0.finalize(), 0x340B_C6D9);
        // Streaming in pieces gives the same digest.
        let mut s = Crc32::new(Crc32Type::JamCrc);
        s.update(b"1234");
        s.update(b"56789");
        assert_eq!(s.finalize(), 0xCBF4_3926);
        // Empty input.
        assert_eq!(Crc32::new(Crc32Type::JamCrc).finalize(), 0);
        assert_eq!(Crc32::name(Crc32Type::JamCrc), "CRC32 (JAMCRC(-1))");
        // Table spot-check against the C++ literal table.
        assert_eq!(CRC32_TABLE[1], 0x7707_3096);
        assert_eq!(CRC32_TABLE[255], 0x2D02_EF8D);
    }

    #[test]
    fn crc64_ecma_and_we_check_values() {
        let mut e = Crc64::new(Crc64Type::Ecma182);
        e.update(CHECK);
        assert_eq!(e.finalize(), 0x6C40_DF5F_0B49_7347);
        assert_eq!(e.hex_value(), "6C40DF5F0B497347");
        // Final is applied once: repeated calls are stable.
        assert_eq!(e.finalize(), 0x6C40_DF5F_0B49_7347);
        let mut w = Crc64::new(Crc64Type::We);
        w.update(CHECK);
        assert_eq!(w.finalize(), 0x62EC_59E3_F1A4_F00A);
        // Table spot-check against the C++ literal table.
        assert_eq!(CRC64_TABLE[1], 0x42F0_E1EB_A9EA_3693);
        assert_eq!(CRC64_TABLE[2], 0x85E1_C3D7_53D4_6D26);
        assert_eq!(Crc64::name(Crc64Type::We), "CRC64 (WE)");
    }

    #[test]
    fn crc16_xmodem_check_and_8_char_hex_quirk() {
        let mut c = Crc16::new();
        c.update(CHECK);
        assert_eq!(c.finalize(), 0x31C3);
        assert_eq!(c.hex_value(), "000031C3");
        assert_eq!(Crc16::name(), "CRC16 (CCITT)");
        assert_eq!(CRC16_TABLE[1], 0x1021);
    }

    #[test]
    fn adler32_vectors_and_unrolled_path() {
        let mut a = Adler32::new();
        a.update(b"Wikipedia");
        assert_eq!(a.finalize(), 0x11E6_0398);
        assert_eq!(a.hex_value(), "11E60398");
        // Exact multiple of 8 and a long buffer exercising the modulo.
        let mut b = Adler32::new();
        b.update(&[b'a'; 4096]);
        let mut reference = Adler32::new();
        for chunk in [b'a'; 4096].chunks(7) {
            reference.update(chunk);
        }
        assert_eq!(b.finalize(), reference.finalize());
        assert_eq!(Adler32::new().finalize(), 1);
    }

    #[test]
    fn hasher_trait_yields_big_endian_bytes() {
        let mut c: Box<dyn Hasher> = Box::new(Crc32::new(Crc32Type::JamCrc));
        c.update(CHECK);
        assert_eq!(c.finalize(), vec![0xCB, 0xF4, 0x39, 0x26]);
        assert_eq!(c.hex_digest(), "CBF43926");
        assert_eq!(hex(&[0xAB, 0x01]), "AB01");
    }
}
