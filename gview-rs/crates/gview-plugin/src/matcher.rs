//! Type-identification pattern matchers (spec `03_DUAL_PLUGIN` §7.1;
//! C++ `Type/Matcher.cpp:6-46`, `MagicMatcher.cpp`,
//! `StartsWithMatcher.cpp`, `LineStartsWithMatcher.cpp`,
//! `TextParser.cpp`).
//!
//! [`Matcher::from_string`] is `Matcher::CreateFromString`: the
//! pattern prefix selects the algorithm and the remainder initialises
//! it; anything else (unknown prefix, empty pattern, bad hex, empty
//! text) yields `None`.
//!
//! | Prefix | Match |
//! |--------|-------|
//! | `magic:4D 5A` | up to 16 bytes at offset 0 (hex pairs, separated by space/tab/comma) |
//! | `startswith:PK` | the probe **text** (leading whitespace skipped) starts with the value |
//! | `linestartswith:#!` | any of the first 10 lines (leading spaces/tabs skipped) starts with the value |
//!
//! The text matchers run on the UTF-16 conversion of the probe buffer
//! the host produces when the encoding is not binary
//! (`Instance::IdentifyTypePlugin`); [`TextParser`] is that C++
//! helper, including its lazily computed 10-line offset table.
//! `startswith:` / `linestartswith:` values are stored in a
//! `FixSizeString<61>`, which silently truncates longer values
//! ([`MAX_TEXT_PATTERN_LEN`]); `magic:` stops after 16 bytes
//! ([`MAX_MAGIC_LEN`]) and ignores the rest.

/// Capacity of the C++ `MagicMatcher` byte union.
pub const MAX_MAGIC_LEN: usize = 16;
/// Capacity of the C++ `FixSizeString<61>` holding text patterns.
pub const MAX_TEXT_PATTERN_LEN: usize = 61;
/// Lines indexed by the C++ `TextParser` (`offsets[10]`).
pub const MAX_LINES: usize = 10;
/// Host probe size for identification (`Instance.cpp`, spec §7.3).
pub const PROBE_SIZE: u32 = 0x8800;

const PREFIX_MAGIC: &str = "magic:";
const PREFIX_STARTS_WITH: &str = "startswith:";
const PREFIX_LINE_STARTS_WITH: &str = "linestartswith:";

/// C++ `Matcher::TextParser`: a view over the probe text with the
/// leading whitespace skipped and up to [`MAX_LINES`] line starts.
#[derive(Clone, Debug)]
pub struct TextParser<'a> {
    text: &'a [u16],
    lines: [u32; MAX_LINES],
    lines_count: usize,
    lines_computed: bool,
}

const fn is_blank(c: u16) -> bool {
    c == u16::from_le_bytes([b' ', 0]) || c == u16::from_le_bytes([b'\t', 0])
}

const fn is_newline(c: u16) -> bool {
    c == u16::from_le_bytes([b'\n', 0]) || c == u16::from_le_bytes([b'\r', 0])
}

impl<'a> TextParser<'a> {
    /// C++ constructor: skips leading spaces, tabs, `\n`, `\r`; an
    /// all-whitespace (or empty) input becomes empty text.
    #[must_use]
    pub fn new(text: &'a [u16]) -> Self {
        let start = text
            .iter()
            .position(|&c| !(is_blank(c) || is_newline(c)))
            .unwrap_or(text.len());
        Self {
            text: text.get(start..).unwrap_or(&[]),
            lines: [0; MAX_LINES],
            lines_count: 0,
            lines_computed: false,
        }
    }

    /// The text after the leading whitespace (`GetText`).
    #[must_use]
    pub const fn text(&self) -> &'a [u16] {
        self.text
    }

    /// C++ `GetLines` / `ComputeLineOffsets`: offsets (into
    /// [`Self::text`]) of the first [`MAX_LINES`] lines, each past its
    /// leading spaces/tabs. Computed once, on first use.
    pub fn lines(&mut self) -> &[u32] {
        if !self.lines_computed {
            self.compute_line_offsets();
        }
        self.lines.get(..self.lines_count).unwrap_or(&[])
    }

    fn compute_line_offsets(&mut self) {
        let e = self.text.len();
        let mut p = 0_usize;
        self.lines_count = 0;
        while p < e && self.lines_count < MAX_LINES {
            while self.text.get(p).is_some_and(|&c| is_newline(c)) {
                p = p.saturating_add(1);
            }
            while self.text.get(p).is_some_and(|&c| is_blank(c)) {
                p = p.saturating_add(1);
            }
            if let Some(slot) = self.lines.get_mut(self.lines_count) {
                *slot = p as u32;
            }
            self.lines_count = self.lines_count.saturating_add(1);
            while self.text.get(p).is_some_and(|&c| !is_newline(c)) {
                p = p.saturating_add(1);
            }
        }
        self.lines_computed = true;
    }
}

/// UTF-16 units of `text` (helper for hosts holding `&str`).
#[must_use]
pub fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// `magic:` hex separator table (`hexCharTypes[...] == SEP`: tab,
/// space, comma).
const fn is_hex_separator(c: u8) -> bool {
    matches!(c, b'\t' | b' ' | b',')
}

const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// One compiled pattern (C++ `Matcher::Interface` implementations).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// `magic:` — raw bytes compared at offset 0.
    Magic {
        /// Pattern bytes.
        bytes: [u8; MAX_MAGIC_LEN],
        /// Valid bytes in `bytes` (1..=16).
        count: u8,
    },
    /// `startswith:` — text prefix (UTF-16 units of the ASCII value).
    StartsWith(Vec<u16>),
    /// `linestartswith:` — any of the first lines starts with the value.
    LineStartsWith(Vec<u16>),
}

impl Matcher {
    /// C++ `Matcher::CreateFromString`.
    #[must_use]
    pub fn from_string(pattern: &str) -> Option<Self> {
        let first = pattern.as_bytes().first().copied()?;
        match first {
            b'm' => pattern.strip_prefix(PREFIX_MAGIC).and_then(Self::init_magic),
            b's' => pattern
                .strip_prefix(PREFIX_STARTS_WITH)
                .and_then(Self::init_text)
                .map(Self::StartsWith),
            b'l' => pattern
                .strip_prefix(PREFIX_LINE_STARTS_WITH)
                .and_then(Self::init_text)
                .map(Self::LineStartsWith),
            _ => None,
        }
    }

    /// C++ `MagicMatcher::Init`: `HH HH …` / `HH,HH,…`; separators are
    /// skipped, every byte needs two hex digits, at most 16 bytes are
    /// kept (the rest is ignored), and at least one byte is required.
    fn init_magic(text: &str) -> Option<Self> {
        let data = text.as_bytes();
        let mut bytes = [0_u8; MAX_MAGIC_LEN];
        let mut count = 0_usize;
        let mut p = 0_usize;
        while p < data.len() {
            while data.get(p).is_some_and(|&c| is_hex_separator(c)) {
                p = p.saturating_add(1);
            }
            if p >= data.len() {
                break;
            }
            let hi = hex_value(data.get(p).copied()?)?;
            let lo = hex_value(data.get(p.saturating_add(1)).copied()?)?;
            *bytes.get_mut(count)? = (hi << 4) | lo;
            count = count.saturating_add(1);
            if count >= MAX_MAGIC_LEN {
                break;
            }
            p = p.saturating_add(2);
        }
        (count > 0).then_some(Self::Magic {
            bytes,
            count: count as u8,
        })
    }

    /// C++ `StartsWithMatcher::Init` / `LineStartsWithMatcher::Init`:
    /// non-empty, truncated to the `FixSizeString<61>` capacity. The
    /// C++ compares `char` values widened to `char16`, so the pattern
    /// is kept byte-wise (each byte one UTF-16 unit).
    fn init_text(text: &str) -> Option<Vec<u16>> {
        if text.is_empty() {
            return None;
        }
        Some(
            text.bytes()
                .take(MAX_TEXT_PATTERN_LEN)
                .map(u16::from)
                .collect(),
        )
    }

    /// The `magic:` bytes, when this is a magic matcher.
    #[must_use]
    pub fn magic_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Magic { bytes, count } => bytes.get(..usize::from(*count)),
            _ => None,
        }
    }

    /// C++ `Interface::Match(buf, text)`.
    #[must_use]
    pub fn matches(&self, buf: &[u8], text: &mut TextParser<'_>) -> bool {
        match self {
            Self::Magic { bytes, count } => {
                let n = usize::from(*count);
                // `CHECK(buf.GetLength() >= count)`; the C++ word/dword
                // switch is an optimised memcmp.
                n > 0 && buf.get(..n) == bytes.get(..n)
            }
            Self::StartsWith(value) => starts_with_at(text.text(), 0, value),
            Self::LineStartsWith(value) => {
                let content = text.text();
                text.lines()
                    .iter()
                    .any(|&ofs| starts_with_at(content, ofs as usize, value))
            }
        }
    }
}

/// C++ `CheckStartsWith(text, offset)` (and `StartsWithMatcher::Match`
/// with offset 0): `offset + len` must fit, then unit-wise equality.
fn starts_with_at(text: &[u16], offset: usize, value: &[u16]) -> bool {
    let end = offset.saturating_add(value.len());
    text.get(offset..end) == Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser_of(s: &str) -> Vec<u16> {
        utf16(s)
    }

    #[test]
    fn magic_pattern_parses_hex_pairs_with_separators() {
        let m = Matcher::from_string("magic:4D 5A").expect("magic");
        assert_eq!(m.magic_bytes(), Some(&[0x4D, 0x5A][..]));
        let m = Matcher::from_string("magic:7f,45,4c,46").expect("magic");
        assert_eq!(m.magic_bytes(), Some(&[0x7F, 0x45, 0x4C, 0x46][..]));
        let m = Matcher::from_string("magic:\t 50 4B\t").expect("magic");
        assert_eq!(m.magic_bytes(), Some(&[0x50, 0x4B][..]));
        // Pairs are not separated in the C++ scanner: "4D5A" is two bytes.
        let m = Matcher::from_string("magic:4D5A").expect("magic");
        assert_eq!(m.magic_bytes(), Some(&[0x4D, 0x5A][..]));
    }

    #[test]
    fn magic_matches_bytes_at_offset_zero() {
        let m = Matcher::from_string("magic:4D 5A").expect("magic");
        let mut empty = TextParser::new(&[]);
        assert!(m.matches(b"MZ\x90\x00", &mut empty));
        assert!(!m.matches(b"ZM", &mut empty));
        assert!(!m.matches(b"M", &mut empty));
        assert!(!m.matches(b"", &mut empty));

        // Every length of the C++ switch (1..=8) plus the memcmp path.
        for n in 1..=MAX_MAGIC_LEN {
            let hex: Vec<String> = (0..n).map(|i| format!("{:02X}", i as u8 + 1)).collect();
            let m = Matcher::from_string(&format!("magic:{}", hex.join(" "))).expect("magic");
            let data: Vec<u8> = (1..=n as u8).chain([0xFF]).collect();
            assert!(m.matches(&data, &mut empty), "n={n}");
            let mut bad = data.clone();
            bad[n - 1] ^= 1;
            assert!(!m.matches(&bad, &mut empty), "n={n}");
            assert!(!m.matches(&data[..n - 1], &mut empty), "n={n}");
        }
    }

    #[test]
    fn magic_caps_at_16_bytes_and_ignores_the_rest() {
        let hex: Vec<String> = (0..20).map(|i| format!("{i:02X}")).collect();
        let m = Matcher::from_string(&format!("magic:{}", hex.join(" "))).expect("magic");
        let expected: Vec<u8> = (0..16).collect();
        assert_eq!(m.magic_bytes(), Some(&expected[..]));
        // The 17th "byte" may even be garbage: it is never scanned.
        let m = Matcher::from_string(&format!("magic:{} ZZ", hex[..16].join(" "))).expect("magic");
        assert_eq!(m.magic_bytes().map(<[u8]>::len), Some(16));
    }

    #[test]
    fn invalid_patterns_return_none() {
        for bad in [
            "",
            "magic:",
            "magic:4",
            "magic:4G",
            "magic:4D 5",
            "magic:xx",
            "magic:  ",
            "startswith:",
            "linestartswith:",
            "startwith:PK",
            "MAGIC:4D",
            "regex:abc",
            "m",
            "s",
            "l",
        ] {
            assert!(Matcher::from_string(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn startswith_matches_text_after_leading_whitespace() {
        let m = Matcher::from_string("startswith:PK").expect("sw");
        assert_eq!(m, Matcher::StartsWith(vec![u16::from(b'P'), u16::from(b'K')]));
        let t = parser_of("PK\x03\x04");
        assert!(m.matches(b"", &mut TextParser::new(&t)));
        let t = parser_of("  \r\n\tPKzip");
        assert!(m.matches(b"", &mut TextParser::new(&t)));
        let t = parser_of("xPK");
        assert!(!m.matches(b"", &mut TextParser::new(&t)));
        let t = parser_of("P");
        assert!(!m.matches(b"", &mut TextParser::new(&t)));
        assert!(!m.matches(b"PK", &mut TextParser::new(&[])));
    }

    #[test]
    fn linestartswith_scans_the_first_ten_lines() {
        let m = Matcher::from_string("linestartswith:#!").expect("lsw");
        let t = parser_of("#!/bin/sh\necho hi");
        assert!(m.matches(b"", &mut TextParser::new(&t)));
        let t = parser_of("line one\r\n   \t#!/usr/bin/env python\n");
        assert!(m.matches(b"", &mut TextParser::new(&t)));
        let t = parser_of("a #! b");
        assert!(!m.matches(b"", &mut TextParser::new(&t)));

        // Line 10 is checked, line 11 is not (offsets[10]).
        let ten = "x\n".repeat(9) + "#!ok";
        let t = parser_of(&ten);
        assert!(m.matches(b"", &mut TextParser::new(&t)));
        let eleven = "x\n".repeat(10) + "#!late";
        let t = parser_of(&eleven);
        assert!(!m.matches(b"", &mut TextParser::new(&t)));
    }

    #[test]
    fn text_parser_line_offsets_match_cpp() {
        let t = parser_of("\n\n  first\r\n\tsecond\n\n\nthird");
        let mut p = TextParser::new(&t);
        // Leading whitespace (including newlines) is dropped from text.
        assert_eq!(p.text(), &utf16("first\r\n\tsecond\n\n\nthird")[..]);
        assert_eq!(p.lines(), &[0, 8, 17]);
        let empty = parser_of("  \t\r\n ");
        let mut p = TextParser::new(&empty);
        assert!(p.text().is_empty());
        assert!(p.lines().is_empty());
    }

    #[test]
    fn text_patterns_truncate_to_61_units() {
        let long = "a".repeat(80);
        let m = Matcher::from_string(&format!("startswith:{long}")).expect("sw");
        assert_eq!(
            m,
            Matcher::StartsWith(vec![u16::from(b'a'); MAX_TEXT_PATTERN_LEN])
        );
        let t = parser_of(&"a".repeat(61));
        assert!(m.matches(b"", &mut TextParser::new(&t)));
        let t = parser_of(&"a".repeat(60));
        assert!(!m.matches(b"", &mut TextParser::new(&t)));
    }

    #[test]
    fn constants_match_cpp() {
        assert_eq!(MAX_MAGIC_LEN, 16);
        assert_eq!(MAX_TEXT_PATTERN_LEN, 61);
        assert_eq!(MAX_LINES, 10);
        assert_eq!(PROBE_SIZE, 0x8800);
    }
}
