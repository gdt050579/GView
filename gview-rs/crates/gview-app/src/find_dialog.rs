//! Find framework: search FSM behind the Find dialog
//! (C++ `BufferViewer/FindDialog.cpp`; spec `02_VIEWER_BUFFER` §7).
//!
//! Search is a **linear regex scan** over `DataCache` chunks — not
//! Boyer-Moore (§7). Text mode escapes the input unless the regex
//! option is set (`FindDialog.cpp:509-516`); binary mode builds a
//! `\xNN` byte pattern with `?` matching any byte
//! (`FindDialog.cpp:579-663`). The modal dialog UI itself is wired by
//! the `buffer-find-integration` task; this module is the engine plus
//! input validation.
//!
//! Hardening (matrix requirement, no C++ analogue): patterns longer
//! than [`MAX_PATTERN_LENGTH`] bytes are rejected before compilation.
//!
//! C++ parity note: like the C++ chunked `regex_search`, a match that
//! straddles a chunk boundary is not found; chunks are
//! `cache_size` bytes (§7.3), so this only affects matches crossing
//! those large boundaries.

use gview_core::cache::DataCache;
use regex::bytes::{Regex, RegexBuilder};

/// Maximum accepted search-pattern length in bytes (hardening cap).
pub const MAX_PATTERN_LENGTH: usize = 4096;

/// A search hit: `length` bytes at `offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    /// File offset of the first matched byte.
    pub offset: u64,
    /// Match length in bytes.
    pub length: u64,
}

/// Errors building a [`FindEngine`].
#[derive(Debug, PartialEq, Eq)]
pub enum FindError {
    /// The pattern is empty.
    EmptyPattern,
    /// The pattern exceeds [`MAX_PATTERN_LENGTH`].
    PatternTooLong {
        /// Actual pattern length in bytes.
        length: usize,
    },
    /// The regex failed to compile.
    InvalidRegex(String),
    /// A binary token failed validation (§7.5).
    InvalidBinaryToken(String),
}

impl std::fmt::Display for FindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPattern => write!(f, "search pattern is empty"),
            Self::PatternTooLong { length } => write!(
                f,
                "search pattern is {length} bytes; maximum accepted is {MAX_PATTERN_LENGTH}"
            ),
            Self::InvalidRegex(msg) => write!(f, "invalid regex: {msg}"),
            Self::InvalidBinaryToken(token) => write!(f, "invalid binary token: '{token}'"),
        }
    }
}

impl std::error::Error for FindError {}

/// Validates one hex byte token: 1–2 hex digits, or `?` wildcard
/// (C++ `ValidateHex`, §7.5). Returns `None` for the wildcard.
fn parse_hex_token(token: &str) -> Result<Option<u8>, FindError> {
    if token == "?" {
        return Ok(None);
    }
    if token.is_empty() || token.len() > 2 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(FindError::InvalidBinaryToken(token.to_owned()));
    }
    u8::from_str_radix(token, 16)
        .map(Some)
        .map_err(|_| FindError::InvalidBinaryToken(token.to_owned()))
}

/// Validates one decimal byte token: 1–3 digits in `0..=255`, or `?`
/// wildcard (C++ `ValidateDecimal`, §7.5).
fn parse_decimal_token(token: &str) -> Result<Option<u8>, FindError> {
    if token == "?" {
        return Ok(None);
    }
    if token.is_empty() || token.len() > 3 || !token.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FindError::InvalidBinaryToken(token.to_owned()));
    }
    token
        .parse::<u8>()
        .map(Some)
        .map_err(|_| FindError::InvalidBinaryToken(token.to_owned()))
}

/// Compiled search pattern plus scan logic.
#[derive(Debug)]
pub struct FindEngine {
    pattern: Regex,
}

impl FindEngine {
    fn compile(pattern: &str, ignore_case: bool) -> Result<Self, FindError> {
        if pattern.len() > MAX_PATTERN_LENGTH {
            return Err(FindError::PatternTooLong {
                length: pattern.len(),
            });
        }
        let regex = RegexBuilder::new(pattern)
            .unicode(false)
            .case_insensitive(ignore_case)
            .build()
            .map_err(|e| FindError::InvalidRegex(e.to_string()))?;
        Ok(Self { pattern: regex })
    }

    /// Text search: `text` is treated as a literal (regex-escaped)
    /// unless `as_regex` (C++ `FindDialog.cpp:505-516`).
    ///
    /// # Errors
    /// [`FindError`] for an empty/oversized pattern or a bad regex.
    pub fn new_text(text: &str, ignore_case: bool, as_regex: bool) -> Result<Self, FindError> {
        if text.is_empty() {
            return Err(FindError::EmptyPattern);
        }
        if text.len() > MAX_PATTERN_LENGTH {
            return Err(FindError::PatternTooLong { length: text.len() });
        }
        let pattern = if as_regex {
            text.to_owned()
        } else {
            regex::escape(text)
        };
        Self::compile(&pattern, ignore_case)
    }

    /// Binary search from whitespace-separated byte tokens, hex or
    /// decimal per `hex`; `?` matches any byte
    /// (C++ `FindDialog.cpp:579-663`).
    ///
    /// # Errors
    /// [`FindError::InvalidBinaryToken`] for a malformed token, plus
    /// the shared empty/length/regex errors.
    pub fn new_binary(tokens: &str, hex: bool, ignore_case: bool) -> Result<Self, FindError> {
        use std::fmt::Write as _;
        if tokens.len() > MAX_PATTERN_LENGTH {
            return Err(FindError::PatternTooLong {
                length: tokens.len(),
            });
        }
        let mut pattern = String::new();
        let mut any = false;
        for token in tokens.split_whitespace() {
            any = true;
            let byte = if hex {
                parse_hex_token(token)?
            } else {
                parse_decimal_token(token)?
            };
            match byte {
                Some(b) => {
                    let _ = write!(pattern, "\\x{b:02X}");
                }
                None => pattern.push_str("[\\x00-\\xFF]"),
            }
        }
        if !any {
            return Err(FindError::EmptyPattern);
        }
        Self::compile(&pattern, ignore_case)
    }

    /// First match in a byte slice, offset by `base`.
    fn first_in(&self, data: &[u8], base: u64) -> Option<Match> {
        self.pattern.find(data).map(|m| Match {
            offset: base.saturating_add(m.start() as u64),
            length: m.end().saturating_sub(m.start()) as u64,
        })
    }

    /// Last match in a byte slice, offset by `base`
    /// (§7.3: `if last: keep searching for last match in chunk`).
    fn last_in(&self, data: &[u8], base: u64) -> Option<Match> {
        self.pattern.find_iter(data).last().map(|m| Match {
            offset: base.saturating_add(m.start() as u64),
            length: m.end().saturating_sub(m.start()) as u64,
        })
    }

    /// First match in `[start, end)`, scanning forward in chunks of
    /// the cache size (§7.3, C++ `ProcessInput` / `GetNextMatch`).
    pub fn find_forward(&self, cache: &mut DataCache, start: u64, end: u64) -> Option<Match> {
        let end = u64::min(end, cache.size());
        let chunk = u64::from(cache.cache_size());
        let mut offset = start;
        while offset < end {
            let to_read = u64::min(chunk, end.saturating_sub(offset));
            let to_read_u32 = u32::try_from(to_read).unwrap_or(u32::MAX);
            let Ok(bytes) = cache.get(offset, to_read_u32, false) else {
                return None;
            };
            if bytes.is_empty() {
                return None;
            }
            let read = bytes.len() as u64;
            if let Some(m) = self.first_in(bytes, offset) {
                return Some(m);
            }
            offset = offset.saturating_add(read);
        }
        None
    }

    /// Last match strictly before `end`, walking backward in
    /// cache-sized windows (§7.4, C++ `GetPreviousMatch`).
    pub fn find_backward(&self, cache: &mut DataCache, start: u64, end: u64) -> Option<Match> {
        let end = u64::min(end, cache.size());
        let chunk = u64::from(cache.cache_size());
        let mut window_end = end;
        while window_end > start {
            let window_start = u64::max(start, window_end.saturating_sub(chunk));
            let len = window_end.saturating_sub(window_start);
            let len_u32 = u32::try_from(len).unwrap_or(u32::MAX);
            let Ok(bytes) = cache.get(window_start, len_u32, false) else {
                return None;
            };
            if let Some(m) = self.last_in(bytes, window_start) {
                return Some(m);
            }
            window_end = window_start;
        }
        None
    }

    /// First match across the inclusive-`(start, end)` selection
    /// zones, in zone order (§7.2 selection scope — C++ iterates
    /// `GetSelectionZone(i)` ranges).
    pub fn find_in_zones(&self, cache: &mut DataCache, zones: &[(u64, u64)]) -> Option<Match> {
        for &(zone_start, zone_end) in zones {
            let exclusive_end = zone_end.saturating_add(1);
            if let Some(m) = self.find_forward(cache, zone_start, exclusive_end) {
                return Some(m);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_core::source::MemorySource;

    fn cache_over(data: &[u8]) -> (DataCache, u64) {
        let cache = DataCache::new(Box::new(MemorySource::from_slice(data)), 0);
        let size = cache.size();
        (cache, size)
    }

    #[test]
    fn ascii_forward_finds_matches_in_order() {
        let (mut cache, size) = cache_over(b"..alpha..beta..alpha..");
        let engine = FindEngine::new_text("alpha", false, false).expect("engine");
        let first = engine.find_forward(&mut cache, 0, size).expect("hit");
        assert_eq!(
            first,
            Match {
                offset: 2,
                length: 5
            }
        );
        // Resume after the first match: next occurrence.
        let next = engine
            .find_forward(&mut cache, first.offset + 1, size)
            .expect("hit");
        assert_eq!(next.offset, 15);
        // No further occurrence.
        assert!(engine
            .find_forward(&mut cache, next.offset + 1, size)
            .is_none());
    }

    #[test]
    fn ascii_backward_finds_last_match() {
        let (mut cache, size) = cache_over(b"..alpha..beta..alpha..");
        let engine = FindEngine::new_text("alpha", false, false).expect("engine");
        let last = engine.find_backward(&mut cache, 0, size).expect("hit");
        assert_eq!(last.offset, 15);
        // Search before the last hit finds the first one.
        let prev = engine
            .find_backward(&mut cache, 0, last.offset)
            .expect("hit");
        assert_eq!(prev.offset, 2);
        assert!(engine.find_backward(&mut cache, 0, prev.offset).is_none());
    }

    #[test]
    fn literal_mode_escapes_regex_metacharacters() {
        let (mut cache, size) = cache_over(b"price is a+b not aab");
        let engine = FindEngine::new_text("a+b", false, false).expect("engine");
        let m = engine.find_forward(&mut cache, 0, size).expect("hit");
        assert_eq!(m.offset, 9); // the literal "a+b" text
                                 // As a regex, "a+b" means 1+ 'a' then 'b': first hit is "aab".
        let engine = FindEngine::new_text("a+b", false, true).expect("engine");
        let m = engine.find_forward(&mut cache, 0, size).expect("hit");
        assert_eq!(
            m,
            Match {
                offset: 17,
                length: 3
            }
        );
    }

    #[test]
    fn ignore_case_matches_both_cases() {
        let (mut cache, size) = cache_over(b"..MZ..mz..");
        let engine = FindEngine::new_text("mz", true, false).expect("engine");
        let m = engine.find_forward(&mut cache, 0, size).expect("hit");
        assert_eq!(m.offset, 2);
    }

    #[test]
    fn selection_scope_restricts_search() {
        let data = b"..key......key......key..";
        let (mut cache, _size) = cache_over(data);
        let engine = FindEngine::new_text("key", false, false).expect("engine");
        // Zone [8, 16] (inclusive) covers only the middle "key" at 11.
        let m = engine.find_in_zones(&mut cache, &[(8, 16)]).expect("hit");
        assert_eq!(m.offset, 11);
        // A zone without a match yields nothing even though the file
        // has matches elsewhere.
        assert!(engine.find_in_zones(&mut cache, &[(4, 9)]).is_none());
        // Zones are searched in order; first zone with a hit wins
        // (third "key" starts at offset 20).
        let m = engine
            .find_in_zones(&mut cache, &[(4, 9), (18, 24)])
            .expect("hit");
        assert_eq!(m.offset, 20);
    }

    #[test]
    fn pattern_length_limit_4096() {
        let long = "a".repeat(MAX_PATTERN_LENGTH);
        assert!(FindEngine::new_text(&long, false, false).is_ok());
        let too_long = "a".repeat(MAX_PATTERN_LENGTH + 1);
        assert_eq!(
            FindEngine::new_text(&too_long, false, false).unwrap_err(),
            FindError::PatternTooLong {
                length: MAX_PATTERN_LENGTH + 1
            }
        );
        assert!(matches!(
            FindEngine::new_binary(&too_long, true, false).unwrap_err(),
            FindError::PatternTooLong { .. }
        ));
    }

    #[test]
    fn binary_hex_pattern_with_wildcard() {
        let (mut cache, size) = cache_over(&[0x00, 0x4D, 0x5A, 0x90, 0x00, 0x4D, 0x00, 0x90]);
        // "4D ? 90" — MZ? header-ish pattern.
        let engine = FindEngine::new_binary("4D ? 90", true, false).expect("engine");
        let m = engine.find_forward(&mut cache, 0, size).expect("hit");
        assert_eq!(
            m,
            Match {
                offset: 1,
                length: 3
            }
        );
        let next = engine.find_forward(&mut cache, 2, size).expect("hit");
        assert_eq!(next.offset, 5);
    }

    #[test]
    fn binary_decimal_pattern() {
        let (mut cache, size) = cache_over(&[10, 20, 255, 30]);
        let engine = FindEngine::new_binary("20 255", false, false).expect("engine");
        let m = engine.find_forward(&mut cache, 0, size).expect("hit");
        assert_eq!(
            m,
            Match {
                offset: 1,
                length: 2
            }
        );
    }

    #[test]
    fn binary_token_validation() {
        // Hex: max 2 digits, hex charset.
        assert!(FindEngine::new_binary("4D5", true, false).is_err());
        assert!(FindEngine::new_binary("G1", true, false).is_err());
        // Decimal: 0-255, max 3 chars.
        assert!(FindEngine::new_binary("256", false, false).is_err());
        assert!(FindEngine::new_binary("1000", false, false).is_err());
        assert!(FindEngine::new_binary("12a", false, false).is_err());
        // Empty input.
        assert_eq!(
            FindEngine::new_binary("   ", true, false).unwrap_err(),
            FindError::EmptyPattern
        );
        assert_eq!(
            FindEngine::new_text("", false, false).unwrap_err(),
            FindError::EmptyPattern
        );
    }

    #[test]
    fn invalid_regex_reported() {
        assert!(matches!(
            FindEngine::new_text("(unclosed", false, true).unwrap_err(),
            FindError::InvalidRegex(_)
        ));
        // The same text as a literal is fine.
        assert!(FindEngine::new_text("(unclosed", false, false).is_ok());
    }

    #[test]
    fn empty_file_finds_nothing() {
        let (mut cache, size) = cache_over(&[]);
        let engine = FindEngine::new_text("x", false, false).expect("engine");
        assert!(engine.find_forward(&mut cache, 0, size).is_none());
        assert!(engine.find_backward(&mut cache, 0, size).is_none());
    }
}
