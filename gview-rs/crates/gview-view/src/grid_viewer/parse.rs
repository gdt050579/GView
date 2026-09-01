//! `GridViewer` CSV/TSV parsing engine
//! (spec `02_VIEWER_GRID` §3.1–§3.3).
//!
//! C++ anchor: `Instance::ProcessContent`
//! (`GridViewer/Instance.cpp:257-337`).
//!
//! The C++ implementation reads one cache window per row and takes
//! the first newline **inside that window** as the row terminator, so
//! a row longer than the cache size is silently split
//! (`Instance.cpp:259-260`, the in-source TODO). Per the task matrix
//! and spec §3.3, the Rust port **fixes** this: parsing runs as a
//! chunked state machine that streams the file through the cache, so
//! rows of any length parse correctly regardless of cache size.
//!
//! Every other C++ behavior is preserved verbatim:
//!
//! - Tokenization splits on `separator[0]` **only** (`separator[1]`
//!   is never used) and there is no RFC 4180 quote handling by
//!   default (§3.2); the optional [`GridParseSettings::quoted_fields`]
//!   mode the spec asks for is off unless enabled.
//! - The **last token of each row** ends at the post-newline offset
//!   (`{tEnd + 1, oSizeProcessed}`, `Instance.cpp:324`), so it covers
//!   the newline byte(s) — and reaches one byte past EOF on an
//!   unterminated final row.
//! - A row with **no separator** produces two tokens: the full line
//!   plus the quirk token `{lineStart + 1, oSizeProcessed}`
//!   (`Instance.cpp:312-324` runs both blocks).
//! - An **empty file** still produces one row (the C++ `do`-`while`
//!   body runs once): line `{0, 0}`, tokens `[{0,0}, {1,1}]`.
//! - `cols` is the token count of the **first** row
//!   (`Instance.cpp:334`).
//!
//! Newline handling follows the C++ branch order: the first `\n` or
//! `\r` ends the row, and a directly following *different* newline
//! char (`\r\n` or `\n\r`) is consumed with it.

use gview_core::cache::DataCache;

/// Parsing options (C++ `SettingsData` subset).
#[derive(Clone, Copy, Debug)]
pub struct GridParseSettings {
    /// Cell separator — C++ uses `separator[0]` only (spec §3.1).
    pub separator: u8,
    /// Optional quoted-field mode (spec §3.2): when set, separators
    /// and newlines between double quotes do not split; quote bytes
    /// stay inside the token ranges. Off by default (C++ parity).
    pub quoted_fields: bool,
}

impl Default for GridParseSettings {
    fn default() -> Self {
        Self {
            separator: b',',
            quoted_fields: false,
        }
    }
}

/// Parsed table layout: absolute `[start, end)` byte ranges into the
/// underlying object (C++ `settings->lines` / `settings->tokens`,
/// keyed 0..N so a `Vec` replaces the `std::map`).
#[derive(Clone, Debug, Default)]
pub struct GridContent {
    /// Per row: the line's byte range **excluding** the newline.
    pub lines: Vec<(u64, u64)>,
    /// Per row: cell byte ranges (C++ quirks preserved — see the
    /// module docs for the last-token and no-separator shapes).
    pub tokens: Vec<Vec<(u64, u64)>>,
    /// Row count (C++ `settings->rows`).
    pub rows: u64,
    /// First row's token count (C++ `settings->cols`).
    pub cols: u64,
}

/// Emits one completed row (C++ `Instance.cpp:299-327`):
/// `line = [line_start, line_end)`, `processed_end` = offset just
/// after the newline (or `EOF + 1` for an unterminated last row).
/// Row-accumulation state carried across chunk boundaries — the
/// stream-like state machine the C++ TODO (`Instance.cpp:259-260`)
/// asks for.
struct RowScanner<'a> {
    settings: &'a GridParseSettings,
    o_size: u64,
    lines: Vec<(u64, u64)>,
    tokens: Vec<Vec<(u64, u64)>>,
    separators: Vec<u64>,
    line_start: u64,
    in_quotes: bool,
    /// A newline byte seen as the last byte of a chunk with more data
    /// following: the pair check needs the next chunk's first byte.
    pending_newline: Option<(u64, u8)>,
}

impl<'a> RowScanner<'a> {
    const fn new(settings: &'a GridParseSettings, o_size: u64) -> Self {
        Self {
            settings,
            o_size,
            lines: Vec::new(),
            tokens: Vec::new(),
            separators: Vec::new(),
            line_start: 0,
            in_quotes: false,
            pending_newline: None,
        }
    }

    /// Emits the row `[line_start, line_end)` (C++
    /// `Instance.cpp:299-327`); `processed_end` is the offset just
    /// after the newline (or `EOF + 1` for an unterminated last row)
    /// and becomes the next row's start.
    fn emit_line(&mut self, line_end: u64, processed_end: u64) {
        self.lines.push((self.line_start, line_end));
        let mut row_tokens = Vec::new();
        if self.separators.is_empty() {
            row_tokens.push((self.line_start, line_end));
        }
        // C++ `tStart = tEnd = oldOSizeProcessed` (the line start),
        // then one token per separator plus the trailing
        // `{tEnd + 1, oSizeProcessed}` token — always.
        let mut t_start = self.line_start;
        let mut t_end = self.line_start;
        for &sep in &self.separators {
            t_end = sep;
            row_tokens.push((t_start, t_end));
            t_start = t_end.saturating_add(1);
        }
        row_tokens.push((t_end.saturating_add(1), processed_end));
        self.tokens.push(row_tokens);
        self.separators.clear();
        self.line_start = processed_end;
    }

    /// Resolves a newline deferred at the previous chunk's edge;
    /// returns the index at which scanning of `chunk` starts.
    fn resolve_pending(&mut self, chunk: &[u8]) -> usize {
        let Some((nl_pos, nl_byte)) = self.pending_newline.take() else {
            return 0;
        };
        let paired = chunk
            .first()
            .is_some_and(|&b| (b == b'\n' || b == b'\r') && b != nl_byte);
        let nl_len = if paired { 2 } else { 1 };
        self.emit_line(nl_pos, nl_pos.saturating_add(nl_len));
        usize::from(paired)
    }

    /// Scans one cache chunk starting at absolute offset `offset`,
    /// emitting every row completed inside it.
    fn scan_chunk(&mut self, chunk: &[u8], offset: u64) {
        let mut i = self.resolve_pending(chunk);
        while i < chunk.len() {
            let Some(&byte) = chunk.get(i) else {
                break;
            };
            let abs = offset.saturating_add(i as u64);
            if self.settings.quoted_fields && byte == b'"' {
                self.in_quotes = !self.in_quotes;
                i = i.saturating_add(1);
                continue;
            }
            if !self.in_quotes && (byte == b'\n' || byte == b'\r') {
                match chunk.get(i.saturating_add(1)) {
                    Some(&next) if (next == b'\n' || next == b'\r') && next != byte => {
                        self.emit_line(abs, abs.saturating_add(2));
                        i = i.saturating_add(2);
                    }
                    Some(_) => {
                        self.emit_line(abs, abs.saturating_add(1));
                        i = i.saturating_add(1);
                    }
                    None => {
                        // Chunk ends on this newline byte.
                        if abs.saturating_add(1) >= self.o_size {
                            // True EOF: no pair possible.
                            self.emit_line(abs, abs.saturating_add(1));
                        } else {
                            self.pending_newline = Some((abs, byte));
                        }
                        i = i.saturating_add(1);
                    }
                }
                continue;
            }
            if !self.in_quotes && byte == self.settings.separator {
                self.separators.push(abs);
            }
            i = i.saturating_add(1);
        }
    }

    /// Closes any open row and packages the result.
    fn finish(mut self) -> GridContent {
        // A pending newline can only remain if a later cache read
        // failed; close the row with a single-byte newline.
        if let Some((nl_pos, _)) = self.pending_newline.take() {
            self.emit_line(nl_pos, nl_pos.saturating_add(1));
        }
        // Unterminated last row (C++ `nPos = data.size()`,
        // `oSizeProcessed += nPos + 1` — the token end lands one past
        // EOF).
        if self.line_start < self.o_size {
            let end = self.o_size;
            self.emit_line(end, end.saturating_add(1));
        }
        let cols = self.tokens.first().map_or(0, |t| t.len() as u64);
        let rows = self.lines.len() as u64;
        GridContent {
            lines: self.lines,
            tokens: self.tokens,
            rows,
            cols,
        }
    }
}

/// C++ `Instance::ProcessContent` (`Instance.cpp:257-337`) as a
/// streaming state machine.
///
/// Scans the whole object through the cache in `cache_size` chunks,
/// carrying row state across chunk boundaries so a row longer than
/// the cache window parses correctly (the §3.3 fix).
#[must_use]
pub fn process_content(cache: &mut DataCache, settings: &GridParseSettings) -> GridContent {
    let o_size = cache.size();
    let mut scanner = RowScanner::new(settings, o_size);

    if o_size == 0 {
        // C++ do-while quirk: the body runs once on an empty file.
        scanner.emit_line(0, 1);
        return scanner.finish();
    }

    let chunk_cap = u64::from(cache.cache_size());
    let mut chunk: Vec<u8> = Vec::new();
    let mut offset = 0_u64;
    while offset < o_size {
        let want = u64::min(o_size.saturating_sub(offset), chunk_cap) as u32;
        let Ok(buf) = cache.get(offset, want, false) else {
            break;
        };
        if buf.is_empty() {
            break;
        }
        chunk.clear();
        chunk.extend_from_slice(buf);
        scanner.scan_chunk(&chunk, offset);
        offset = offset.saturating_add(chunk.len() as u64);
    }
    scanner.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_core::source::MemorySource;

    /// Cache over `data`; `requested_cache_size = 1` aligns up to the
    /// 64 KiB minimum window.
    fn cache_over(data: &[u8], cache_size: u32) -> DataCache {
        DataCache::new(Box::new(MemorySource::from_slice(data)), cache_size)
    }

    fn parse(data: &[u8]) -> GridContent {
        let mut cache = cache_over(data, 1);
        process_content(&mut cache, &GridParseSettings::default())
    }

    #[test]
    fn basic_csv_rows_and_tokens() {
        // "a,b\ncc,d\n" — offsets: a0 ,1 b2 \n3 c4 c5 ,6 d7 \n8.
        let content = parse(b"a,b\ncc,d\n");
        assert_eq!(content.rows, 2);
        assert_eq!(content.cols, 2);
        assert_eq!(content.lines, vec![(0, 3), (4, 8)]);
        // Last token of each row extends past the newline (C++
        // parity: `{tEnd + 1, oSizeProcessed}`).
        assert_eq!(content.tokens[0], vec![(0, 1), (2, 4)]);
        assert_eq!(content.tokens[1], vec![(4, 6), (7, 9)]);
    }

    #[test]
    fn crlf_and_lfcr_pairs_advance_two() {
        // "a\r\nb" — the \r\n pair is one terminator.
        let content = parse(b"a\r\nb");
        assert_eq!(content.lines, vec![(0, 1), (3, 4)]);
        // "a\n\rb" — \n\r is also a pair (C++ checks both orders).
        let content = parse(b"a\n\rb");
        assert_eq!(content.lines, vec![(0, 1), (3, 4)]);
        // "\n\n" is NOT a pair: two empty rows.
        let content = parse(b"a\n\nb");
        assert_eq!(content.lines, vec![(0, 1), (2, 2), (3, 4)]);
    }

    #[test]
    fn separator_less_line_gets_quirk_double_token() {
        // C++ pushes the whole line AND the `{start+1, processed}`
        // token when no separator exists (Instance.cpp:312-324).
        let content = parse(b"abc\n");
        assert_eq!(content.rows, 1);
        assert_eq!(content.lines, vec![(0, 3)]);
        assert_eq!(content.tokens[0], vec![(0, 3), (1, 4)]);
        assert_eq!(content.cols, 2);
    }

    #[test]
    fn unterminated_last_row_token_ends_past_eof() {
        // "a,b" (no trailing newline): C++ advances `nPos + 1` past
        // EOF, so the final token end is o_size + 1.
        let content = parse(b"a,b");
        assert_eq!(content.rows, 1);
        assert_eq!(content.lines, vec![(0, 3)]);
        assert_eq!(content.tokens[0], vec![(0, 1), (2, 4)]);
    }

    #[test]
    fn empty_file_produces_one_quirk_row() {
        // The C++ do-while body runs once on an empty file.
        let content = parse(b"");
        assert_eq!(content.rows, 1);
        assert_eq!(content.cols, 2);
        assert_eq!(content.lines, vec![(0, 0)]);
        assert_eq!(content.tokens[0], vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn row_spanning_cache_window_parses_whole() {
        // One 200 KiB row across a 64 KiB cache window — the C++
        // implementation would split it at each window; the Rust
        // state machine must keep it as a single row (§3.3 fix).
        let row_len = 200 * 1024_usize;
        let mut data = vec![b'x'; row_len];
        // Sprinkle separators, including some far past the first
        // cache window.
        let sep_positions = [10_usize, 70_000, 150_000];
        for &pos in &sep_positions {
            data[pos] = b',';
        }
        data.push(b'\n');
        data.extend_from_slice(b"tail\n");

        let mut cache = cache_over(&data, 1);
        assert_eq!(cache.cache_size(), 0x10000); // 64 KiB window
        let content = process_content(&mut cache, &GridParseSettings::default());

        assert_eq!(content.rows, 2);
        assert_eq!(content.lines[0], (0, row_len as u64));
        assert_eq!(content.tokens[0].len(), 4);
        assert_eq!(content.tokens[0][0], (0, 10));
        assert_eq!(content.tokens[0][1], (11, 70_000));
        assert_eq!(content.tokens[0][2], (70_001, 150_000));
        assert_eq!(
            content.tokens[0][3],
            (150_001, row_len as u64 + 1) // past the newline
        );
        let tail_start = row_len as u64 + 1;
        assert_eq!(content.lines[1], (tail_start, tail_start + 4));
    }

    #[test]
    fn crlf_pair_split_across_chunk_boundary() {
        // '\r' as the last byte of the first 64 KiB chunk, '\n' as
        // the first byte of the next: one terminator, not two rows.
        let window = 0x10000_usize;
        let mut data = vec![b'x'; window - 1];
        data.push(b'\r');
        data.push(b'\n');
        data.extend_from_slice(b"next");
        let mut cache = cache_over(&data, 1);
        let content = process_content(&mut cache, &GridParseSettings::default());
        assert_eq!(content.rows, 2);
        assert_eq!(content.lines[0], (0, (window - 1) as u64));
        assert_eq!(content.lines[1], ((window + 1) as u64, (window + 5) as u64));
    }

    #[test]
    fn tab_separator_uses_first_byte_only() {
        let mut cache = cache_over(b"a\tb\tc\n", 1);
        let settings = GridParseSettings {
            separator: b'\t',
            quoted_fields: false,
        };
        let content = process_content(&mut cache, &settings);
        assert_eq!(content.tokens[0], vec![(0, 1), (2, 3), (4, 6)]);
        assert_eq!(content.cols, 3);
    }

    #[test]
    fn quoted_fields_mode_is_optional_and_off_by_default() {
        // Default (C++ parity): quotes are plain bytes, both commas
        // split — 3 cells.
        let content = parse(b"\"a,b\",c\n");
        assert_eq!(content.tokens[0].len(), 3);
        // Opt-in mode: the comma inside quotes does not split.
        let mut cache = cache_over(b"\"a,b\",c\n", 1);
        let settings = GridParseSettings {
            separator: b',',
            quoted_fields: true,
        };
        let content = process_content(&mut cache, &settings);
        assert_eq!(content.tokens[0], vec![(0, 5), (6, 8)]);
        assert_eq!(content.cols, 2);
    }

    #[test]
    fn quoted_newline_does_not_end_the_row() {
        let mut cache = cache_over(b"\"a\nb\",c\nd\n", 1);
        let settings = GridParseSettings {
            separator: b',',
            quoted_fields: true,
        };
        let content = process_content(&mut cache, &settings);
        assert_eq!(content.rows, 2);
        assert_eq!(content.lines[0], (0, 7));
        assert_eq!(content.tokens[0], vec![(0, 5), (6, 8)]);
    }

    #[test]
    fn hundred_mib_csv_row_50000_parses() {
        // 100 MiB of fixed-width rows through a 64 KiB cache window.
        let row = b"cell-one,cell-two,cell-three,0123456789abcdef\n"; // 46 bytes
        let row_len = row.len();
        let target = 100 * 1024 * 1024_usize;
        let row_count = target / row_len;
        let mut data = Vec::with_capacity(row_count * row_len);
        for _ in 0..row_count {
            data.extend_from_slice(row);
        }
        assert!(data.len() >= 100 * 1024 * 1024 - row_len);

        let mut cache = cache_over(&data, 1);
        let content = process_content(&mut cache, &GridParseSettings::default());

        assert_eq!(content.rows, row_count as u64);
        assert_eq!(content.cols, 4);
        // Row 50000 (0-based) sits at a deterministic offset.
        let base = 50_000 * row_len as u64;
        assert_eq!(content.lines[50_000], (base, base + row_len as u64 - 1));
        assert_eq!(
            content.tokens[50_000],
            vec![
                (base, base + 8),
                (base + 9, base + 17),
                (base + 18, base + 28),
                (base + 29, base + row_len as u64), // covers the newline
            ]
        );
    }
}
