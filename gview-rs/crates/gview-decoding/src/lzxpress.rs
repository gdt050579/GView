//! LZXPRESS Huffman (MS-XCA "LZ77+Huffman") decompression
//! (spec `04_SERVICES` §4.1–4.2, §4.4).
//!
//! C++ anchor: `GView::Decoding::LZXPRESS::Huffman::Decompress`
//! (`LZXPRESS.cpp`). On Windows the C++ calls
//! `RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF)` and only
//! falls back to its own port of `libfwnt` elsewhere; the OS routine
//! implements [MS-XCA] §2.2 exactly, so that algorithm is the ground
//! truth ported here (cross-checked against samba's bit-exact
//! `lzxpress_huffman.c`):
//!
//! - the stream is a sequence of **64 KiB output blocks**
//!   ([`CHUNK_SIZE`]); each block starts with a 256-byte table of
//!   512 nibble code lengths ([`SYMBOLS_ARRAY_SIZE`], max length
//!   [`MAXIMUM_CODE_SIZE`]) from which a canonical Huffman code is
//!   built (codes assigned by increasing length, then symbol);
//! - bits are read from a 32-bit window fed with little-endian
//!   16-bit words, refilled whenever fewer than 16 bits remain
//!   (`ExtraBits < 0`); raw length-extension bytes are read from the
//!   byte cursor, which runs ahead of the bit window;
//! - symbols `< 256` are literals; `symbol - 256` packs
//!   `length = low nibble` (15 → +byte, 270 → u16, 0 → u32 as in
//!   `libfwnt`/Windows 10) and `offset_bits = high nibble`
//!   (`offset = (1 << bits) | bits-from-stream`), `length += 3`;
//! - a block ends when its 64 KiB are produced; the next table starts
//!   at the byte cursor as it stands (prefetched words count). The
//!   encoder writes the EOF symbol (256) only in the final block, and
//!   the decoder stops at the expected size without needing it.
//!
//! Discrepancies with the C++ fallback (`Decompress_FallBack`) are
//! deliberate: that path calls `Stream::Read(maximumCodeSize)` /
//! `Read(bitsToRead)` — which overwrite the *code size* with a stream
//! byte instead of refilling the bit window — and consumes the match
//! offset bits before the length-extension bytes, so it cannot decode
//! what `RtlCompressBuffer` produces. The Windows path (and this
//! port) read the length bytes first (MS-XCA §2.2.4).
//!
//! Hardening: the expected output size is checked against
//! [`LzxpressLimits::max_output_size`] **before** allocation (spec
//! §4.4 / §9.2); every match is bounds-checked against the bytes
//! produced so far and the remaining output; a block needs
//! [`MIN_CHUNK_INPUT`] bytes (C++ `CHECK(remaining >= 260)`); any
//! read past the input is an error instead of an OOB access.

/// Bytes of output per Huffman table (C++ `CHUNK_SIZE`).
pub const CHUNK_SIZE: usize = 0x1_0000;
/// Longest Huffman code (C++ `MAXIMUM_CODE_SIZE`).
pub const MAXIMUM_CODE_SIZE: u32 = 15;
/// Alphabet size: 256 literals + 256 match symbols
/// (C++ `SYMBOLS_ARRAY_SIZE`).
pub const SYMBOLS_ARRAY_SIZE: usize = 512;
/// First match symbol (C++ `SYMBOL_MAX_SIZE`).
pub const SYMBOL_MAX_SIZE: u32 = 256;
/// Bytes of packed code lengths at the start of every block.
pub const HUFFMAN_TABLE_BYTES: usize = SYMBOLS_ARRAY_SIZE / 2;
/// Smallest input a block can start with: the table plus the 32-bit
/// window prefetch (C++ `CHECK((size - offset) >= 260)`).
pub const MIN_CHUNK_INPUT: usize = HUFFMAN_TABLE_BYTES + 4;
/// Largest accepted input (C++ `CHECK(size <= INT32_MAX)`).
pub const MAX_INPUT_SIZE: usize = i32::MAX as usize;

const LOOKUP_BITS: u32 = MAXIMUM_CODE_SIZE;
const LOOKUP_SIZE: usize = 1 << LOOKUP_BITS;
const WINDOW_BITS: u32 = 32;
const WORD_BITS: i32 = 16;

/// Output-size policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LzxpressLimits {
    /// Hard cap on the expected (and therefore allocated) output.
    pub max_output_size: u64,
}

impl Default for LzxpressLimits {
    /// 256 MiB.
    fn default() -> Self {
        Self {
            max_output_size: 256 * 1024 * 1024,
        }
    }
}

/// Decompression failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LzxpressError {
    /// Empty compressed input (C++ `CHECK(_stream != nullptr)`).
    EmptyInput,
    /// Input larger than [`MAX_INPUT_SIZE`].
    InputTooLarge {
        /// Actual input length.
        size: usize,
    },
    /// Expected output larger than the configured cap.
    OutputLimitExceeded {
        /// The configured cap.
        limit: u64,
    },
    /// A block header or a bit/byte read ran past the input.
    TruncatedInput {
        /// Byte offset the read was attempted at.
        offset: usize,
    },
    /// Over-subscribed or empty code-length table
    /// (C++ `HuffmanTree::Build` `CHECK(leftValue >= 0)`).
    InvalidHuffmanTable {
        /// Byte offset of the offending table.
        offset: usize,
    },
    /// The bit pattern matches no code in the current table.
    InvalidSymbol {
        /// Byte offset of the reader when the lookup failed.
        offset: usize,
    },
    /// A back-reference before the output start or past its end.
    InvalidMatch {
        /// Output position of the match.
        position: usize,
        /// Match distance (bytes back).
        distance: usize,
        /// Match length.
        length: u64,
    },
    /// Input ended before the expected output was produced
    /// (C++ `CHECK(decompressed.GetLength() == offset)`).
    SizeMismatch {
        /// Expected output size.
        expected: usize,
        /// Bytes actually produced.
        produced: usize,
    },
}

impl core::fmt::Display for LzxpressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty input"),
            Self::InputTooLarge { size } => write!(f, "input of {size} bytes exceeds {MAX_INPUT_SIZE}"),
            Self::OutputLimitExceeded { limit } => write!(f, "output exceeds {limit} bytes"),
            Self::TruncatedInput { offset } => write!(f, "input truncated at offset {offset}"),
            Self::InvalidHuffmanTable { offset } => write!(f, "invalid Huffman table at offset {offset}"),
            Self::InvalidSymbol { offset } => write!(f, "invalid Huffman code near offset {offset}"),
            Self::InvalidMatch {
                position,
                distance,
                length,
            } => write!(
                f,
                "invalid match at output {position}: distance {distance}, length {length}"
            ),
            Self::SizeMismatch { expected, produced } => {
                write!(f, "expected {expected} bytes, produced {produced}")
            }
        }
    }
}

impl std::error::Error for LzxpressError {}

/// One canonical-code lookup entry: `symbol << 4 | length`
/// (length 0 = no code maps here).
#[derive(Clone, Copy, Default)]
struct Entry(u16);

impl Entry {
    const fn new(symbol: u16, length: u8) -> Self {
        Self((symbol << 4) | (length as u16 & 0x0F))
    }

    const fn length(self) -> u32 {
        (self.0 & 0x0F) as u32
    }

    const fn symbol(self) -> u32 {
        (self.0 >> 4) as u32
    }
}

/// MS-XCA `DecodingTable`: indexed by the next 15 bits of the stream.
struct DecodeTable {
    entries: Vec<Entry>,
}

impl DecodeTable {
    fn new() -> Self {
        Self {
            entries: vec![Entry::default(); LOOKUP_SIZE],
        }
    }

    /// Builds the canonical code from the 512 nibble lengths
    /// (MS-XCA §2.2.4 step 1; C++ `HuffmanTree::Build`).
    fn build(&mut self, lengths: &[u8; SYMBOLS_ARRAY_SIZE], table_offset: usize) -> Result<(), LzxpressError> {
        let invalid = LzxpressError::InvalidHuffmanTable { offset: table_offset };
        self.entries.fill(Entry::default());

        // Code-length histogram (a nibble never exceeds 15).
        let mut counts = [0_u32; MAXIMUM_CODE_SIZE as usize + 1];
        for &len in lengths {
            let Some(slot) = counts.get_mut(usize::from(len)) else {
                return Err(invalid);
            };
            *slot = slot.saturating_add(1);
        }
        if counts.first().copied() == Some(SYMBOLS_ARRAY_SIZE as u32) {
            return Err(invalid);
        }

        // Kraft check: the code must not be over-subscribed.
        let mut left: i64 = 1;
        for &count in counts.iter().skip(1) {
            left = left.saturating_mul(2).saturating_sub(i64::from(count));
            if left < 0 {
                return Err(invalid);
            }
        }

        // First code of every length (DEFLATE-style canonical order:
        // increasing length, then increasing symbol).
        let mut next_code = [0_u32; MAXIMUM_CODE_SIZE as usize + 1];
        let mut code = 0_u32;
        for len in 1..=MAXIMUM_CODE_SIZE as usize {
            // Unused symbols (length 0) do not occupy code space.
            let prev = if len == 1 {
                0
            } else {
                counts.get(len.wrapping_sub(1)).copied().unwrap_or(0)
            };
            code = code.saturating_add(prev) << 1;
            if let Some(slot) = next_code.get_mut(len) {
                *slot = code;
            }
        }

        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let Some(slot) = next_code.get_mut(usize::from(len)) else {
                return Err(invalid);
            };
            let code = *slot;
            *slot = slot.saturating_add(1);
            let shift = LOOKUP_BITS.saturating_sub(u32::from(len));
            let start = (code << shift) as usize;
            let span = 1_usize << shift;
            let end = start.saturating_add(span);
            let Some(range) = self.entries.get_mut(start..end) else {
                return Err(invalid);
            };
            range.fill(Entry::new(symbol as u16, len));
        }
        Ok(())
    }

    fn lookup(&self, next15: u32) -> Option<Entry> {
        self.entries.get(next15 as usize).copied().filter(|e| e.length() != 0)
    }
}

/// MS-XCA bit window: 32 bits, MSB-first, fed from little-endian
/// 16-bit words; raw bytes are read from the same cursor.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    window: u32,
    extra_bits: i32,
}

impl<'a> BitReader<'a> {
    /// `NextBits = Read16 << 16 | Read16; ExtraBits = 16`.
    fn new(data: &'a [u8], pos: usize) -> Result<Self, LzxpressError> {
        let mut reader = Self {
            data,
            pos,
            window: 0,
            extra_bits: WORD_BITS,
        };
        let high = u32::from(reader.read_u16()?);
        let low = u32::from(reader.read_u16()?);
        reader.window = (high << 16) | low;
        Ok(reader)
    }

    const fn position(&self) -> usize {
        self.pos
    }

    fn read_u8(&mut self) -> Result<u8, LzxpressError> {
        let byte = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(LzxpressError::TruncatedInput { offset: self.pos })?;
        self.pos = self.pos.saturating_add(1);
        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16, LzxpressError> {
        let lo = self.read_u8()?;
        let hi = self.read_u8()?;
        Ok(u16::from_le_bytes([lo, hi]))
    }

    fn read_u32(&mut self) -> Result<u32, LzxpressError> {
        let lo = self.read_u16()?;
        let hi = self.read_u16()?;
        Ok((u32::from(hi) << 16) | u32::from(lo))
    }

    /// The next `n` (0..=15) bits without consuming them.
    const fn peek(&self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.window >> WINDOW_BITS.saturating_sub(n)
        }
    }

    /// `NextBits <<= n; ExtraBits -= n; refill when ExtraBits < 0`.
    fn consume(&mut self, n: u32) -> Result<(), LzxpressError> {
        if n == 0 {
            return Ok(());
        }
        self.window <<= n;
        self.extra_bits = self.extra_bits.saturating_sub(n.cast_signed());
        if self.extra_bits < 0 {
            let shift = self.extra_bits.unsigned_abs();
            let word = u32::from(self.read_u16()?);
            self.window |= word << shift;
            self.extra_bits = self.extra_bits.saturating_add(WORD_BITS);
        }
        Ok(())
    }
}

/// Reads the 256-byte nibble table at `pos` (`codeSizes[i++] = v & 0x0f;
/// codeSizes[i++] = v >> 4`).
fn read_code_lengths(data: &[u8], pos: usize) -> Result<[u8; SYMBOLS_ARRAY_SIZE], LzxpressError> {
    let end = pos.saturating_add(HUFFMAN_TABLE_BYTES);
    let table = data
        .get(pos..end)
        .ok_or(LzxpressError::TruncatedInput { offset: pos })?;
    let mut lengths = [0_u8; SYMBOLS_ARRAY_SIZE];
    for (i, &byte) in table.iter().enumerate() {
        let idx = i.saturating_mul(2);
        if let Some(slot) = lengths.get_mut(idx) {
            *slot = byte & 0x0F;
        }
        if let Some(slot) = lengths.get_mut(idx.saturating_add(1)) {
            *slot = byte >> 4;
        }
    }
    Ok(lengths)
}

/// Decodes one block starting at `pos`, writing at `out[*out_pos..]`
/// until the block's 64 KiB are produced or `out` is full. Returns
/// the input position after the block.
fn decode_chunk(
    data: &[u8],
    pos: usize,
    table: &mut DecodeTable,
    out: &mut [u8],
    out_pos: &mut usize,
) -> Result<usize, LzxpressError> {
    if data.len().saturating_sub(pos) < MIN_CHUNK_INPUT {
        return Err(LzxpressError::TruncatedInput { offset: pos });
    }
    let lengths = read_code_lengths(data, pos)?;
    table.build(&lengths, pos)?;

    let mut reader = BitReader::new(data, pos.saturating_add(HUFFMAN_TABLE_BYTES))?;
    let chunk_end = out_pos.saturating_add(CHUNK_SIZE).min(out.len());

    while *out_pos < chunk_end {
        let entry = table
            .lookup(reader.peek(LOOKUP_BITS))
            .ok_or_else(|| LzxpressError::InvalidSymbol {
                offset: reader.position(),
            })?;
        reader.consume(entry.length())?;
        let symbol = entry.symbol();

        if symbol < SYMBOL_MAX_SIZE {
            if let Some(slot) = out.get_mut(*out_pos) {
                *slot = symbol as u8;
            }
            *out_pos = out_pos.saturating_add(1);
            continue;
        }

        // Match: length nibble (+ extensions from the byte cursor),
        // then the offset bits from the window (MS-XCA §2.2.4).
        let packed = symbol.saturating_sub(SYMBOL_MAX_SIZE);
        let mut length = u64::from(packed & 0x0F);
        let offset_bits = packed >> 4;
        if length == 15 {
            length = length.saturating_add(u64::from(reader.read_u8()?));
            if length == 270 {
                length = u64::from(reader.read_u16()?);
                if length == 0 {
                    length = u64::from(reader.read_u32()?);
                }
            }
        }
        length = length.saturating_add(3);

        let low = reader.peek(offset_bits);
        reader.consume(offset_bits)?;
        let distance = ((1_u32 << offset_bits) | low) as usize;

        let position = *out_pos;
        let remaining = out.len().saturating_sub(position) as u64;
        if distance > position || distance == 0 || length > remaining {
            return Err(LzxpressError::InvalidMatch {
                position,
                distance,
                length,
            });
        }
        let src = position.saturating_sub(distance);
        // Byte-by-byte: the source may overlap the destination.
        for i in 0..length as usize {
            let byte = out.get(src.saturating_add(i)).copied().unwrap_or(0);
            if let Some(slot) = out.get_mut(position.saturating_add(i)) {
                *slot = byte;
            }
        }
        *out_pos = position.saturating_add(length as usize);
    }
    Ok(reader.position())
}

/// Decompresses `compressed` into `out`, which must be exactly the
/// expected uncompressed size (C++ `Decompress(compressed,
/// decompressed)`; the caller sizes the buffer).
///
/// # Errors
///
/// Any [`LzxpressError`]; in particular
/// [`LzxpressError::SizeMismatch`] when the input ends before `out`
/// is full.
pub fn decompress_into(compressed: &[u8], out: &mut [u8]) -> Result<(), LzxpressError> {
    if compressed.is_empty() {
        return Err(LzxpressError::EmptyInput);
    }
    if compressed.len() > MAX_INPUT_SIZE {
        return Err(LzxpressError::InputTooLarge {
            size: compressed.len(),
        });
    }
    let mut table = DecodeTable::new();
    let mut pos = 0_usize;
    let mut out_pos = 0_usize;
    while pos < compressed.len() && out_pos < out.len() {
        pos = decode_chunk(compressed, pos, &mut table, out, &mut out_pos)?;
    }
    if out_pos != out.len() {
        return Err(LzxpressError::SizeMismatch {
            expected: out.len(),
            produced: out_pos,
        });
    }
    Ok(())
}

/// Decompresses `compressed` to exactly `uncompressed_size` bytes,
/// refusing sizes above [`LzxpressLimits::max_output_size`] before
/// allocating anything.
///
/// # Errors
///
/// [`LzxpressError::OutputLimitExceeded`] for an oversized request,
/// otherwise as [`decompress_into`].
pub fn decompress(
    compressed: &[u8],
    uncompressed_size: u64,
    limits: LzxpressLimits,
) -> Result<Vec<u8>, LzxpressError> {
    if uncompressed_size > limits.max_output_size {
        return Err(LzxpressError::OutputLimitExceeded {
            limit: limits.max_output_size,
        });
    }
    let size = usize::try_from(uncompressed_size).map_err(|_| LzxpressError::OutputLimitExceeded {
        limit: limits.max_output_size,
    })?;
    let mut out = vec![0_u8; size];
    decompress_into(compressed, &mut out)?;
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
mod tests {
    use super::*;

    /// Test-only MS-XCA encoder (§2.2.3 bit discipline, as in samba's
    /// `write_bits`): two 16-bit slots are reserved ahead of the raw
    /// bytes; a word is flushed into the older slot once more than 16
    /// bits accumulate and a new slot is reserved at the current end.
    struct Encoder {
        out: Vec<u8>,
        acc: u64,
        nacc: u32,
        slot1: usize,
        slot2: usize,
    }

    #[derive(Clone, Copy)]
    enum Token {
        Lit(u8),
        Match { length: u32, distance: u32 },
    }

    impl Encoder {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                acc: 0,
                nacc: 0,
                slot1: 0,
                slot2: 0,
            }
        }

        fn begin_chunk(&mut self, lengths: &[u8; SYMBOLS_ARRAY_SIZE]) {
            for pair in lengths.chunks(2) {
                self.out.push(pair[0] | (pair[1] << 4));
            }
            self.slot1 = self.out.len();
            self.out.extend_from_slice(&[0, 0]);
            self.slot2 = self.out.len();
            self.out.extend_from_slice(&[0, 0]);
            self.acc = 0;
            self.nacc = 0;
        }

        fn put_word(&mut self, slot: usize, word: u16) {
            let [lo, hi] = word.to_le_bytes();
            self.out[slot] = lo;
            self.out[slot + 1] = hi;
        }

        fn write_bits(&mut self, n: u32, value: u32) {
            if n == 0 {
                return;
            }
            self.acc = (self.acc << n) | u64::from(value);
            self.nacc += n;
            if self.nacc > 16 {
                let word = (self.acc >> (self.nacc - 16)) as u16;
                self.put_word(self.slot1, word);
                self.slot1 = self.slot2;
                self.slot2 = self.out.len();
                self.out.extend_from_slice(&[0, 0]);
                self.nacc -= 16;
                self.acc &= (1_u64 << self.nacc) - 1;
            }
        }

        /// Block flush: the pending bits padded into the older slot,
        /// the newer slot stays a zero word.
        fn end_chunk(&mut self) {
            let word = if self.nacc == 0 {
                0
            } else {
                (self.acc << (16 - self.nacc)) as u16
            };
            self.put_word(self.slot1, word);
            self.nacc = 0;
            self.acc = 0;
        }

        fn symbol(&mut self, codes: &Codes, symbol: usize) {
            let (code, len) = codes.0[symbol];
            assert!(len > 0, "symbol {symbol} has no code");
            self.write_bits(len, code);
        }

        fn token(&mut self, codes: &Codes, token: Token) {
            match token {
                Token::Lit(b) => self.symbol(codes, usize::from(b)),
                Token::Match { length, distance } => {
                    assert!(length >= 3 && distance >= 1);
                    let len = length - 3;
                    let mut bits = 0_u32;
                    while (distance >> (bits + 1)) != 0 {
                        bits += 1;
                    }
                    let low = distance & ((1 << bits) - 1);
                    let nibble = len.min(15);
                    self.symbol(codes, 256 + ((bits as usize) << 4) + nibble as usize);
                    if len >= 15 {
                        let rest = len - 15;
                        if rest < 255 {
                            self.out.push(rest as u8);
                        } else {
                            self.out.push(255);
                            if len <= 0xFFFF {
                                self.out.extend_from_slice(&(len as u16).to_le_bytes());
                            } else {
                                self.out.extend_from_slice(&[0, 0]);
                                self.out.extend_from_slice(&len.to_le_bytes());
                            }
                        }
                    }
                    self.write_bits(bits, low);
                }
            }
        }
    }

    /// Canonical codes for a length table: `(code, len)` per symbol.
    struct Codes([(u32, u32); SYMBOLS_ARRAY_SIZE]);

    fn canonical(lengths: &[u8; SYMBOLS_ARRAY_SIZE]) -> Codes {
        let mut codes = [(0_u32, 0_u32); SYMBOLS_ARRAY_SIZE];
        let mut code = 0_u32;
        for len in 1..=15_u8 {
            for (symbol, &l) in lengths.iter().enumerate() {
                if l == len {
                    codes[symbol] = (code, u32::from(len));
                    code += 1;
                }
            }
            code <<= 1;
        }
        Codes(codes)
    }

    fn flat_lengths() -> [u8; SYMBOLS_ARRAY_SIZE] {
        [9; SYMBOLS_ARRAY_SIZE]
    }

    fn encode_chunks(chunks: &[Vec<Token>], lengths: &[u8; SYMBOLS_ARRAY_SIZE]) -> Vec<u8> {
        let codes = canonical(lengths);
        let mut enc = Encoder::new();
        let last = chunks.len().saturating_sub(1);
        for (i, chunk) in chunks.iter().enumerate() {
            enc.begin_chunk(lengths);
            for &t in chunk {
                enc.token(&codes, t);
            }
            if i == last {
                // Windows writes the EOF symbol only in the final block;
                // intermediate blocks just pad and flush.
                enc.symbol(&codes, 256);
            }
            enc.end_chunk();
        }
        enc.out
    }

    fn literals(data: &[u8]) -> Vec<Token> {
        data.iter().map(|&b| Token::Lit(b)).collect()
    }

    #[test]
    fn hand_packed_flat_table_golden_chunk() {
        // All 512 symbols have 9-bit codes, so symbol s has code s.
        // "abc" = 0x61 0x62 0x63 -> 001100001 001100010 001100011 ...
        // then EOF 100000000. Bits (MSB-first, 16-bit LE words):
        // 0011000010011000 1000110001110000 0000000000000000 ...
        let mut data = vec![0x99_u8; HUFFMAN_TABLE_BYTES];
        let words: [u16; 3] = [0b0011_0000_1001_1000, 0b1000_1100_0111_0000, 0];
        for w in words {
            data.extend_from_slice(&w.to_le_bytes());
        }
        let out = decompress(&data, 3, LzxpressLimits::default()).expect("decode");
        assert_eq!(out, b"abc");
    }

    #[test]
    fn hand_packed_variable_lengths_golden_chunk() {
        // 'a' = 1 bit (0), 'b' = 2 bits (10), EOF(256) = 2 bits (11).
        let mut lengths = [0_u8; SYMBOLS_ARRAY_SIZE];
        lengths[b'a' as usize] = 1;
        lengths[b'b' as usize] = 2;
        lengths[256] = 2;
        let mut data = Vec::new();
        for pair in lengths.chunks(2) {
            data.push(pair[0] | (pair[1] << 4));
        }
        // "aab" + EOF -> 0 0 10 11 -> 0010 1100 0000 0000 = 0x2C00
        data.extend_from_slice(&0x2C00_u16.to_le_bytes());
        data.extend_from_slice(&[0, 0]);
        let out = decompress(&data, 3, LzxpressLimits::default()).expect("decode");
        assert_eq!(out, b"aab");
    }

    #[test]
    fn matches_roundtrip_with_every_length_encoding() {
        // Literal "abcd", then repeats of increasing length using the
        // nibble, byte, u16 and u32 length encodings.
        let mut expected = b"abcd".to_vec();
        let mut tokens = literals(b"abcd");
        for (length, distance) in [(3_u32, 4_u32), (17, 4), (200, 3), (300, 7), (1000, 1)] {
            tokens.push(Token::Match { length, distance });
            for _ in 0..length {
                let b = expected[expected.len() - distance as usize];
                expected.push(b);
            }
        }
        let data = encode_chunks(&[tokens], &flat_lengths());
        let out = decompress(&data, expected.len() as u64, LzxpressLimits::default()).expect("decode");
        assert_eq!(out, expected);
    }

    #[test]
    fn u32_length_extension_is_honored() {
        // A match longer than 0xFFFF forces the u32 extension; the
        // match may span past the block boundary (decoder tolerates
        // it, capped at the output end).
        let length = 0x1_0010_u32;
        let mut expected = vec![b'x'];
        expected.extend(std::iter::repeat_n(b'x', length as usize));
        let tokens = vec![Token::Lit(b'x'), Token::Match { length, distance: 1 }];
        let data = encode_chunks(&[tokens], &flat_lengths());
        let out = decompress(&data, expected.len() as u64, LzxpressLimits::default()).expect("decode");
        assert_eq!(out, expected);
    }

    #[test]
    fn chunk_size_0x10000_starts_a_new_table() {
        let first: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
        let second = b"tail!".to_vec();
        let data = encode_chunks(&[literals(&first), literals(&second)], &flat_lengths());
        let mut expected = first;
        expected.extend_from_slice(&second);
        let out = decompress(&data, expected.len() as u64, LzxpressLimits::default()).expect("decode");
        assert_eq!(out.len(), CHUNK_SIZE + 5);
        assert_eq!(out, expected);

        // The second block's table starts exactly where the first
        // block's bit stream ended: 65536 nine-bit codes = 589824 bits
        // = 2 prefetched words + floor((589824 - 1) / 16) refills.
        let first_bits = CHUNK_SIZE * 9;
        let first_words = 2 + (first_bits - 1) / 16;
        let second_table = HUFFMAN_TABLE_BYTES + first_words * 2;
        assert_eq!(second_table, 73986);
        assert_eq!(
            &data[second_table..second_table + HUFFMAN_TABLE_BYTES],
            &[0x99; HUFFMAN_TABLE_BYTES][..]
        );

        // Corrupting that table (over-subscribed 1-bit codes) must be
        // reported at exactly that offset: the decoder re-reads it there.
        let mut corrupted = data;
        corrupted[second_table] = 0x11;
        assert_eq!(
            decompress(&corrupted, expected.len() as u64, LzxpressLimits::default()),
            Err(LzxpressError::InvalidHuffmanTable { offset: second_table })
        );
    }

    #[test]
    fn output_cap_is_checked_before_allocation() {
        let data = vec![0x99_u8; MIN_CHUNK_INPUT];
        let limits = LzxpressLimits { max_output_size: 16 };
        assert_eq!(
            decompress(&data, 17, limits),
            Err(LzxpressError::OutputLimitExceeded { limit: 16 })
        );
        assert_eq!(
            decompress(&data, u64::MAX, LzxpressLimits::default()),
            Err(LzxpressError::OutputLimitExceeded {
                limit: LzxpressLimits::default().max_output_size
            })
        );
    }

    #[test]
    fn empty_and_short_inputs_are_rejected() {
        let mut out = [0_u8; 4];
        assert_eq!(decompress_into(&[], &mut out), Err(LzxpressError::EmptyInput));
        assert_eq!(
            decompress_into(&[0x99; MIN_CHUNK_INPUT - 1], &mut out),
            Err(LzxpressError::TruncatedInput { offset: 0 })
        );
    }

    #[test]
    fn oversubscribed_and_empty_tables_are_rejected() {
        let mut out = [0_u8; 4];
        // Every symbol with a 1-bit code: Kraft sum 256 > 1.
        let data = vec![0x11_u8; MIN_CHUNK_INPUT];
        assert_eq!(
            decompress_into(&data, &mut out),
            Err(LzxpressError::InvalidHuffmanTable { offset: 0 })
        );
        let data = vec![0_u8; MIN_CHUNK_INPUT];
        assert_eq!(
            decompress_into(&data, &mut out),
            Err(LzxpressError::InvalidHuffmanTable { offset: 0 })
        );
    }

    #[test]
    fn incomplete_code_space_yields_invalid_symbol() {
        // Only 'a' has a (1-bit) code; the '1' prefix maps nowhere.
        let mut lengths = [0_u8; SYMBOLS_ARRAY_SIZE];
        lengths[b'a' as usize] = 1;
        let mut data = Vec::new();
        for pair in lengths.chunks(2) {
            data.push(pair[0] | (pair[1] << 4));
        }
        data.extend_from_slice(&0x8000_u16.to_le_bytes()); // first bit 1
        data.extend_from_slice(&[0, 0]);
        let mut out = [0_u8; 1];
        assert!(matches!(
            decompress_into(&data, &mut out),
            Err(LzxpressError::InvalidSymbol { .. })
        ));
    }

    #[test]
    fn match_before_output_start_is_rejected() {
        let tokens = vec![Token::Lit(b'a'), Token::Match { length: 3, distance: 2 }];
        let data = encode_chunks(&[tokens], &flat_lengths());
        assert_eq!(
            decompress(&data, 4, LzxpressLimits::default()),
            Err(LzxpressError::InvalidMatch {
                position: 1,
                distance: 2,
                length: 3
            })
        );
    }

    #[test]
    fn match_past_output_end_is_rejected() {
        let tokens = vec![Token::Lit(b'a'), Token::Match { length: 10, distance: 1 }];
        let data = encode_chunks(&[tokens], &flat_lengths());
        assert_eq!(
            decompress(&data, 5, LzxpressLimits::default()),
            Err(LzxpressError::InvalidMatch {
                position: 1,
                distance: 1,
                length: 10
            })
        );
    }

    #[test]
    fn declared_size_larger_than_stream_fails_closed() {
        let data = encode_chunks(&[literals(b"abc")], &flat_lengths());
        let err = decompress(&data, 64, LzxpressLimits::default()).expect_err("too short");
        assert!(matches!(
            err,
            LzxpressError::TruncatedInput { .. }
                | LzxpressError::SizeMismatch { .. }
                | LzxpressError::InvalidMatch { .. }
        ));
    }

    #[test]
    fn declared_size_smaller_than_stream_stops_early() {
        let data = encode_chunks(&[literals(b"abcdef")], &flat_lengths());
        let out = decompress(&data, 4, LzxpressLimits::default()).expect("decode");
        assert_eq!(out, b"abcd");
    }

    #[test]
    fn many_chunks_with_random_like_content_roundtrip() {
        let total = CHUNK_SIZE * 2 + 777;
        let mut state = 0x1234_5678_u32;
        let data: Vec<u8> = (0..total)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        let chunks: Vec<Vec<Token>> = data.chunks(CHUNK_SIZE).map(literals).collect();
        let packed = encode_chunks(&chunks, &flat_lengths());
        let out = decompress(&packed, total as u64, LzxpressLimits::default()).expect("decode");
        assert_eq!(out, data);
    }

    #[test]
    fn constants_match_cpp() {
        assert_eq!(CHUNK_SIZE, 0x10000);
        assert_eq!(MAXIMUM_CODE_SIZE, 15);
        assert_eq!(SYMBOLS_ARRAY_SIZE, 512);
        assert_eq!(MIN_CHUNK_INPUT, 260);
    }
}
