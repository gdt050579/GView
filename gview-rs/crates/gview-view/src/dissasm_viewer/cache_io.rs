//! `DissasmViewer` sidecar cache persistence
//! (spec `02_VIEWER_DISSASM` cache persistence note, §11 Ctrl+S /
//! Escape `SaveCacheData`).
//!
//! C++ anchors: `DissasmCache` (`DissasmCache.hpp`,
//! `DissasmCache.cpp:11-125`), `DisassemblyZone::ToBuffer`
//! (`DissasmCache.cpp:127-141`), `Instance::LoadCacheData` /
//! `SaveCacheData` (`DissasmCache.cpp:143-181`),
//! `SettingsData::SaveToCache` / `ValidateCacheData`
//! (`DissasmCache.cpp:183-213`), `DissasmCodeZone::ToBuffer` /
//! `TryLoadDataFromCache` (`DissasmCache.cpp:215-256`),
//! `DissasmComments` / `AnnotationContainer` serialization
//! (`DissasmDataTypes.cpp:52-152`), LE primitives
//! (`DissasmIOHelpers.hpp`).
//!
//! File layout (`<analyzed file>.dissasm.cache`, all little-endian):
//!
//! ```text
//! u32 zonesCount
//! zonesCount x { u32 nameLen, name bytes, u32 dataLen, data bytes }
//! ```
//!
//! Regions: `DisassemblyZone.<start>` = MD5 hex of the zone bytes +
//! the raw 32-byte `DisassemblyZone` struct (validation fingerprint,
//! compared with `memcmp`), and `DissasmParseZoneType.<startLine>` =
//! serialized comments + annotations of a code zone. The MD5 digest
//! is supplied by the caller (see [`ZoneDigest`]) so this module
//! stays independent of the hashing crate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::zone::{
    AnnotationContainer, DisassemblyLanguage, DisassemblyZone, DissasmCodeZone, DissasmComments,
};

/// Cache file suffix appended to the analyzed file's path
/// (`DissasmCache.cpp:38`).
pub const CACHE_FILE_SUFFIX: &str = ".dissasm.cache";

// ------------------------------------------------------------------
// LE primitive helpers (DissasmIOHelpers.hpp)
// ------------------------------------------------------------------

fn append_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// C++ `append_string`: `u32` length prefix + raw bytes.
fn append_string(buffer: &mut Vec<u8>, s: &str) {
    append_u32(buffer, s.len() as u32);
    buffer.extend_from_slice(s.as_bytes());
}

/// Bounds-checked little-endian cursor (C++ `read_primitive` /
/// `read_bytes`).
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if len > self.remaining() {
            return None;
        }
        let end = self.pos.checked_add(len)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn read_u32(&mut self) -> Option<u32> {
        let b = self.read_bytes(4)?;
        Some(u32::from_le_bytes([
            *b.first()?,
            *b.get(1)?,
            *b.get(2)?,
            *b.get(3)?,
        ]))
    }

    fn read_u64(&mut self) -> Option<u64> {
        let lo = self.read_u32()?;
        let hi = self.read_u32()?;
        Some(u64::from(lo) | (u64::from(hi) << 32))
    }

    /// C++ `read_string_with_size`.
    fn read_string(&mut self) -> Option<String> {
        let len = self.read_u32()? as usize;
        let bytes = self.read_bytes(len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

// ------------------------------------------------------------------
// Comments / annotations serialization (DissasmDataTypes.cpp)
// ------------------------------------------------------------------

/// C++ `DissasmComments::GetRequiredSizeForSerialization`.
#[must_use]
pub fn comments_required_size(comments: &DissasmComments) -> u32 {
    comments.iter().fold(0_u32, |acc, (_, text)| {
        acc.saturating_add(4)
            .saturating_add(4)
            .saturating_add(text.len() as u32)
    })
}

/// C++ `DissasmComments::ToBuffer` (`DissasmDataTypes.cpp:61-67`):
/// `u32 count` then `{ u32 storedKey, u32 len, bytes }` per entry.
pub fn comments_to_buffer(comments: &DissasmComments, buffer: &mut Vec<u8>) {
    append_u32(buffer, comments.len() as u32);
    for (key, text) in comments.iter() {
        append_u32(buffer, *key);
        append_string(buffer, text);
    }
}

fn comments_load(cursor: &mut Cursor<'_>, comments: &mut DissasmComments) -> Option<()> {
    let mut count = cursor.read_u32()?;
    while count > 0 {
        let key = cursor.read_u32()?;
        let text = cursor.read_string()?;
        comments.insert_stored(key, text);
        count = count.saturating_sub(1);
    }
    Some(())
}

/// C++ `DissasmComments::LoadFromBuffer` (`DissasmDataTypes.cpp:69-91`):
/// entries are inserted at their **stored** keys. Returns the number
/// of bytes consumed, or `None` on a truncated buffer.
pub fn comments_from_buffer(data: &[u8], comments: &mut DissasmComments) -> Option<usize> {
    let mut cursor = Cursor::new(data);
    comments_load(&mut cursor, comments)?;
    Some(cursor.pos)
}

/// C++ `AnnotationContainer::GetRequiredSizeForSerialization`.
#[must_use]
pub fn annotations_required_size(annotations: &AnnotationContainer) -> u32 {
    let mut result: u32 = 3 * 4;
    for (name, _) in annotations.mappings.values() {
        result = result
            .saturating_add(4)
            .saturating_add(4)
            .saturating_add(name.len() as u32)
            .saturating_add(8);
    }
    for map in [
        &annotations.initial_name_to_current_name,
        &annotations.current_name_to_initial_name,
    ] {
        for (a, b) in map {
            result = result
                .saturating_add(4)
                .saturating_add(a.len() as u32)
                .saturating_add(4)
                .saturating_add(b.len() as u32);
        }
    }
    result
}

/// C++ `AnnotationContainer::ToBuffer` (`DissasmDataTypes.cpp:107-122`).
///
/// Mappings (`u32 line, str name, u64 value`) then the two rename
/// link maps (`u32 count, {str, str}...`). Hash-map order is
/// unspecified in both languages; the loader is order-agnostic.
pub fn annotations_to_buffer(annotations: &AnnotationContainer, buffer: &mut Vec<u8>) {
    append_u32(buffer, annotations.mappings.len() as u32);
    for (line, (name, value)) in &annotations.mappings {
        append_u32(buffer, *line);
        append_string(buffer, name);
        append_u64(buffer, *value);
    }
    for map in [
        &annotations.initial_name_to_current_name,
        &annotations.current_name_to_initial_name,
    ] {
        append_u32(buffer, map.len() as u32);
        for (a, b) in map {
            append_string(buffer, a);
            append_string(buffer, b);
        }
    }
}

fn annotations_load(cursor: &mut Cursor<'_>, annotations: &mut AnnotationContainer) -> Option<()> {
    let mut count = cursor.read_u32()?;
    while count > 0 {
        let line = cursor.read_u32()?;
        let name = cursor.read_string()?;
        let value = cursor.read_u64()?;
        annotations.mappings.insert(line, (name, value));
        count = count.saturating_sub(1);
    }
    for map_index in 0..2 {
        let mut entries = cursor.read_u32()?;
        while entries > 0 {
            let a = cursor.read_string()?;
            let b = cursor.read_string()?;
            if map_index == 0 {
                annotations.initial_name_to_current_name.insert(a, b);
            } else {
                annotations.current_name_to_initial_name.insert(a, b);
            }
            entries = entries.saturating_sub(1);
        }
    }
    Some(())
}

/// C++ `AnnotationContainer::LoadFromBuffer`
/// (`DissasmDataTypes.cpp:124-152`). Returns bytes consumed.
pub fn annotations_from_buffer(
    data: &[u8],
    annotations: &mut AnnotationContainer,
) -> Option<usize> {
    let mut cursor = Cursor::new(data);
    annotations_load(&mut cursor, annotations)?;
    Some(cursor.pos)
}

// ------------------------------------------------------------------
// DissasmCache (DissasmCache.cpp)
// ------------------------------------------------------------------

/// The in-memory sidecar cache (C++ `DissasmCache`).
#[derive(Clone, Debug, Default)]
pub struct DissasmCache {
    /// Set once a loaded file passed validation (C++ `hasCache`).
    pub has_cache: bool,
    /// Region name → raw bytes (C++ `zonesData`).
    pub zones_data: HashMap<String, Vec<u8>>,
}

impl DissasmCache {
    /// C++ `ClearCache(forceClear)` (`DissasmCache.cpp:11-17`): a
    /// cache that never validated is left alone unless forced.
    pub fn clear_cache(&mut self, force_clear: bool) {
        if !self.has_cache && !force_clear {
            return;
        }
        self.zones_data.clear();
    }

    /// C++ `AddRegion` (`DissasmCache.cpp:19-27`): `false` when the
    /// name already exists.
    pub fn add_region(&mut self, region_name: &str, data: &[u8]) -> bool {
        if self.zones_data.contains_key(region_name) {
            return false;
        }
        self.zones_data
            .insert(region_name.to_owned(), data.to_vec());
        true
    }

    /// C++ `GetCacheFilePath` (`DissasmCache.cpp:29-37`): the analyzed
    /// file's path (or `"."` when caching in the working directory)
    /// plus [`CACHE_FILE_SUFFIX`].
    #[must_use]
    pub fn get_cache_file_path(
        file_location: &str,
        cache_same_location_as_analyzed_file: bool,
    ) -> PathBuf {
        let base = if cache_same_location_as_analyzed_file {
            file_location
        } else {
            "."
        };
        PathBuf::from(format!("{base}{CACHE_FILE_SUFFIX}"))
    }

    /// C++ `SaveCacheFile` serialization (`DissasmCache.cpp:39-62`);
    /// `None` when there is nothing to save.
    #[must_use]
    pub fn serialize(&self) -> Option<Vec<u8>> {
        if self.zones_data.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        append_u32(&mut out, self.zones_data.len() as u32);
        for (name, entry) in &self.zones_data {
            append_string(&mut out, name);
            append_u32(&mut out, entry.len() as u32);
            out.extend_from_slice(entry);
        }
        Some(out)
    }

    /// C++ `SaveCacheFile` (`DissasmCache.cpp:39-62`): `false` when
    /// empty or the write fails.
    #[must_use]
    pub fn save_cache_file(&self, location: &Path) -> bool {
        let Some(bytes) = self.serialize() else {
            return false;
        };
        std::fs::write(location, bytes).is_ok()
    }

    /// C++ `LoadCacheFile` parsing (`DissasmCache.cpp:64-125`).
    ///
    /// An empty file is accepted as "no data"; a truncated entry, a
    /// size that overruns the buffer, or more entries than
    /// `zonesCount` announced fails. Entries load into `zones_data` as
    /// they are parsed (a later failure leaves the earlier ones in
    /// place, as in C++ — callers clear on failure).
    pub fn deserialize(&mut self, buffer: &[u8]) -> bool {
        if buffer.is_empty() {
            return true;
        }
        if buffer.len() < 4 {
            return false;
        }
        let mut cursor = Cursor::new(buffer);
        let Some(mut zones_count) = cursor.read_u32() else {
            return false;
        };
        while cursor.remaining() > 0 {
            if zones_count == 0 {
                return false;
            }
            zones_count = zones_count.saturating_sub(1);
            let Some(name) = cursor.read_string() else {
                return false;
            };
            let Some(size) = cursor.read_u32() else {
                return false;
            };
            let Some(data) = cursor.read_bytes(size as usize) else {
                return false;
            };
            self.zones_data.insert(name, data.to_vec());
        }
        true
    }

    /// C++ `LoadCacheFile` (`DissasmCache.cpp:64-125`).
    pub fn load_cache_file(&mut self, location: &Path) -> bool {
        std::fs::read(location).is_ok_and(|bytes| self.deserialize(&bytes))
    }
}

// ------------------------------------------------------------------
// Zone fingerprints and code-zone payloads
// ------------------------------------------------------------------

/// Supplies the MD5 hex fingerprint of a zone's bytes.
///
/// C++ `Hashes::OpenSSLHash(Md5).GetHexValue()` — uppercase hex.
/// Returns `None` when the zone data cannot be read (C++ `ToBuffer`
/// fails on an empty read).
pub type ZoneDigest<'a> = dyn Fn(&DisassemblyZone) -> Option<String> + 'a;

/// `DisassemblyLanguage` as the C++ `uint32` enum value.
const fn language_value(language: DisassemblyLanguage) -> u32 {
    match language {
        DisassemblyLanguage::Default => 0,
        DisassemblyLanguage::X86 => 1,
        DisassemblyLanguage::X64 => 2,
        DisassemblyLanguage::JavaByteCode => 3,
    }
}

const fn language_from_value(value: u32) -> Option<DisassemblyLanguage> {
    match value {
        0 => Some(DisassemblyLanguage::Default),
        1 => Some(DisassemblyLanguage::X86),
        2 => Some(DisassemblyLanguage::X64),
        3 => Some(DisassemblyLanguage::JavaByteCode),
        _ => None,
    }
}

/// C++ `DisassemblyZone::ToBuffer` (`DissasmCache.cpp:127-141`).
///
/// The digest hex followed by the raw struct image — three `u64`,
/// the `u32` language and 4 padding bytes (`sizeof(DisassemblyZone)`
/// = 32). `None` when the digest is unavailable.
#[must_use]
pub fn disassembly_zone_to_buffer(
    zone: &DisassemblyZone,
    digest: &ZoneDigest<'_>,
) -> Option<Vec<u8>> {
    let hex = digest(zone)?;
    let mut out = Vec::with_capacity(hex.len().saturating_add(32));
    out.extend_from_slice(hex.as_bytes());
    append_u64(&mut out, zone.starting_zone_point);
    append_u64(&mut out, zone.size);
    append_u64(&mut out, zone.entry_point);
    append_u32(&mut out, language_value(zone.language));
    append_u32(&mut out, 0); // struct tail padding
    Some(out)
}

/// Parses the struct image written by [`disassembly_zone_to_buffer`]
/// (after a `digest_len`-byte hex prefix) — inverse used by tests and
/// tooling; the C++ code only ever `memcmp`s the image.
#[must_use]
pub fn disassembly_zone_from_buffer(buffer: &[u8], digest_len: usize) -> Option<DisassemblyZone> {
    let mut cursor = Cursor::new(buffer.get(digest_len..)?);
    let starting_zone_point = cursor.read_u64()?;
    let size = cursor.read_u64()?;
    let entry_point = cursor.read_u64()?;
    let language = language_from_value(cursor.read_u32()?)?;
    Some(DisassemblyZone {
        starting_zone_point,
        size,
        entry_point,
        language,
    })
}

/// C++ region name for a plugin-declared zone (`DissasmCache.cpp:189`).
#[must_use]
pub fn disassembly_zone_region_name(start: u64) -> String {
    format!("DisassemblyZone.{start}")
}

/// C++ region name for a code zone's payload (`DissasmCache.cpp:169`,
/// `241`).
#[must_use]
pub fn code_zone_region_name(start_line_index: u32) -> String {
    format!("DissasmParseZoneType.{start_line_index}")
}

/// C++ `SettingsData::SaveToCache` (`DissasmCache.cpp:183-195`): one
/// fingerprint region per declared zone; `false` on the first
/// failure (unreadable zone or duplicate name).
pub fn save_to_cache(
    cache: &mut DissasmCache,
    disassembly_zones: &[(u64, DisassemblyZone)],
    digest: &ZoneDigest<'_>,
) -> bool {
    for (start, zone) in disassembly_zones {
        let Some(buffer) = disassembly_zone_to_buffer(zone, digest) else {
            return false;
        };
        if !cache.add_region(&disassembly_zone_region_name(*start), &buffer) {
            return false;
        }
    }
    true
}

/// C++ `SettingsData::ValidateCacheData` (`DissasmCache.cpp:197-213`):
/// every declared zone must have a region whose bytes `memcmp`-equal
/// a freshly computed fingerprint.
pub fn validate_cache_data(
    cache: &DissasmCache,
    disassembly_zones: &[(u64, DisassemblyZone)],
    digest: &ZoneDigest<'_>,
) -> bool {
    for (start, zone) in disassembly_zones {
        let Some(entry) = cache
            .zones_data
            .get(&disassembly_zone_region_name(*start))
        else {
            return false;
        };
        let Some(buffer) = disassembly_zone_to_buffer(zone, digest) else {
            return false;
        };
        if entry.len() != buffer.len() || *entry != buffer {
            return false;
        }
    }
    true
}

/// C++ `DissasmCodeZone::ToBuffer` (`DissasmCache.cpp:215-226`):
/// comments then annotations of the root region.
#[must_use]
pub fn code_zone_to_buffer(zone: &DissasmCodeZone) -> Vec<u8> {
    let reserve = comments_required_size(&zone.dissasm_type.comments_data)
        .saturating_add(annotations_required_size(&zone.dissasm_type.annotations));
    let mut buffer = Vec::with_capacity(reserve as usize);
    comments_to_buffer(&zone.dissasm_type.comments_data, &mut buffer);
    annotations_to_buffer(&zone.dissasm_type.annotations, &mut buffer);
    buffer
}

/// C++ `DissasmCodeZone::TryLoadDataFromCache`
/// (`DissasmCache.cpp:228-256`): `true` when the cache is absent
/// (nothing to do) or the zone's region loaded; `false` when the
/// region is missing or malformed.
pub fn try_load_code_zone_from_cache(zone: &mut DissasmCodeZone, cache: &DissasmCache) -> bool {
    if !cache.has_cache {
        return true;
    }
    let Some(data) = cache
        .zones_data
        .get(&code_zone_region_name(zone.zone.start_line_index))
    else {
        return false;
    };
    if data.len() < 4 {
        return false;
    }
    let mut cursor = Cursor::new(data);
    if comments_load(&mut cursor, &mut zone.dissasm_type.comments_data).is_none() {
        return false;
    }
    annotations_load(&mut cursor, &mut zone.dissasm_type.annotations).is_some()
}

/// C++ `Instance::SaveCacheData` region assembly
/// (`DissasmCache.cpp:158-181`).
///
/// Fingerprints for every declared zone plus one payload region per
/// code zone. Returns the assembled cache, or `None` on any failure.
#[must_use]
pub fn build_cache(
    disassembly_zones: &[(u64, DisassemblyZone)],
    code_zones: &[&DissasmCodeZone],
    digest: &ZoneDigest<'_>,
) -> Option<DissasmCache> {
    let mut cache = DissasmCache::default();
    if !save_to_cache(&mut cache, disassembly_zones, digest) {
        return None;
    }
    for zone in code_zones {
        let buffer = code_zone_to_buffer(zone);
        if !cache.add_region(&code_zone_region_name(zone.zone.start_line_index), &buffer) {
            return None;
        }
    }
    Some(cache)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unnecessary_wraps)] // must match the `ZoneDigest` signature
    fn fixed_digest(_: &DisassemblyZone) -> Option<String> {
        Some("D41D8CD98F00B204E9800998ECF8427E".to_owned())
    }

    fn sample_zone() -> DisassemblyZone {
        DisassemblyZone {
            starting_zone_point: 0x400,
            size: 0x1000,
            entry_point: 0x420,
            language: DisassemblyLanguage::X86,
        }
    }

    #[test]
    fn comments_roundtrip_at_stored_keys() {
        let mut comments = DissasmComments::default();
        comments.add_or_update_comment(5, "alpha".to_owned());
        comments.add_or_update_comment(20, "beta".to_owned());
        let mut buffer = Vec::new();
        comments_to_buffer(&comments, &mut buffer);
        assert_eq!(buffer.len() as u32, 4 + comments_required_size(&comments));
        let mut loaded = DissasmComments::default();
        let consumed = comments_from_buffer(&buffer, &mut loaded).expect("valid");
        assert_eq!(consumed, buffer.len());
        assert_eq!(loaded.get_comment(5), Some("alpha"));
        assert_eq!(loaded.get_comment(20), Some("beta"));
        // Truncated buffer → None.
        let short = &buffer[..buffer.len() - 2];
        assert!(comments_from_buffer(short, &mut DissasmComments::default()).is_none());
    }

    #[test]
    fn annotations_roundtrip_with_name_links() {
        let mut ann = AnnotationContainer::default();
        ann.mappings
            .insert(12, ("sub_0x000000420".to_owned(), 0x420));
        ann.mappings.insert(30, ("EntryPoint".to_owned(), 0x400));
        ann.add_initial_name("sub_0x000000420");
        ann.initial_name_to_current_name
            .insert("sub_0x000000420".to_owned(), "my_func".to_owned());
        let mut buffer = Vec::new();
        annotations_to_buffer(&ann, &mut buffer);
        assert_eq!(buffer.len() as u32, annotations_required_size(&ann));
        let mut loaded = AnnotationContainer::default();
        assert_eq!(
            annotations_from_buffer(&buffer, &mut loaded),
            Some(buffer.len())
        );
        assert_eq!(
            loaded.mappings.get(&12),
            Some(&("sub_0x000000420".to_owned(), 0x420))
        );
        assert_eq!(
            loaded.mappings.get(&30).map(|(n, _)| n.as_str()),
            Some("EntryPoint")
        );
        assert_eq!(
            loaded
                .initial_name_to_current_name
                .get("sub_0x000000420")
                .map(String::as_str),
            Some("my_func")
        );
        assert_eq!(loaded.current_name_to_initial_name.len(), 1);
    }

    #[test]
    fn cache_file_roundtrip_serialize_deserialize() {
        let mut cache = DissasmCache::default();
        assert!(cache.add_region("DisassemblyZone.1024", b"fingerprint"));
        assert!(cache.add_region("DissasmParseZoneType.7", &[1, 2, 3]));
        assert!(!cache.add_region("DissasmParseZoneType.7", &[9])); // duplicate
        let bytes = cache.serialize().expect("non-empty");
        let mut loaded = DissasmCache::default();
        assert!(loaded.deserialize(&bytes));
        assert_eq!(loaded.zones_data.len(), 2);
        assert_eq!(loaded.zones_data["DisassemblyZone.1024"], b"fingerprint");
        assert_eq!(loaded.zones_data["DissasmParseZoneType.7"], vec![1, 2, 3]);
        // Empty cache: nothing to save.
        assert!(DissasmCache::default().serialize().is_none());
        // Empty file: accepted with no data.
        assert!(DissasmCache::default().deserialize(&[]));
    }

    #[test]
    fn deserialize_rejects_malformed_input() {
        // Too short for the count.
        assert!(!DissasmCache::default().deserialize(&[1, 2]));
        // Count says 1 entry but two follow → extra entry rejected.
        let mut cache = DissasmCache::default();
        cache.add_region("a", b"x");
        cache.add_region("b", b"y");
        let mut bytes = cache.serialize().unwrap();
        bytes[0] = 1; // zonesCount = 1
        assert!(!DissasmCache::default().deserialize(&bytes));
        // Truncated data → rejected.
        let mut cache = DissasmCache::default();
        cache.add_region("a", b"xyz");
        let mut truncated = cache.serialize().unwrap();
        truncated.truncate(truncated.len() - 1);
        assert!(!DissasmCache::default().deserialize(&truncated));
    }

    #[test]
    fn validate_cache_data_memcmp() {
        let zones = vec![(0x400_u64, sample_zone())];
        let mut cache = DissasmCache::default();
        assert!(save_to_cache(&mut cache, &zones, &fixed_digest));
        assert!(validate_cache_data(&cache, &zones, &fixed_digest));
        // A different digest (zone bytes changed) → mismatch.
        let other = |_: &DisassemblyZone| Some("00000000000000000000000000000000".to_owned());
        assert!(!validate_cache_data(&cache, &zones, &other));
        // A changed zone struct → mismatch.
        let mut changed = zones.clone();
        changed[0].1.entry_point = 0x999;
        assert!(!validate_cache_data(&cache, &changed, &fixed_digest));
        // Missing region → invalid; unreadable zone → invalid.
        assert!(!validate_cache_data(&DissasmCache::default(), &zones, &fixed_digest));
        let unreadable = |_: &DisassemblyZone| None;
        assert!(!validate_cache_data(&cache, &zones, &unreadable));
    }

    #[test]
    fn zone_fingerprint_layout_is_32_bytes_after_digest() {
        let buffer = disassembly_zone_to_buffer(&sample_zone(), &fixed_digest).unwrap();
        assert_eq!(buffer.len(), 32 + 32);
        let parsed = disassembly_zone_from_buffer(&buffer, 32).unwrap();
        assert_eq!(parsed.starting_zone_point, 0x400);
        assert_eq!(parsed.size, 0x1000);
        assert_eq!(parsed.entry_point, 0x420);
        assert_eq!(parsed.language, DisassemblyLanguage::X86);
        // Padding bytes are zero.
        assert_eq!(&buffer[60..64], &[0, 0, 0, 0]);
    }

    #[test]
    fn code_zone_payload_roundtrip_through_cache() {
        let mut zone = DissasmCodeZone::default();
        zone.zone.start_line_index = 7;
        zone.dissasm_type
            .comments_data
            .add_or_update_comment(3, "check".to_owned());
        zone.dissasm_type
            .annotations
            .mappings
            .insert(2, ("sub_0x000000400".to_owned(), 0x400));
        let zones = vec![(0x400_u64, sample_zone())];
        let cache = build_cache(&zones, &[&zone], &fixed_digest).expect("cache");
        let bytes = cache.serialize().unwrap();

        let mut loaded = DissasmCache::default();
        assert!(loaded.deserialize(&bytes));
        assert!(validate_cache_data(&loaded, &zones, &fixed_digest));
        loaded.has_cache = true;

        let mut fresh = DissasmCodeZone::default();
        fresh.zone.start_line_index = 7;
        assert!(try_load_code_zone_from_cache(&mut fresh, &loaded));
        assert_eq!(
            fresh.dissasm_type.comments_data.get_comment(3),
            Some("check")
        );
        assert!(fresh.dissasm_type.annotations.mappings.contains_key(&2));
        // A zone with no region fails; no cache at all is a no-op success.
        let mut other = DissasmCodeZone::default();
        other.zone.start_line_index = 99;
        assert!(!try_load_code_zone_from_cache(&mut other, &loaded));
        assert!(try_load_code_zone_from_cache(&mut other, &DissasmCache::default()));
    }

    #[test]
    fn clear_cache_respects_has_cache_unless_forced() {
        let mut cache = DissasmCache::default();
        cache.add_region("a", b"x");
        cache.clear_cache(false);
        assert_eq!(cache.zones_data.len(), 1); // never validated: kept
        cache.clear_cache(true);
        assert!(cache.zones_data.is_empty());
    }

    #[test]
    fn cache_path_follows_analyzed_file_or_cwd() {
        assert_eq!(
            DissasmCache::get_cache_file_path("C:/samples/a.exe", true),
            PathBuf::from("C:/samples/a.exe.dissasm.cache")
        );
        assert_eq!(
            DissasmCache::get_cache_file_path("C:/samples/a.exe", false),
            PathBuf::from("..dissasm.cache")
        );
    }

    #[test]
    fn save_and_load_sidecar_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("gview_dissasm_cache_test.dissasm.cache");
        let mut cache = DissasmCache::default();
        cache.add_region("DisassemblyZone.1", b"abc");
        assert!(cache.save_cache_file(&path));
        let mut loaded = DissasmCache::default();
        assert!(loaded.load_cache_file(&path));
        assert_eq!(loaded.zones_data["DisassemblyZone.1"], b"abc");
        std::fs::remove_file(&path).ok();
        assert!(!loaded.load_cache_file(&path)); // missing file
    }
}
