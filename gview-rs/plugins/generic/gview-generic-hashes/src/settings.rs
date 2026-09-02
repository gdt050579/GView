//! `[Generic.Hashes]` persistence (`SetFlagsFromSettings`,
//! `SetSettingsFromFlags`, `UpdateSettings`).
//!
//! Each algorithm has a `Types.<NAME>` boolean; `UpdateSettings`
//! writes them all as `true`. Reading: every entry of the section is
//! visited, non-boolean values are skipped (`AsBool` has no value),
//! `false` entries are skipped, unknown keys are ignored. Booleans
//! follow `AppCUI` `IniValue::AsBool`: `1`/`0`, `on`/`no`,
//! `yes`/`off`, `true`/`false`, case-insensitive.

use crate::compute::{HashFlags, HASH_LIST};

/// Section name.
pub const SECTION: &str = "Generic.Hashes";

/// `SetFlagsFromSettings`: the enabled algorithms in `[Generic.Hashes]`
/// of `ini_text` (empty when the section is missing).
#[must_use]
pub fn flags_from_ini_str(ini_text: &str) -> HashFlags {
    let mut flags = HashFlags::NONE;
    let mut in_section = false;
    for raw_line in ini_text.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = name.trim().eq_ignore_ascii_case(SECTION);
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(true) = parse_bool(value.trim()) else {
            continue;
        };
        let key = key.trim();
        if let Some(kind) = HASH_LIST.iter().copied().find(|k| k.ini_key().eq_ignore_ascii_case(key)) {
            flags = flags.with(kind);
        }
    }
    flags
}

/// `SetSettingsFromFlags`: the `Types.<NAME> = true|false` lines for
/// every algorithm, in `hashList` order.
#[must_use]
pub fn flags_to_ini_lines(flags: HashFlags) -> Vec<String> {
    HASH_LIST
        .iter()
        .map(|kind| format!("{} = {}", kind.ini_key(), flags.contains(*kind)))
        .collect()
}

/// `UpdateSettings` defaults: every algorithm enabled.
#[must_use]
pub const fn default_flags() -> HashFlags {
    HashFlags::ALL
}

/// `AppCUI` `IniValue_ToBool`.
#[must_use]
pub fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "on" | "yes" | "true" => Some(true),
        "0" | "no" | "off" | "false" => Some(false),
        _ => None,
    }
}

fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if (b == b';' || b == b'#')
            && (i == 0
                || i
                    .checked_sub(1)
                    .and_then(|p| bytes.get(p))
                    .is_some_and(u8::is_ascii_whitespace))
        {
            return line.get(..i).unwrap_or("");
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::HashKind;

    #[test]
    fn reads_enabled_types_only() {
        let ini = "[Generic.Hashes]\nTypes.Adler32 = true\nTypes.CRC16 = false\ntypes.sha256 = YES\nTypes.MD5 = maybe\nTypes.Unknown = true\n[Other]\nTypes.SHA1 = true\n";
        let flags = flags_from_ini_str(ini);
        assert_eq!(flags, HashKind::Adler32.flag().with(HashKind::Sha256));
        assert_eq!(flags_from_ini_str(""), HashFlags::NONE);
        assert_eq!(flags_from_ini_str("[Generic.Hashes]\nTypes.SHA1 = 1 ; on\n"), HashKind::Sha1.flag());
    }

    #[test]
    fn writes_every_type() {
        let lines = flags_to_ini_lines(HashKind::Sha1.flag());
        assert_eq!(lines.len(), 22);
        assert_eq!(lines.first().map(String::as_str), Some("Types.Adler32 = false"));
        assert!(lines.contains(&"Types.SHA1 = true".to_owned()));
        assert_eq!(default_flags(), HashFlags::ALL);
        // Round trip.
        let text = format!("[Generic.Hashes]\n{}\n", lines.join("\n"));
        assert_eq!(flags_from_ini_str(&text), HashKind::Sha1.flag());
    }

    #[test]
    fn bool_parsing_matches_appcui() {
        for v in ["1", "on", "ON", "yes", "True"] {
            assert_eq!(parse_bool(v), Some(true), "{v}");
        }
        for v in ["0", "no", "OFF", "false", "FaLsE"] {
            assert_eq!(parse_bool(v), Some(false), "{v}");
        }
        assert_eq!(parse_bool("truthy"), None);
        assert_eq!(parse_bool(""), None);
    }
}
