//! Instance configuration loaded from the `GView` INI file
//! (C++ `Instance::LoadSettings`, `Instance.cpp:88-127`; defaults in
//! `Instance.cpp:13-14`).
//!
//! Only the cache-size setting is modeled here; plugin sections and
//! key bindings are consumed by their own subsystems.
//!
//! C++ parity notes:
//! - The loader reads the **literal key** `Config.CacheSize` from
//!   section `[GView]` (`Instance.cpp:119`; `AppCUI` INI keys have no
//!   dot hierarchy), while the default settings writer emits the key
//!   `CacheSize` (`GViewApp.cpp:105`) — so the generated default file
//!   never actually overrides the built-in default. Preserved as-is.
//! - The value is clamped below by `MIN_CACHE_SIZE`
//!   (`std::max`, `Instance.cpp:119`); the upper bound
//!   `MAX_CACHE_SIZE` is enforced here too (C++ applies it later in
//!   `DataCache::Init`, so the end result is identical).
//! - Hardening (spec/matrix requirement, stricter than the C++
//!   `File::ReadContent` cap of `0xFFFFFFF` bytes whose error message
//!   misleadingly says `0xFFFFF`): a config file larger than 1 MiB is
//!   rejected outright.

use std::path::Path;

use crate::constants::{DEFAULT_CACHE_SIZE, MAX_CACHE_SIZE, MIN_CACHE_SIZE};

/// Maximum accepted size of a configuration file (1 MiB).
pub const MAX_CONFIG_FILE_SIZE: u64 = 0x10_0000;

/// Validated cache-size setting, always within
/// `[MIN_CACHE_SIZE, MAX_CACHE_SIZE]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheSize(u32);

impl CacheSize {
    /// Clamps `requested` into `[MIN_CACHE_SIZE, MAX_CACHE_SIZE]`.
    #[must_use]
    pub const fn clamped(requested: u32) -> Self {
        if requested < MIN_CACHE_SIZE {
            Self(MIN_CACHE_SIZE)
        } else if requested > MAX_CACHE_SIZE {
            Self(MAX_CACHE_SIZE)
        } else {
            Self(requested)
        }
    }

    /// The clamped byte count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for CacheSize {
    /// `DEFAULT_CACHE_SIZE` (10 MiB, `Instance.cpp:13`).
    fn default() -> Self {
        Self(DEFAULT_CACHE_SIZE)
    }
}

/// Errors from [`Config::load_from_file`].
#[derive(Debug)]
pub enum ConfigError {
    /// The file exceeds [`MAX_CONFIG_FILE_SIZE`].
    FileTooLarge {
        /// Actual size of the rejected file.
        size: u64,
    },
    /// The file could not be read.
    Io(std::io::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileTooLarge { size } => write!(
                f,
                "config file is {size} bytes; maximum accepted is {MAX_CONFIG_FILE_SIZE}"
            ),
            Self::Io(e) => write!(f, "cannot read config file: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::FileTooLarge { .. } => None,
        }
    }
}

/// Loaded instance settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Default cache size for newly opened objects.
    pub cache_size: CacheSize,
}

impl Config {
    /// Loads settings from an INI file, rejecting files larger than
    /// [`MAX_CONFIG_FILE_SIZE`].
    ///
    /// # Errors
    /// [`ConfigError::FileTooLarge`] for an oversized file,
    /// [`ConfigError::Io`] when the file cannot be read.
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let meta = std::fs::metadata(path).map_err(ConfigError::Io)?;
        if meta.len() > MAX_CONFIG_FILE_SIZE {
            return Err(ConfigError::FileTooLarge { size: meta.len() });
        }
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Ok(Self::from_ini_str(&text))
    }

    /// Parses settings from INI text. Unknown sections/keys are
    /// ignored; a missing or unparsable value falls back to the
    /// default (C++ `ToUInt32(DEFAULT_CACHE_SIZE)`).
    #[must_use]
    pub fn from_ini_str(text: &str) -> Self {
        let raw = ini_lookup(text, "GView", "Config.CacheSize")
            .and_then(parse_u32)
            .unwrap_or(DEFAULT_CACHE_SIZE);
        Self {
            cache_size: CacheSize::clamped(raw),
        }
    }
}

/// Minimal INI scan: finds `key = value` inside `[section]`.
/// Section and key names compare case-insensitively (`AppCUI` hashes
/// keys case-insensitively); `;` and `#` start comments.
fn ini_lookup<'a>(text: &'a str, section: &str, key: &str) -> Option<&'a str> {
    let mut in_section = false;
    for raw_line in text.lines() {
        let line = raw_line
            .split_once([';', '#'])
            .map_or(raw_line, |(before, _)| before)
            .trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = name.trim().eq_ignore_ascii_case(section);
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim().eq_ignore_ascii_case(key) {
                return Some(v.trim());
            }
        }
    }
    None
}

/// Parses a decimal or `0x`-prefixed hexadecimal u32.
fn parse_u32(value: &str) -> Option<u32> {
    let value = value.trim();
    value.strip_prefix("0x").map_or_else(
        || {
            value.strip_prefix("0X").map_or_else(
                || value.parse().ok(),
                |hex| u32::from_str_radix(hex, 16).ok(),
            )
        },
        |hex| u32::from_str_radix(hex, 16).ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ten_mib() {
        assert_eq!(Config::default().cache_size.get(), DEFAULT_CACHE_SIZE);
        assert_eq!(CacheSize::default().get(), 0x00A0_0000);
    }

    #[test]
    fn parses_cache_size_from_gview_section() {
        let cfg = Config::from_ini_str("[GView]\nConfig.CacheSize = 0x2000000\n");
        assert_eq!(cfg.cache_size.get(), 0x0200_0000);
        let cfg = Config::from_ini_str("[gview]\nconfig.cachesize = 1048576 ; comment\n");
        assert_eq!(cfg.cache_size.get(), 0x0010_0000);
    }

    #[test]
    fn key_outside_section_ignored() {
        // The same key in another section (or before any section) does
        // not count.
        let cfg = Config::from_ini_str(
            "Config.CacheSize = 0x40000\n[Other]\nConfig.CacheSize = 0x40000\n",
        );
        assert_eq!(cfg.cache_size.get(), DEFAULT_CACHE_SIZE);
    }

    #[test]
    fn plain_cache_size_key_is_not_read() {
        // C++ parity quirk: the loader looks for the literal key
        // "Config.CacheSize"; the "CacheSize" key that GViewApp.cpp
        // writes into the default settings file is ignored.
        let cfg = Config::from_ini_str("[GView]\nCacheSize = 0x40000\n");
        assert_eq!(cfg.cache_size.get(), DEFAULT_CACHE_SIZE);
    }

    #[test]
    fn clamps_min_and_max() {
        let cfg = Config::from_ini_str("[GView]\nConfig.CacheSize = 100\n");
        assert_eq!(cfg.cache_size.get(), MIN_CACHE_SIZE);
        let cfg = Config::from_ini_str("[GView]\nConfig.CacheSize = 0xFFFFFFFF\n");
        assert_eq!(cfg.cache_size.get(), MAX_CACHE_SIZE);
    }

    #[test]
    fn invalid_or_missing_value_falls_back() {
        let cfg = Config::from_ini_str("[GView]\nConfig.CacheSize = banana\n");
        assert_eq!(cfg.cache_size.get(), DEFAULT_CACHE_SIZE);
        let cfg = Config::from_ini_str("[GView]\n");
        assert_eq!(cfg.cache_size.get(), DEFAULT_CACHE_SIZE);
        let cfg = Config::from_ini_str("");
        assert_eq!(cfg.cache_size.get(), DEFAULT_CACHE_SIZE);
    }

    #[test]
    fn rejects_config_file_over_one_mib() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("big.ini");
        // 1 MiB + 1 byte of comment padding.
        let mut text = String::from("[GView]\n;");
        text.push_str(&"x".repeat(0x10_0000));
        std::fs::write(&path, &text).expect("write");
        assert!(matches!(
            Config::load_from_file(&path),
            Err(ConfigError::FileTooLarge { .. })
        ));
    }

    #[test]
    fn loads_small_config_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("gview.ini");
        std::fs::write(&path, "[GView]\nConfig.CacheSize = 0x300000\n").expect("write");
        let cfg = Config::load_from_file(&path).expect("load");
        assert_eq!(cfg.cache_size.get(), 0x0030_0000);
    }

    #[test]
    fn missing_file_is_io_error() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let missing = dir.path().join("none.ini");
        assert!(matches!(
            Config::load_from_file(&missing),
            Err(ConfigError::Io(_))
        ));
    }
}
