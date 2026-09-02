//! `[SmartAssistants]` INI section (`QueryInterface.cpp`
//! `SmartAssistantPromptInterfaceProxy::Start`, spec §2.1, §2.2, §2.4).
//!
//! ```ini
//! [SmartAssistants]
//! GPT4o = sk-...
//! GeminiPro1.5 = AIza...
//! PromptRetries = 1
//! ```
//!
//! Each assistant's token lives under a key equal to its registered
//! name. `PromptRetries` is read with `IniValue::AsUInt32` (decimal or
//! `0x` hexadecimal); anything unparsable leaves the default in place.
//! Key and section names compare case-insensitively (`AppCUI` hashes
//! INI keys case-insensitively).

use std::collections::BTreeMap;

use crate::{PROMPT_RETRIES_KEY, SMART_ASSISTANTS_SECTION};

/// Parsed `[SmartAssistants]` section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssistantConfig {
    /// Whether the section exists at all (`settings->HasSection`).
    pub has_section: bool,
    /// `PromptRetries` when present and parsable.
    pub prompt_retries: Option<u32>,
    /// Lower-cased key → raw value for every other entry.
    tokens: BTreeMap<String, String>,
}

impl AssistantConfig {
    /// Parses the `[SmartAssistants]` section out of INI text. Missing
    /// section → `has_section == false` and no tokens.
    #[must_use]
    pub fn from_ini_str(text: &str) -> Self {
        let mut cfg = Self::default();
        let mut in_section = false;
        for raw_line in text.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                in_section = name.trim().eq_ignore_ascii_case(SMART_ASSISTANTS_SECTION);
                if in_section {
                    cfg.has_section = true;
                }
                continue;
            }
            if !in_section {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = unquote(value.trim());
            if key.is_empty() {
                continue;
            }
            if key.eq_ignore_ascii_case(PROMPT_RETRIES_KEY) {
                cfg.prompt_retries = parse_u32(value);
            } else {
                cfg.tokens.insert(key.to_ascii_lowercase(), value.to_owned());
            }
        }
        cfg
    }

    /// Raw token for an assistant name (case-insensitive). `Some("")`
    /// when the key exists with an empty value — the caller treats that
    /// as *not configured* like the C++ `strlen(actualValue) == 0`.
    #[must_use]
    pub fn token(&self, assistant_name: &str) -> Option<&str> {
        self.tokens
            .get(&assistant_name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Number of token entries (excluding `PromptRetries`).
    #[must_use]
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }
}

/// Drops a `;` / `#` comment that starts at the beginning of the line
/// or after whitespace. A `#` glued to a value (as may appear inside
/// an API token) is kept.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b';' || b == b'#' {
            let at_start = i == 0;
            let after_space = i
                .checked_sub(1)
                .and_then(|p| bytes.get(p))
                .is_some_and(u8::is_ascii_whitespace);
            if at_start || after_space {
                return line.get(..i).unwrap_or("");
            }
        }
    }
    line
}

/// Removes one pair of matching surrounding quotes (`"…"` or `'…'`).
fn unquote(value: &str) -> &str {
    let stripped = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')));
    stripped.unwrap_or(value)
}

/// Decimal or `0x`-prefixed hexadecimal `u32`.
fn parse_u32(value: &str) -> Option<u32> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse().ok(), |hex| u32::from_str_radix(hex, 16).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_section_yields_defaults() {
        let cfg = AssistantConfig::from_ini_str("[GView]\nGPT4o = nope\n");
        assert!(!cfg.has_section);
        assert_eq!(cfg.prompt_retries, None);
        assert_eq!(cfg.token("GPT4o"), None);
        assert_eq!(cfg.token_count(), 0);
    }

    #[test]
    fn reads_tokens_and_retries_case_insensitively() {
        let cfg = AssistantConfig::from_ini_str(
            "[smartassistants]\nGPT4o = \"sk-a#b\"   ; comment\ngeminipro1.5='g'\npromptretries = 0x2\n",
        );
        assert!(cfg.has_section);
        assert_eq!(cfg.prompt_retries, Some(2));
        assert_eq!(cfg.token("gpt4o"), Some("sk-a#b"));
        assert_eq!(cfg.token("GeminiPro1.5"), Some("g"));
        assert_eq!(cfg.token_count(), 2);
    }

    #[test]
    fn empty_value_is_reported_as_empty_string() {
        let cfg = AssistantConfig::from_ini_str("[SmartAssistants]\nGPT4o =\n");
        assert_eq!(cfg.token("GPT4o"), Some(""));
    }

    #[test]
    fn unparsable_retries_are_ignored() {
        let cfg = AssistantConfig::from_ini_str("[SmartAssistants]\nPromptRetries = many\n");
        assert!(cfg.has_section);
        assert_eq!(cfg.prompt_retries, None);
        let cfg = AssistantConfig::from_ini_str("[SmartAssistants]\nPromptRetries = 7\n");
        assert_eq!(cfg.prompt_retries, Some(7));
    }

    #[test]
    fn only_the_assistant_section_is_read() {
        let cfg = AssistantConfig::from_ini_str("[Other]\nGPT4o = x\n[SmartAssistants]\n[Third]\nGPT4o = y\n");
        assert!(cfg.has_section);
        assert_eq!(cfg.token("GPT4o"), None);
    }

    #[test]
    fn comment_and_quote_helpers() {
        assert_eq!(strip_comment("# whole"), "");
        assert_eq!(strip_comment("a=b ;c"), "a=b ");
        assert_eq!(strip_comment("a=b#c"), "a=b#c");
        assert_eq!(unquote("\"x\""), "x");
        assert_eq!(unquote("'x'"), "x");
        assert_eq!(unquote("\"x'"), "\"x'");
        assert_eq!(parse_u32(" 0X10 "), Some(16));
        assert_eq!(parse_u32("-1"), None);
    }
}
